"use client"

import { useState, useRef, useMemo, useCallback, useEffect } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn, formatTime, formatTimestamp, streamConversationKey } from "@/lib/utils"
import { useVirtualizer } from "@tanstack/react-virtual"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Search, X, Bookmark, Code, FileText, ChevronDown, ChevronRight } from "lucide-react"
import type { AnalysisPacket } from "@/lib/analysis"

const COLUMNS = [
  { key: "num", label: "#", width: "minmax(32px, 48px)", grow: false },
  { key: "time", label: "Time", width: "minmax(80px, 110px)", grow: false },
  { key: "src", label: "Source", width: "minmax(110px, 1.5fr)", grow: true },
  { key: "dst", label: "Destination", width: "minmax(110px, 1.5fr)", grow: true },
  { key: "sport", label: "SPort", width: "minmax(50px, 70px)", grow: false },
  { key: "dport", label: "DPort", width: "minmax(50px, 70px)", grow: false },
  { key: "proto", label: "Proto", width: "minmax(56px, 72px)", grow: false },
  { key: "len", label: "Len", width: "minmax(40px, 55px)", grow: false },
  { key: "info", label: "Info", width: "minmax(140px, 2fr)", grow: true },
]

function formatHexDump(num: number, length: number): string {
  // ponytail: AnalysisPacket carries no payload bytes — the old dump
  // fabricated `(num*256+i)%256` from the packet number, fake data that
  // never existed. The honest statement is what we have, no made-up hex.
  void num
  return `Payload bytes are not retained in this analysis (${length} bytes captured).`
}

interface ProtocolTreeNode {
  label: string
  value: string
  children?: ProtocolTreeNode[]
}

function buildProtocolTree(p: AnalysisPacket): ProtocolTreeNode[] {
  const tree: ProtocolTreeNode[] = []
  tree.push({ label: "Frame", value: `Length: ${p.length} bytes` })
  if (p.srcIp || p.dstIp) {
    const ipChildren = [
      { label: "Src IP", value: p.srcIp || "" },
      { label: "Dst IP", value: p.dstIp || "" },
    ]
    tree.push({ label: (p.srcIp || p.dstIp || "").includes(":") ? "IPv6" : "IPv4", value: "", children: ipChildren })
  }
  if (p.protocol === "TCP" || p.protocol === "UDP") {
    const transChildren = [
      { label: "Src Port", value: String(p.srcPort || "\u2014") },
      { label: "Dst Port", value: String(p.dstPort || "\u2014") },
    ]
    if (p.protocol === "TCP" && p.flags) {
      transChildren.push({ label: "Flags", value: p.flags })
    }
    tree.push({ label: p.protocol, value: "", children: transChildren })
  }
  if (p.info) {
    tree.push({ label: "Info", value: p.info })
  }
  return tree
}

export default function PacketsPage() {
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const packets = useAnalysisStore((s) => s.packets)
  const [search, setSearch] = useState("")
  const [selectedPacket, setSelectedPacket] = useState<number | null>(null)
  const [bookmarks, setBookmarks] = useState<Set<number>>(new Set())
  const [comments, setComments] = useState<Record<number, string>>({})
  const [commentInput, setCommentInput] = useState("")
  const [activeTab, setActiveTab] = useState<"details" | "hex" | "stream">("details")
  const [streamPair, setStreamPair] = useState<string | null>(null)
  const parentRef = useRef<HTMLDivElement>(null)

  const filtered = useMemo(
    () => packets.filter((p) =>
      !search || (p.srcIp || "").includes(search) || (p.dstIp || "").includes(search) ||
      p.protocol.toLowerCase().includes(search.toLowerCase()) ||
      String(p.srcPort).includes(search) || String(p.dstPort).includes(search) ||
      (p.info || "").toLowerCase().includes(search.toLowerCase())
    ),
    [search, packets]
  )

  const gridCols = COLUMNS.map((c) => c.width).join(" ")

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 34,
    overscan: 15,
  })

  // Resolve against the FILTERED list: when a search removes the selected row,
  // the details panel used to stay stuck on a packet no longer in view (QA).
  const selectedPacketData = selectedPacket ? filtered.find((p) => p.num === selectedPacket) : null

  // And drop the stale selection state entirely once the row leaves the filter.
  useEffect(() => {
    if (selectedPacket !== null && !filtered.some((p) => p.num === selectedPacket)) setSelectedPacket(null)
  }, [filtered, selectedPacket])

  const protocolBadge = (proto: string) => {
    const colors: Record<string, string> = {
      TCP: "bg-info/10 text-info border-info/20",
      UDP: "bg-success/10 text-success border-success/20",
      DNS: "bg-warning/10 text-warning border-warning/20",
      TLS: "bg-chart-3/10 text-chart-3 border-chart-3/20",
    }
    return colors[proto] || "bg-muted text-muted-foreground"
  }

  const toggleBookmark = useCallback((num: number) => {
    setBookmarks(prev => {
      const next = new Set(prev)
      if (next.has(num)) next.delete(num)
      else next.add(num)
      return next
    })
  }, [])

  const saveComment = useCallback((num: number) => {
    if (!commentInput.trim()) return
    setComments(prev => ({ ...prev, [num]: commentInput }))
    setCommentInput("")
  }, [commentInput])

  const followStream = useCallback(() => {
    if (!selectedPacketData) return
    const p = selectedPacketData
    const key = streamConversationKey(p)
    setStreamPair(prev => prev === key ? null : key)
    setActiveTab("stream")
  }, [selectedPacketData])

  const streamPackets = useMemo(() => {
    if (!streamPair || !selectedPacketData) return []
    // Endpoints are "ip:port" strings — split each on the LAST colon so
    // IPv6 addresses (which contain colons) survive.
    const [epA, epB] = streamPair.split("|")
    const ai = epA.lastIndexOf(":"), bi = epB.lastIndexOf(":")
    const ipA = epA.slice(0, ai), portA = Number(epA.slice(ai + 1))
    const ipB = epB.slice(0, bi), portB = Number(epB.slice(bi + 1))
    return packets.filter(p =>
      (p.srcIp === ipA && p.srcPort === portA && p.dstIp === ipB && p.dstPort === portB) ||
      (p.srcIp === ipB && p.srcPort === portB && p.dstIp === ipA && p.dstPort === portA)
    ).sort((a, b) => a.num - b.num)
  }, [streamPair, selectedPacketData, packets])

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 flex overflow-hidden">
          <div className="flex-1 flex flex-col min-w-0">
            <div className="p-4 border-b shrink-0">
              <h1 className="text-lg font-bold mb-2">Packets</h1>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder={beginnerMode ? "Search by address, protocol, or port..." : "Filter packets (IP, port, protocol, regex)..."}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-10" maxLength={200}
                />
              </div>
              <p className="text-xs text-muted-foreground mt-1">{filtered.length} / {packets.length} packets</p>
            </div>

            <div className="flex-1 overflow-auto min-h-0" ref={parentRef}>
              <div
                className="sticky top-0 z-10 grid gap-0 px-4 py-2 text-xs font-medium text-muted-foreground border-b bg-background shadow-sm"
                style={{ gridTemplateColumns: gridCols }}
              >
                {COLUMNS.map((c) => (
                  <span key={c.key} className="px-2">{c.label}</span>
                ))}
              </div>

              <div style={{ height: `${virtualizer.getTotalSize()}px`, position: "relative" }}>
                {virtualizer.getVirtualItems().map((virtualItem) => {
                  const p = filtered[virtualItem.index]
                  if (!p) return null
                  return (
                    <div
                      key={virtualItem.key}
                      onClick={() => setSelectedPacket(selectedPacket === p.num ? null : p.num)}
                      className={cn(
                        "grid gap-0 px-4 py-1 text-xs items-center cursor-pointer hover:bg-accent/50 border-b border-border/50",
                        selectedPacket === p.num && "bg-accent",
                        bookmarks.has(p.num) && "bg-warning/5"
                      )}
                      style={{
                        position: "absolute",
                        top: 0,
                        left: 0,
                        width: "100%",
                        height: `${virtualItem.size}px`,
                        transform: `translateY(${virtualItem.start}px)`,
                        gridTemplateColumns: gridCols,
                      }}
                    >
                      <span className="font-mono text-muted-foreground px-2">{p.num}</span>
                      <span className="font-mono text-muted-foreground px-2 hl-time">
                        {formatTime(p.timestamp)}
                      </span>
                      <span className="font-mono px-2 truncate hl-src">{p.srcIp}</span>
                      <span className="font-mono px-2 truncate">{p.dstIp}</span>
                      <span className="font-mono text-muted-foreground px-2">{p.srcPort || '\u2014'}</span>
                      <span className="font-mono text-muted-foreground px-2">{p.dstPort || '\u2014'}</span>
                      <Badge variant="outline" className={cn("text-[11px] py-0 px-1.5 font-mono w-fit", protocolBadge(p.protocol))}>
                        {p.protocol}
                      </Badge>
                      <span className="text-muted-foreground px-2">{p.length}</span>
                      <span className="truncate text-muted-foreground px-2">{p.info}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>

          {selectedPacketData && (
            <div className="w-full lg:w-[420px] border-l bg-background overflow-y-auto shrink-0 max-lg:max-h-96 max-lg:border-t max-lg:border-l-0">
              <div className="p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-sm">
                    Packet {selectedPacketData.num}
                    {bookmarks.has(selectedPacketData.num) && <Bookmark className="h-3 w-3 inline ml-1 text-warning" />}
                  </h3>
                  <div className="flex items-center gap-1">
                    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => toggleBookmark(selectedPacketData.num)} title="Bookmark">
                      <Bookmark className={`h-3.5 w-3.5 ${bookmarks.has(selectedPacketData.num) ? "text-warning fill-warning" : ""}`} />
                    </Button>
                    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={followStream} title="Follow Stream">
                      <Code className="h-3.5 w-3.5" />
                    </Button>
                    <button onClick={() => setSelectedPacket(null)} className="text-muted-foreground hover:text-foreground">
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                <div className="flex gap-1 border-b">
                  {(["details", "hex", "stream"] as const).map(tab => (
                    <button key={tab} onClick={() => setActiveTab(tab)}
                      className={cn("px-3 py-1.5 text-xs font-medium border-b-2 transition-colors",
                        activeTab === tab ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground")}>
                      {tab === "details" ? <><FileText className="h-3 w-3 inline mr-1" />Details</> :
                        tab === "hex" ? <><Code className="h-3 w-3 inline mr-1" />Hex</> :
                          <><Code className="h-3 w-3 inline mr-1" />Stream</>}
                    </button>
                  ))}
                </div>

                {activeTab === "details" && (
                  <div className="space-y-3">
                    <div className="space-y-1">
                      <h4 className="text-xs font-medium text-muted-foreground">Protocol Tree</h4>
                      <ProtocolTree key={selectedPacketData.num} nodes={buildProtocolTree(selectedPacketData)} />
                    </div>
                    <div className="divide-y divide-border/50 text-xs">
                      {[
                        { label: "Timestamp", value: formatTimestamp(selectedPacketData.timestamp) },
                        { label: "Source", value: selectedPacketData.srcIp + ":" + (selectedPacketData.srcPort || "\u2014") },
                        { label: "Destination", value: selectedPacketData.dstIp + ":" + (selectedPacketData.dstPort || "\u2014") },
                        { label: "Protocol", value: selectedPacketData.protocol },
                        { label: "Length", value: selectedPacketData.length + " bytes" },
                        { label: "TTL", value: String(selectedPacketData.ttl ?? "\u2014") },
                        { label: "Flags", value: selectedPacketData.flags },
                      ].map(({ label, value }) => (
                        <div key={label} className="flex justify-between py-2">
                          <span className="text-muted-foreground">{label}</span>
                          <span className="font-mono text-right max-w-[220px] truncate">{value}</span>
                        </div>
                      ))}
                    </div>
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground mb-2">Info</h4>
                      <p className="text-xs font-mono bg-muted rounded p-2">{selectedPacketData.info}</p>
                    </div>
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground mb-2">Comment</h4>
                      <div className="flex gap-2">
                        <Input
                          value={commentInput}
                          onChange={e => setCommentInput(e.target.value)}
                          placeholder="Add a note..."
                          className="text-xs"
                          maxLength={500}
                        />
                        <Button size="sm" variant="outline" onClick={() => saveComment(selectedPacketData.num)}>Save</Button>
                      </div>
                      {comments[selectedPacketData.num] && (
                        <p className="text-xs text-muted-foreground mt-1 bg-muted rounded p-2">{comments[selectedPacketData.num]}</p>
                      )}
                    </div>
                  </div>
                )}

                {activeTab === "hex" && (
                  <div>
                    <h4 className="text-xs font-medium text-muted-foreground mb-2">Hex Dump</h4>
                    <pre className="bg-muted rounded p-3 text-[10px] font-mono leading-5 overflow-x-auto whitespace-pre max-h-64 overflow-y-auto">
                      {formatHexDump(selectedPacketData.num, selectedPacketData.length)}
                    </pre>
                  </div>
                )}

                {activeTab === "stream" && (
                  <div>
                    <h4 className="text-xs font-medium text-muted-foreground mb-2">TCP/UDP Stream</h4>
                    {streamPackets.length === 0 ? (
                      <p className="text-xs text-muted-foreground">Select a TCP/UDP packet and click Follow Stream to see the conversation.</p>
                    ) : (
                      <div className="space-y-1 max-h-64 overflow-y-auto">
                        {streamPackets.map(p => (
                          <div key={p.num} className={cn(
                            "text-[10px] font-mono p-1.5 rounded border-l-2",
                            p.srcIp === selectedPacketData.srcIp ? "border-primary bg-primary/5" : "border-muted-foreground bg-muted/30"
                          )}>
                            <span className="text-muted-foreground">{formatTime(p.timestamp)}</span>
                            <span className={cn("ml-1", p.srcIp === selectedPacketData.srcIp ? "text-info" : "text-success")}>
                              {p.srcIp}:{p.srcPort || '\u2014'} → {p.dstIp}:{p.dstPort || '\u2014'}
                            </span>
                            <span className="text-muted-foreground ml-1">{p.length}B</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}

function ProtocolTree({ nodes }: { nodes: ProtocolTreeNode[] }) {
  return (
    <div className="space-y-0.5 text-xs">
      {nodes.map((node, i) => (
        <TreeNode key={i} node={node} depth={0} />
      ))}
    </div>
  )
}

function TreeNode({ node, depth }: { node: ProtocolTreeNode; depth: number }) {
  const [expanded, setExpanded] = useState(depth < 1)
  const hasChildren = node.children && node.children.length > 0
  return (
    <div>
      <div className="flex items-center gap-1 py-0.5 cursor-pointer hover:bg-accent/50 rounded px-1"
        style={{ paddingLeft: `${depth * 12 + 4}px` }}
        onClick={() => hasChildren && setExpanded(!expanded)}>
        {hasChildren ? (expanded ? <ChevronDown className="h-3 w-3 shrink-0" /> : <ChevronRight className="h-3 w-3 shrink-0" />) : <span className="w-3 shrink-0" />}
        <span className="font-medium text-muted-foreground shrink-0">{node.label}</span>
        {node.value && <span className="font-mono text-muted-foreground ml-1 truncate">{node.value}</span>}
      </div>
      {expanded && hasChildren && (
        <div>
          {node.children!.map((child: ProtocolTreeNode, i: number) => (
            <TreeNode key={i} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  )
}