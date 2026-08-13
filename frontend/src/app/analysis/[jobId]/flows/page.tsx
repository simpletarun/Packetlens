"use client"

import { useState, useMemo } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn } from "@/lib/utils"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Search, ArrowRight, Inbox } from "lucide-react"
import { formatBytes, formatEndpoint } from "@/lib/map-data"

// One shared template so header and rows can never drift out of sync.
const GRID = "grid-cols-[1fr_auto_1fr_70px_70px_70px_70px_70px_70px] min-w-[880px]"
export default function FlowsPage() {
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const flows = useAnalysisStore((s) => s.flows)
  const [search, setSearch] = useState("")

  const filtered = useMemo(
    () => flows.filter((f) =>
      !search || f.srcIp.includes(search) || f.dstIp.includes(search) ||
      f.protocol.toLowerCase().includes(search.toLowerCase())
    ),
    [search, flows]
  )

  const protocolColor = (p: string) => {
    const m: Record<string, string> = { TCP: "bg-info/10 text-info border-info/20", UDP: "bg-success/10 text-success border-success/20", DNS: "bg-warning/10 text-warning border-warning/20", TLS: "bg-chart-3/10 text-chart-3 border-chart-3/20" }
    return m[p] || "bg-muted text-muted-foreground"
  }

  // Aggregate TCP health across flows (v3.2 F-05). Hidden when no TCP: the
  // card would be pure zeros on UDP-only captures. RTT is reported as
  // median/p95 of per-flow handshake RTTs — a raw mean is dragged up by a
  // few retransmit-backoff flows (F-04 QA: 428 ms avg was implausible).
  // Memoized filter: an inline flows.filter() would hand the memo a fresh
  // array every render, defeating it (QA).
  const tcpFlows = useMemo(() => flows.filter((f) => f.protocol === "TCP"), [flows])
  const tcpHealth = useMemo(() => {
    const rtts: number[] = []
    let retrans = 0, ooo = 0, zeroWindow = 0, rst = 0, lossy = 0
    for (const f of tcpFlows) {
      retrans += f.retrans ?? 0
      ooo += f.ooo ?? 0
      zeroWindow += f.zeroWindow ?? 0
      rst += f.rstCount ?? 0
      if ((f.lossPct ?? 0) > 0) lossy++
      if (typeof f.rttMs === "number") rtts.push(f.rttMs)
    }
    const sorted = [...rtts].sort((a, b) => a - b)
    // Nearest-rank percentile: ceil(p·n)−1 gives the LOWER middle for even n
    // (a 2-sample median is the smaller RTT, not the max — the old floor
    // landed on the upper-middle element, QA).
    const pct = (p: number) => sorted.length ? sorted[Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1)] : null
    return {
      retrans, ooo, zeroWindow, rst, lossy,
      rttMedian: pct(0.5), rttP95: pct(0.95),
    }
  }, [tcpFlows])

  const healthItems = [
    { label: ["Retransmissions", "Retransmission"], value: tcpHealth.retrans },
    { label: ["Out-of-order", "Out-of-order"], value: tcpHealth.ooo },
    { label: ["Zero-window", "Zero-window"], value: tcpHealth.zeroWindow },
    { label: ["Resets", "Reset"], value: tcpHealth.rst },
    { label: ["Lossy flows", "Lossy flow"], value: tcpHealth.lossy },
    { label: ["RTT med/p95", "RTT med/p95"], value: tcpHealth.rttMedian === null ? "N/A" : `${tcpHealth.rttMedian}/${tcpHealth.rttP95}ms` },
  ]

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 flex flex-col overflow-hidden">
          <div className="p-4 border-b">
            <h1 className="text-lg font-bold mb-2">{beginnerMode ? "Conversations" : "Flows"}</h1>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Filter flows..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" maxLength={200} />
            </div>
            <p className="text-xs text-muted-foreground mt-1">{filtered.length} flows</p>
          </div>
          {tcpFlows.length > 0 && (
            <div className="px-4 py-2 flex flex-wrap gap-x-6 gap-y-1 text-xs border-b">
              {healthItems.map((h) => (
                <span key={h.label[0]} className="text-muted-foreground">
                  <span className="text-foreground font-semibold">{h.value}</span> {typeof h.value === "number" && h.value === 1 ? h.label[1] : h.label[0]}
                </span>
              ))}
              {tcpHealth.rttMedian === null && <span className="text-warning" title="No SYN/SYN-ACK pair was captured in-window (capture started mid-session)">RTT N/A — no TCP handshake captured</span>}
            </div>
          )}
          <div className="flex-1 overflow-auto">
            <div className={cn("grid gap-3 px-4 py-2 text-xs font-medium text-muted-foreground border-b bg-background shadow-sm sticky top-0", GRID)}>
              <span>{beginnerMode ? "Source" : "Src IP"}</span>
              <span></span>
              <span>{beginnerMode ? "Destination" : "Dst IP"}</span>
              <span>Proto</span>
              <span>{beginnerMode ? "Packets" : "Pkts"}</span>
              <span>{beginnerMode ? "Sent" : "Sent"}</span>
              <span>{beginnerMode ? "Received" : "Recv"}</span>
              <span>{beginnerMode ? "Response time" : "RTT"}</span>
              <span>Dur</span>
            </div>
            {filtered.map((f) => (
              <div key={f.id} className={cn("grid gap-3 px-4 py-2 text-xs items-center border-b border-border/50 hover:bg-accent/30", GRID)}>
                <span className="font-mono hl-src">{formatEndpoint(f.srcIp, f.srcPort)}</span>
                <ArrowRight className="h-3 w-3 text-muted-foreground" />
                <span className="font-mono">{formatEndpoint(f.dstIp, f.dstPort)}</span>
                <Badge variant="outline" className={cn("text-[10px] px-1 py-0 font-mono", protocolColor(f.protocol))}>{f.protocol}</Badge>
                <span className="text-muted-foreground">{f.packets}</span>
                <span className="text-muted-foreground">{f.directionUnknown ? "—" : formatBytes(f.bytesSent)}</span>
                <span className="text-muted-foreground">{f.directionUnknown ? "—" : formatBytes(f.bytesRecv)}</span>
                {/* Per-flow handshake RTT (TCP only) — the aggregate strip is
                    med/p95; this is the value behind it (F-04 QA). Empty is
                    not data loss: no SYN/SYN-ACK pair was captured (capture
                    started mid-session) so no RTT exists (QA audit). */}
                <span className="text-muted-foreground" title={f.protocol === "TCP" && typeof f.rttMs !== "number" ? "RTT unavailable — no TCP handshake captured" : undefined}>{f.protocol === "TCP" ? (typeof f.rttMs === "number" ? `${f.rttMs}ms` : "no handshake") : "—"}</span>
                <span className="text-muted-foreground">{f.duration}s</span>
              </div>
            ))}
            {filtered.length === 0 && (
              <div className="flex flex-col items-center gap-2 py-16 text-center">
                <Inbox className="h-8 w-8 text-muted-foreground/40" />
                <p className="text-sm text-muted-foreground">
                  {search ? `No ${beginnerMode ? "conversations" : "flows"} match "${search}"` : "No flows in this capture"}
                </p>
                {search && (
                  <button onClick={() => setSearch("")} className="text-xs text-primary hover:underline">
                    Clear filter
                  </button>
                )}
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}
