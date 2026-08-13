"use client"

import { useState, useMemo } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn, formatTime } from "@/lib/utils"
import { formatBytes } from "@/lib/map-data"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Search } from "lucide-react"
import { DecodeBanner } from "@/components/analysis/decode-banner"
export default function HttpPage() {
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const http = useAnalysisStore((s) => s.http)
  const [search, setSearch] = useState("")
  const [open, setOpen] = useState<string | null>(null)

  const filtered = useMemo(
    () => http.filter((h) =>
      !search || h.uri.includes(search) || h.host.includes(search) ||
      h.method.toLowerCase().includes(search.toLowerCase()) || String(h.status).includes(search)
    ),
    [search, http]
  )

  const statusColor = (s: number) => {
    if (s < 300) return "bg-success/10 text-success"
    if (s < 400) return "bg-info/10 text-info"
    if (s < 500) return "bg-warning/10 text-warning"
    return "bg-danger/10 text-danger"
  }

  const methodColor = (m: string) => {
    const map: Record<string, string> = { GET: "bg-info/10 text-info", POST: "bg-success/10 text-success", PUT: "bg-warning/10 text-warning", DELETE: "bg-danger/10 text-danger" }
    return map[m] || "bg-muted text-muted-foreground"
  }

  const errorCount = http.filter((h) => h.status >= 400).length

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 flex flex-col overflow-hidden">
          <div className="p-4 border-b">
            <h1 className="text-lg font-bold mb-1">HTTP Analysis</h1>
            <p className="text-xs text-muted-foreground">Hypertext Transfer Protocol requests and responses</p>
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Total Requests</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{http.length}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Unique Hosts</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{new Set(http.map((h) => h.host).filter(Boolean)).size}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Error Responses</CardTitle></CardHeader><CardContent><div className={"text-2xl font-bold" + (errorCount > 0 ? " text-danger" : " text-muted-foreground")}>{errorCount}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Total Data</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{formatBytes(http.reduce((s, h) => s + (h.length ?? 0), 0))}</div></CardContent></Card>
          </div>
          <div className="px-4 pb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Filter by URI, host, method, or status..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" maxLength={200} />
            </div>
          </div>
          <div className="px-4 pb-4"><DecodeBanner /></div>
          <div className="flex-1 overflow-auto px-4">
            <div className="grid grid-cols-[100px_1fr_70px_80px_1fr_80px] gap-3 px-4 py-2 text-xs font-medium text-muted-foreground border-b bg-background shadow-sm sticky top-0">
              <span>Time</span>
              <span>URI</span>
              <span>Method</span>
              <span>Status</span>
              <span>Host</span>
              <span>Size</span>
            </div>
            {filtered.length === 0 && (
              <p className="px-4 py-8 text-center text-xs text-muted-foreground">
                {search ? "No HTTP requests match your filter" : "No HTTP requests captured"}
              </p>
            )}
            {filtered.slice(0, 500).map((h) => (
              <div key={h.id}>
                <div onClick={() => setOpen(open === h.id ? null : h.id)}
                  className="grid grid-cols-[100px_1fr_70px_80px_1fr_80px] gap-3 px-4 py-2 text-xs items-center border-b border-border/50 hover:bg-accent/30 cursor-pointer">
                  <span className="font-mono text-muted-foreground hl-time">{formatTime(h.timestamp)}</span>
                  <span className="truncate font-mono">{h.uri}</span>
                  <Badge variant="outline" className={cn("text-[10px] px-1 py-0", methodColor(h.method))}>{h.method}</Badge>
                  <span className={cn("font-mono text-xs", h.status === 0 ? "text-muted-foreground" : statusColor(h.status))}>{h.status === 0 ? "—" : h.status}</span>
                  <span className="truncate">{h.host}</span>
                  {/* formatBytes keeps sub-KB sizes honest — /1024 floor showed
                      "0KB" for any request under 1KB (U2). */}
                  <span className="text-muted-foreground whitespace-nowrap">{formatBytes(h.length ?? 0)}</span>
                </div>
                {open === h.id && (
                  <div className="grid grid-cols-[100px_1fr] gap-3 px-4 py-2 text-xs border-b border-border/50 bg-muted/20">
                    <span className="text-muted-foreground">User-Agent</span>
                    <span className="break-all">{h.userAgent || "—"}</span>
                    <span className="text-muted-foreground">Content-Type</span>
                    <span className="break-all">{h.contentType || "—"}</span>
                    <span className="text-muted-foreground">Peers</span>
                    <span className="font-mono break-all">{h.srcIp} → {h.dstIp}</span>
                  </div>
                )}
              </div>
            ))}
            {filtered.length > 500 && (
              <p className="px-4 py-3 text-center text-xs text-muted-foreground">Showing first 500 of {filtered.length} — refine the search to narrow down</p>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}
