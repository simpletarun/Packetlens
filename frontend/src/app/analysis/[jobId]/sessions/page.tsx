"use client"

import { useState, useMemo } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn } from "@/lib/utils"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Search } from "lucide-react"
import { formatBytes, formatEndpoint } from "@/lib/map-data"
export default function SessionsPage() {
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const sessions = useAnalysisStore((s) => s.sessions)
  const [search, setSearch] = useState("")

  const filtered = useMemo(
    () => sessions.filter((s) =>
      !search || s.srcIp.includes(search) || s.dstIp.includes(search) || s.state.toLowerCase().includes(search.toLowerCase())
    ),
    [search, sessions]
  )

  const stateColor = (s: string) => {
    const m: Record<string, string> = { ESTABLISHED: "bg-success/10 text-success", CLOSED: "bg-muted text-muted-foreground", "TIME_WAIT": "bg-warning/10 text-warning", "SYN_SENT": "bg-info/10 text-info", STATELESS: "bg-chart-3/10 text-chart-3" }
    return m[s] || "bg-muted text-muted-foreground"
  }

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 flex flex-col overflow-hidden">
          <div className="p-4 border-b">
            <h1 className="text-lg font-bold mb-2">{beginnerMode ? "Connections" : "Sessions"}</h1>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Filter sessions..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" maxLength={200} />
            </div>
            <p className="text-xs text-muted-foreground mt-1">{filtered.length} sessions</p>
          </div>
          <div className="flex-1 overflow-auto">
            <div className="grid grid-cols-[1fr_1fr_70px_60px_80px_80px_70px_90px] gap-3 min-w-[880px] px-4 py-2 text-xs font-medium text-muted-foreground border-b bg-background shadow-sm sticky top-0">
              <span>Src IP</span>
              <span>Dst IP</span>
              <span>Proto</span>
              <span>SPort</span>
              <span>DPort</span>
              <span>{beginnerMode ? "Packets" : "Pkts"}</span>
              <span>{beginnerMode ? "Size" : "Bytes"}</span>
              <span>State</span>
            </div>
            {filtered.map((s) => (
              <div key={s.id} className="grid grid-cols-[1fr_1fr_70px_60px_80px_80px_70px_90px] gap-3 min-w-[880px] px-4 py-2 text-xs items-center border-b border-border/50 hover:bg-accent/30">
                <span className="font-mono hl-src">{formatEndpoint(s.srcIp, s.srcPort)}</span>
                <span className="font-mono">{formatEndpoint(s.dstIp, s.dstPort)}</span>
                <Badge variant="outline" className="text-[10px] px-1 py-0 font-mono">{s.protocol}</Badge>
                <span className="text-muted-foreground">{s.srcPort}</span>
                <span className="text-muted-foreground">{s.dstPort}</span>
                <span className="text-muted-foreground">{s.packets}</span>
                <span className="text-muted-foreground">{formatBytes(s.bytes)}</span>
                <Badge variant="outline" className={cn("text-[10px] px-1 py-0", stateColor(s.state))}>{s.state}</Badge>
              </div>
            ))}
          </div>
        </main>
      </div>
    </div>
  )
}
