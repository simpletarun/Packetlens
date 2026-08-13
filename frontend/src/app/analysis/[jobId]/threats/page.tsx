"use client"

import { useState, useMemo } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn, formatTime } from "@/lib/utils"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Search, AlertTriangle, X } from "lucide-react"
export default function ThreatsPage() {
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const alerts = useAnalysisStore((s) => s.alerts)
  const [search, setSearch] = useState("")
  const [selected, setSelected] = useState<string | null>(null)

  const filtered = useMemo(
    () => alerts.filter((t) =>
      !search || t.signature.includes(search) || t.category.includes(search) ||
      t.srcIp.includes(search) || t.dstIp.includes(search)
    ),
    [search, alerts]
  )

  const selectedThreat = selected ? alerts.find((t) => t.id === selected) : null

  const sevColor = (s: number) => {
    if (s >= 4) return "destructive"
    if (s >= 3) return "warning"
    return "default"
  }

  const sevLabel = (s: number) => {
    if (s >= 4) return "High"
    if (s >= 3) return "Medium"
    return "Low"
  }

  const highCount = alerts.filter((t) => t.severity >= 4).length

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 flex flex-col overflow-hidden">
          <div className="p-4 border-b">
            <h1 className="text-lg font-bold mb-1">{beginnerMode ? "Security Threats" : "Threats"}</h1>
            <p className="text-xs text-muted-foreground">Detected security events and anomalies</p>
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Total Alerts</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{alerts.length}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">High Severity</CardTitle></CardHeader><CardContent><div className={"text-2xl font-bold" + (highCount > 0 ? " text-danger" : " text-muted-foreground")}>{highCount}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Categories</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{new Set(alerts.map((t) => t.category)).size}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Unique Signatures</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{new Set(alerts.map((t) => t.signature)).size}</div></CardContent></Card>
          </div>
          <div className="px-4 pb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Filter by signature, category, or IP..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" maxLength={200} />
            </div>
          </div>
          <div className="flex-1 flex overflow-hidden px-4 pb-4 gap-4">
            <div className="flex-1 overflow-auto">
              <div className="grid grid-cols-[100px_1fr_90px_80px_1fr] gap-3 px-4 py-2 text-xs font-medium text-muted-foreground border-b bg-background shadow-sm sticky top-0">
                <span>Time</span>
                <span>{beginnerMode ? "Event" : "Signature"}</span>
                <span>Category</span>
                <span>Severity</span>
                <span>{beginnerMode ? "Source → Destination" : "Src → Dst"}</span>
              </div>
              {filtered.length === 0 && (
                <p className="px-4 py-8 text-center text-xs text-muted-foreground">
                  {search ? "No threats match your filter" : "No threats detected"}
                </p>
              )}
              {filtered.slice(0, 500).map((t) => (
                <div
                  key={t.id}
                  onClick={() => setSelected(selected === t.id ? null : t.id)}
                  className={cn(
                    "grid grid-cols-[100px_1fr_90px_80px_1fr] gap-3 px-4 py-2 text-xs items-center border-b border-border/50 cursor-pointer hover:bg-accent/30",
                    selected === t.id && "bg-accent"
                  )}
                >
                  <span className="font-mono text-muted-foreground hl-time">{formatTime(t.timestamp)}</span>
                  <span className="truncate"><AlertTriangle className="h-3 w-3 inline mr-1 text-warning" />{t.signature}</span>
                  <Badge variant="outline" className="text-[10px] px-1 py-0">{t.category}</Badge>
                  <Badge variant={sevColor(t.severity) as "destructive" | "warning" | "default"} className="text-[10px] px-1 py-0">{sevLabel(t.severity)}</Badge>
                  <span className="truncate font-mono hl-src">{t.srcIp} &rarr; {t.dstIp} <span className="text-muted-foreground">({t.confidence}% conf)</span></span>
                </div>
              ))}
              {filtered.length > 500 && (
                <p className="px-4 py-3 text-center text-xs text-muted-foreground">Showing first 500 of {filtered.length} — refine the search to narrow down</p>
              )}
            </div>
            {selectedThreat && (
              <div className="w-80 border-l pl-4 space-y-3 overflow-y-auto">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-sm">Alert Details</h3>
                  <button onClick={() => setSelected(null)} className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
                </div>
                <div className="space-y-2 text-xs">
                  {[
                    { label: "Signature", value: selectedThreat.signature },
                    { label: "Category", value: selectedThreat.category },
                    { label: "Severity", value: sevLabel(selectedThreat.severity) + " (" + selectedThreat.severity + "/5)" },
                    { label: "Source", value: selectedThreat.srcIp + ":" + selectedThreat.srcPort },
                    { label: "Destination", value: selectedThreat.dstIp + ":" + selectedThreat.dstPort },
                    { label: "Confidence", value: selectedThreat.confidence + "%" },
                    { label: "Protocol", value: selectedThreat.protocol },
                    { label: "Evidence", value: selectedThreat.evidence },
                  ].map(({ label, value }) => (
                    <div key={label} className="flex justify-between">
                      <span className="text-muted-foreground">{label}</span>
                      <span className="font-mono text-right max-w-[200px] truncate">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}
