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
import { Search, FileIcon } from "lucide-react"
import { DecodeBanner } from "@/components/analysis/decode-banner"
export default function FilesPage() {
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const files = useAnalysisStore((s) => s.files)
  const [search, setSearch] = useState("")

  // The search must match what the UI SHOWS: rows display "file upload"/"form
  // body" but the store carries "file-transfer"/"form-body" — searching on the
  // raw token silently hid rows the count still showed (QA).
  const kindLabel = (kind: string) => (kind === "file-transfer" ? "file upload" : kind === "form-body" ? "form body" : kind)
  const filtered = useMemo(
    () => files.filter((f) =>
      !search || f.filename.toLowerCase().includes(search.toLowerCase()) || f.mimeType.toLowerCase().includes(search.toLowerCase()) || f.srcIp.toLowerCase().includes(search.toLowerCase()) || kindLabel(f.kind).includes(search.toLowerCase())
    ),
    [search, files]
  )

  const totalSize = files.reduce((s, f) => s + f.size, 0)

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 flex flex-col overflow-hidden">
          <div className="p-4 border-b">
            <h1 className="text-lg font-bold mb-1">Extracted HTTP Payloads</h1>
            <p className="text-xs text-muted-foreground">HTTP request bodies and file transfers observed in the capture (per-packet payload size, no reassembly). Form bodies are request payloads, not files.</p>
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Total Payloads</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{files.length}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Total Size</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{formatBytes(totalSize)}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Types</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{new Set(files.map((f) => f.mimeType)).size}</div></CardContent></Card>
          </div>
          <div className="px-4 pb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Filter by filename, type, or IP..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" maxLength={200} />
            </div>
          </div>
          <div className="px-4 pb-4"><DecodeBanner /></div>
          <div className="flex-1 overflow-auto px-4">
            <div className="grid grid-cols-[100px_70px_1fr_1fr_90px_70px] gap-3 min-w-[620px] px-4 py-2 text-xs font-medium text-muted-foreground border-b bg-background shadow-sm sticky top-0">
              <span>Time</span>
              <span>Kind</span>
              <span>{beginnerMode ? "Filename" : "File"}</span>
              <span>MIME Type</span>
              <span>Size</span>
              <span>Protocol</span>
            </div>
            {filtered.length === 0 && (
              <p className="px-4 py-8 text-center text-xs text-muted-foreground">
                {search ? "No payloads match your filter" : "No HTTP payloads detected"}
              </p>
            )}
            {filtered.slice(0, 500).map((f) => (
              <div key={f.id} className="grid grid-cols-[100px_70px_1fr_1fr_90px_70px] gap-3 min-w-[620px] px-4 py-2 text-xs items-center border-b border-border/50 hover:bg-accent/30">
                <span className="font-mono text-muted-foreground hl-time">{formatTime(f.timestamp)}</span>
                <span>{kindLabel(f.kind)}</span>
                <span className="truncate"><FileIcon className="h-3 w-3 inline mr-1 text-muted-foreground" />{f.filename || '\u2014'}</span>
                <span className="truncate text-muted-foreground">{f.mimeType}</span>
                <span className="text-muted-foreground">{formatBytes(f.size)}</span>
                <Badge variant="outline" className="text-[10px] px-1 py-0 font-mono">{f.protocol}</Badge>
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