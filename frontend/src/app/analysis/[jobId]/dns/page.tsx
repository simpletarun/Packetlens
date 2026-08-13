"use client"

import { useState, useMemo } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn, formatTime } from "@/lib/utils"
import { dnsLookupCount } from "@/lib/report"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Search, Globe } from "lucide-react"
export default function DnsPage() {
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const dns = useAnalysisStore((s) => s.dns)
  const [search, setSearch] = useState("")

  const filtered = useMemo(
    () => dns.filter((d) =>
      !search || d.query.includes(search) || d.srcIp.includes(search) || d.type.toLowerCase().includes(search.toLowerCase())
    ),
    [search, dns]
  )

  const nxdomainCount = dns.filter((d) => d.responseCode === "NXDOMAIN").length
  const queryCount = dns.filter((d) => !d.isResponse).length
  const responseCount = dns.length - queryCount

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 flex flex-col overflow-hidden">
          <div className="p-4 border-b">
            <h1 className="text-lg font-bold mb-1">DNS Analysis</h1>
            <p className="text-xs text-muted-foreground">Domain Name System queries and responses</p>
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Query Packets</CardTitle></CardHeader>
              <CardContent><div className="text-2xl font-bold">{queryCount}</div></CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Distinct Lookups</CardTitle></CardHeader>
              <CardContent><div className="text-2xl font-bold">{dnsLookupCount(dns)}</div></CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Responses</CardTitle></CardHeader>
              <CardContent><div className="text-2xl font-bold">{responseCount}</div></CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">NXDOMAIN Responses</CardTitle></CardHeader>
              <CardContent><div className={"text-2xl font-bold" + (nxdomainCount > 0 ? " text-warning" : " text-muted-foreground")}>{nxdomainCount}</div></CardContent>
            </Card>
          </div>
          <p className="px-4 pb-3 text-[10px] text-muted-foreground">Distinct Lookups counts each name+type once for the capturing client: a LAN router relaying a query upstream — or the response coming back down — is not a second query. The table below lists every DNS message, with responses marked.</p>
          <div className="px-4 pb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Filter by domain, IP, or type..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" maxLength={200} />
            </div>
          </div>
          <div className="flex-1 overflow-auto px-4">
            <div className="grid grid-cols-[1fr_1fr_1fr_110px_90px_70px]
        gap-3 px-4 py-2 text-xs font-medium text-muted-foreground border-b bg-background shadow-sm sticky top-0">
              <span>Time</span>
              <span>{beginnerMode ? "Source" : "Src"}</span>
              <span>Query</span>
              <span>Type</span>
              <span>Response</span>
              <span>TTL</span>
            </div>
            {filtered.length === 0 && (
              <p className="px-4 py-8 text-center text-xs text-muted-foreground">
                {search ? "No DNS messages match your filter" : "No DNS queries in this capture"}
              </p>
            )}
            {filtered.map((d) => (
              <div key={d.id} className="grid grid-cols-[1fr_1fr_1fr_110px_90px_70px] gap-3 px-4 py-2 text-xs items-center border-b border-border/50 hover:bg-accent/30">
                <span className="font-mono text-muted-foreground hl-time">{formatTime(d.timestamp)}</span>
                <span className="font-mono hl-src">{d.srcIp}</span>
                <span className="truncate"><Globe className="h-3 w-3 inline mr-1 text-muted-foreground" />{d.query}</span>
                <span className="flex items-center gap-1">
                  <Badge variant={d.isResponse ? "secondary" : "default"} className="text-[9px] px-1 py-0">{d.isResponse ? "R" : "Q"}</Badge>
                  <Badge variant="outline" className="text-[10px] px-1 py-0 font-mono">{d.type}</Badge>
                </span>
                <Badge variant={d.responseCode !== "NOERROR" ? "destructive" : "success"} className="text-[10px] px-1 py-0">{d.responseCode}</Badge>
                {/* Queries carry no TTL (there is no answer record); a raw "0s"
                    reads as a real zero-lease record — show a dash instead (D3).
                    Answer-less responses also have no TTL (null), not 0. */}
                <span className="text-muted-foreground">{d.isResponse && d.ttl !== null ? `${d.ttl}s` : '\u2014'}</span>
              </div>
            ))}
          </div>
        </main>
      </div>
    </div>
  )
}
