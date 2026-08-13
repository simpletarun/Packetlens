"use client"

import { useState, useMemo } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn, formatTime } from "@/lib/utils"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Search, Shield } from "lucide-react"
import { DecodeBanner } from "@/components/analysis/decode-banner"
export default function TlsPage() {
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const tls = useAnalysisStore((s) => s.tls)
  const [search, setSearch] = useState("")
  const [selected, setSelected] = useState<string | null>(null)

  const filtered = useMemo(
    () => tls.filter((t) =>
      !search || t.sni.includes(search) || t.srcIp.includes(search) || t.version.includes(search)
    ),
    [search, tls]
  )

  // Desktop emits "TLS 1.3" (space), browser analysis "TLSv1.3" — match the
  // version, not the spelling (QA: the 1.3 counter read 0 on desktop jobs).
  const isTls13 = (v: string) => /1\.3/.test(v)
  const isTls12 = (v: string) => /1\.2/.test(v)
  const tls13 = tls.filter((t) => isTls13(t.version)).length
  const tls12 = tls.filter((t) => isTls12(t.version)).length
  const selectedCert = selected ? tls.find((t) => t.id === selected) : null

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 flex flex-col overflow-hidden">
          <div className="p-4 border-b">
            <h1 className="text-lg font-bold mb-1">TLS Analysis</h1>
            <p className="text-xs text-muted-foreground">Transport Layer Security handshakes and certificates</p>
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Total Handshakes</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{tls.length}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">TLSv1.3</CardTitle></CardHeader><CardContent><div className={"text-2xl font-bold" + (tls13 > 0 ? " text-success" : " text-muted-foreground")}>{tls13}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">TLSv1.2</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{tls12}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Unique SNIs</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{new Set(tls.map((t) => t.sni)).size}</div></CardContent></Card>
          </div>
          <div className="px-4 pb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Filter by SNI, IP, or version..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" maxLength={200} />
            </div>
          </div>
          <div className="px-4 pb-4"><DecodeBanner /></div>
          <div className="flex-1 flex overflow-hidden px-4 pb-4 gap-4">
            <div className="flex-1 overflow-auto">
              <div className="grid grid-cols-[100px_1fr_1fr_90px_1fr] gap-3 min-w-[480px] px-4 py-2 text-xs font-medium text-muted-foreground border-b bg-background shadow-sm sticky top-0">
                <span>Time</span>
                <span>Source</span>
                <span>SNI</span>
                <span>Version</span>
                <span>Cipher Suite</span>
              </div>
              {filtered.length === 0 && (
                <p className="px-4 py-8 text-center text-xs text-muted-foreground">
                  {search ? "No TLS handshakes match your filter" : "No TLS handshake packets captured"}
                </p>
              )}
              {filtered.slice(0, 500).map((t) => (
                <div
                  key={t.id}
                  onClick={() => setSelected(selected === t.id ? null : t.id)}
                  className={cn(
                    "grid grid-cols-[100px_1fr_1fr_90px_1fr] gap-3 min-w-[480px] px-4 py-2 text-xs items-center border-b border-border/50 cursor-pointer hover:bg-accent/30",
                    selected === t.id && "bg-accent"
                  )}
                >
                  <span className="font-mono text-muted-foreground hl-time">{formatTime(t.timestamp)}</span>
                  <span className="font-mono hl-src">{t.srcIp}</span>
                  <span className="truncate"><Shield className="h-3 w-3 inline mr-1 text-chart-3" />{t.sni}</span>
                  <Badge variant={isTls13(t.version) ? "success" : "default"} className="text-[10px] px-1 py-0">{t.version}</Badge>
                  <span className="truncate text-muted-foreground">{t.cipherSuite}</span>
                </div>
              ))}
              {filtered.length > 500 && (
                <p className="px-4 py-3 text-center text-xs text-muted-foreground">Showing first 500 of {filtered.length} — refine the search to narrow down</p>
              )}
            </div>
            {selectedCert && (
              <div className="w-80 border-l pl-4 space-y-3 overflow-y-auto">
                <h3 className="font-semibold text-sm">{beginnerMode ? "Handshake Details" : "TLS Details"}</h3>
                <div className="space-y-2 text-xs">
                  {[
                    { label: "SNI", value: selectedCert.sni },
                    { label: "Version", value: selectedCert.version },
                    { label: "Cipher Suite", value: selectedCert.cipherSuite },
                    { label: "JA3", value: selectedCert.ja3 || "—" },
                    { label: "Issuer", value: selectedCert.issuer || "—" },
                    { label: "Validity", value: selectedCert.validityDays > 0 ? selectedCert.validityDays + " days" : "—" },
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
