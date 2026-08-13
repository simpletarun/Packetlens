"use client"

import { useState } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn } from "@/lib/utils"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { ShieldCheck, X } from "lucide-react"
import { DecodeBanner } from "@/components/analysis/decode-banner"
export default function CertificatesPage() {
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const certificates = useAnalysisStore((s) => s.certificates)
  const job = useAnalysisStore((s) => s.currentJob)
  const packets = useAnalysisStore((s) => s.packets)
  const [selected, setSelected] = useState<string | null>(null)

  const selectedCert = selected ? certificates.find((c) => c.id === selected) : null
  // Certificates are judged at CAPTURE end, not analysis time: job.createdAt
  // is the upload moment on real jobs (always after the capture), so a cert
  // valid during the capture read "Expired" (QA: refTime drifted).
  const captureEnd = packets.reduce((max, p) => {
    const t = Date.parse(p.timestamp)
    return Number.isNaN(t) ? max : Math.max(max, t)
  }, 0)
  const refTime = captureEnd > 0 ? captureEnd : job ? new Date(job.createdAt).getTime() : 0

  // A certificate without a notAfter (no valid time in the capture) is
  // neither expired nor valid — "Unknown", not a fabricated 1969 date (QA).
  const isExpiredCert = (c: { notAfter: string | null }) => c.notAfter !== null && new Date(c.notAfter).getTime() < refTime
  const expired = certificates.filter(isExpiredCert).length
  const valid = certificates.filter((c) => c.notAfter !== null && new Date(c.notAfter).getTime() >= refTime).length

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 flex flex-col overflow-hidden">
          <div className="p-4 border-b">
            <h1 className="text-lg font-bold mb-1">Certificates</h1>
            <p className="text-xs text-muted-foreground">TLS/SSL certificates observed in network traffic</p>
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Total Certificates</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{certificates.length}</div></CardContent></Card>
            {/* Zero expired is good news: neutral grey, not red (QA: "Expired 0" in red read as bad). */}
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Expired</CardTitle></CardHeader><CardContent><div className={"text-2xl font-bold" + (expired > 0 ? " text-danger" : " text-muted-foreground")}>{expired}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Valid</CardTitle></CardHeader><CardContent><div className={"text-2xl font-bold" + (valid > 0 ? " text-success" : " text-muted-foreground")}>{valid}</div></CardContent></Card>
          </div>
          <div className="px-4 pb-4"><DecodeBanner /></div>
          <div className="flex-1 flex overflow-hidden px-4 pb-4 gap-4">
            <div className="flex-1 overflow-auto">
              <div className="grid grid-cols-[1fr_1fr_100px_100px] gap-3 min-w-[480px] px-4 py-2 text-xs font-medium text-muted-foreground border-b bg-background shadow-sm sticky top-0">
                <span>Subject</span>
                <span>Issuer</span>
                <span>Key Size</span>
                <span>Status</span>
              </div>
              {certificates.length === 0 && (
                <p className="px-4 py-8 text-center text-xs text-muted-foreground">No certificates observed</p>
              )}
              {certificates.map((c) => {
                const isExpired = isExpiredCert(c)
                const isUnknown = c.notAfter === null
                return (
                  <div
                    key={c.id}
                    onClick={() => setSelected(selected === c.id ? null : c.id)}
                    className={cn(
                      "grid grid-cols-[1fr_1fr_100px_100px] gap-3 min-w-[480px] px-4 py-2 text-xs items-center border-b border-border/50 cursor-pointer hover:bg-accent/30",
                      selected === c.id && "bg-accent"
                    )}
                  >
                    <span className="truncate"><ShieldCheck className="h-3 w-3 inline mr-1 text-chart-3" />{c.subject}</span>
                    <span className="truncate text-muted-foreground">{c.issuer}</span>
                    <span className="text-muted-foreground">{c.keySize >= 2048 ? c.keySize + "bit" : c.keySize}</span>
                    <Badge variant={isUnknown ? "outline" : isExpired ? "destructive" : "success"} className="text-[10px] px-1 py-0">{isUnknown ? "Unknown" : isExpired ? "Expired" : "Valid"}</Badge>
                  </div>
                )
              })}
            </div>
            {selectedCert && (
              <div className="w-96 border-l pl-4 space-y-3 overflow-y-auto">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-sm">Certificate Details</h3>
                  <button onClick={() => setSelected(null)} className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
                </div>
                <div className="space-y-2 text-xs">
                  {[
                    { label: "Subject", value: selectedCert.subject },
                    { label: "Issuer", value: selectedCert.issuer },
                    { label: "Serial", value: selectedCert.serial },
                    { label: "Not Before", value: selectedCert.notBefore ? new Date(selectedCert.notBefore).toISOString() : "Unknown" },
                    { label: "Not After", value: selectedCert.notAfter ? new Date(selectedCert.notAfter).toISOString() : "Unknown" },
                    { label: "Signature Algorithm", value: selectedCert.signatureAlgorithm },
                    { label: "Key Size", value: String(selectedCert.keySize) },
                    { label: "SANs", value: (selectedCert.san ?? []).join(", ") },
                  ].map(({ label, value }) => (
                    <div key={label} className="flex justify-between">
                      <span className="text-muted-foreground">{label}</span>
                      <span className="font-mono text-right max-w-[250px] truncate">{value}</span>
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
