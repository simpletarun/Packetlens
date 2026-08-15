"use client"

import { useState, useMemo } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn, formatTime } from "@/lib/utils"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Search, Eye, EyeOff, KeyRound } from "lucide-react"
import { DecodeBanner } from "@/components/analysis/decode-banner"
export default function CredentialsPage() {
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const credentials = useAnalysisStore((s) => s.credentials)
  const [search, setSearch] = useState("")
  const [showPasswords, setShowPasswords] = useState(false)

  const filtered = useMemo(
    () => credentials.filter((c) =>
      !search || c.username.toLowerCase().includes(search.toLowerCase()) || c.service.toLowerCase().includes(search.toLowerCase()) || c.srcIp.toLowerCase().includes(search.toLowerCase())
    ),
    [search, credentials]
  )

  // Password-only matches carry the "—" username placeholder (no username was
  // seen) — counting it as a unique username inflates the count by one (QA).
  const uniqueUsernames = useMemo(() => {
    const names = new Set<string>()
    for (const c of credentials) {
      const name = (c.username || "").replace(/^[\u2014\s]+$/, "")
      if (name) names.add(name)
    }
    return names.size
  }, [credentials])

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 flex flex-col overflow-hidden">
          <div className="p-4 border-b">
            <h1 className="text-lg font-bold mb-1">{beginnerMode ? "Captured Credential Submissions" : "Credential Submissions"}</h1>
            <p className="text-xs text-muted-foreground">Cleartext credentials detected in network traffic — one row per submission; the same account may appear multiple times</p>
          </div>
          <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Total Submissions</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{credentials.length}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Unique Usernames</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{uniqueUsernames}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Services</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{new Set(credentials.map((c) => c.service)).size}</div></CardContent></Card>
          </div>
          <div className="px-4 pb-4 flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Filter by username, service, or IP..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" maxLength={200} />
            </div>
            {credentials.length > 0 && (
            <button onClick={() => setShowPasswords(!showPasswords)} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
              {showPasswords ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              {showPasswords ? "Hide" : "Show"} passwords
            </button>
            )}
          </div>
          <div className="px-4 pb-4"><DecodeBanner /></div>
          <div className="flex-1 overflow-auto px-4">
            <div className="grid grid-cols-[100px_1fr_1fr_1fr_80px] gap-3 min-w-[520px] px-4 py-2 text-xs font-medium text-muted-foreground border-b bg-background shadow-sm sticky top-0">
              <span>Time</span>
              <span>Source</span>
              <span>Username</span>
              <span>Password</span>
              <span>Service</span>
            </div>
            {filtered.length === 0 && (
              <p className="px-4 py-8 text-center text-xs text-muted-foreground">
                {search ? "No credentials match your filter" : "No credentials found"}
              </p>
            )}
            {filtered.slice(0, 500).map((c) => (
              <div key={c.id} className="grid grid-cols-[100px_1fr_1fr_1fr_80px] gap-3 min-w-[520px] px-4 py-2 text-xs items-center border-b border-border/50 hover:bg-accent/30">
                <span className="font-mono text-muted-foreground hl-time">{formatTime(c.timestamp)}</span>
                <span className="font-mono hl-src">{c.srcIp}</span>
                <span className="hl-user"><KeyRound className="h-3 w-3 inline mr-1 text-warning" />{c.username}</span>
                <span className="font-mono hl-pass">{showPasswords ? c.password : "••••••••"}</span>
                <Badge variant="outline" className="text-[10px] px-1 py-0 hl-svc">{c.service}</Badge>
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
