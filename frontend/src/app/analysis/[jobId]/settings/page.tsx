"use client"

import { useEffect, useRef, useState } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { useRouter } from "next/navigation"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Settings, Trash2, RefreshCw, Network, Globe2, Upload, Database } from "lucide-react"

const DLT_NAMES: Record<number, string> = {
  0: "NULL / Loopback",
  1: "Ethernet",
  101: "Raw IP (IPv4/IPv6)",
  113: "Linux cooked v1 (SLL)",
  276: "Linux cooked v2 (SLL2)",
}

interface GeoDbStatus {
  present: boolean
  name?: string
  size?: number
  attribution?: string
  downloading?: boolean
  // Auto-install failed (server offline etc.) — show the error + retry
  // instead of spinning "downloading…" forever.
  error?: string
}

function formatSize(b: number): string {
  if (b >= 1048576) return `${(b / 1048576).toFixed(1)} MB`
  if (b >= 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${b} B`
}

// Poll loop shared by the mount effect and the Retry button: re-arming it
// on retry is what lets the page track the re-started install instead of
// freezing on a permanent "downloading…" spinner (QA). Module-scope so no
// component hook deps are involved in the self-scheduling setTimeout.
async function pollGeoStatus(opts: { cancelled: () => boolean; onStatus: (s: GeoDbStatus) => void }): Promise<void> {
  try {
    const s = await (await fetch("/api/v1/geo/status")).json()
    if (opts.cancelled()) return
    opts.onStatus(s)
    // First run: the server auto-installs the database in the background —
    // poll until it lands so the page flips to "installed" on its own.
    // A failed install reports downloading:false + error, which stops
    // the loop (it used to poll "downloading…" forever).
    if (!s.present && s.downloading && !s.error) {
      setTimeout(() => pollGeoStatus(opts), 3000)
    }
  } catch { /* unreachable — leave status unknown */ }
}

export default function SettingsPage() {
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const toggleBeginnerMode = useAnalysisStore((s) => s.toggleBeginnerMode)
  const resetAnalysis = useAnalysisStore((s) => s.resetAnalysis)
  const router = useRouter()
  const dltOverride = useAnalysisStore((s) => s.dltOverride)
  const setDltOverride = useAnalysisStore((s) => s.setDltOverride)
  const settings = useAnalysisStore((s) => s.settings)
  const setSettings = useAnalysisStore((s) => s.setSettings)
  const [confirming, setConfirming] = useState(false)
  const [dbStatus, setDbStatus] = useState<GeoDbStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [dbMessage, setDbMessage] = useState<string | null>(null)
  const geoFileRef = useRef<HTMLInputElement>(null)
  const [latInput, setLatInput] = useState<string>(settings.homeLat == null ? "" : String(settings.homeLat))
  const [lonInput, setLonInput] = useState<string>(settings.homeLon == null ? "" : String(settings.homeLon))
  const [homeError, setHomeError] = useState<string | null>(null)
  const [homeSaved, setHomeSaved] = useState(false)

  const applyHome = () => {
    setHomeError(null)
    if (latInput.trim() === "" || lonInput.trim() === "") {
      setHomeError("Enter both latitude and longitude.")
      return
    }
    const la = Number(latInput)
    const lo = Number(lonInput)
    if (!Number.isFinite(la) || la < -90 || la > 90) { setHomeError("Latitude must be between -90 and 90."); return }
    if (!Number.isFinite(lo) || lo < -180 || lo > 180) { setHomeError("Longitude must be between -180 and 180."); return }
    setSettings({ homeLat: la, homeLon: lo })
    setHomeSaved(true)
    const t = setTimeout(() => setHomeSaved(false), 2500)
    return () => clearTimeout(t)
  }

  const clearHome = () => {
    setSettings({ homeLat: null, homeLon: null })
    setLatInput("")
    setLonInput("")
    setHomeError(null)
    setHomeSaved(false)
  }

  const refreshDb = async () => {
    try {
      const res = await fetch("/api/v1/geo/status")
      setDbStatus(await res.json())
    } catch { /* unreachable — leave status unknown */ }
  }

  useEffect(() => {
    let cancelled = false
    pollGeoStatus({ cancelled: () => cancelled, onStatus: setDbStatus })
    return () => { cancelled = true }
  }, [])

  const uploadDb = async (f: File) => {
    setBusy(true)
    setDbMessage(null)
    try {
      const fd = new FormData()
      fd.append("file", f)
      const res = await fetch("/api/v1/geo/db", { method: "POST", body: fd })
      const body = await res.json()
      if (!res.ok) { setDbMessage(body.error || "Upload failed"); return }
      setDbMessage(`${body.name} installed`)
      await refreshDb()
    } catch {
      setDbMessage("Upload failed — could not reach server")
    } finally {
      setBusy(false)
    }
  }

  const removeDb = async () => {
    setBusy(true)
    setDbMessage(null)
    try {
      await fetch("/api/v1/geo/db", { method: "DELETE" })
      await refreshDb()
      setDbMessage("Database removed")
    } catch {
      setDbMessage("Remove failed")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-2xl mx-auto space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  Settings
                </CardTitle>
                <CardDescription>Configure PacketLens analysis preferences</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="border rounded-md p-4">
                  <h3 className="font-semibold text-sm mb-2 flex items-center gap-2">
                    <Network className="h-4 w-4" />
                    Link Layer Override
                  </h3>
                  <p className="text-xs text-muted-foreground mb-3">
                    Applied to the next upload when the capture uses non-Ethernet encapsulation (raw IP, Linux cooked frames, loopback), so headers can be decoded.
                  </p>
                  <div className="flex items-center gap-2">
                    <select
                      aria-label="Link layer override"
                      className="h-9 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      value={dltOverride === null ? "" : String(dltOverride)}
                      onChange={(e) => setDltOverride(e.target.value === "" ? null : Number(e.target.value))}
                    >
                      <option value="">Auto (detect from file)</option>
                      {Object.entries(DLT_NAMES).map(([v, label]) => (
                        <option key={v} value={v}>{label}</option>
                      ))}
                    </select>
                    {dltOverride !== null && (
                      <p className="text-xs text-muted-foreground">Using: {DLT_NAMES[dltOverride] ?? `DLT ${dltOverride}`}</p>
                    )}
                  </div>
                </div>
                <div className="border rounded-md p-4">
                  <h3 className="font-semibold text-sm mb-2">Beginner Mode</h3>
                  <p className="text-xs text-muted-foreground mb-3">Simplify advanced features for easier navigation (plain labels, fewer tables)</p>
                  <Button
                    variant={beginnerMode ? "default" : "outline"}
                    size="sm"
                    onClick={toggleBeginnerMode}
                    aria-pressed={beginnerMode}
                  >
                    {beginnerMode ? "Beginner Mode: On" : "Beginner Mode: Off"}
                  </Button>
                </div>
                <div className="border rounded-md p-4">
                  <h3 className="font-semibold text-sm mb-2">Online GeoIP Lookups</h3>
                  <p className="text-xs text-muted-foreground mb-3">
                    When off, external IP locations come only from the offline GeoIP database. Enabling sends unresolved public IPs to ipwho.is — lookups leave the device.
                  </p>
                  <div className="flex items-center gap-2">
                    <Button
                      variant={settings.onlineGeo ? "default" : "outline"}
                      size="sm"
                      onClick={() => setSettings({ onlineGeo: !settings.onlineGeo })}
                      aria-pressed={settings.onlineGeo}
                    >
                      {settings.onlineGeo ? "Online lookups: On" : "Online lookups: Off"}
                    </Button>
                    {settings.onlineGeo && (
                      <p className="text-xs text-muted-foreground">Resolved by ipwho.is when the local database has no entry.</p>
                    )}
                  </div>
                </div>
                <div className="border rounded-md p-4">
                  <h3 className="font-semibold text-sm mb-2 flex items-center gap-2">
                    <Database className="h-4 w-4" />
                    GeoIP Database
                  </h3>
                  <p className="text-xs text-muted-foreground mb-3">
                    Offline MaxMind-format (.mmdb) database, e.g. DB-IP Lite. Lookups are local and never leave the device.
                    The server installs the free DB-IP Lite database automatically on first use (CC BY 4.0).
                  </p>
                  {dbStatus?.present ? (
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-sm">
                        <p className="font-medium">{dbStatus.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {dbStatus.size ? formatSize(dbStatus.size) : ""}{" · "}{dbStatus.attribution || "DB-IP Lite (CC BY 4.0)"}
                        </p>
                      </div>
                      <Button variant="outline" size="sm" disabled={busy} onClick={removeDb}>Remove</Button>
                    </div>
                  ) : dbStatus?.downloading ? (
                    <div className="flex items-center gap-2 text-sm">
                      <RefreshCw className="h-4 w-4 animate-spin text-muted-foreground" />
                      <span className="text-muted-foreground">Downloading DB-IP Lite automatically… (one-time, ~125 MB)</span>
                    </div>
                  ) : dbStatus?.error ? (
                    <div className="flex flex-col gap-2">
                      <p className="text-sm text-destructive">{dbStatus.error}</p>
                      <Button variant="outline" size="sm" onClick={() => {
                          setDbStatus(null)
                          // Fire-and-forget: the download endpoint starts the
                          // auto-install server-side; the poll loop tracks it.
                          fetch("/api/v1/geo/db").catch(() => {})
                          pollGeoStatus({ cancelled: () => false, onStatus: setDbStatus })
                        }}>
                        <RefreshCw className="h-3.5 w-3.5 mr-1" /> Retry auto-install
                      </Button>
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">No database installed — external IPs resolve to Unknown.</p>
                  )}
                  <div className="flex items-center gap-2 flex-wrap">
                    <input
                      ref={geoFileRef}
                      type="file"
                      accept=".mmdb"
                      className="hidden"
                      onChange={(e) => { const f = e.target.files?.[0]; if (f) uploadDb(f) }}
                    />
                    <Button variant="outline" size="sm" disabled={busy} onClick={() => geoFileRef.current?.click()}>
                      <Upload className="h-4 w-4 mr-1" /> {dbStatus?.present ? "Replace .mmdb" : "Upload .mmdb"}
                    </Button>
                  </div>
                  {dbMessage && <p className="text-xs mt-2 text-muted-foreground">{dbMessage}</p>}
                </div>
                <div className="border rounded-md p-4">
                  <h3 className="font-semibold text-sm mb-2">Manual Home Location</h3>
                  <p className="text-xs text-muted-foreground mb-3">
                    Optional coordinates shown in the Home Location card — a fallback that never needs the network, unlike the online self-lookup. Latitude -90…90, longitude -180…180.
                  </p>
                  <div className="flex flex-wrap items-end gap-2">
                    <label className="flex flex-col gap-1 text-xs text-muted-foreground">
                      Latitude (-90…90)
                      <input
                        type="number"
                        inputMode="decimal"
                        aria-label="Manual home latitude"
                        className="h-9 w-28 rounded-md border border-input bg-background px-3 text-sm"
                        value={latInput}
                        onChange={(e) => { setLatInput(e.target.value); setHomeError(null) }}
                      />
                    </label>
                    <label className="flex flex-col gap-1 text-xs text-muted-foreground">
                      Longitude (-180…180)
                      <input
                        type="number"
                        inputMode="decimal"
                        aria-label="Manual home longitude"
                        className="h-9 w-28 rounded-md border border-input bg-background px-3 text-sm"
                        value={lonInput}
                        onChange={(e) => { setLonInput(e.target.value); setHomeError(null) }}
                      />
                    </label>
                    <Button variant="outline" size="sm" onClick={applyHome}>Apply</Button>
                    <Button variant="ghost" size="sm" onClick={clearHome}>Clear</Button>
                  </div>
                  {homeError && <p className="text-xs text-destructive mt-2">{homeError}</p>}
                  {homeSaved && <p className="text-xs text-success mt-2">Saved — the Home Location card now uses your coordinates.</p>}
                  {settings.homeLat !== null && settings.homeLat !== undefined && settings.homeLon !== null && settings.homeLon !== undefined && (
                    <p className="text-xs text-muted-foreground mt-2">Manual coordinates take precedence over online resolution.</p>
                  )}
                </div>
                <div className="border rounded-md p-4">
                  <h3 className="font-semibold text-sm mb-2"><Globe2 className="h-4 w-4 inline" /> Country Counts</h3>
                  <p className="text-xs text-muted-foreground">The Countries metric on the dashboard reflects resolved locations from the local database (or the online fallback when enabled).</p>
                </div>
                <div className="border rounded-md p-4">
                  <h3 className="font-semibold text-sm mb-2">Display</h3>
                  <p className="text-xs text-muted-foreground">Graph appearance and visual preferences are set per view (map zoom, graph layout). No global display options are offered in this build.</p>
                </div>
                <div className="border rounded-md p-4">
                  <h3 className="font-semibold text-sm mb-2">Export Options</h3>
                  <p className="text-xs text-muted-foreground">Reports export via the print dialog (PDF) or the Markdown download on the Reports page. PNG/SVG export is available on the map and graph views.</p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Trash2 className="h-5 w-5 text-destructive" />
                  Danger Zone
                </CardTitle>
                <CardDescription className="text-destructive">Irreversible actions</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="border rounded-md p-4">
                  <h3 className="font-semibold text-sm mb-2 flex items-center gap-2">
                    <RefreshCw className="h-4 w-4" />
                    Clear Analysis
                  </h3>
                  <p className="text-xs text-muted-foreground mb-3">Remove all loaded analysis data and return to the job list</p>
                  {confirming ? (
                    <div className="flex items-center gap-2">
                      <Button variant="destructive" size="sm" onClick={() => { resetAnalysis(); setConfirming(false); router.push("/") }}>
                        Confirm Clear
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => setConfirming(false)}>Cancel</Button>
                    </div>
                  ) : (
                    <Button variant="outline" size="sm" onClick={() => setConfirming(true)}>
                      Clear Analysis
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </main>
      </div>
    </div>
  )
}