"use client"

import { useState, useMemo, useEffect } from "react"
import dynamic from "next/dynamic"

import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn } from "@/lib/utils"
import { riskLevel, riskColorClass, verdictLevel } from "@/lib/risk"
import { formatBytes, isLanFlow } from "@/lib/map-data"
import { packetProtocolCounts } from "@/lib/analysis"
import { localOwnedAddresses, decodeRateOf, confirmedSeverityOf } from "@/lib/report"
import { resolveHomeLocation, type GeoLocation } from "@/lib/geo"
import { ProtoDonut } from "@/components/analysis/map-chrome"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

const FlowWorldMap = dynamic(() => import("@/components/analysis/interactive-world-map").then(m => m.InteractiveWorldMap), { ssr: false })
const InvestigationGraphView = dynamic(() => import("@/components/analysis/investigation-graph").then(m => m.InvestigationGraph), { ssr: false })

export default function VisualizationsPage() {
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const settings = useAnalysisStore((s) => s.settings)
  const stats = useAnalysisStore((s) => s.stats)
  const packets = useAnalysisStore((s) => s.packets)
  const flows = useAnalysisStore((s) => s.flows)
  const alerts = useAnalysisStore((s) => s.alerts)
  const dns = useAnalysisStore((s) => s.dns)
  const devices = useAnalysisStore((s) => s.devices)
  const http = useAnalysisStore((s) => s.http)
  const tls = useAnalysisStore((s) => s.tls)
  const files = useAnalysisStore((s) => s.files)
  const credentials = useAnalysisStore((s) => s.credentials)
  const certificates = useAnalysisStore((s) => s.certificates)
  const decode = useAnalysisStore((s) => s.decode)

  const [home, setHome] = useState<GeoLocation | null>(null)
  const [view, setView] = useState<"map" | "graph">("graph")

  // Same verdict gate as the reports page: <5% decoded → no verdict, so the
  // Statistics Risk block must not read "0/100 SAFE" on undecodable traffic
  // while the report says UNKNOWN (QA).
  const undecodable = useMemo(() => decodeRateOf(decode, packets) < 0.05, [decode, packets])

  // Verdict level = score band floored by the highest CONFIRMED finding
  // severity — identical to the report's buildReportRisk — a HIGH-severity
  // alert at a 39/100 LOW score must read HIGH here too, while a SUSPECTED
  // critical rule never headlines above a confirmed High finding, and a
  // capture with no confirmed findings is never lifted above its score band
  // (QA: log.pcapng / time.pcapng verdicts overstated the confirmed state).
  const riskLevelObj = useMemo(() => {
    const confirmed = confirmedSeverityOf(alerts)
    return verdictLevel(riskLevel(stats.riskScore), confirmed)
  }, [stats.riskScore, alerts])

  // Home = the analyst's own location, known only from an online self-lookup
  // (offline databases cannot tell you where you are). A MANUAL lat/lon set
  // in Settings takes precedence and never needs the network (F-04 QA).
  const manualHome = settings.homeLat !== null && settings.homeLat !== undefined
    && settings.homeLon !== null && settings.homeLon !== undefined
  useEffect(() => {
    if (!settings.onlineGeo || manualHome) return
    let cancelled = false
    resolveHomeLocation().then((h) => { if (!cancelled) setHome(h) })
    return () => { cancelled = true }
  }, [settings.onlineGeo, manualHome])

  // Shared classifier: same counts as the dashboard/timeline use, so the
  // percentages can't drift between views (C2).
  const { protoCount, protoTotal } = useMemo(() => {
    const protoCount = packetProtocolCounts(packets)
    const protoTotal = Object.values(protoCount).reduce((a, b) => a + b, 0)
    return { protoCount, protoTotal }
  }, [packets])

  const topFlows = useMemo(() => [...flows].sort((a, b) => b.bytesTotal - a.bytesTotal).slice(0, 10), [flows])
  const maxFlowBytes = Math.max(...topFlows.map((f) => f.bytesTotal), 1)
  // Top Flows label: show the DNS-resolved name for the external side when
  // known, else the (truncated) raw address. The full pair is in the title
  // tooltip so a long IPv6 doesn't dominate the bar (reviewer feedback).
  const flowLabel = (f: { srcIp?: string; dstIp?: string }, resolvers: Map<string, string>): string => {
    const s = f.srcIp ?? "\u2014"
    const d = f.dstIp ?? "\u2014"
    if (resolvers.has(s)) return `${resolvers.get(s)} → ${d}`
    if (resolvers.has(d)) return `${s} → ${resolvers.get(d)}`
    const slice = (ip: string) => ip.length > 22 ? ip.slice(0, 20) + "…" : ip
    return `${slice(s)} → ${slice(d)}`
  }
  // A flow the map never draws: LAN↔LAN traffic, or a public side that is a
  // local-owned address (the LAN's own WAN IP / router delegated /64). Tag it
  // here so Top Flows can be reconciled with the map's drawn totals.
  const isLocalOwnedFlow = (f: { srcIp?: string; dstIp?: string }, aliases: Set<string>) =>
    (f.srcIp !== undefined && f.dstIp !== undefined && isLanFlow(f.srcIp, f.dstIp))
    || (f.srcIp !== undefined && aliases.has(f.srcIp)) || (f.dstIp !== undefined && aliases.has(f.dstIp))

  // DNS answers map resolved IPs back to names, so the Top Flows row of a long
  // IPv6 address can read "client → api.example.com" instead of the raw ::.
  const ipHostname = useMemo(() => {
    const m = new Map<string, string>()
    for (const d of dns) if (d.isResponse && d.answer && d.answer !== "\u2014" && !m.has(d.answer)) m.set(d.answer, d.query)
    return m
  }, [dns])

  const sevCount = useMemo(() => {
    const c = { High: 0, Medium: 0, Low: 0 }
    for (const t of alerts) {
      if (t.severity >= 4) c.High++
      else if (t.severity >= 3) c.Medium++
      else c.Low++
    }
    return c
  }, [alerts])
  const sevTotal = sevCount.High + sevCount.Medium + sevCount.Low || 1

  // Capture window (QA): the page had no time-range indicator — show the
  // first→last observed packet timestamps. Min/max folded into a loop:
  // Math.min/max(...spread) overflows the call stack past ~125k packets.
  const captureWindow = useMemo(() => {
    let min = Infinity
    let max = -Infinity
    for (const p of packets) {
      const t = typeof p.timestamp === "string" ? Date.parse(p.timestamp) : NaN
      if (!Number.isFinite(t) || t <= 0) continue
      if (t < min) min = t
      if (t > max) max = t
    }
    if (!Number.isFinite(min)) return null
    const fmt = (t: number) => new Date(t).toLocaleTimeString()
    return `${fmt(min)} → ${fmt(max)}`
  }, [packets])

  const dnsByType = useMemo(() => {
    // Queries only (F-04 QA): responses echo the question, so counting both
    // sides of a lookup doubles every number — 54 "queries" for 27 real ones.
    const m: Record<string, number> = {}
    for (const d of dns) {
      if (d.isResponse) continue
      m[d.type] = (m[d.type] || 0) + 1
    }
    return m
  }, [dns])
  const dnsTotal = Object.values(dnsByType).reduce((a, b) => a + b, 0) || 1
  const dnsQueryCount = useMemo(() => dns.filter((d) => !d.isResponse).length, [dns])

  // B-69/B-72: local-owned addresses (private primaries + MAC-merged aliases +
  // MAC groups + /64 SLAAC siblings) — the map must never plot any of them as
  // external dots (India read 4 IPs for the client's own aliases + router).
  const localAliases = useMemo(() => localOwnedAddresses(devices), [devices])
  // B-71: local↔public arcs anchor at the analyst's home location — manual
  // settings win, else the online self-lookup (offline databases cannot tell
  // you where you are; both are null when neither is available). Toggling
  // Online GeoIP off must also drop the resolved anchor — a stale online
  // location kept anchoring the arcs while the card said lookups were off (QA).
  const homeAnchor = useMemo(
    () => manualHome ? { lat: settings.homeLat!, lon: settings.homeLon! } : (settings.onlineGeo ? home : null),
    [manualHome, settings.homeLat, settings.homeLon, home, settings.onlineGeo],
  )

  // LAN card: LAN↔LAN traffic only — private-IP traffic with a PUBLIC peer is
  // egress (WAN), not LAN traffic (F-04 QA). "Local hosts" reuses the
  // merge-aware device count so it can never disagree with the report.
  // The source must be a private UNICAST host (the DHCPv6 client
  // 0:0:0:0:0:0:0:0 is interface chatter, not a LAN peer), and the
  // destination must NOT be a public-unicast IP: multicast/broadcast peers
  // (mDNS, SSDP, HOPOPT→ff02::) are LAN traffic. Requiring BOTH ends unicast
  // over-corrected and dropped 97 packets of local→multicast/broadcast
  // traffic (QA B-68: LAN card read 2.4 KB/31 pkts vs the true 13.9 KB/128).
  const lan = useMemo(() => {
    let lanPackets = 0
    let lanBytes = 0
    const bySrc = new Map<string, number>()
    for (const p of packets) {
      if (!p.srcIp || !p.dstIp || !isLanFlow(p.srcIp, p.dstIp)) continue
      lanPackets++
      lanBytes += p.length
      bySrc.set(p.srcIp, (bySrc.get(p.srcIp) || 0) + p.length)
    }
    const top = [...bySrc.entries()].sort((a, b) => b[1] - a[1])[0]
    return {
      srcCount: bySrc.size,
      packets: lanPackets,
      bytes: lanBytes,
      topSrc: top ? top[0] : null,
      topBytes: top ? top[1] : 0,
    }
  }, [packets])

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          <div>
            <h1 className="text-lg font-bold mb-1">Visualizations</h1>
            <p className="text-xs text-muted-foreground">
              Graphical views of network traffic data
              {captureWindow && <span className="ml-2">· capture {captureWindow}</span>}
            </p>
          </div>

          <div className="flex gap-1.5">
            {(["graph", "map"] as const).map((v) => (
              <button
                key={v}
                onClick={() => setView(v)}
                className={cn(
                  "px-3 py-1.5 rounded-full border text-xs font-medium transition-colors",
                  view === v ? "bg-primary/10 border-primary/30 text-primary" : "bg-muted/50 border-muted text-muted-foreground hover:bg-accent/60",
                )}
              >
                {v === "map" ? "World Map" : "Investigation Graph"}
              </button>
            ))}
          </div>

          {/* World Map view carries its own KPI bar + sidebar chrome, so the
              page rail only renders for the graph view — two stacked right
              columns squeezed the map into misaligned slivers (QA). */}
          <div className={cn("grid gap-6", view === "graph" && "grid-cols-1 lg:grid-cols-[1fr_220px]")}>
            <div>
              {view === "map" ? (
                <FlowWorldMap packets={packets} alerts={alerts} localDevices={stats.devices} localAliases={localAliases} homeAnchor={homeAnchor} />
              ) : (
                <InvestigationGraphView
                  packets={packets} flows={flows} dns={dns}
                  http={http} tls={tls} files={files}
                  credentials={credentials} certificates={certificates}
                  devices={devices} alerts={alerts}
                />
              )}
            </div>

            {view === "graph" && (
            <div className="space-y-6">
              <Card>
                <CardHeader className="pb-2"><CardTitle className="text-sm">Local Network</CardTitle></CardHeader>
                <CardContent className="pt-2 space-y-3 text-xs">
                  {lan.srcCount > 0 ? (
                    <>
                      <div className="flex items-center justify-between border-b border-border/40 pb-2">
                        <span className="text-muted-foreground">Local hosts</span>
                        <span className="font-semibold">{stats.devices.toLocaleString()}</span>
                      </div>
                      <div className="flex items-center justify-between border-b border-border/40 pb-2">
                        <span className="text-muted-foreground">LAN traffic</span>
                        <span className="font-semibold">{formatBytes(lan.bytes)} ({lan.packets.toLocaleString()} pkts)</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Top LAN host</span>
                        <span className="font-mono font-semibold flex items-center gap-1">{lan.topSrc} <span className="text-muted-foreground/70">({formatBytes(lan.topBytes)})</span></span>
                      </div>
                      <p className="text-muted-foreground/70 pt-1">Private-IP nodes are never drawn on the map — they have no geography.</p>
                    </>
                  ) : (
                    <p className="text-muted-foreground">No private-IP traffic in this capture — every peer is external.</p>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2"><CardTitle className="text-sm">Home Location</CardTitle></CardHeader>
                <CardContent className="pt-2 text-xs space-y-2">
                  {manualHome ? (
                    <>
                      <p className="font-semibold">Manual coordinates ({settings.homeLat!.toFixed(2)}, {settings.homeLon!.toFixed(2)})</p>
                      <p className="text-muted-foreground">Set in Settings — no network lookup performed.</p>
                    </>
                  ) : settings.onlineGeo && home ? (
                    <>
                      <p className="font-semibold">{home.city ? `${home.city}, ` : ""}{home.country}</p>
                      <p className="text-muted-foreground">Coordinates {home.lat.toFixed(2)}, {home.lon.toFixed(2)}</p>
                      <p className="text-muted-foreground/70">Your location, resolved from your public IP.</p>
                    </>
                  ) : settings.onlineGeo ? (
                    <p className="text-muted-foreground">📍 Home location unavailable — could not resolve your public IP.</p>
                  ) : (
                    <>
                      <p className="font-semibold">📍 Home location unavailable</p>
                      <p className="text-muted-foreground">Enable Online GeoIP in Settings, or choose a manual location.</p>
                    </>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2"><CardTitle className="text-sm">Statistics</CardTitle></CardHeader>
                <CardContent className="pt-2 space-y-3 text-xs">
                  {[
                    { label: "Devices", value: stats.devices.toLocaleString() },
                    // Same classifier as the chips/donut: stats.protocols is a
                    // different basis and disagrees with the
                    // panel on the same capture (QA: 5 chips vs 6 stat card).
                    { label: "Protocols", value: Object.keys(protoCount).length.toLocaleString() },
                    { label: "Connections", value: stats.sessions.toLocaleString() },
                    { label: "Alerts", value: stats.alerts.toLocaleString(), danger: stats.alerts > 0 },
                    { label: "Countries", value: stats.countries > 0 ? stats.countries.toLocaleString() : (stats.externalIps === 0 ? "No public IPs" : "GeoIP unavailable") },
                  ].map(({ label, value, danger }) => (
                    <div key={label} className="flex items-center justify-between border-b border-border/40 last:border-0 pb-2 last:pb-0">
                      <span className="text-muted-foreground">{label}</span>
                      <span className={cn("font-semibold", danger && "text-danger")}>{value}</span>
                    </div>
                  ))}
                  <div>
                    <div className="flex items-center justify-between pb-2">
                      <span className="text-muted-foreground">Risk</span>
                      {undecodable ? (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold text-muted-foreground">UNKNOWN / INSUFFICIENT DATA</span>
                      ) : (
                        <span className={cn("px-2 py-0.5 rounded-full text-[10px] font-semibold", riskColorClass(riskLevelObj))}>{riskLevelObj.label.toUpperCase()}</span>
                      )}
                    </div>
                    {undecodable ? (
                      <div className="text-[10px] text-muted-foreground mt-1">Only {((decodeRateOf(decode, packets)) * 100).toFixed(0)}% decoded — no verdict on undecodable traffic</div>
                    ) : (
                      <>
                        <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                          <div className="h-full rounded-full transition-all"
                            style={{ width: `${stats.riskScore}%`, background: "linear-gradient(90deg, var(--chart-2), var(--warning, #f59e0b) 50%, var(--danger, #ef4444))" }} />
                        </div>
                        <div className="text-[10px] text-muted-foreground mt-1">{stats.riskScore}/100</div>
                      </>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>)}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader><CardTitle className="text-base">{beginnerMode ? "Protocols" : "Protocol Distribution"}</CardTitle></CardHeader>
              <CardContent>
                <ProtoDonut protoCounts={[...Object.entries(protoCount)].sort((a, b) => b[1] - a[1])} protoTotal={protoTotal} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle className="text-base">Alert Severity</CardTitle></CardHeader>
              <CardContent>
                {alerts.length === 0 ? (
                  <div className="flex h-[200px] flex-col items-center justify-center gap-1.5 rounded border border-dashed text-center">
                    <span className="text-2xl leading-none">🛡️</span>
                    <span className="text-xs font-medium text-success">No alerts detected</span>
                    <span className="text-[10px] text-muted-foreground">{undecodable ? "Only " + (decodeRateOf(decode, packets) * 100).toFixed(0) + "% decoded — no verdict on undecodable traffic" : `Threat score ${stats.riskScore}/100 · last alert: never`}</span>
                  </div>
                ) : (
                <div className="flex items-end gap-2 h-[200px]">
                  <div className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs font-bold">{sevCount.High}</span>
                    <div className="w-full bg-danger/20 rounded-t-sm" style={{ height: (sevCount.High / sevTotal * 200) + "px" }}>
                      <div className="w-full bg-danger rounded-t-sm" style={{ height: "100%" }} />
                    </div>
                    <span className="text-xs text-muted-foreground">High</span>
                  </div>
                  <div className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs font-bold">{sevCount.Medium}</span>
                    <div className="w-full bg-warning/20 rounded-t-sm" style={{ height: (sevCount.Medium / sevTotal * 200) + "px" }}>
                      <div className="w-full bg-warning rounded-t-sm" style={{ height: "100%" }} />
                    </div>
                    <span className="text-xs text-muted-foreground">Medium</span>
                  </div>
                  <div className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs font-bold">{sevCount.Low}</span>
                    <div className="w-full bg-info/20 rounded-t-sm" style={{ height: (sevCount.Low / sevTotal * 200) + "px" }}>
                      <div className="w-full bg-info rounded-t-sm" style={{ height: "100%" }} />
                    </div>
                    <span className="text-xs text-muted-foreground">Low</span>
                  </div>
                </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle className="text-base">DNS Query Types</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {/* One or two types (A/AAAA on a small capture): a 50/50 bar
                      pair is noise — a simple table reads better (reviewer). */}
                  {Object.keys(dnsByType).length > 0 && Object.keys(dnsByType).length <= 2 ? (
                    <table className="w-full text-xs">
                      <tbody>
                        {Object.entries(dnsByType).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
                          <tr key={type} className="border-b border-border/40 last:border-0">
                            <td className="py-1.5 font-mono">{type}</td>
                            <td className="py-1.5 text-muted-foreground tabular-nums">{count} ({((count / dnsTotal) * 100).toFixed(1)}%)</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                  <div className="space-y-3">
                    {Object.entries(dnsByType).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
                      <div key={type} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="font-mono">{type}</span>
                          <span className="text-muted-foreground tabular-nums">{count}</span>
                        </div>
                        <div className="h-4 bg-muted rounded-sm overflow-hidden">
                          <div className="h-full bg-chart-2 rounded-sm transition-all" style={{ width: (count / dnsTotal * 100) + "%" }} />
                        </div>
                      </div>
                    ))}
                  </div>
                  )}
                  {/* Empty state: a capture with no DNS shows nothing today —
                      a dead card confuses more than "no data" (D4). */}
                  {Object.keys(dnsByType).length === 0 && (
                    <div className="flex h-20 items-center justify-center rounded border border-dashed text-xs text-muted-foreground">
                      No DNS queries in this capture
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle className="text-base">Top Flows by Volume</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {topFlows.map((f) => (
                    <div key={f.id} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="truncate font-mono" title={`${f.srcIp} → ${f.dstIp}`}>
                          {flowLabel(f, ipHostname)}
                        </span>
                        <span className="text-muted-foreground whitespace-nowrap flex items-center gap-1">
                          {isLocalOwnedFlow(f, localAliases) && <span className="text-[9px] text-warning">local</span>}
                          {formatBytes(f.bytesTotal)}
                        </span>
                      </div>
                      <div className="h-3 bg-muted rounded-sm overflow-hidden">
                        <div className="h-full bg-chart-4 rounded-sm transition-all" style={{ width: (f.bytesTotal / maxFlowBytes * 100) + "%" }} />
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader><CardTitle className="text-base">{beginnerMode ? "Network Activity" : "Traffic Overview"}</CardTitle></CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[
                  // Job-summary counts (authoritative) — array lengths would
                  // drift if payload caps ever retain fewer rows (QA: latent
                  // divergence from the dashboard cards).
                  { label: "Total Packets", value: stats.totalPackets, color: "text-info", bg: "bg-info/10" },
                  { label: "Total Flows", value: stats.totalFlows, color: "text-chart-2", bg: "bg-chart-2/10" },
                  { label: "DNS Queries", value: dnsQueryCount, color: "text-warning", bg: "bg-warning/10" },
                  { label: "Threats Detected", value: stats.alerts, color: "text-danger", bg: "bg-danger/10" },
                ].map(({ label, value, color, bg }) => (
                  <div key={label} className={cn("rounded-lg p-4 text-center", bg)}>
                    <div className={cn("text-4xl font-bold tabular-nums", color)}>{value.toLocaleString()}</div>
                    <div className="text-xs text-muted-foreground mt-1">{label}</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </main>
      </div>
    </div>
  )
}
