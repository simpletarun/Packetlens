"use client"

// Shared "security dashboard" chrome for BOTH map views (MapLibre interactive
// and the offline globe fallback). KPI bar + map slot + right sidebar
// (Top Countries by bytes with flags, Protocol donut + toggleable legend,
// Unresolved Externals) + bottom info cards. Both maps used to duplicate the
// sidebar; this is the one implementation.

import { ReactNode } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PROTOCOL_COLORS, formatBytes } from "@/lib/map-data"

interface CountryRow {
  name: string
  code: string
  bytes: number
}

interface UnresolvedRow {
  ip: string
  bytes: number
}

interface MapChromeProps {
  // KPI bar
  publicIps: number
  flows: number
  trafficBytes: number
  homeValue: string
  homeSub: string
  privateHosts: number
  // Top Countries
  topCountries: CountryRow[]
  // A clicked pin dims every country except the focused one ("" = no focus).
  focusCountry?: string | null
  // Top Protocols (donut)
  protoCounts: [string, number][]
  protoTotal: number
  hiddenProtocols: ReadonlySet<string>
  // Optional: maps that implement protocol toggling pass a handler; maps that
  // don't (the offline globe) pass neither and get plain non-clickable rows.
  onToggleProtocol?: (proto: string) => void
  // Unresolved Externals
  unresolved: UnresolvedRow[]
  undecodable: { packets: number; bytes: number } | null
  // Bottom info cards
  info: { mapType: string; geoDb: string; dataSource: string }
  // Map slot: each map renders its own canvas/toolbar here
  children: ReactNode
  className?: string
}

// Country code -> regional-indicator flag emoji ("" for non-2-letter codes).
function flagEmoji(cc: string): string {
  if (!/^[A-Z]{2}$/.test(cc)) return ""
  return String.fromCodePoint(...[...cc].map(c => 0x1f1a5 + c.charCodeAt(0)))
}

function kpiCard(label: string, value: string, sub: string) {
  return (
    <div className="rounded-xl border bg-card shadow-sm px-4 py-3 min-w-0">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="text-2xl font-bold tabular-nums leading-tight truncate">{value}</div>
      <div className="text-[10px] text-muted-foreground truncate">{sub}</div>
    </div>
  )
}

// Donut center shows the packet total; legend rows toggle a protocol on/off
// (the map fades/removes that protocol's arcs — spec: "toggle from legend").
// `hidden`/`onToggle` are optional: the dashboard's non-interactive donut just
// omits both to get plain legend rows.
export function ProtoDonut({ protoCounts, protoTotal, hidden = new Set<string>(), onToggle }: {
  protoCounts: [string, number][]
  protoTotal: number
  hidden?: ReadonlySet<string>
  onToggle?: (proto: string) => void
}) {
  if (protoTotal === 0) {
    return <div className="flex h-28 items-center justify-center rounded border border-dashed text-xs text-muted-foreground">No packets</div>
  }
  const entries = protoCounts.filter(([, c]) => c > 0)
  let acc = 0
  let gradient = ""
  const stops: string[] = []
  for (const [proto, count] of entries) {
    const from = acc
    acc += count / protoTotal * 100
    const off = hidden.has(proto)
    const color = off ? "var(--muted-foreground)" : PROTOCOL_COLORS[proto] || "#64748b"
    stops.push(`${proto} ${color} ${from.toFixed(2)}% ${acc.toFixed(2)}%`)
  }
  // conic-gradient with 1% hard stops between segments keeps slices crisp.
  gradient = `conic-gradient(from -90deg, ${stops.map(([, color, a, b]) => `${color} ${a} ${b}`).join(", ")})`
  const visibleTotal = entries.filter(([p]) => !hidden.has(p)).reduce((s, [, c]) => s + c, 0)
  return (
    <div className="text-center">
      <div
        className="relative mx-auto h-32 w-32 rounded-full"
        style={{ background: gradient }}
        role="img" aria-label="Protocol distribution donut"
      >
        <div className="absolute inset-2 flex flex-col items-center justify-center rounded-full bg-card">
          <span className="text-xl font-bold tabular-nums leading-none">{visibleTotal}</span>
          <span className="text-[9px] text-muted-foreground mt-0.5">{hidden.size > 0 ? "shown" : "packets"}</span>
        </div>
      </div>
      <div className="mt-3 space-y-1 text-left">
        {entries.map(([proto, count]) => {
          const off = hidden.has(proto)
          const rowInner = (
            <>
              <span className="flex items-center gap-1.5 min-w-0">
                <span className="h-2 w-2 rounded-full shrink-0" style={{ background: off ? "#64748b" : PROTOCOL_COLORS[proto] || "#64748b" }} />
                <span className={`truncate font-medium ${off ? "text-muted-foreground line-through" : ""}`}>{proto}</span>
              </span>
              <span className="tabular-nums text-muted-foreground shrink-0">{count.toLocaleString()} · {((count / protoTotal) * 100).toFixed(0)}%</span>
            </>
          )
          return onToggle
            ? (
              <button key={proto}
                onClick={() => onToggle(proto)}
                className="flex w-full items-center justify-between gap-2 rounded px-1.5 py-0.5 text-[11px] hover:bg-accent/60 transition-colors"
                title={off ? "Click to show" : "Click to hide"}
              >
                {rowInner}
              </button>
            )
            : (
              <div key={proto} className="flex items-center justify-between gap-2 px-1.5 py-0.5 text-[11px]">
                {rowInner}
              </div>
            )
        })}
      </div>
    </div>
  )
}

export function MapChrome({
  publicIps, flows, trafficBytes, homeValue, homeSub, privateHosts,
  topCountries, protoCounts, protoTotal, hiddenProtocols, onToggleProtocol,
  unresolved, undecodable, info, focusCountry, children, className,
}: MapChromeProps) {
  const panelMax = Math.max(...topCountries.map(c => c.bytes), 1)
  return (
    <div className={className}>
      {/* Top summary bar */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-3 mb-4">
        {kpiCard("Public IPs", publicIps.toLocaleString(), "drawn on the map")}
        {kpiCard("Destinations", flows.toLocaleString(), "external flows drawn")}
        {kpiCard("Total Traffic", formatBytes(trafficBytes), "sum across flows")}
        {kpiCard("Home Network", homeValue, homeSub)}
        {kpiCard("Private Hosts", privateHosts.toLocaleString(), "hidden from globe")}
      </div>

      <div className="flex gap-4 items-start">
        {/* Map slot */}
        <div className="relative flex-1 min-w-0">{children}</div>

        {/* Right sidebar */}
        <aside className="hidden lg:flex shrink-0 flex-col gap-3" style={{ width: "15.5rem" }}>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Top Countries</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5 pt-2">
              {topCountries.length === 0 && <p className="text-xs text-muted-foreground">No public country traffic</p>}
              {topCountries.slice(0, 7).map(({ name, code, bytes }) => (
                <div key={name} className={`flex items-center gap-2 transition-opacity ${focusCountry && code !== focusCountry ? "opacity-40" : ""}`}>
                  <span className="w-6 shrink-0 text-sm leading-none text-center" aria-hidden>{flagEmoji(code) || <span className="text-[10px]">{code}</span>}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex justify-between items-baseline gap-1">
                      <span className="text-[11px] font-medium truncate" title={name}>{name}</span>
                      <span className="text-[10px] text-muted-foreground tabular-nums shrink-0">{formatBytes(bytes)} · {Math.round(bytes / panelMax * 100)}%</span>
                    </div>
                    <div className="h-1 mt-0.5 bg-muted rounded-sm overflow-hidden">
                      <div className="h-full bg-primary rounded-sm transition-all" style={{ width: `${(bytes / panelMax) * 100}%` }} />
                    </div>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Top Protocols</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              <ProtoDonut protoCounts={protoCounts} protoTotal={protoTotal} hidden={hiddenProtocols} onToggle={onToggleProtocol} />
            </CardContent>
          </Card>

          {(unresolved.length > 0 || (undecodable && undecodable.packets > 0)) && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Unresolved Externals</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1 pt-2">
                {unresolved.slice(0, 6).map(u => (
                  <div key={u.ip} className="flex justify-between gap-2 text-[11px]">
                    <span className="font-mono truncate">{u.ip}</span>
                    <span className="tabular-nums text-muted-foreground shrink-0">{formatBytes(u.bytes)}</span>
                  </div>
                ))}
                {unresolved.length > 6 && <div className="text-[10px] text-muted-foreground">&hellip;and {unresolved.length - 6} more</div>}
                {undecodable && undecodable.packets > 0 && (
                  <div className="flex justify-between gap-2 text-[11px]">
                    <span className="truncate text-muted-foreground">undecodable/other</span>
                    <span className="tabular-nums text-muted-foreground shrink-0">{formatBytes(undecodable.bytes)}</span>
                  </div>
                )}
                <p className="pt-1 text-[10px] leading-snug text-muted-foreground">
                  {unresolved.length > 0 ? "No GeoIP: countries unresolved, nothing drawn." : "Undecodable packets carry no address."}
                </p>
              </CardContent>
            </Card>
          )}
        </aside>
      </div>

      {/* Bottom info cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
        <div className="rounded-xl border bg-card shadow-sm px-4 py-2.5">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Map</div>
          <div className="text-xs font-medium mt-0.5">{info.mapType}</div>
        </div>
        <div className="rounded-xl border bg-card shadow-sm px-4 py-2.5">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground">GeoIP</div>
          <div className="text-xs font-medium mt-0.5">{info.geoDb}</div>
        </div>
        <div className="rounded-xl border bg-card shadow-sm px-4 py-2.5">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Private IPs</div>
          <div className="text-xs font-medium mt-0.5">{privateHosts.toLocaleString()} hidden</div>
        </div>
        <div className="rounded-xl border bg-card shadow-sm px-4 py-2.5">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Source</div>
          <div className="text-xs font-medium mt-0.5">{info.dataSource}</div>
        </div>
      </div>
    </div>
  )
}