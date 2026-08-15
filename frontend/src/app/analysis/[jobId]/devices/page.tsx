"use client"

import { useState, useMemo } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn } from "@/lib/utils"
import { vendorLabel } from "@/lib/oui"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Search, X } from "lucide-react"
import { DecodeBanner } from "@/components/analysis/decode-banner"

// F-03: clicking a device row opens its profile — one endpoint, everything
// the capture shows about it: aliases, fingerprint, protocols/ports, peers,
// threat hits and geo. Everything derives from the store; no new data.

interface DeviceProfile {
  protocols: string[]
  ports: { port: number; count: number }[]
  peers: { ip: string; port: number; packets: number }[]
  threats: number
  geo: string
}

export default function DevicesPage() {
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const devices = useAnalysisStore((s) => s.devices)
  const alerts = useAnalysisStore((s) => s.alerts)
  const geoMap = useAnalysisStore((s) => s.geoMap)
  const packets = useAnalysisStore((s) => s.packets)
  const stats = useAnalysisStore((s) => s.stats)
  const [search, setSearch] = useState("")
  const [selectedIp, setSelectedIp] = useState<string | null>(null)

  const filtered = useMemo(
    () => devices.filter((d) => !search ||
      d.ip.toLowerCase().includes(search.toLowerCase()) ||
      d.hostname.toLowerCase().includes(search.toLowerCase()) ||
      d.mac.toLowerCase().includes(search.toLowerCase()) ||
      (d.addresses ?? []).some((a) => a.toLowerCase().includes(search.toLowerCase()))),
    [search, devices]
  )

  // Empty-string vendors (unknown) must not count as a vendor — same rule as
  // the report's §12 count, or the two numbers drift (F-04 QA).
  const uniqueVendors = new Set(devices.map((d) => d.vendor).filter(Boolean)).size

  const selected = useMemo(
    () => devices.find((d) => d.ip === selectedIp) ?? null,
    [devices, selectedIp]
  )

  // Per-endpoint aggregation (F-03). "—" flows carry no real endpoint; a
  // selected device always has a decoded IP, so those never match here.
  const profile: DeviceProfile | null = useMemo(() => {
    if (!selected) return null
    const ip = selected.ip
    const protocols = new Set<string>()
    const ports = new Map<number, number>()
    const peers = new Map<string, Map<number, number>>()
    // Direction-accurate counts: a flow's packets are bidirectional, so
    // crediting f.packets to the device's own port double-counts the peer's
    // half (QA: a 10-pkt flow showed port 443 at 10 with only 5 on the wire).
    // Count only the packets that actually carried the device's address.
    for (const p of packets) {
      if (p.protocol === '\u2014') continue
      if (p.srcIp === ip && typeof p.srcPort === 'number') {
        protocols.add(p.protocol)
        ports.set(p.srcPort, (ports.get(p.srcPort) ?? 0) + 1)
        if (p.dstIp && p.dstIp !== '\u2014' && typeof p.dstPort === 'number') {
          const m = peers.get(p.dstIp) ?? new Map()
          m.set(p.dstPort, (m.get(p.dstPort) ?? 0) + 1)
          peers.set(p.dstIp, m)
        }
      } else if (p.dstIp === ip && typeof p.dstPort === 'number') {
        protocols.add(p.protocol)
        ports.set(p.dstPort, (ports.get(p.dstPort) ?? 0) + 1)
        if (p.srcIp && p.srcIp !== '\u2014' && typeof p.srcPort === 'number') {
          const m = peers.get(p.srcIp) ?? new Map()
          m.set(p.srcPort, (m.get(p.srcPort) ?? 0) + 1)
          peers.set(p.srcIp, m)
        }
      }
    }
    const geo = geoMap.get(ip)
    return {
      protocols: [...protocols].sort(),
      ports: [...ports.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([port, count]) => ({ port, count })),
      peers: [...peers.entries()].map(([peerIp, m]) => {
        const entries = [...m.entries()].sort((a, b) => b[1] - a[1])
        return { ip: peerIp, port: entries[0][0], packets: entries.reduce((s, [, c]) => s + c, 0) }
      }).sort((a, b) => b.packets - a.packets).slice(0, 5),
      threats: alerts.filter((a) => a.srcIp === ip || a.dstIp === ip).length,
      geo: geo ? (geo.city ? `${geo.city}, ${geo.country}` : geo.country) : "GeoIP unavailable",
    }
  }, [selected, packets, alerts, geoMap])

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 flex flex-col overflow-hidden">
          <div className="p-4 border-b">
            <h1 className="text-lg font-bold mb-1">Devices</h1>
            <p className="text-xs text-muted-foreground">Network endpoints discovered in the capture — click a row for its profile</p>
          </div>
          <div className="p-4 grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Endpoints</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{devices.length}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Local Devices</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{stats.devices}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Public IPs</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{stats.externalIps}</div></CardContent></Card>
            <Card><CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground">Vendors</CardTitle></CardHeader><CardContent><div className="text-2xl font-bold">{uniqueVendors}</div></CardContent></Card>
          </div>
          {/* Raw-IP captures carry no Ethernet headers, so the MAC column is
              always "—" and vendor lookup can't run. Say so instead of showing
              a bare 0 (QA: Vendors 0 on the raw-IP capture). CGNAT ranges
              (100.64/10) are also treated as local per RFC 6598 — the counts
              below follow that rule (QA: CGNAT classification undocumented). */}
          {!devices.some((d) => d.mac && d.mac !== "\u2014") && (
            <p className="px-4 pb-2 text-xs text-muted-foreground">No MAC addresses in this capture — vendor lookup needs Ethernet headers (raw IP / IP-only pcap).</p>
          )}
          {devices.some((d) => { const p = d.ip.split("."); return p[0] === "100" && Number(p[1]) >= 64 && Number(p[1]) <= 127 }) && (
            <p className="px-4 pb-2 text-xs text-muted-foreground">CGNAT addresses (100.64.0.0/10, RFC 6598) are counted as local/internal hosts, not public IPs.</p>
          )}
          <div className="px-4 pb-4">
            <DecodeBanner className="mb-2" />
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Filter by IP, hostname, or MAC..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" maxLength={200} />
            </div>
          </div>
          <div className="flex-1 flex overflow-hidden px-4 pb-4 gap-4">
            <div className="flex-1 overflow-auto">
              {/* Table, not fixed-width grid rows: fixed px columns overlap at
                  narrow widths and header/body grids drift apart (E6). */}
              <table className="w-full text-xs min-w-[900px]">
                <thead>
                  <tr className="text-muted-foreground border-b bg-background shadow-sm sticky top-0">
                    <th className="text-left py-2 pl-4 pr-2 font-medium">IP</th>
                    <th className="text-left py-2 pr-2 font-medium">Hostname</th>
                    <th className="text-left py-2 pr-2 font-medium">MAC</th>
                    <th className="text-left py-2 pr-2 font-medium">Other Addresses</th>
                    <th className="text-left py-2 pr-2 font-medium">Vendor</th>
                    <th className="text-left py-2 pr-2 font-medium">OS</th>
                    <th className="text-right py-2 pr-2 font-medium">Packets</th>
                    <th className="text-right py-2 pr-4 font-medium">Bytes</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.length === 0 && (
                    <tr><td colSpan={8} className="py-8 text-center text-xs text-muted-foreground">No devices discovered — no decodable addresses in this capture</td></tr>
                  )}
                  {filtered.length === 0 && devices.length > 0 && (
                    <tr><td colSpan={8} className="py-8 text-center text-xs text-muted-foreground">No devices match your filter</td></tr>
                  )}
                  {filtered.map((d) => (
                    <tr
                      key={d.ip}
                      onClick={() => setSelectedIp(selectedIp === d.ip ? null : d.ip)}
                      className={cn(
                        "border-b border-border/50 hover:bg-accent/30 cursor-pointer",
                        selectedIp === d.ip && "bg-accent/60"
                      )}
                    >
                      <td className="py-2 pl-4 pr-2 font-mono text-muted-foreground whitespace-nowrap">{d.ip}</td>
                      <td className="py-2 pr-2 font-mono truncate max-w-[160px]" title={d.hostname && d.hostname !== d.ip ? d.hostname : "Not resolved"}>{d.hostname && d.hostname !== d.ip ? d.hostname : <span className="italic text-muted-foreground">Not resolved</span>}</td>
                      <td className="py-2 pr-2 font-mono text-muted-foreground whitespace-nowrap">{d.mac}</td>
                      <td className="py-2 pr-2 font-mono text-muted-foreground truncate max-w-[200px]" title={(d.addresses ?? []).join(", ")}>
                        {d.addresses && d.addresses.length > 0 ? d.addresses.join(", ") : '\u2014'}
                      </td>
                      <td className="py-2 pr-2 truncate max-w-[120px]" title={vendorLabel(d.vendor, d.mac)}>{vendorLabel(d.vendor, d.mac) || '\u2014'}</td>
                      {/* OS now comes from the UA/TTL fingerprint (A2); fall
                          back to a dash instead of a blank cell (U4). The
                          title names the evidence source (QA: TTL-based
                          fingerprints look fabricated without it). */}
                      <td className="py-2 pr-2 truncate max-w-[120px]" title={d.os ? (d.osSource === "ttl" ? `${d.os} — inferred from TTL` : d.osSource === "ua" ? `${d.os} — from User-Agent` : d.os) : ""}>{d.os || '\u2014'}</td>
                      <td className="py-2 pr-2 text-right text-muted-foreground whitespace-nowrap">{d.packets.toLocaleString()}</td>
                      <td className="py-2 pr-4 text-right font-mono whitespace-nowrap">{d.bytes.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {selected && profile && (
                <div className="border-b bg-muted/20 px-4 py-3">
                  <div className="flex items-center justify-between mb-2">
                    <h2 className="text-sm font-bold font-mono">{selected.ip}</h2>
                    <button onClick={() => setSelectedIp(null)} aria-label="Close profile" className="text-muted-foreground hover:text-foreground">
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-2 text-xs">
                    <div className="space-y-1">
                      <p><span className="text-muted-foreground">Hostname: </span>{selected.hostname && selected.hostname !== selected.ip ? selected.hostname : <span className="text-muted-foreground italic">Not resolved</span>}</p>
                      <p><span className="text-muted-foreground">MAC: </span>{selected.mac}</p>
                      <p><span className="text-muted-foreground">Other addresses: </span>{(selected.addresses ?? []).join(", ") || '\u2014'}</p>
                      <p><span className="text-muted-foreground">Vendor: </span>{vendorLabel(selected.vendor, selected.mac) || '\u2014'}</p>
                      <p><span className="text-muted-foreground">OS: </span>{selected.os || '\u2014'}{selected.osSource === "ttl" && <span className="text-muted-foreground italic"> (inferred from TTL)</span>}{selected.osSource === "ua" && <span className="text-muted-foreground italic"> (from User-Agent)</span>}</p>
                      <p><span className="text-muted-foreground">Location: </span>{profile.geo}</p>
                    </div>
                    <div className="space-y-1">
                      <p><span className="text-muted-foreground">Protocols: </span>{profile.protocols.length > 0 ? profile.protocols.join(", ") : <span className="text-muted-foreground italic">No decoded flows</span>}</p>
                      <p><span className="text-muted-foreground">Threat hits: </span><span className={profile.threats > 0 ? "text-danger font-semibold" : ""}>{profile.threats}</span></p>
                      <p><span className="text-muted-foreground">Packets: </span>{selected.packets.toLocaleString()}</p>
                      <p><span className="text-muted-foreground">Bytes: </span>{selected.bytes.toLocaleString()}</p>
                      <p><span className="text-muted-foreground">First seen: </span>{new Date(selected.firstSeen).toISOString()}</p>
                      <p><span className="text-muted-foreground">Last seen: </span>{new Date(selected.lastSeen).toISOString()}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-muted-foreground">Ports (by packets):</p>
                      {profile.ports.length > 0 ? (
                        <p className="font-mono">{profile.ports.map((p) => `${p.port} (${p.count})`).join(", ")}</p>
                      ) : (
                        <p className="text-muted-foreground italic">None — no decoded flows</p>
                      )}
                      <p className="text-muted-foreground pt-1">Top peers:</p>
                      {profile.peers.length > 0 ? (
                        <p className="font-mono">{profile.peers.map((p) => `${p.ip}:${p.port} (${p.packets} pkts)`).join(", ")}</p>
                      ) : (
                        <p className="text-muted-foreground italic">None — no decoded flows</p>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
