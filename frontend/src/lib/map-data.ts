// Shared IP-map data derivation — used by the static SVG world map and the
// MapLibre interactive map so both views always agree on nodes and arcs.

import { isNonUnicast, safeIso } from "@/lib/analysis"

export const PROTOCOL_COLORS: Record<string, string> = {
  TCP: "#3b82f6", UDP: "#22c55e", DNS: "#eab308", TLS: "#a855f7",
  HTTP: "#06b6d4", HTTPS: "#8b5cf6", ICMP: "#ef4444", ARP: "#f97316",
  SSH: "#14b8a6", SMTP: "#ec4899", FTP: "#f59e0b", QUIC: "#6366f1",
  STUN: "#94a3b8", mDNS: "#f472b6", LLMNR: "#fbbf24", DoT: "#7c3aed",
  "WS-Discovery": "#84cc16", DHCP: "#a3e635", NTP: "#2dd4bf",
  SSDP: "#fb923c", "NetBIOS-NS": "#64748b", WireGuard: "#0ea5e9",
  Syslog: "#e879f9", TFTP: "#22d3ee", SNMP: "#c084fc", RIP: "#bef264",
}

export interface MapNode {
  ip: string; country: string; countryCode: string; city: string
  lat: number; lon: number; isPrivate: boolean
  packets: number; bytes: number; connections: number
  bytesSent: number; bytesRecv: number
  protocols: Record<string, number>
  isSource: boolean; isDest: boolean
  asn?: string; isp?: string; org?: string; hostname?: string
  firstSeen?: string; lastSeen?: string
  // Local↔public traffic for this external peer (B-71): the tooltip says
  // "↔ your local network (N conns)" instead of pretending the peer only
  // talks public↔public.
  localConns?: number
}

interface MapArc {
  srcIp: string; dstIp: string; protocol: string
  packets: number; bytes: number
  coordinates: [number, number][]
  color: string
}

export interface GeoLocationLike {
  country?: string; countryCode?: string; city?: string
  lat?: number; lon?: number; isPrivate?: boolean
  asn?: string; isp?: string; org?: string; hostname?: string
}

export function clampLat(v: number): number {
  if (!Number.isFinite(v)) return 0
  return Math.max(-90, Math.min(90, v))
}
export function clampLon(v: number): number {
  if (!Number.isFinite(v)) return 0
  return Math.max(-180, Math.min(180, v))
}

// ponytail: great-circle arcs for public IPs on world map
function greatCirclePoints(lat1: number, lon1: number, lat2: number, lon2: number, steps = 60): [number, number][] {
  const φ1 = lat1 * Math.PI / 180; const λ1 = lon1 * Math.PI / 180
  const φ2 = lat2 * Math.PI / 180; const λ2 = lon2 * Math.PI / 180
  const d = Math.acos(Math.max(-1, Math.min(1, Math.sin(φ1) * Math.sin(φ2) + Math.cos(φ1) * Math.cos(φ2) * Math.cos(λ2 - λ1))))
  if (d < 0.001 || d > Math.PI - 0.001) return [[clampLat(lat1), clampLon(lon1)], [clampLat(lat2), clampLon(lon2)]]
  const pts: [number, number][] = []
  for (let i = 0; i <= steps; i++) {
    const f = i / steps
    const A = Math.sin((1 - f) * d) / Math.sin(d)
    const B = Math.sin(f * d) / Math.sin(d)
    const x = A * Math.cos(φ1) * Math.cos(λ1) + B * Math.cos(φ2) * Math.cos(λ2)
    const y = A * Math.cos(φ1) * Math.sin(λ1) + B * Math.cos(φ2) * Math.sin(λ2)
    const z = A * Math.sin(φ1) + B * Math.sin(φ2)
    const lat = Math.atan2(z, Math.sqrt(x * x + y * y)) * 180 / Math.PI
    const lon = Math.atan2(y, x) * 180 / Math.PI
    pts.push([clampLat(lat), clampLon(lon)])
  }
  return pts
}

export function formatBytes(b: number): string {
  if (!Number.isFinite(b)) return "—"
  // Round sub-KB values: a rate like 832.2682926829268 B/s printed raw would
  // leak floating-point noise into every table that reuses this formatter.
  if (b < 1024) return Math.round(b) + " B"
  if (b < 1048576) return (b / 1024).toFixed(1) + " KB"
  if (b < 1073741824) return (b / 1048576).toFixed(1) + " MB"
  // GB/TB tiers: a multi-GB capture rendered "3174.4 MB" on the file card (QA).
  if (b < 1099511627776) return (b / 1073741824).toFixed(1) + " GB"
  return (b / 1099511627776).toFixed(1) + " TB"
}

// UI tables and the CSV/report exporters must render endpoints identically:
// an undecodable address (the "—" placeholder) is never suffixed with a port,
// which read as "— :0 → — :0" on the Sessions page (QA).
export function formatEndpoint(ip: string, port?: number | null): string {
  if (!ip || ip === "\u2014") return ip || "\u2014"
  return port == null || Number.isNaN(port) ? ip : `${ip}:${port}`
}

// Side-panel aggregates for a map view: Top Countries (by bytes) and the
// drawn/undrawn split. Shared by both map implementations so the flat map and
// the globe can never disagree on their panels (B-54). Top Protocols chips
// are NOT here: they must count packets via analysis's packetProtocolCounts
// (the ONE classifier), or the chips and the Protocol Distribution panel on
// the Visualizations page diverge (QA F-04, B-59).
export interface MapPanels {
  topCountries: CountryRow[]
  drawnNodes: number
  drawnBytes: number
  undrawnCount: number
  undrawnBytes: number
  localHosts: number
}

interface CountryRow {
  name: string
  code: string
  bytes: number
}

// Top Countries aggregation over an EXPLICIT node set. mapPanels ranks all
// nodes; the interactive map re-uses this on its search-filtered set so a
// search ("Google", a city, an ASN) filters the sidebar exactly like it
// filters pins and arcs — the old behavior kept an India-first list next to
// 2 Google pins (QA).
export function topCountriesOf(nodes: MapNode[]): CountryRow[] {
  const byCountry = new Map<string, CountryRow>()
  for (const n of nodes) {
    const name = n.country || n.countryCode || "Unknown"
    const cur = byCountry.get(name) ?? { name, code: n.countryCode || "", bytes: 0 }
    cur.bytes += n.bytes
    byCountry.set(name, cur)
  }
  return [...byCountry.values()].sort((a, b) => b.bytes - a.bytes)
}

export function mapPanels(data: MapData): MapPanels {
  const topCountries = topCountriesOf(data.nodes)
  // "Drawn bytes" includes local↔public traffic (B-71): after the B-69 alias
  // reclassification every flow became local↔public, and drawing only
  // public↔public read "0 B" for 52.2 KB of real traffic.
  const drawnBytes = data.arcs.reduce((s, a) => s + a.bytes, 0)
    + data.localPublicFlows.reduce((s, f) => s + f.bytes, 0)
  return {
    topCountries,
    drawnNodes: data.nodes.length,
    drawnBytes,
    undrawnCount: data.undrawnPublic.length,
    undrawnBytes: data.undrawnPublic.reduce((s, u) => s + u.bytes, 0),
    localHosts: data.localSummary.hosts,
  }
}

// /64 of a public IPv6 — SLAAC siblings share the LAN's delegated prefix, so
// an address with no MAC evidence on the same /64 as a local device's alias is
// that same machine (QA B-72: …:f027/…:234c share …:308f's /64 but never
// MAC-merged). Compressed forms included: the first four hextets must all be
// non-empty for a clean /64 (2001:db8::1 → ["2001","db8","","1"] → skipped).
export function slaacPrefixesOf(ips: Iterable<string>): Set<string> {
  const out = new Set<string>()
  for (const ip of ips) {
    if (!ip || !ip.includes(":")) continue
    if (isPrivateIP(ip) || isNonUnicast(ip)) continue
    const h = ip.split(":")
    if (h.length < 4 || h.slice(0, 4).some((s) => s.length === 0)) continue
    out.add(h.slice(0, 4).join(":") + ":")
  }
  return out
}

export function matchesSlaacPrefix(ip: string, prefixes?: ReadonlySet<string> | null): boolean {
  if (!prefixes) return false
  for (const pre of prefixes) if (ip.startsWith(pre)) return true
  return false
}

// A home anchor when the analyst set none (QA: every local↔public flow died
// — "0 flows drawn · 0 B drawn" — because the capture has no public↔public
// flows and no Home location was configured, online or manual). The LAN's own
// public addresses (router global, delegated /64 aliases) geolocate at the
// home's ISP PoP — that IS where home sits on the map. First geocoded owned
// public address wins.
export function homeAnchorFromOwnedPublic(
  aliases: ReadonlySet<string> | undefined,
  geo: ReadonlyMap<string, GeoLocationLike> | Map<string, GeoLocationLike>,
): { lat: number; lon: number } | null {
  if (!aliases) return null
  for (const ip of aliases) {
    if (isPrivateIP(ip)) continue
    const loc = geo.get(ip)
    if (isGeocoded(loc)) return { lat: loc.lat, lon: loc.lon }
  }
  return null
}

// The LAN-card predicate (F-04): a flow is local iff its SOURCE is a private
// unicast host and its destination is NOT a public-unicast IP. Multicast and
// broadcast destinations (mDNS 224.0.0.251, SSDP 239.255.255.250, ff02::x)
// are LAN peers — requiring both ends unicast over-corrected and dropped
// local→multicast/broadcast traffic from the LAN card (QA B-68: 128 → 31
// pkts). Only a public-unicast destination means egress (WAN).
export function isLanFlow(src: string, dst: string): boolean {
  if (!isPrivateIP(src) || isNonUnicast(src)) return false
  if (!isPrivateIP(dst) && !isNonUnicast(dst)) return false
  return true
}

export function isPrivateIP(ip: string): boolean {
  const t = ip.trim() // some writers emit ":: " with trailing space; and no
  // padded/labeled public IP should ever be counted as an external peer
  if (!t) return true
  if (t.includes(":")) {
    const v = t.toLowerCase()
    // ponytail: also non-routable IPv6 — multicast ff00::/8, link-local fe80::/10,
    // unique-local fc/fd::/8, loopback ::1, and the unspecified/mapped :: / ::ffff:
    // placeholders (never real endpoints; counting them as external inflates peers).
    // Full-form placeholders 0:0:0:0:0:0:0:0 / 0:0:0:0:0:0:0:1 are :: / ::1 emitted
    // uncompressed — missing them sent the unspecified address to GeoIP (QA B-58).
    return v === "::" || v === "::1" || v === "0:0:0:0:0:0:0:0" || v === "0:0:0:0:0:0:0:1" || v.startsWith("::ffff:") ||
      v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") || v.startsWith("ff")
  }
  const first = Number(t.split(".")[0])
  // ponytail: also non-routable IPv4 — multicast 224/4 (mDNS 224.0.0.251, SSDP
  // 239.255.255.250), reserved 240/4, broadcast 255, 0.0.0.0 — these are LAN
  // artifacts, never internet endpoints
  if (first === 0 || first >= 224) return true
  if (t.startsWith("192.168.") || t.startsWith("10.") || t.startsWith("169.254.") || t.startsWith("192.0.0.") || t === "127.0.0.1" || t === "0.0.0.0") return true
  if (t.startsWith("172.")) {
    const n = Number(t.split(".")[1])
    if (n >= 16 && n <= 31) return true
  }
  if (first === 100) {
    const n = Number(t.split(".")[1])
    if (n >= 64 && n <= 127) return true // CGNAT 100.64/10
  }
  if (first === 198) {
    const n = Number(t.split(".")[1])
    if (n === 18 || n === 19) return true // benchmark 198.18/15
  }
  return false
}

// One search haystack for a map node — used by both the node filter and the
// arc filter so "search a city/ASN" never shows a node with its arcs gone.
export function nodeSearchHaystack(
  n: Pick<MapNode, "ip" | "country" | "countryCode" | "city" | "asn" | "org" | "hostname"> | undefined,
): string {
  if (!n) return ""
  return [n.ip, n.country, n.countryCode, n.city, n.asn || "", n.org || "", n.hostname || ""].join(" ").toLowerCase()
}

// The globe draws ONLY IPs with a resolved country. Public IPs with no GeoIP
// row (unknownLocation's fabricated "Unknown" anchor included) are counted in
// undrawnPublic and never placed. Private IPs are never anchored anywhere:
// they have no geography, so they are not drawn on the globe at all and only
// surface in localSummary (sidebar) and the header hint.
export const UNKNOWN_ZONE = { lat: -40, lon: 82, label: "Unknown Location" }

// Private unicast only: link-local/multicast/unspecified IPv6 are not hosts
// (mirrors analysis's isNonUnicast for the device list — the map has no MACs
// to merge with, so the raw-address filter is the best parity available).
function isLocalHostCandidate(ip: string): boolean {
  if (!ip.includes(":")) return true
  const v = ip.trim().toLowerCase() // same trim as analysis's isNonUnicast
  // Full-form unspecified/loopback (0:0:0:0:0:0:0:0, 0:0:0:0:0:0:0:1) are the
  // uncompressed :: / ::1 — never hosts either (QA B-58).
  return !["::", "::1", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1"].includes(v) &&
    !v.startsWith("ff") && !v.startsWith("fe8") && !v.startsWith("::ffff:")
}

export interface CityCluster {
  ips: string[]
  lat: number
  lon: number
}

// At country zoom, dots from one metro overprint into a blob (QA: Bengaluru +
// Mumbai merged into one). Group nodes into 1°×1° proximity cells per country
// (neighboring cities — Delhi/Dadri/Noida — land in the SAME cell at world
// zoom, so one count bubble stands for the pile instead of overlaid badges)
// and return one centroid marker per cell — the map paints a count bubble per
// cluster below a zoom threshold instead of the individual dots. Order = node
// order (traffic). A city label is NOT the key: geo rows name the same metro
// differently (Dadri vs Greater Noida) or omit the city entirely.
export function clusterByCity(
  nodes: Pick<MapNode, "ip" | "countryCode" | "city" | "lat" | "lon">[],
): CityCluster[] {
  const m = new Map<string, { ips: string[]; latSum: number; lonSum: number }>()
  for (const n of nodes) {
    const key = `${n.countryCode || "?"}/${Math.floor(n.lat)}/${Math.floor(n.lon)}`
    const c = m.get(key) ?? { ips: [], latSum: 0, lonSum: 0 }
    c.ips.push(n.ip)
    c.latSum += n.lat
    c.lonSum += n.lon
    m.set(key, c)
  }
  return [...m.values()].map((c) => ({
    ips: c.ips,
    lat: c.latSum / c.ips.length,
    lon: c.lonSum / c.ips.length,
  }))
}

interface LocalPublicFlow {
  peerIp: string
  bytes: number
  packets: number
  // Dominant protocol by bytes (home arcs are colored by it, B-77).
  protocol: string
  // Directional bytes for home-arc color (blue = home→peer out, green = in).
  inBytes: number
  outBytes: number
  // Directional local↔public pairs (srcIp>dstIp): the old "flows drawn"
  // header counted arcs per direction, so this keeps the same numbers.
  flows: number
}

export interface MapData {
  nodes: MapNode[]
  arcs: MapArc[]
  protocols: string[]
  nodeMap: Map<string, MapNode>
  localSummary: { hosts: number; bytes: number; packets: number; topHost: string }
  // Local↔public traffic (B-71): aggregated per external peer. After B-69
  // reclassified the client's aliases as local, every flow to the internet is
  // local↔public — the header must count it and, when Home Location is set,
  // the map anchors one arc at home for each peer.
  localPublicFlows: LocalPublicFlow[]
  undrawnPublic: { ip: string; bytes: number; packets: number }[]
  // Undecodable packets ("—" placeholder on a side, a pcap the decoder could
  // not attribute) have no address to place — they are neither LAN nor public,
  // so they surface here as "undecodable/other" instead of a fake external IP.
  undecodable: { packets: number; bytes: number }
  totalBytes: number
  totalPackets: number
}

type GeoResolved = GeoLocationLike & { country: string; countryCode: string; lat: number; lon: number }

// Drawable iff the geo row carries a real country — a miss, an "Unknown"
// fallback, or a bare coordinate must never reach the globe.
function isGeocoded(loc: GeoLocationLike | undefined): loc is GeoResolved {
  if (!loc) return false
  if (!loc.country || loc.country === "Unknown") return false
  if (!loc.countryCode || loc.countryCode === "??") return false
  return Number.isFinite(loc.lat) && Number.isFinite(loc.lon)
}

export function deriveMapData(
  packets: { srcIp?: string; dstIp?: string; protocol?: string; length?: number; timestamp?: string | number }[],
  geo: Map<string, GeoLocationLike> = new Map(),
  // MAC-merged aliases of LOCAL devices (ownerOfDevices/localOwnedAddresses):
  // a local host's public-looking IPv6 (2401:…:308f) is the same machine as
  // its private primary — it must never draw as an external dot, inflate a
  // country, or spin an arc. Skipped everywhere: no node, no undrawn row, no
  // bytes (QA B-69: India read 4 IPs / 173.3 KB for the client's own aliases
  // + router). The set also drives /64 SLAAC sibling matching (B-72): whole
  // delegated prefixes of owned public IPv6 are local, no MAC needed.
  aliases?: ReadonlySet<string>,
): MapData {
  const nodeMap = new Map<string, MapNode>()
  const protoSet = new Set<string>()
  const flowMap = new Map<string, { packets: number; bytes: number; protocol: string }>()
  const privateSeen = new Set<string>()
  const lanStats = new Map<string, { bytes: number; packets: number }>()
  let lanBytes = 0
  let lanPackets = 0
  const undrawnPublicMap = new Map<string, { bytes: number; packets: number }>()
  const publicSeen = new Set<string>()
  // Per-node distinct flow keys (src>dst) — a node's "connections" must be how
  // many real directed sessions it has, not how many source packets it sent
  // (the old counter inflated the number ~packets-per-session-fold).
  const nodeFlowKeys = new Map<string, Set<string>>()
  let undecodableBytes = 0
  let undecodablePackets = 0
  const prefixSet = aliases ? slaacPrefixesOf(aliases) : null
  const localPublicMap = new Map<string, { bytes: number; packets: number; flows: number; protoBytes: Record<string, number>; inBytes: number; outBytes: number }>()
  const localPublicSeen = new Map<string, Set<string>>()

  const epochOf = (ts?: string | number) => {
    if (!ts) return 0
    const epoch = typeof ts === 'string' ? new Date(ts).getTime() / 1000 : ts
    return Number.isFinite(epoch) && epoch > 0 ? epoch : 0
  }

  for (const p of packets) {
    if (!p.srcIp || !p.dstIp) continue
    // A "—" side is a pcap the decoder could not attribute — it has no
    // address, so it is never a node, an arc, a LAN host, or an unresolved
    // external. Counted once per packet (QA: such packets inflated "external
    // not drawn (no GeoIP)" with fake IPs).
    if (p.srcIp === "\u2014" || p.dstIp === "\u2014") {
      undecodableBytes += p.length || 0
      undecodablePackets++
    }
    protoSet.add(p.protocol || "Unknown")
    const key = `${p.srcIp}>${p.dstIp}`
    const existing = flowMap.get(key)
    if (existing) {
      existing.packets++; existing.bytes += p.length || 0
    } else {
      flowMap.set(key, { packets: 1, bytes: p.length || 0, protocol: p.protocol || "Unknown" })
    }

    // One LAN definition everywhere (QA: the map panel read 14.1 KB where the
    // Visualizations LAN card read 13.4 KB — the old srcPrivate&&dstPrivate
    // rule counted placeholder-sourced chatter the card correctly excludes).
    // Same predicate as the page's LAN card: src private UNICAST, dst not
    // public-unicast.
    if (isLanFlow(p.srcIp, p.dstIp)) {
      // LAN-only traffic: counted for localSummary, never drawn.
      lanBytes += p.length || 0
      lanPackets++
      for (const ip of [p.srcIp, p.dstIp]) {
        const s = lanStats.get(ip) ?? { bytes: 0, packets: 0 }
        s.bytes += p.length || 0
        s.packets++
        lanStats.set(ip, s)
      }
    }
    // Local↔public (B-71): exactly one side is a LOCAL unicast host (private
    // unicast, or a local-owned alias / SLAAC sibling), the other a real
    // public IP. Aggregated per peer so the header can count these flows and
    // the map can draw one home-anchored arc per peer.
    const srcLocal = isPrivateIP(p.srcIp) && !isNonUnicast(p.srcIp) ||
      (aliases?.has(p.srcIp) && !isPrivateIP(p.srcIp)) || matchesSlaacPrefix(p.srcIp, prefixSet)
    const dstLocal = isPrivateIP(p.dstIp) && !isNonUnicast(p.dstIp) ||
      (aliases?.has(p.dstIp) && !isPrivateIP(p.dstIp)) || matchesSlaacPrefix(p.dstIp, prefixSet)
    if (srcLocal !== dstLocal) {
      const peer = srcLocal ? p.dstIp : p.srcIp
      if (!isPrivateIP(peer) && !isNonUnicast(peer)) {
        const agg = localPublicMap.get(peer) ?? { bytes: 0, packets: 0, flows: 0, protoBytes: {}, inBytes: 0, outBytes: 0 }
        agg.bytes += p.length || 0
        agg.packets++
        agg.protoBytes[p.protocol || "Unknown"] = (agg.protoBytes[p.protocol || "Unknown"] || 0) + (p.length || 0)
        const seen = localPublicSeen.get(peer) ?? new Set<string>()
        const pk = `${p.srcIp}>${p.dstIp}`
        if (!seen.has(pk)) { seen.add(pk); agg.flows++ }
        localPublicSeen.set(peer, seen)
        if (srcLocal) agg.outBytes += p.length || 0
        else agg.inBytes += p.length || 0
        localPublicMap.set(peer, agg)
      }
    }

    for (const ip of [p.srcIp, p.dstIp]) {
      // The packet-level check above already tallied the undecodable bytes;
      // here the placeholder side is just skipped so it never becomes a node,
      // a LAN host, or an unresolved external.
      if (ip === "\u2014") continue
      // B-69/B-72: a local device's alias (or a /64 sibling of one) is not an
      // external peer — skip before any node/undrawn/LAN bookkeeping. Private
      // IPs in the set are harmless: they never drew anyway, and must still
      // count as local hosts (B-72: the set includes private primaries).
      if (aliases?.has(ip) && !isPrivateIP(ip)) continue
      if (matchesSlaacPrefix(ip, prefixSet)) continue
      const isPrivate = isPrivateIP(ip)
      if (isPrivate) {
        // A "local host" is a private UNICAST address — multicast (ff00::),
        // link-local (fe80::) and the :: placeholders are interface chatter on
        // the same NICs, not extra machines. Counting them made the map report
        // "7 local hosts" where the device list (MAC-merged) says 3 (QA).
        if (isLocalHostCandidate(ip)) privateSeen.add(ip)
        continue
      }
      if (!publicSeen.has(ip)) {
        publicSeen.add(ip)
        const loc = geo.get(ip)
        if (isGeocoded(loc)) {
          nodeMap.set(ip, {
            ip, country: loc.country, countryCode: loc.countryCode, city: loc.city || "",
            lat: loc.lat, lon: loc.lon,
            isPrivate: false,
            packets: 0, bytes: 0, connections: 0, bytesSent: 0, bytesRecv: 0, protocols: {},
            isSource: false, isDest: false,
            asn: loc.asn, isp: loc.isp, org: loc.org, hostname: loc.hostname,
          })
        } else {
          undrawnPublicMap.set(ip, { bytes: 0, packets: 0 })
        }
      }
      const n = nodeMap.get(ip)
      if (n) {
        n.packets++; n.bytes += p.length || 0
        if (ip === p.srcIp) n.bytesSent += p.length || 0
        else n.bytesRecv += p.length || 0
        n.protocols[p.protocol || "Unknown"] = (n.protocols[p.protocol || "Unknown"] || 0) + 1
        const keys = nodeFlowKeys.get(ip) ?? new Set<string>()
        keys.add(key)
        nodeFlowKeys.set(ip, keys)
        if (ip === p.srcIp) { n.isSource = true }
        if (ip === p.dstIp) { n.isDest = true }
        const epoch = epochOf(p.timestamp)
        if (epoch > 0) {
          // safeIso: a crafted capture timestamp beyond the Date range must
          // not crash the map pass (QA: overflow pcapng).
          const iso = safeIso(epoch * 1000)
          if (!n.firstSeen || iso < n.firstSeen) n.firstSeen = iso
          if (!n.lastSeen || iso > n.lastSeen) n.lastSeen = iso
        }
      } else {
        const u = undrawnPublicMap.get(ip)
        if (u) { u.bytes += p.length || 0; u.packets++ }
      }
    }
  }

  // Arcs only ever connect two drawn (public, resolved) nodes. Private↔public
  // and private↔private flows are invisible on the globe; LAN ones live in
  // localSummary instead.
  const arcs: MapArc[] = []
  for (const [key, flow] of flowMap) {
    const [srcIp, dstIp] = key.split(">")
    const src = nodeMap.get(srcIp); const dst = nodeMap.get(dstIp)
    if (!src || !dst) continue
    const color = PROTOCOL_COLORS[flow.protocol] || "#6b7280"
    const coordinates = greatCirclePoints(src.lat, src.lon, dst.lat, dst.lon)
    arcs.push({ srcIp, dstIp, ...flow, coordinates, color })
  }

  const nodes = [...nodeMap.values()].sort((a, b) => b.packets - a.packets)
  for (const [ip, s] of nodeFlowKeys) {
    const nn = nodeMap.get(ip)
    if (nn) nn.connections = s.size
  }
  const localPublicFlows = [...localPublicMap.entries()]
    .map(([peerIp, v]) => ({
      peerIp, bytes: v.bytes, packets: v.packets, flows: v.flows,
      inBytes: v.inBytes, outBytes: v.outBytes,
      // Dominant protocol by bytes so a home-anchored arc carries the peer's
      // real color (QA: every local↔public arc rendered legend-gray).
      protocol: Object.entries(v.protoBytes).sort((a, b) => b[1] - a[1])[0]?.[0] || "Unknown",
    }))
    .sort((a, b) => b.bytes - a.bytes)
  // Tooltip: peers with local↔public traffic read "↔ your local network".
  for (const f of localPublicFlows) {
    const n = nodeMap.get(f.peerIp)
    if (n) n.localConns = f.flows
  }
  let topHost = ""
  let topBytes = 0
  for (const [ip, s] of lanStats) {
    if (s.bytes > topBytes) { topBytes = s.bytes; topHost = ip }
  }
  return {
    nodes,
    arcs: arcs.sort((a, b) => b.bytes - a.bytes).slice(0, 500),
    protocols: [...protoSet].sort(),
    nodeMap,
    localSummary: { hosts: privateSeen.size, bytes: lanBytes, packets: lanPackets, topHost },
    localPublicFlows,
    undrawnPublic: [...undrawnPublicMap.entries()].map(([ip, s]) => ({ ip, ...s })).sort((a, b) => b.bytes - a.bytes),
    undecodable: { packets: undecodablePackets, bytes: undecodableBytes },
    totalBytes: packets.reduce((s, p) => s + (p.length || 0), 0),
    totalPackets: packets.length,
  }
}
