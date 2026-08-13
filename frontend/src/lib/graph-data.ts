// Investigation-graph element builder — pure and unit-testable. The component
// memory-safe-wraps this in a useMemo; separating it lets B-49 (geo country/ASN
// nodes) and B-50 (IP↔Device identity edges) carry regression tests without
// mounting cytoscape (needs real canvas).

import type { ElementDefinition } from "cytoscape"
import { formatBytes, isPrivateIP } from "@/lib/map-data"
import { isNonUnicast } from "@/lib/analysis"
import type { GeoLocation } from "@/lib/geo"

// Privacy-masked IPv4: keep the network part, drop the host part (a.b.x.x).
// IPv6: keep the /64 (first four hextets, the SLAAC prefix rule the map
// uses) — an unmasked v6 in Beginner mode leaked the full address while v4
// was masked (QA).
function shortIp(ip: string): string {
  const v4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (v4) return `${v4[1]}.${v4[2]}.x.x`
  if (ip.includes(":")) {
    const hextets = ip.split(":")
    if (hextets.slice(0, 4).length === 4 && hextets.slice(0, 4).every((h) => h.length > 0)) {
      return `${hextets.slice(0, 4).join(":")}::`
    }
  }
  return ip
}

const NODE_ICONS: Record<string, string> = {
  pcap: "📦", ip: "🖥️", asn: "🏢", country: "🌍", protocol: "📡", dns: "🔍",
  http: "🌐", tls: "🔒", file: "📄", credential: "🔑", certificate: "📜",
  device: "🖥️", alert: "🚨",
}

export interface GraphElementsInput {
  packets: { srcIp?: string; dstIp?: string; protocol?: string }[]
  flows: { srcIp: string; dstIp: string; protocol: string; packets: number; bytesTotal: number; duration?: number }[]
  dns: { query: string; srcIp: string; dstIp: string; type: string; responseCode?: string }[]
  http: { method: string; uri: string; host: string; srcIp: string; dstIp: string }[]
  tls: { sni: string; srcIp: string; dstIp: string; version: string }[]
  files: { filename: string; srcIp: string; dstIp: string; size: number }[]
  credentials: { username: string; protocol: string; srcIp: string; dstIp: string; service?: string }[]
  certificates: { subject: string; issuer: string; san: string[] }[]
  devices: { ip: string; hostname: string; mac: string; vendor: string; os: string }[]
  alerts: { signature: string; srcIp: string; dstIp: string; severity: number }[]
  geoMap: Map<string, GeoLocation>
  beginnerMode: boolean
}

export function buildGraphElements(input: GraphElementsInput): { nodes: ElementDefinition[]; edges: ElementDefinition[] } {
  const { geoMap, beginnerMode } = input
  const nodes: ElementDefinition[] = []
  const edges: ElementDefinition[] = []
  const nodeIds = new Set<string>()
  const edgeIds = new Set<string>()

  function addNode(id: string, label: string, type: string, info?: string, degree = 1, icon?: string) {
    if (nodeIds.has(id)) return
    nodeIds.add(id)
    const glyph = icon || NODE_ICONS[type] || "●"
    nodes.push({ data: { id, label: `${glyph} ${label}`, type, info: info || label, degree }, classes: type })
  }

  // kind segments edge STYLE (see the component's stylesheet): "flow" carries
  // real traffic and gets strength + color by weight; "struct" edges are the
  // pcap-hub hierarchy (contains/uses/has/triggered), kept quiet; "relation"
  // edges are observed findings (DNS/HTTP/TLS/file/credential/geo), dashed;
  // "identity" pairs an IP with its device, dashed too. type stays "edge" (or
  // "identity" for B-50) so the filter/visibility logic is unaffected.
  function addEdge(src: string, dst: string, label: string, kind = "flow" as string, weight = 0, type = "edge") {
    const id = `${src}->${dst}`
    if (edgeIds.has(id)) return
    if (!nodeIds.has(src) || !nodeIds.has(dst)) return
    edgeIds.add(id)
    const data: Record<string, unknown> = { id, source: src, target: dst, label, type, kind }
    if (weight > 0) data.weight = weight
    edges.push({ data })
  }

  const { packets, flows, dns, http, tls, files, credentials, certificates, devices, alerts } = input

  addNode("pcap", "PCAP", "pcap", `Packet Capture\n${packets.length} packets, ${flows.length} flows`, 10)

  const allIps = new Set<string>()
  for (const f of flows) { allIps.add(f.srcIp); allIps.add(f.dstIp) }
  for (const ip of allIps) {
    if (ip === "\u2014") {
      // Undecodable endpoint: NOT a discovered device — a neutral unknown glyph.
      addNode(`ip:${ip}`, "unknown endpoint", "ip", "Undecodable endpoint — no address parsed (unsupported encapsulation)", 2, "❓")
    } else {
      const masked = shortIp(ip)
      addNode(`ip:${ip}`, beginnerMode ? masked : ip, "ip", `IP: ${beginnerMode ? masked : ip}`, 2)
    }
  }

  const protoSet = new Set<string>()
  for (const f of flows) protoSet.add(f.protocol)
  for (const p of protoSet) addNode(`proto:${p}`, p, "protocol", `Protocol: ${p}`, 1)

  // Geo wiring (B-49): external IPs get Country + ASN nodes from the geoMap
  // (offline MMDB lookups, resolved once in the job layout). Private IPs have
  // no geography and unresolved IPs have no country row — neither gets nodes,
  // so the Countries/ASNs chips light up only with real rows.
  const countryNames = new Map<string, string>()
  const asnNames = new Map<string, string>()
  for (const ip of allIps) {
    if (ip === "\u2014") continue
    const g = geoMap.get(ip)
    if (!g || g.isPrivate || g.countryCode === "??" || g.countryCode === "LOC") continue
    if (!countryNames.has(g.countryCode)) countryNames.set(g.countryCode, g.country || g.countryCode)
    if (g.asn && !asnNames.has(g.asn)) asnNames.set(g.asn, g.org || g.asn)
  }
  for (const [cc, name] of countryNames) addNode(`country:${cc}`, name, "country", `Country: ${name}`, 1)
  for (const [asn, org] of asnNames) addNode(`asn:${asn}`, org.length > 30 ? org.slice(0, 30) + "…" : org, "asn", `ASN: ${asn}\nOrg: ${org}`, 1)

  // Aggregate DNS records per domain: a domain node must show ALL record
  // types + counts for that domain.
  const dnsAgg = new Map<string, { types: Map<string, number>; codes: Map<string, number>; total: number }>()
  for (const d of dns) {
    if (!d.query) continue
    let agg = dnsAgg.get(d.query)
    if (!agg) { agg = { types: new Map(), codes: new Map(), total: 0 }; dnsAgg.set(d.query, agg) }
    agg.total++
    agg.types.set(d.type, (agg.types.get(d.type) || 0) + 1)
    if (d.responseCode) agg.codes.set(d.responseCode, (agg.codes.get(d.responseCode) || 0) + 1)
  }
  for (const [query, agg] of dnsAgg) {
    const types = [...agg.types.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([t, c]) => `${t} ×${c}`).join(", ")
    const codes = agg.codes.size > 0 ? `\nResponses: ${[...agg.codes.entries()].sort((a, b) => b[1] - a[1]).map(([c, n]) => `${c} ×${n}`).join(", ")}` : ""
    addNode(`dns:${query}`, query.length > 30 ? query.slice(0, 30) + "…" : query, "dns", `DNS Query: ${query}\nRecords: ${types}\nQueries: ${agg.total}${codes}`, 1)
  }
  for (const h of http) { if (h.host) addNode(`http:${h.host}`, h.host.length > 30 ? h.host.slice(0, 30) + "…" : h.host, "http", `HTTP Host: ${h.host}\n${h.method} ${h.uri}`, 1) }
  for (const t of tls) { if (t.sni) addNode(`tls:${t.sni}`, t.sni.length > 30 ? t.sni.slice(0, 30) + "…" : t.sni, "tls", `TLS SNI: ${t.sni}\nVersion: ${t.version}`, 1) }
  for (const f of files) addNode(`file:${f.filename}`, f.filename.length > 30 ? f.filename.slice(0, 30) + "…" : f.filename, "file", `File: ${f.filename}\nSize: ${formatBytes(f.size)}`, 1)
  for (const c of credentials) { const cid = `cred:${c.username}@${c.service || c.protocol}`; addNode(cid, `${c.username}@${c.service || c.protocol}`, "credential", `Credential: ${c.username}\nService: ${c.service || c.protocol}`, 1) }

  const certLabels = new Set<string>()
  for (const c of certificates) {
    const label = c.subject.split("=").pop() || c.subject
    if (certLabels.has(label)) continue
    certLabels.add(label)
    addNode(`cert:${label}`, label.length > 30 ? label.slice(0, 30) + "…" : label, "certificate", `Certificate: ${c.subject}\nIssuer: ${c.issuer}\nSANs: ${(c.san || []).join(", ")}`, 1)
  }

// Special addresses (unspecified 0.0.0.0/::, broadcast 255.255.255.255) are
  // protocol placeholders, not devices — never draw them as device nodes. The
  // devices array also holds remote service IPs (CDNs, geocoded endpoints), so
  // only LOCAL endpoints become device nodes — the same predicate the
  // Statistics "Devices" card uses, or the graph shows dozens of teal device
  // squares while the card reads "4 devices" (QA: call.pcap 28 vs 2 hosts).
  const localDevices = devices.filter((d) => isPrivateIP(d.ip) && !isNonUnicast(d.ip))
  for (const d of localDevices) {
    // Device node label must differ from its IP node: hostname, else vendor,
    // else a neutral "Device" — two nodes with identical labels next to each
    // other (blue IP + teal Device, no link) read as a duplicate (B-50).
    addNode(`dev:${d.ip}`, d.hostname || d.vendor || "Device", "device", `Device: ${d.hostname || d.ip}\nMAC: ${d.mac}\nVendor: ${d.vendor}\nOS: ${d.os}`, 1)
  }
  // Alert node ids must be unique per ALERT, not per signature: two distinct
  // incidents sharing a signature used to collapse into one node (the pair
  // merged onto whichever alert came first) — QA: label stuck on a TLS node
  // while the real alert octagon sat elsewhere.
  alerts.forEach((a, i) => { const label = a.signature.length > 30 ? a.signature.slice(0, 30) + "…" : a.signature; addNode(`alert:${i}`, label, "alert", `Alert: ${a.signature}\nSeverity: ${a.severity}\n${a.srcIp} → ${a.dstIp}`, 1) })

  // Flow edge weights were clamped to an ABSOLUTE 0–60 bucket
  // (min(60, bytesKB)) — any flow over ~60KB hit the cap, so on real captures
  // nearly every flow edge rendered at maximum thickness and color. The
  // capture-wide max is now the scale: edge strength is the flow's share of
  // the biggest flow (sqrt, so a 2× bigger flow reads ~1.4× thicker), mapping
  // the whole width/color gradient across the visible range.
  // Folded into a loop: Math.max(...flows.map()) spreads >125k args and
  // throws RangeError on big captures (QA: graph page blanked out).
  let maxFlowBytes = 1
  for (const f of flows) {
    if (f.bytesTotal > maxFlowBytes) maxFlowBytes = f.bytesTotal
  }

  for (const f of flows) { addEdge("pcap", `ip:${f.srcIp}`, "contains", "struct"); addEdge("pcap", `ip:${f.dstIp}`, "contains", "struct") }
  for (const f of flows) {
    const rel = Math.sqrt(f.bytesTotal) / Math.sqrt(maxFlowBytes)
    addEdge(`ip:${f.srcIp}`, `ip:${f.dstIp}`, `${f.protocol} | ${f.packets}pkts | ${formatBytes(f.bytesTotal)}${f.duration ? ` | ${Math.round(f.duration)}s` : ""}`, "flow", Math.max(1, Math.round(rel * 50)), "edge")
  }
  for (const p of protoSet) addEdge("pcap", `proto:${p}`, "uses", "struct")
  for (const d of dns) { if (d.query && d.dstIp) addEdge(`ip:${d.dstIp}`, `dns:${d.query}`, "resolved", "relation") }
  for (const h of http) { if (h.host && h.dstIp) addEdge(`ip:${h.dstIp}`, `http:${h.host}`, "serves", "relation") }
  for (const t of tls) { if (t.sni && t.dstIp) addEdge(`ip:${t.dstIp}`, `tls:${t.sni}`, "tls", "relation") }
  for (const f of files) { if (f.srcIp) addEdge(`ip:${f.srcIp}`, `file:${f.filename}`, "transferred", "relation"); if (f.dstIp) addEdge(`ip:${f.dstIp}`, `file:${f.filename}`, "transferred", "relation") }
  for (const c of credentials) { const cid = `cred:${c.username}@${c.service || c.protocol}`; if (c.srcIp) addEdge(`ip:${c.srcIp}`, cid, "used", "relation") }
  for (const label of certLabels) addEdge("pcap", `cert:${label}`, "has", "struct")
  for (const d of localDevices) addEdge("pcap", `dev:${d.ip}`, "has", "struct")
  alerts.forEach((a, i) => addEdge("pcap", `alert:${i}`, "triggered", "struct"))
  // Same-host links (B-50): the IP node (traffic) and the Device node
  // (identity) are the same endpoint — a dashed identity edge pairs them.
  for (const d of localDevices) addEdge(`ip:${d.ip}`, `dev:${d.ip}`, "same host", "identity", 0, "identity")
  // Geo edges: every geocoded external IP hangs off its country and ASN.
  for (const ip of allIps) {
    if (ip === "\u2014") continue
    const g = geoMap.get(ip)
    if (!g || g.isPrivate || g.countryCode === "??" || g.countryCode === "LOC") continue
    addEdge(`ip:${ip}`, `country:${g.countryCode}`, "in", "relation")
    if (g.asn) addEdge(`ip:${ip}`, `asn:${g.asn}`, "AS", "relation")
  }

  return { nodes, edges }
}