// Canonical statistics — the single source of truth every page reads from.
// Aggregates come from the job summary (authoritative full-table counts from
// engine); array counts are fallbacks only. Geo-derived values (countries)
// come from the shared geoMap resolved once at load time.

import type { JobSummary, Packet, Flow, Session, DnsEntry, DeviceEntry, AlertEntry } from "@/stores/analysis"
import type { GeoLocation } from "@/lib/geo"
import { isPrivateIP } from "@/lib/map-data"
import { isNonUnicast } from "@/lib/analysis"

export interface AnalysisStats {
  totalPackets: number
  totalFlows: number
  sessions: number
  devices: number
  externalIps: number
  countries: number
  domains: number
  protocols: string[]
  alerts: number
  riskScore: number
  captureDuration: number
}

export function computeStats(input: {
  job: JobSummary | null
  packets: Packet[]
  flows: Flow[]
  sessions: Session[]
  dns: DnsEntry[]
  devices: DeviceEntry[]
  alerts: AlertEntry[]
  geo: Map<string, GeoLocation>
}): AnalysisStats {
  const j = input.job
  // An address belongs to a LOCAL device if it IS one of the merged rows (ip)
  // or an alias (addresses) of a device whose primary IP is private. Devices
  // that surface a delegated home-prefix IPv6 (from the /64 the LAN itself
  // sources) fold that v6 into a private host, so it must not count in the
  // external set too (QA: calls.pcap External dropped when the client's own
  // 2401:…:308f merged into 192.168.1.20).
  const localOwned = new Set<string>()
  for (const d of input.devices) {
    // A local device is a private UNICAST address. isPrivateIP alone is too
    // wide: the unspecified/loopback placeholders (:: and its full-form
    // 0:0:0:0:0:0:0:0 — the DHCPv6 client) pass it, and a regenerated capture
    // drifted the census 5 → 6 when DHCPv6 chatter entered the LAN set (QA).
    // isNonUnicast mirrors the analyzer's device filter, so the frontend count
    // can never admit a row the Rust device list excluded.
    if (!isPrivateIP(d.ip) || isNonUnicast(d.ip)) continue
    localOwned.add(d.ip)
    for (const a of d.addresses ?? []) {
      if (!isNonUnicast(a)) localOwned.add(a)
    }
  }
  const externalIps = new Set<string>()
  for (const p of input.packets) {
    // isNonUnicast also rejects the "—" placeholder and any undecodable
    // string — an unparseable address is never an external peer.
    if (p.srcIp && !isNonUnicast(p.srcIp) && !isPrivateIP(p.srcIp) && !localOwned.has(p.srcIp)) externalIps.add(p.srcIp)
    if (p.dstIp && !isNonUnicast(p.dstIp) && !isPrivateIP(p.dstIp) && !localOwned.has(p.dstIp)) externalIps.add(p.dstIp)
  }
  const countries = new Set<string>()
  for (const loc of input.geo.values()) {
    if (loc.countryCode && loc.countryCode !== "??" && loc.countryCode !== "LOC") countries.add(loc.countryCode)
  }
  return {
    totalPackets: j?.totalPackets ?? input.packets.length,
    totalFlows: j?.totalFlows ?? input.flows.length,
    sessions: j?.conversations ?? input.sessions.length,
    // "Devices" = LOCAL endpoints. The devices array also holds every remote
    // service IP (Cloudflare/Akamai/WhatsApp CDN), which would otherwise
    // inflate the device count to "28 devices" for a 2-host LAN. Falls back to
    // the job summary only when no device rows were loaded at all.
    devices: input.devices.some((d) => d.ip)
      ? input.devices.filter((d) => isPrivateIP(d.ip) && !isNonUnicast(d.ip)).length
      : (j?.devices ?? 0),
    externalIps: externalIps.size || j?.externalIps || 0,
    countries: countries.size,
    domains: j?.domains ?? new Set(input.dns.map(d => d.query).filter(Boolean)).size,
    // The protocol list must agree with the packet rows, not just the job
    // summary: undecodable packets carry protocol "OTHER" in the store but the
    // job summary used to omit it, so the dashboard Protocols card silently
    // dropped a real protocol (QA: card listed 5, packets showed 6).
    protocols: j?.protocols?.length
      ? [...new Set([...j.protocols, ...input.packets.map(p => p.protocol).filter(Boolean)])]
      : [...new Set(input.packets.map(p => p.protocol).filter(Boolean))],
    alerts: input.alerts.length || j?.alerts || 0,
    riskScore: j?.riskScore ?? 0,
    captureDuration: j?.captureDuration ?? 0,
  }
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "0 s"
  const total = Math.round(seconds)
  if (total < 60) return `${total} s`
  const m = Math.floor(total / 60)
  const s = total % 60
  if (m < 60) return `${m} m ${s} s`
  return `${Math.floor(m / 60)} h ${m % 60} m ${s} s`
}
