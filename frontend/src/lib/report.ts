// Canonical report analysis — the ONE object every report surface (Dashboard,
// Report page, PDF, HTML, Markdown) reads from. No section recomputes risk,
// IOCs, MITRE, or recommendations; they all derive here from store state.

import type {
  AdvancedMetrics, AlertEntry, BandwidthPoint, DnsEntry, Flow, HttpEntry,
  JobInfo, JobSummary, Packet, Session, TimelineEntry, TlsEntry,
} from "@/stores/analysis"
import { isPrivateIP, slaacPrefixesOf, matchesSlaacPrefix } from "@/lib/map-data"
import { isNonUnicast, safeIso } from "@/lib/analysis"
import type { GeoLocation } from "@/lib/geo"
import { buildRiskInputs, burstConfidenceBoost, computeRiskBreakdown, riskLevel } from "./risk"
import type { RiskBreakdownItem } from "./risk"

// MAC-merged alias → owning device IP (the analyzer's addresses[] field).
// Only devices whose primary IP is private own aliases — public primaries are
// off-link and never merged. Top Talkers folds each alias's traffic into its
// owner so a host with multiple IPs appears once (QA: the 2401:4900:…:308f
// alias of a local host must not read "External · IN" on its own row).
export function ownerOfDevices(devices: { ip: string; addresses?: string[] }[]): Map<string, string> {
  const m = new Map<string, string>()
  for (const d of devices) {
    if (!isPrivateIP(d.ip)) continue
    for (const a of d.addresses ?? []) {
      if (a !== d.ip) m.set(a, d.ip)
    }
  }
  return m
}

// The full local-ownership closure (B-72): every address that belongs to a
// LOCAL machine, merged three ways —
// 1. private-primary devices own their primary + every alias (existing rule);
// 2. MAC groups: a device sharing a MAC with an owned device is the same NIC,
//    so its addresses are local too (the router's global
//    2401:4900:8910:960f::1 shares fe80::1's MAC, but its primary is
//    public-looking and rule 1 alone missed it);
// 3. /64 SLAAC: the whole delegated prefix of an owned public IPv6 is the
//    LAN's own subnet — sibling addresses with no MAC evidence (…:f027,
//    …:234c) are the same machines.
export function localOwnedAddresses(devices: { ip: string; addresses?: string[]; mac?: string }[]): Set<string> {
  const owned = new Set<string>()
  const add = (ip?: string) => { if (ip && ip !== "\u2014") owned.add(ip) }
  for (const d of devices) {
    if (!isPrivateIP(d.ip) || isNonUnicast(d.ip)) continue
    add(d.ip)
    for (const a of d.addresses ?? []) if (!isNonUnicast(a)) add(a)
  }
  const byMac = new Map<string, string[]>()
  for (const d of devices) {
    if (!d.mac || d.mac === "\u2014") continue
    const ips = byMac.get(d.mac) ?? []
    ips.push(d.ip)
    for (const a of d.addresses ?? []) ips.push(a)
    byMac.set(d.mac, ips)
  }
  for (const ips of byMac.values()) {
    if (!ips.some((ip) => owned.has(ip))) continue
    for (const ip of ips) add(ip)
  }
  const prefixes = slaacPrefixesOf(owned)
  if (prefixes.size > 0) {
    for (const d of devices) {
      for (const ip of [d.ip, ...(d.addresses ?? [])]) {
        if (!ip || owned.has(ip) || isPrivateIP(ip) || isNonUnicast(ip)) continue
        if (matchesSlaacPrefix(ip, prefixes)) add(ip)
      }
    }
  }
  return owned
}

// §8 Top Countries: each packet counts toward its destination's country.
// IPCisc-drawn: a MAC-merged alias of a LOCAL device (public-looking IPv6)
// is the same machine as its private primary — crediting it to an external
// country inflates that country (QA B-69: India read 173.3 KB for the local
// host's four aliases + router). skipDst carries those aliases.
export function countryCountsByDst(
  packets: { dstIp?: string }[],
  geo: ReadonlyMap<string, { countryCode?: string }>,
  skipDst?: ReadonlySet<string>,
): Map<string, number> {
  const counts = new Map<string, number>()
  for (const p of packets) {
    const dst = p.dstIp
    if (!dst || skipDst?.has(dst)) continue
    const loc = geo.get(dst)
    if (loc && loc.countryCode && loc.countryCode !== "??" && loc.countryCode !== "LOC") {
      counts.set(loc.countryCode, (counts.get(loc.countryCode) || 0) + 1)
    }
  }
  return counts
}

// TCP Health RTT caption: rtts empty with TCP flows present means the capture
// joined mid-session — no SYN-ACK was seen in-window, so no handshake delay
// could be measured. Say that, not "RTT unavailable".
export function tcpHealthRttCaption(rtts: number[]): string {
  if (rtts.length === 0) return "no handshakes captured (mid-session flows)"
  const avg = Math.round(rtts.reduce((s, v) => s + v, 0) / rtts.length)
  return `avg handshake RTT ${avg} ms`
}

// Endpoint table rows: unspecified/multicast placeholders (::, ::1, ff00::/8)
// are interface chatter, not hosts — never listed as endpoint rows (QA).
export function endpointRowsOf<T extends { ip: string }>(devices: T[]): T[] {
  return devices.filter((d) => !isNonUnicast(d.ip))
}

const REPORT_SCHEMA_VERSION = "1.0"

// The risk spec (shared/risk-spec.json) has no embedded version key; the app's
// canonical spec revision is 1.3. Used when jobInfo.riskSpecVersion is absent
// so reports never show "Not Installed" for the bundled spec.
export const RISK_SPEC_VERSION = "1.3"

export type FindingSource = "CONFIRMED_ALERT" | "BEHAVIORAL_METRIC"

export const SOURCE_LABELS: Record<FindingSource, string> = {
  CONFIRMED_ALERT: "Confirmed alert",
  BEHAVIORAL_METRIC: "Behavioral indicator (advanced metrics)",
}

// technique → alert rules backing it. T1071.004 is the metrics module's
// technique label for DNS tunneling, while the alert rule fires as
// DNS-TUNNEL-001 (T1048) — both labels describe the same finding.
const TECHNIQUE_RULES: Record<string, string[]> = {
  T1046: ["PORT-SCAN-001"],
  T1498: ["SYN-FLOOD-001"],
  T1048: ["DNS-TUNNEL-001"],
  "T1071.004": ["DNS-TUNNEL-001"],
  T1041: ["DATA-EXFIL-001"],
  T1071: ["C2-BEACON-001"],
  T1040: ["HTTP-CREDS-001"],
  T1552: ["CRED-LEAK-001"],
  T1105: ["MALWARE-DL-001"],
  "T1583.001": ["TLS-SUSPICIOUS-001"],
}

function ruleIdsForTechnique(technique: string): string[] {
  return TECHNIQUE_RULES[technique] ?? []
}

// Reverse map: alert rule → primary MITRE technique id (for alert-derived
// mappings; TECHNIQUE_RULES remains the source of truth for confirmation).
const TECHNIQUE_ID: Record<string, string> = {
  "PORT-SCAN-001": "T1046",
  "SYN-FLOOD-001": "T1498",
  "DNS-TUNNEL-001": "T1048",
  "CRED-LEAK-001": "T1552",
  "MALWARE-DL-001": "T1105",
  "C2-BEACON-001": "T1071",
  "DATA-EXFIL-001": "T1041",
  "TLS-SUSPICIOUS-001": "T1583.001",
  "HTTP-CREDS-001": "T1040",
}

// IOC type → alert rule that backs it. The engine fires DNS-TUNNEL-001,
// DATA-EXFIL-001 and C2-BEACON-001 as real alerts whenever these behavioral
// flags are detected, so the IOC is a confirmed alert, not a bare metric.
const IOC_TO_RULE: Record<string, string> = {
  "dns-tunneling": "DNS-TUNNEL-001",
  "data-exfiltration": "DATA-EXFIL-001",
  "beaconing": "C2-BEACON-001",
}

// Every alert rule maps to an IOC type so the IOC list stays consistent with
// the alert list (22 alerts can never produce a single IOC again).
const IOC_RULE_TYPE: Record<string, string> = {
  "PORT-SCAN-001": "port-scan",
  "SYN-FLOOD-001": "syn-flood",
  "DNS-TUNNEL-001": "dns-tunneling",
  "CRED-LEAK-001": "credential-theft",
  "MALWARE-DL-001": "malware-download",
  "C2-BEACON-001": "beaconing",
  "DATA-EXFIL-001": "data-exfiltration",
  "TLS-SUSPICIOUS-001": "tls-anomaly",
  "HTTP-CREDS-001": "credential-theft",
}

// MITRE technique id → analyst-readable label + description for alert-derived
// mappings (TECHNIQUE_RULES says which rules back which technique).
const TECHNIQUE_NAMES: Record<string, { name: string; desc: string }> = {
  T1046: { name: "Network Scanning", desc: "Probing multiple ports on target hosts to discover services" },
  T1498: { name: "Network Denial of Service", desc: "Flooding a target to disrupt availability" },
  T1048: { name: "Exfiltration Over Alternative Protocol", desc: "Moving data out over non-standard channels" },
  "T1071.004": { name: "DNS Tunneling", desc: "Data encoded in DNS queries/responses" },
  T1041: { name: "Exfiltration Over C2 Channel", desc: "Data sent to external server" },
  T1071: { name: "Application Layer Protocol", desc: "Periodic C2 beaconing detected" },
  T1040: { name: "Network Sniffing", desc: "Credentials transmitted in cleartext, sniffable over the network" },
  T1552: { name: "Unsecured Credentials", desc: "Credential exposure via authentication traffic" },
  T1105: { name: "Ingress Tool Transfer", desc: "Download of files from remote systems" },
  "T1583.001": { name: "Acquire Infrastructure: Domains", desc: "Suspicious TLS or domain infrastructure" },
}

// Alert finding aggregated per signature so reports never repeat near-identical
// rows ("DNS Tunneling ×3" becomes one row with occurrences/hosts/time span).
interface AlertGroup {
  signature: string
  ruleId: string
  category: string
  severity: number
  confidence: number
  occurrences: number
  srcHosts: string[]
  dstHosts: string[]
  firstSeen: string
  lastSeen: string
  evidence: string
  alertIds: string[]
  packets: number | null
  bytes: number | null
  flowIds: string[]
  sessionIds: string[]
  packetRange: [number, number] | null
}

function groupAlerts(alerts: AlertEntry[]): AlertGroup[] {
  const groups = new Map<string, AlertEntry[]>()
  for (const a of alerts) {
    const key = `${a.ruleId}::${a.signature}`
    const list = groups.get(key) || []
    list.push(a)
    groups.set(key, list)
  }
  return [...groups.entries()].map(([, list]) => {
    const first = list[0]
    const times = list.map((a) => new Date(a.timestamp).getTime()).sort((x, y) => x - y)
    return {
      signature: first.signature,
      ruleId: first.ruleId,
      category: first.category,
      severity: Math.max(...list.map((a) => a.severity)),
      confidence: Math.max(...list.map((a) => a.confidence)),
      occurrences: list.length,
      srcHosts: [...new Set(list.map((a) => a.srcIp))],
      dstHosts: [...new Set(list.map((a) => a.dstIp))],
      firstSeen: safeIso(times[0]),
      lastSeen: safeIso(times[times.length - 1]),
      evidence: first.evidence,
      alertIds: list.map((a) => a.id),
      packets: null,
      bytes: null,
      flowIds: [],
      sessionIds: [],
      packetRange: null,
    }
  }).sort((a, b) => b.severity - a.severity || b.occurrences - a.occurrences || a.signature.localeCompare(b.signature))
}

function pairMatches(alert: AlertEntry, srcIp: string, dstIp: string): boolean {
  return (alert.srcIp === srcIp && alert.dstIp === dstIp) ||
    (alert.srcIp === dstIp && alert.dstIp === srcIp)
}

function sameTuple(alert: AlertEntry, srcPort: number, dstPort: number): boolean {
  if (alert.srcPort === 0 && alert.dstPort === 0) return true
  return (alert.srcPort === srcPort && alert.dstPort === dstPort) ||
    (alert.srcPort === dstPort && alert.dstPort === srcPort)
}

// Flow/session/packet references for an alert: matches the alert's host pair
// (either direction) plus ports when the alert carries them.
function alertReferences(
  alert: AlertEntry,
  flows: Flow[],
  sessions: Session[],
  packets: Packet[]
): { flowIds: string[]; sessionIds: string[]; packetRange: [number, number] | null } {
  const flowIds = new Set<string>()
  const sessionIds = new Set<string>()
  for (const f of flows) {
    if (pairMatches(alert, f.srcIp, f.dstIp) && sameTuple(alert, f.srcPort, f.dstPort)) flowIds.add(f.id)
  }
  for (const s of sessions) {
    if (pairMatches(alert, s.srcIp, s.dstIp) && sameTuple(alert, s.srcPort, s.dstPort)) sessionIds.add(s.id)
  }
  let range: [number, number] | null = null
  for (const p of packets) {
    if (!pairMatches(alert, p.srcIp, p.dstIp) || !sameTuple(alert, p.srcPort, p.dstPort)) continue
    range = range ? [Math.min(range[0], p.num), Math.max(range[1], p.num)] : [p.num, p.num]
  }
  return {
    flowIds: [...flowIds],
    sessionIds: [...sessionIds],
    packetRange: range,
  }
}

export interface ReportRisk {
  rawScore: number
  normalizedScore: number
  formula: string
  levelLabel: string
  levelColor: string
  items: RiskBreakdownItem[]
  burstApplied: boolean
}

interface IocFinding {
  type: string
  value: string
  description: string
  severity: number
  source: FindingSource
  ruleId?: string
  confidence?: number
  occurrences?: number
  firstSeen?: string
  lastSeen?: string
}

interface MitreFinding {
  technique: string
  id: string
  description: string
  severity: number
  source: FindingSource
}

interface Recommendation {
  text: string
  severity: number
  source: FindingSource
}

export interface ReportAnalysis {
  risk: ReportRisk | null
  alerts: AlertEntry[]
  groups: AlertGroup[]
  iocs: IocFinding[]
  mitre: MitreFinding[]
  recommendations: Recommendation[]
  timeline: { time: string; packets: number }[]
  bandwidth: { time: string; in: number; out: number }[]
  alertTraffic: Map<string, { packets: number | null; bytes: number | null }>
  emptyReasons: { files: string; credentials: string; certificates: string }
  metadata: {
    mode: string
    schemaVersion: string
    analyzerVersion?: string
    ruleVersion?: string
    riskSpecVersion?: string
    analysisDurationSec?: number
    /** Capture quality (VALID/SINGLE_PACKET/ZERO_DURATION/EMPTY) + whether
     *  rate metrics exist — the report shows N/A when they do not. */
    captureQuality?: string
    ratesAvailable?: boolean
  }
}

export interface ReportState {
  job: JobSummary | null
  jobInfo: JobInfo
  alerts: AlertEntry[]
  packets: Packet[]
  flows: Flow[]
  sessions: Session[]
  tls: TlsEntry[]
  http: HttpEntry[]
  timeline: TimelineEntry[]
  bandwidth: BandwidthPoint[]
  advancedMetrics: AdvancedMetrics | null
}

// Rules the burst detection can boost the confidence of (risk-spec.json
// burst_params). Kept in sync with the spec's bonus keys.
const burstEligibleRules = ["DATA-EXFIL-001", "C2-BEACON-001", "DNS-TUNNEL-001"]

export function buildReportRisk(alerts: AlertEntry[], advancedMetrics: AdvancedMetrics | null): ReportRisk | null {
  if (!advancedMetrics) return null
  const riskAlerts = buildRiskInputs(alerts)
  // "Applied" means at least one alert actually received the burst confidence
  // bonus. A bare burst with no C2/exfil/DNS rule to boost shows "No".
  const burstApplied = burstConfidenceBoost(advancedMetrics) &&
    riskAlerts.some((a) => burstEligibleRules.includes(a.ruleId))
  const b = computeRiskBreakdown(riskAlerts, burstApplied)
  const level = riskLevel(b.normalizedScore)
  return {
    rawScore: Math.round(b.rawScore),
    normalizedScore: b.normalizedScore,
    formula: b.formula,
    levelLabel: level.label,
    levelColor: level.color,
    items: b.items,
    burstApplied,
  }
}

// Canonical severity for a finding: the max severity of the alerts backing it.
// Falls back to the metric's own severity when no alert covers the finding.
function maxSeverityForAlerts(alerts: AlertEntry[], ruleIds: string[]): number | null {
  let max: number | null = null
  for (const a of alerts) {
    if (ruleIds.includes(a.ruleId)) max = Math.max(max ?? 0, a.severity)
  }
  return max
}

export function iocSource(type: string, alerts: AlertEntry[]): FindingSource {
  if (type === "threat") return "CONFIRMED_ALERT"
  const ruleId = IOC_TO_RULE[type]
  return ruleId && alerts.some((a) => a.ruleId === ruleId) ? "CONFIRMED_ALERT" : "BEHAVIORAL_METRIC"
}

function iocSeverity(ioc: { type: string; severity: number }, alerts: AlertEntry[]): number {
  if (ioc.type === "threat") return ioc.severity
  const ruleId = IOC_TO_RULE[ioc.type]
  return ruleId ? maxSeverityForAlerts(alerts, [ruleId]) ?? ioc.severity : ioc.severity
}

export function mitreSource(mapping: { id: string }, alerts: AlertEntry[]): FindingSource {
  return alerts.some((a) => ruleIdsForTechnique(mapping.id).includes(a.ruleId))
    ? "CONFIRMED_ALERT"
    : "BEHAVIORAL_METRIC"
}

function mitreSeverity(mapping: { id: string; severity: number }, alerts: AlertEntry[]): number {
  return maxSeverityForAlerts(alerts, ruleIdsForTechnique(mapping.id)) ?? mapping.severity
}

const MITRE_REC: Record<string, string> = {
  T1046: "Block scanning source IPs at the perimeter and tighten firewall/IDS policies",
  "T1071.004": "Inspect DNS logs for encoded payloads; enable DNS security monitoring and sinkholing",
  T1048: "Inspect DNS logs for encoded payloads; enable DNS security monitoring and sinkholing",
  T1041: "Review egress allow-lists; investigate large transfers to external servers",
  T1071: "Isolate beaconing endpoints and hunt for C2 malware on affected hosts",
  T1090: "Enforce blocking of known proxy/TOR/VPN endpoints; review outbound policy",
  T1003: "Rotate exposed credentials and investigate hosts involved in authentication traffic",
  T1040: "Plaintext credentials were exposed in cleartext traffic; rotate the affected accounts and migrate the service to HTTPS",
  T1213: "Review data-collection endpoints and restrict access to sensitive repositories",
}

function mitreRec(m: { id: string; technique: string }): string {
  return MITRE_REC[m.id] || `Review activity related to ${m.technique} and verify its legitimacy`
}

// Severity and source of a flag-based recommendation: the backing alert's
// when one fired (the engine emits DNS-TUNNEL-001 / DATA-EXFIL-001 /
// C2-BEACON-001 on these flags), else the metric's own value.
function flagRec(
  alerts: AlertEntry[],
  ruleId: string,
  defaultSeverity: number
): { severity: number; source: FindingSource } {
  const severity = maxSeverityForAlerts(alerts, [ruleId]) ?? defaultSeverity
  const source: FindingSource = alerts.some((a) => a.ruleId === ruleId) ? "CONFIRMED_ALERT" : "BEHAVIORAL_METRIC"
  return { severity, source }
}

// Canonical topic of a recommendation so near-identical advice from different
// sources (a metric flag, a MITRE mapping, an alert group) collapses to one
// item instead of repeating the same remediation three times.
function recTopic(text: string): string {
  const lower = text.toLowerCase()
  if (/(exfil|egress|outbound|transfer)/.test(lower)) return "egress-exfil"
  if (/dns/.test(lower)) return "dns"
  if (/(beacon|c2)/.test(lower)) return "beaconing"
  if (/(scan|probing)/.test(lower)) return "scanning"
  if (/(credential|auth|rotate|password)/.test(lower)) return "credentials"
  if (/tls/.test(lower)) return "tls"
  if (/(malware|download|tool)/.test(lower)) return "tool-transfer"
  return lower.slice(0, 40)
}

function buildRecommendations(
  advancedMetrics: AdvancedMetrics | null,
  mitre: MitreFinding[],
  alerts: AlertEntry[]
): Recommendation[] {
  const items: Recommendation[] = []
  if (!advancedMetrics) return items
  if (advancedMetrics.dataExfiltrationSuspected) {
    items.push({
      text: "Investigate large outbound transfers to external IPs. Consider blocking suspicious destinations and implementing egress filtering.",
      ...flagRec(alerts, "DATA-EXFIL-001", 4),
    })
  }
  if (advancedMetrics.dnsTunnelingSuspected) {
    items.push({
      text: "Unusual DNS query patterns detected. Monitor DNS traffic for encoded data and consider implementing DNS security policies.",
      ...flagRec(alerts, "DNS-TUNNEL-001", 4),
    })
  }
  if (advancedMetrics.beaconDetected) {
    items.push({
      text: "Periodic communication patterns detected. Investigate for C2 activity and malware beaconing behavior.",
      ...flagRec(alerts, "C2-BEACON-001", 3),
    })
  }
  if (advancedMetrics.portScanEnhanced) {
    items.push({
      text: "Port scan activity detected. Block source IPs and review firewall rules.",
      ...flagRec(alerts, "PORT-SCAN-001", 3),
    })
  }
  for (const m of mitre) {
    items.push({ text: mitreRec(m), severity: m.severity, source: m.source })
  }
  // Collapse by topic, keeping the highest-severity variant.
  const best = new Map<string, Recommendation>()
  for (const r of items) {
    const topic = recTopic(r.text)
    const cur = best.get(topic)
    if (!cur || r.severity > cur.severity) best.set(topic, r)
  }
  return [...best.values()]
}

export function packetEpochSec(p: { timestamp: string | number }): number {
  // Numeric timestamps >= 1e12 are milliseconds, not seconds — mirror the
  // ms guard the reports page's packetDate uses, or durations/bin widths
  // would be off by ~1.7e9 on numeric-ms data (QA parity fix).
  if (typeof p.timestamp === "number") return p.timestamp >= 1e12 ? p.timestamp / 1000 : p.timestamp
  return new Date(p.timestamp).getTime() / 1000
}

// Shared decode-rate predicate for the verdict gate. Unsupported link types
// parse lengths + timestamps only, so a SAFE/risk verdict on invisible
// traffic is dishonest — the report says UNKNOWN and the dashboard/viz cards
// must agree (QA: dashboard badge read "0/100 SAFE" on a 0% decode capture).
export function decodeRateOf(decode: { decoded: number; total: number } | null | undefined, packets: Packet[]): number {
  if (decode && decode.total > 0) return decode.decoded / decode.total
  if (packets.length === 0) return 1
  return packets.filter((p) => p.srcIp !== "\u2014" || p.dstIp !== "\u2014").length / packets.length
}

// Min/max epoch seconds over packets. First/last array elements lie when the
// capture is out of order (QA: [100, 50, 90] s read a -10 s duration).
function packetSpanSec(packets: Array<{ timestamp: string | number }>): [number, number] {
  let min = Infinity
  let max = -Infinity
  for (const p of packets) {
    const t = packetEpochSec(p)
    if (t < min) min = t
    if (t > max) max = t
  }
  return [min, max]
}

function timelineLabel(secFromStart: number): string {
  const s = Math.max(0, Math.floor(secFromStart))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  const mm = String(m).padStart(2, "0")
  const ss = String(sec).padStart(2, "0")
  return h > 0 ? `${String(h).padStart(2, "0")}:${mm}:${ss}` : `${mm}:${ss}`
}

export interface TimelineBin {
  time: string
  packets: number
  bytes: number
  in: number
  out: number
  // Transport/app split for the timeline's stacked breakdown — counted from
  // the same packets, so the breakdown always sums to `packets` (M4/C2).
  tcp: number
  udp: number
  dns: number
  tls: number
}

// Rebin packets into 1s (capture <= 2 min), 5s (<= 10 min), else capped bins.
export function binPackets(packets: Packet[], durationSec: number, maxBins = 120): TimelineBin[] {
  if (!packets.length) return []
  const [s0, s1] = packetSpanSec(packets)
  const dur = Math.max(durationSec, packets.length > 1 ? s1 - s0 : 0, 1)
  const bin = dur <= 120 ? 1 : dur <= 600 ? 5 : Math.max(1, Math.ceil(dur / maxBins))
  const t0 = s0
  const buckets = new Map<number, TimelineBin>()
  for (const p of packets) {
    const idx = Math.floor((packetEpochSec(p) - t0) / bin)
    const b = buckets.get(idx) || {
      time: timelineLabel(idx * bin),
      packets: 0,
      bytes: 0,
      in: 0,
      out: 0,
      tcp: 0,
      udp: 0,
      dns: 0,
      tls: 0,
    }
    b.packets += 1
    b.bytes += p.length
    if (isPrivateIP(p.srcIp)) b.out += p.length
    else b.in += p.length
    // One bucket per packet: DNS/TLS are app-layer slices of TCP/UDP — a
    // packet counted in both udp and dns (or tcp and tls) double-counts it in
    // the stacked protocol bars (QA: 527 UDP + 2 DNS while only 529 UDP).
    if (p.appProtocol === 'DNS') b.dns += 1
    else if (p.appProtocol === 'TLS' || p.appProtocol === 'HTTPS') b.tls += 1
    else if (p.protocol === 'TCP') b.tcp += 1
    else if (p.protocol === 'UDP') b.udp += 1
    buckets.set(idx, b)
  }
  return [...buckets.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v)
}

// Capture-length-aware bin width in seconds: 1s up to 2 min, 5s up to 10 min,
// then capped at maxBins. Exported so the timeline and bandwidth derivations
// agree with binPackets on interval width.
export function binWidthSec(durationSec: number, maxBins = 120): number {
  const dur = Math.max(durationSec, 1)
  return dur <= 120 ? 1 : dur <= 600 ? 5 : Math.max(1, Math.ceil(dur / maxBins))
}

// Store timeline/bandwidth are 5-minute bins: for captures under
// 10 minutes they are coarser than the packet rebin (an 88s capture collapses
// to 2 coarse bins), so only short captures rebin from packets — long
// captures keep the store (fewer points, exact SQL counts).
function buildTimeline(
  packets: Packet[],
  storeTimeline: TimelineEntry[],
  durationSec: number
): { time: string; packets: number }[] {
  if (durationSec > 600 && storeTimeline.length >= 2) {
    // Spread the whole entry: the timeline page draws protocol slices
    // (TCP/UDP/DNS/TLS/OTHER) from these rows too, not just packet counts.
    return storeTimeline.map((t) => ({ ...t }))
  }
  return binPackets(packets, durationSec).map((b) => ({ time: b.time, packets: b.packets }))
}

// Wall-clock overlap of a clock-aligned 5-min bucket with the capture, in
// seconds. Store bandwidth is summed into wall-clock buckets (m5Bucket), so
// the first and last buckets hold less than 300 s of traffic — dividing them
// by a fixed 300 understates the per-second rate there (QA: a 10:03–10:07
// capture showed both buckets at sum/300). Labels are "HH:MM" (single-day)
// or "MM-DD HH:MM" (multi-day); the capture's date context reconstructs the
// epoch. A non-positive overlap means a year-crossing label (January bucket
// resolved against the capture's start year) — a full 300 s is the honest
// answer for a bucket that carries traffic.
export function bucketOverlapSec(label: string, captureStartSec: number, captureEndSec: number): number {
  const start = new Date(captureStartSec * 1000)
  const y = start.getFullYear()
  let iso: string
  if (label.includes("-")) {
    const [md, hhmm] = label.split(" ")
    iso = `${y}-${md} ${hhmm}`
  } else {
    const mm = String(start.getMonth() + 1).padStart(2, "0")
    const dd = String(start.getDate()).padStart(2, "0")
    iso = `${y}-${mm}-${dd} ${label}`
  }
  const bStart = new Date(iso).getTime() / 1000
  const overlap = Math.min(bStart + 300, captureEndSec) - Math.max(bStart, captureStartSec)
  return overlap >= 1 ? Math.min(overlap, 300) : 300
}

// Bandwidth points are displayed per-second ("KB/s"), so both sources divide
// by the interval width: store bins are 5-minute sums, packet rebins divide by
// their bin width. Without this a 5-min bucket sum would be drawn as a
// per-second rate and overshoot the stated peak.
export function buildBandwidth(
  packets: Array<{ timestamp: string | number }>,
  storeBandwidth: BandwidthPoint[],
  durationSec: number | null
): { time: string; in: number; out: number }[] {
  // No time interval (single packet / zero duration): rates do not exist.
  // An empty series is honest — a 1-packet chart divided by a fabricated
  // interval would draw a fake per-second rate (QA: 66 B/s one-packet peak).
  if (durationSec === null || durationSec <= 0) return []
  if (durationSec > 600 && storeBandwidth.length >= 2) {
    const [start, end] = packetSpanSec(packets)
    return storeBandwidth.map((b) => ({
      time: b.time,
      // Each bucket divided by its real capture overlap, not fixed 300
      // (QA: partial first/last buckets understated rates by up to 2.5x).
      in: b.in / bucketOverlapSec(b.time, start, end),
      out: b.out / bucketOverlapSec(b.time, start, end),
    }))
  }
  const bin = binWidthSec(durationSec)
  return binPackets(packets as Packet[], durationSec).map((b) => ({ time: b.time, in: b.in / bin, out: b.out / bin }))
}

// Real packet/byte counts per alert from flow stats. Flow pairs are stored
// direction-normalized (smaller IP as src), so match either orientation.
// null means the capture rows were not retained for that pair (caps
// the payload) — the UI must show N/A, never a fake zero.
export function alertTrafficFor(alert: AlertEntry, flows: Flow[]): { packets: number | null; bytes: number | null } {
  let packets = 0
  let bytes = 0
  for (const f of flows) {
    const samePair =
      (f.srcIp === alert.srcIp && f.dstIp === alert.dstIp) ||
      (f.srcIp === alert.dstIp && f.dstIp === alert.srcIp)
    // Ports too, like alertReferences: without the tuple gate, a 53-flow alert
    // would sum every flow between the two hosts (QA: DNS-TUNNEL on the DNS
    // pair absorbed the pair's 443 traffic).
    if (samePair && sameTuple(alert, f.srcPort, f.dstPort)) {
      packets += f.packets
      bytes += f.bytesTotal
    }
  }
  return packets > 0 ? { packets, bytes } : { packets: null, bytes: null }
}

// IANA well-known service names for common ports (analyst readability).
// Ports are transport-neutral here; portServiceName() disambiguates 443.
const PORT_SERVICES: Record<number, string> = {
  7: "Echo", 20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
  135: "MS-RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
  143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 1900: "SSDP",
   194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
   520: "RIP", 546: "DHCPv6", 547: "DHCPv6", 587: "SMTP-Sub", 636: "LDAPS", 853: "DoT",
  993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
  1723: "PPTP", 1812: "RADIUS", 19302: "STUN", 2049: "NFS", 2375: "Docker",
  3000: "Web-Dev", 3128: "Proxy", 3306: "MySQL", 3389: "RDP", 3702: "WS-Discovery",
  5060: "SIP", 5222: "XMPP", 5349: "STUN", 5353: "mDNS", 5355: "LLMNR",
  5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 6443: "K8s-API",
  8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9000: "App", 9092: "Kafka",
   8001: "HTTP-Alt",
  27017: "MongoDB", 3478: "STUN", 51820: "WireGuard", 5228: "GCM (FCM)",
}

// Port → human service label. Ephemeral-looking ports get "Dynamic/Ephemeral":
// IANA dynamic (49152–65535) plus the Linux default ephemeral range
// (32768+); unknown fixed ports are "Unknown service" (some are custom apps,
// so the honest label is "unknown", not "unassigned").
// Protocol disambiguates: 443/TCP is HTTPS but 443/UDP is QUIC, and 53/TCP is
// zone-transfer DNS while 53/UDP is query DNS.
export function portServiceName(port: number, protocol?: string): string {
  if (protocol === "UDP" && port === 443) return "QUIC"
  if (PORT_SERVICES[port]) return PORT_SERVICES[port]
  if (port >= 32768 && port <= 65535) return "Dynamic/Ephemeral"
  return "Unknown service"
}

// App-layer labels the decoder assigns ONLY after payload verification
// (STUN magic cookie, DNS structure, HTTP start line, TLS record, SIP start
// line, QUIC header). A service label backed by one of these is
// payload-confirmed; every other service label is a port inference — the
// same label can never mean "verified" on one surface and "guessed" on
// another (audit: UDP/3478 read as 622 confirmed STUN packets while only
// the 26 cookie-verified ones were STUN). HTTPS is port-inferred; its
// confirmed evidence is the content-parsed TLS label. HTTP-Alt likewise:
// only content-parsed HTTP on 8001 counts, never the port fallback.
const SERVICE_EVIDENCE: Record<string, Set<string>> = {
  STUN: new Set(["STUN"]),
  DNS: new Set(["DNS"]),
  SIP: new Set(["SIP"]),
  HTTP: new Set(["HTTP"]),
  "HTTP-Alt": new Set(["HTTP"]),
  HTTPS: new Set(["TLS"]),
  QUIC: new Set(["QUIC"]),
}

function evidenceAppProtocols(service: string): Set<string> | undefined {
  return SERVICE_EVIDENCE[service]
}

// Service label with its evidence qualifier, for report tables: a label that
// is fully payload-confirmed stays plain; a partially confirmed one carries
// the verified count; an entirely port-inferred one says so.
export function serviceEvidenceLabel(service: string, confirmed: number, count: number): string {
  if (confirmed >= count) return service
  if (confirmed > 0) return `${service} (${confirmed.toLocaleString()} of ${count.toLocaleString()} payload-confirmed)`
  return `${service} (port-inferred)`
}

// Rank ports by their SERVICE side, one rule for every transport. Static
// range checks (e.g. "port >= 32768 is ephemeral") fail: clients pick
// ephemeral ports below 32768 too, so reply packets get attributed to the
// client's port and the service count splits. "First packet's destination"
// also fails when the capture starts mid-session: the first observed packet
// is then a server reply, and the whole flow lands on the client's
// ephemeral port (test.pcapng: TCP/42224 295 vs TCP/443 880, sum 1,175).
// The service port is instead decided per conversation, by PORT:
//   1. the endpoint whose port is well-known (< 1024) or a known service
//      (443, 80, 53, 3478…) wins;
//   2. otherwise the LOWER port wins (both known — 443 vs 8443 — or both
//      unknown registered-range ports, e.g. a custom app);
//   3. a conversation whose lower port is in the IANA dynamic range
//      (≥ 49152) is P2P between two ephemeral endpoints and is skipped
//      (its volume still shows under Top Protocols).
// Every packet of a conversation (both legs) counts under that service
// port, so TCP/443 sums to all 1,175 packets. Port-less packets (ICMP,
// GRE, ESP) are skipped.
export interface ServicePortCount {
  protocol: string
  port: number
  count: number
  // Packets in the conversation whose app layer was payload-verified as the
  // service (see SERVICE_EVIDENCE). count - confirmed is port-inferred.
  confirmed: number
}
const knownServicePort = (port: number): boolean => port < 1024 || PORT_SERVICES[port] !== undefined
function servicePortOf(a: number, b: number): number | undefined {
  const ka = knownServicePort(a)
  const kb = knownServicePort(b)
  // Known service ports win — even >= 49152 (WireGuard 51820): the client
  // port is dynamic, so dropping known ports at the ephemeral threshold
  // mislabels the service as "Dynamic/Ephemeral" (QA).
  if (ka || kb) return ka ? a : b
  if (a >= 49152) return undefined
  return a
}
export function servicePortCounts(packets: { srcIp: string; dstIp: string; srcPort?: number; dstPort?: number; protocol: string; appProtocol?: string }[]): ServicePortCount[] {
  const counts = new Map<string, ServicePortCount>()
  for (const p of packets) {
    if (!p.srcPort || !p.dstPort) continue
    const s = p.srcPort
    const d = p.dstPort
    const port = servicePortOf(Math.min(s, d), Math.max(s, d))
    if (!port) continue
    const key = `${p.protocol}/${port}`
    const e = counts.get(key) || { protocol: p.protocol, port, count: 0, confirmed: 0 }
    e.count += 1
    const evidence = evidenceAppProtocols(portServiceName(port, p.protocol))
    if (evidence && p.appProtocol && evidence.has(p.appProtocol)) e.confirmed += 1
    counts.set(key, e)
  }
  return [...counts.values()].sort((a, b) => b.count - a.count)
}

// DLT (link type) number → friendly encapsulation name, for the decode
// diagnostics. Unknown numbers keep the numeric form — the analyst needs the
// actual DLT value to re-capture with the right override.
const DLT_NAMES: Record<number, string> = {
  0: "NULL/Loopback", 1: "Ethernet", 9: "PPP", 12: "Raw IP", 101: "Raw IP (IPv4/IPv6)",
  105: "Wi-Fi (802.11)", 108: "Loopback (OpenBSD)", 113: "Linux cooked v1 (SLL)",
  127: "Wi-Fi (802.11 + radiotap)", 228: "NFC (LLCP)", 229: "NFC (LLCP + raw)",
  276: "Linux cooked v2 (SLL2)",
}
export function dltName(linkTypes: number[]): string {
  if (!linkTypes.length) return "unknown"
  return linkTypes.map((n) => `${DLT_NAMES[n] ?? `DLT ${n}`}`).join(", ")
}

// HTTP User-Agent → client OS fingerprint for observations. Microsoft's
// CryptoAPI client (crl/ocsp validation) is a Windows component but its UA
// string says "Microsoft-CryptoAPI", not "Windows".
export function osFromUserAgent(ua: string): string | undefined {
  if (!ua) return undefined
  if (/Microsoft-CryptoAPI|Windows|MSIE|Trident/i.test(ua)) return "Windows"
  if (/Android/i.test(ua)) return "Android"
  if (/iPhone|iPad/i.test(ua)) return "iOS"
  if (/Mac OS X|Macintosh/i.test(ua)) return "macOS"
  if (/Linux/i.test(ua)) return "Linux"
  return undefined
}

// Distinct DNS lookups actually performed by clients. A recursive resolver
// (typically the LAN router) relays every client query to an upstream server,
// so the same (name, type) appears as client→resolver and resolver→upstream.
// Responses echo the question too, so they are flagged isResponse and never
// counted as queries. Counting raw packets ("54") would count one lookup up
// to three times. Resolvers are hosts that RECEIVED DNS queries in the
// capture; their own forwarded copies are not client lookups. Falls back to
// counting every non-response entry when no resolver was observed
// (server-side capture), so the number is never silently zero.
export function dnsLookupCount(entries: DnsEntry[]): number {
  const queries = entries.filter((d) => !d.isResponse)
  const resolvers = new Set<string>()
  for (const d of queries) resolvers.add(d.dstIp)
  const seen = new Set<string>()
  for (const d of queries) {
    if (resolvers.has(d.srcIp)) continue
    seen.add(`${d.query}\u0000${d.type}`)
  }
  if (seen.size === 0) {
    for (const d of queries) seen.add(`${d.query}\u0000${d.type}`)
  }
  return seen.size
}

// Distribution stats over capture interval sums. null when there is no data
// to characterize (empty or single-bin captures).
export function bandwidthStats(bw: { in: number; out: number }[]): { min: number | null; median: number | null; p95: number | null } {
  if (bw.length < 2) return { min: null, median: null, p95: null }
  const sums = bw.map((b) => b.in + b.out).sort((a, b) => a - b)
  const median = (arr: number[]) => {
    const mid = Math.floor(arr.length / 2)
    return arr.length % 2 ? arr[mid] : (arr[mid - 1] + arr[mid]) / 2
  }
  return {
    min: sums[0],
    median: median(sums),
    p95: sums[Math.min(sums.length - 1, Math.floor(sums.length * 0.95))],
  }
}

// Internal IOC type identifiers → analyst-readable labels.
const IOC_TYPE_LABELS: Record<string, string> = {
  threat: "Network Threat",
  "dns-tunneling": "DNS Tunneling",
  "data-exfiltration": "Data Exfiltration",
  beaconing: "Beaconing",
  "tor-vpn-proxy": "TOR/VPN/Proxy",
  ja3: "Suspicious JA3",
  "port-scan": "Port Scan",
  "syn-flood": "SYN Flood",
  "credential-theft": "Credential Theft",
  "malware-download": "Malware Download",
  "tls-anomaly": "TLS Anomaly",
}

export function iocTypeLabel(type: string): string {
  return IOC_TYPE_LABELS[type] || type.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
}

// Alert signature → short finding name for the timeline legend
// ("TCP Port Scan Detected" → "Port Scan", "Possible DNS Tunneling" → "DNS Tunneling").
export function shortAlertName(signature: string): string {
  return signature
    .replace(/^(Possible|Suspected|Regular|Potential)\s+/i, "")
    .replace(/\s+(Detected|Suspected)$/i, "")
    .trim()
}

// The analyst-conclusion verdict line, shared by the markdown export and tests
// so the export can't regress to "N/A" or a fake score (QA: verdict text).
export function verdictLine(levelLabel: string, scoreVal: number, undecodable: boolean): string {
  // A SAFE verdict only means nothing matched the configured rules — the
  // wrapper must not read as an absolute safety guarantee (QA audit).
  return `- **Final verdict:** **${levelLabel}** — ${undecodable ? "risk not computable (insufficient data)" : `risk ${scoreVal}/100`}${levelLabel === "SAFE" ? " — no configured detection rules triggered" : ""}`
}

// Escaping for the standalone HTML report export. Escapes ONCE: the mdInline
// helper escapes the whole input before splitting it on ** (bold) and `
// (code) markers, so the marked-up segments are never double-escaped (QA:
// the exported HTML rendered "&amp;amp;" and literal "&lt;" because callers
// pre-escaped and mdInline escaped again).
export function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}

// Markdown text → HTML paragraph/cell content: **bold**, `code`. Older
// versions escaped first and left backticks literal, so `key-test` rendered
// as plain text instead of a <code> link (QA: real-artifact export check).
export function mdInline(s: string): string {
  const render = (part: string, strong: boolean, italic: boolean) => {
    const seg = part.split("`").map((c, j) => (j % 2 === 1 ? `<code>${escHtml(c)}</code>` : escHtml(c))).join("")
    return strong ? `<strong>${seg}</strong>` : italic ? `<em>${seg}</em>` : seg
  }
  // **bold** first, then *italic* inside the non-bold spans — a bare *…*
  // footnote used to leak literal asterisks into the HTML export (QA:
  // "(+3 more services…)" rendered as *(+3 more services…)*).
  return s.split("**").map((part, i) => {
    if (i % 2 === 1) return render(part, true, false)
    return part.split("*").map((seg, j) => render(seg, false, j % 2 === 1)).join("")
  }).join("")
}

// Flow cell → CSV. Cells are left unquoted when plain (Excel-friendly), but
// embedded commas/quotes/newlines are quoted with doubled quotes, and
// formula-prefixed cells (= + - @) are defused with a leading apostrophe so
// hostile GeoIP ASN strings can't execute as Excel formulas (CSV injection).
function csvCell(v: string | number): string {
  const s = String(v ?? "")
  if (s === "") return ""
  const defused = /^[=+\-@]/.test(s) ? `'${s}` : s
  if (/[",\r\n]/.test(defused)) return `"${defused.replace(/"/g, '""')}"`
  return defused
}

// Standalone HTML export artifact — the ONLY renderer of the exported report
// file, so it lives in a testable lib instead of the page component. The
// converter is structural: every NUMBER in the export comes from the report
// data (stats/report/engine), which the export tests cross-check per capture.
export function markdownToHtml(
  md: string,
  opts: { jobId: string; jobFilename: string; origin: string },
): string {
  const { jobId, jobFilename, origin } = opts
  const appUrl = `${origin}/analysis/${encodeURIComponent(jobId)}`
  const out: string[] = []
  let inUl = false
  let tableRows: string[] = []
  const closeUl = () => { if (inUl) { out.push("</ul>"); inUl = false } }
  const closeTable = () => {
    if (tableRows.length === 0) return
    const cells = (r: string) => r.replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim())
    const rows = tableRows.filter((r) => !/^\|[\s:|-]+\|$/.test(r)).map(cells)
    const header = rows[0]
    out.push("<table><thead><tr>", ...header.map((h) => `<th>${mdInline(h)}</th>`), "</tr></thead><tbody>")
    for (const r of rows.slice(1)) out.push("<tr>", ...r.map((c) => `<td>${mdInline(c)}</td>`), "</tr>")
    out.push("</tbody></table>")
    tableRows = []
  }
  for (const line of md.split("\n")) {
    if (line.startsWith("|")) { closeUl(); tableRows.push(line); continue }
    closeTable()
    if (line.startsWith("- ")) {
      if (!inUl) { out.push("<ul>"); inUl = true }
      let html = mdInline(line.slice(2))
      if (html.includes("Final verdict")) {
        // Verdict label gets the risk color class (lv-safe/lv-low/…), derived
        // from the markdown itself so the converter needs no page state.
        html = html.replace(/<strong>([^<]*)<\/strong>(?!.*<strong>)/, (_, lbl) => `<strong class="lv-${lbl.toLowerCase()}">${lbl}</strong>`)
      }
      out.push(`<li>${html}</li>`)
      continue
    }
    closeUl()
    if (line.startsWith("### ")) out.push(`<h3>${escHtml(line.slice(4))}</h3>`)
    else if (line.startsWith("## ")) out.push(`<h2>${escHtml(line.slice(3))}</h2>`)
    else if (line.startsWith("# ")) {
      out.push(`<h1>${escHtml(line.slice(2))}</h1>`)
      // This export is the summary artifact, not the full in-app report.
      out.push(`<p class="note">Summary export — the full report (Packets, Flows, Sessions, DNS, TCP Health, Endpoints, Timeline, Risk Breakdown, IOCs, MITRE) is only in PacketLens. <a href="${appUrl}">View in PacketLens</a></p>`)
    }
    else if (line.startsWith("_") && line.endsWith("_")) out.push(`<p class="note">${mdInline(line.slice(1, -1))}</p>`)
    else if (line.trim() !== "") out.push(`<p>${mdInline(line)}</p>`)
  }
  closeUl()
  closeTable()
  const bodyHtml = out.join("\n").replace(`<code>${escHtml(jobId)}</code>`, `<code><a href="${appUrl}">${escHtml(jobId)}</a></code>`)
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>PacketLens Report — ${escHtml(jobFilename)}</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:900px;margin:2rem auto;padding:0 1.5rem;color:#1a1a2e;line-height:1.5}h1{color:#2563eb;border-bottom:2px solid #2563eb;padding-bottom:.5rem}h2{color:#1e3a8a;margin-top:2rem}h3{color:#374151;margin-top:1.5rem}li{margin:.3rem 0}p{margin:.5rem 0}p.note{font-size:.85rem;color:#6b7280;font-style:italic}table{border-collapse:collapse;width:100%;margin:.75rem 0;font-size:.9rem}th,td{border:1px solid #d1d5db;padding:.35rem .6rem;text-align:left}th{background:#f3f4f6}.lv-safe{color:#15803d}.lv-low{color:#2563eb}.lv-medium{color:#d97706}.lv-high{color:#dc2626}.lv-critical{color:#991b1b}</style></head><body>${bodyHtml}</body></html>`
}

// Port → service label for a FLOW (not a packet): a conversation whose known
// service port sits on the SOURCE side (capture started mid-session, or the
// server answered first) must still be classified by that port. Same rule as
// servicePortCounts: known service port wins, otherwise the lower port,
// otherwise Dynamic/Ephemeral when both sides are dynamic (P2P).
export function flowServiceName(srcPort: number, dstPort: number, protocol?: string): string {
  // Port-less protocols (ARP, ICMPv6, HOPOPT…) carry 0/0 — they have no
  // transport service, so "Unknown service" would be misleading (QA audit).
  if (srcPort === 0 && dstPort === 0) return "N/A"
  const port = servicePortOf(Math.min(srcPort, dstPort), Math.max(srcPort, dstPort))
  if (port === undefined) return "Dynamic/Ephemeral"
  return portServiceName(port, protocol)
}

// Per-talker service sets for the Top Talkers cards. A conversation's service
// is canonical (known service port wins on either side — flowServiceName) and
// is the SAME service for both participants, on BOTH cards: the old rule only
// labeled the flow-row sides, so the STUN server 101.2.27.162:3478 →
// 192.168.1.20:65242 sat on the flow's source side and its destination card
// row read "Services —" next to 350 packets (QA: top-talkers services audit).
// "Unknown service"/"Dynamic/Ephemeral"/"N/A" are not real labels; empty is a
// phantom-HTTP gate result (port :80 but no HTTP decoded).
export function talkerServicesOf(
  flows: { srcIp: string; dstIp: string; srcPort: number; dstPort: number; protocol?: string }[],
  ownerOf: ReadonlyMap<string, string>,
  httpIps: ReadonlySet<string>,
): { src: Map<string, Set<string>>; dst: Map<string, Set<string>> } {
  const src = new Map<string, Set<string>>()
  const dst = new Map<string, Set<string>>()
  const named = (svc: string | undefined | null) => !!svc && svc !== "Unknown service" && svc !== "Dynamic/Ephemeral" && svc !== "N/A"
  for (const f of flows) {
    const sIp = ownerOf.get(f.srcIp) ?? f.srcIp
    const dIp = ownerOf.get(f.dstIp) ?? f.dstIp
    const svc = flowServiceName(f.srcPort, f.dstPort, f.protocol)
    // Port-derived "HTTP" is only a service if the decoder actually saw HTTP
    // on that endpoint — a 3-packet TCP flow to :80 is not HTTP traffic
    // (QA: talker showed "HTTP" while the report said 0 HTTP requests).
    const namedSvc = svc === "HTTP" && !(httpIps.has(sIp) || httpIps.has(dIp)) ? "" : svc
    if (named(namedSvc)) {
      for (const map of [src, dst]) {
        for (const ip of [sIp, dIp]) {
          const set = map.get(ip) ?? new Set<string>()
          set.add(namedSvc)
          map.set(ip, set)
        }
      }
    }
  }
  return { src, dst }
}

// Evidence for a flow's service label: "payload" when every packet of the
// conversation carried a payload-verified app layer matching the service,
// "mixed" when only some did (audit: 26 of 622 UDP/3478 packets were
// cookie-confirmed STUN), "port" when none did. Empty when no service label
// applies (port-less protocols, unknown direction).
function flowServiceEvidence(f: Flow, packets: { srcIp: string; dstIp: string; srcPort?: number; dstPort?: number; protocol: string; appProtocol?: string }[]): string {
  if (f.directionUnknown) return ""
  const service = flowServiceName(f.srcPort, f.dstPort, f.protocol)
  if (!service || service === "N/A") return ""
  const evidence = evidenceAppProtocols(service)
  if (!evidence) return "port"
  let confirmed = 0
  for (const p of packets) {
    if (p.protocol !== f.protocol) continue
    const same =
      (p.srcIp === f.srcIp && p.dstIp === f.dstIp && p.srcPort === f.srcPort && p.dstPort === f.dstPort) ||
      (p.srcIp === f.dstIp && p.dstIp === f.srcIp && p.srcPort === f.dstPort && p.dstPort === f.srcPort)
    if (!same) continue
    if (p.appProtocol && evidence.has(p.appProtocol)) confirmed += 1
  }
  if (confirmed === 0) return "port"
  return confirmed >= f.packets ? "payload" : "mixed"
}

// Flows CSV export — shared by the Report page download button and tests so
// the schema can't drift (QA: CSV schema + missing bytesTotal + tcp health).
// The file starts with a UTF-8 BOM so Excel/Sheets decode non-ASCII (vendor
// names, UA strings) correctly. IPs and ports are SEPARATE columns so IPv6
// rows parse in pandas/SIEMs — the old "ip:port" pair produced broken
// 9-group "addresses" like 2401:…:308f:61153 (QA).
// Null policy (documented): a cell is EMPTY when the value is not applicable
// (unknown direction → empty sent/recv, non-TCP or no observed handshake →
// empty rttMs, insufficient data → empty lossPct, no geo/ASN record → empty
// srcAsn/dstAsn). A real numeric 0 means the metric was computed as 0
// (e.g. lossPct=0 is a measured 0% loss, distinct from an empty cell).
// The "—" placeholder is never emitted — undecodable endpoints get an empty
// IP cell, never a range-dash that mojibakes in the spreadsheet.
// Pure CSV by design: NO comment/footer rows, so strict importers never see
// a non-schema record (audit: the trailing "# Note:" row broke parsers).
export function buildFlowsCsv(
  flows: Flow[],
  geo: Map<string, GeoLocation> = new Map(),
  packets: { srcIp: string; dstIp: string; srcPort?: number; dstPort?: number; protocol: string; appProtocol?: string }[] = [],
): string {
  const header = "srcIp,srcPort,dstIp,dstPort,protocol,packets,bytesSent,bytesRecv,bytesTotal,startTime,endTime,durationSec,srcCountry,dstCountry,srcAsn,dstAsn,service,serviceEvidence,rttMs,retrans,lossPct"
  // Undecodable endpoints (unsupported encapsulation) keep a visible label
  // instead of a silent blank — a blank IP looks like a data loss bug (QA).
  const ipCell = (ip: string) => (ip === "\u2014" ? "Undecoded/unknown endpoint" : ip)
  const cc = (ip: string) => {
    if (ip === "\u2014") return ""
    const g = geo.get(ip)
    return g && g.countryCode !== "??" && g.countryCode !== "LOC" ? g.countryCode : ""
  }
  const asn = (ip: string) => (ip === "\u2014" ? "" : geo.get(ip)?.asn ?? "")
  // Per-flow packet index (canonical endpoint order, so both directions hash
  // to the same bucket): turns the per-flow evidence scan from O(F×P) into
  // O(F+P). The old scan froze the tab on large exports (10k flows × 100k
  // packets ≈ 1e9 iterations) (QA).
  const flowKey = (x: { srcIp: string; dstIp: string; srcPort?: number; dstPort?: number; protocol: string }) => {
    const [a, b] = [x.srcIp, x.dstIp].sort()
    const pa = x.srcPort !== undefined && x.dstPort !== undefined ? Math.min(x.srcPort, x.dstPort) : undefined
    const pb = x.srcPort !== undefined && x.dstPort !== undefined ? Math.max(x.srcPort, x.dstPort) : undefined
    return `${x.protocol}|${a}|${b}|${pa ?? ""}|${pb ?? ""}`
  }
  const flowPackets = new Map<string, typeof packets>()
  for (const p of packets) {
    const k = flowKey(p)
    const arr = flowPackets.get(k)
    if (arr) arr.push(p)
    else flowPackets.set(k, [p])
  }
  const rows = flows.map((f) => [
    ipCell(f.srcIp), f.srcPort,
    ipCell(f.dstIp), f.dstPort,
    f.protocol,
    f.packets,
    f.directionUnknown ? "" : f.bytesSent,
    f.directionUnknown ? "" : f.bytesRecv,
    f.bytesTotal,
    f.startTime, f.endTime,
    f.duration,
    cc(f.srcIp), cc(f.dstIp),
    asn(f.srcIp), asn(f.dstIp),
    f.directionUnknown ? "" : flowServiceName(f.srcPort, f.dstPort, f.protocol),
    flowServiceEvidence(f, flowPackets.get(flowKey(f)) ?? []),
    f.rttMs ?? "",
    f.retrans ?? "",
    f.lossPct ?? "",
  ].map(csvCell).join(","))
  return "\uFEFF" + [header, ...rows].join("\n")
}

// Analyst Conclusion wording — the verdict must NEVER claim the capture is
// clean while confirmed findings exist (QA: never_end.pcapng reported 1 High
// alert + IOC yet concluded "No suspicious indicators were detected"), and a
// capture without a measurable time interval (single packet / zero duration)
// has NO rate or burst evidence — "insufficient evidence", not proof of
// safety (QA: 1-SYN capture concluded clean).
export function analystConclusion(opts: {
  undecodable: boolean
  decodeRatePct: number
  encapName: string
  alerts: { signature: string }[]
  score: number
  quality?: string
}): string {
  if (opts.undecodable) {
    return `Only ${opts.decodeRatePct}% of packets could be decoded — the capture uses unsupported encapsulation (${opts.encapName}), so lengths and timestamps parsed but no headers did. No verdict is possible on undecodable traffic; re-capture with Ethernet encapsulation (or an explicit DLT override) and re-analyze.`
  }
  if (opts.alerts.length > 0) {
    return `${opts.alerts.length} confirmed finding${opts.alerts.length === 1 ? "" : "s"} detected (${opts.alerts[0].signature}). The capture is NOT clean — review the alerts, IOCs, and MITRE mappings above and apply the recommended mitigations.`
  }
  // 0 alerts on a VALID capture: no configured rule triggered. This is not
  // "proven safe" — it is clean under the configured rules only.
  if (opts.quality && opts.quality !== "VALID") {
    return `No configured detection rules triggered, but the capture provides insufficient evidence (${opts.quality.toLowerCase().replace("_", " ")}): rate analysis, burst detection, and behavioral detection were not possible. This is NOT proof of safety — collect a longer capture and re-analyze.`
  }
  if (opts.score >= 70) {
    return "Significant malicious activity was detected. Prioritize immediate remediation and incident response."
  }
  if (opts.score >= 40) {
    return "Suspicious or anomalous behavior was detected. Review the findings above and apply the recommended mitigations."
  }
  return "No configured detection rules triggered on this capture; under those rules no findings were confirmed. Continue routine monitoring."
}

export function buildReportAnalysis(state: ReportState): ReportAnalysis {
  const { job, jobInfo, alerts, packets, flows, sessions, tls, http, timeline, bandwidth, advancedMetrics } = state
  // Duration from the CANONICAL metrics engine (real min/max packet span,
  // null when no time interval exists — single packet or identical
  // timestamps). Never fabricated with a 0.001 s / 1 s fallback denominator:
  // a one-packet capture has no rates, and the report must show N/A
  // (QA: 1-SYN capture showed 66 B/s average over a fake 1 s interval).
  // Fixtures built without the engine's rates field fall back to the real
  // packet span (never a rounded job summary).
  const durationSec = advancedMetrics?.rates?.durationSec ??
    (packets.length > 1 ? (() => { const [a, b] = packetSpanSec(packets); return b - a > 0 ? b - a : null })() : null)

  const risk = buildReportRisk(alerts, advancedMetrics)
  const groups = groupAlerts(alerts)

  // Groups carry the exact evidence/flows/sessions/packet span of the alert
  // series so the report can cite references instead of repeating rows.
  const enriched = groups.map((g) => {
    const refs = alertReferences(alerts.find((a) => a.id === g.alertIds[0]) ?? alerts[0], flows, sessions, packets)
    // A group is N alerts on the same tuple (SYN-FLOOD x3): summing the pair's
    // traffic per alert triples it. Sum once per unique (pair, ports) tuple.
    const uniq = new Map<string, AlertEntry>()
    for (const id of g.alertIds) {
      const a = alerts.find((x) => x.id === id)
      if (!a) continue
      const key = [a.srcIp, a.dstIp].sort().join("|") + "|" + [a.srcPort, a.dstPort].sort((x, y) => x - y).join("|")
      if (!uniq.has(key)) uniq.set(key, a)
    }
    const traffic = [...uniq.values()]
      .map((a) => alertTrafficFor(a, flows))
      .reduce((acc, t) => ({ packets: (acc.packets ?? 0) + (t.packets ?? 0), bytes: (acc.bytes ?? 0) + (t.bytes ?? 0) }), { packets: null, bytes: null })
    return { ...g, ...refs, packets: traffic.packets || null, bytes: traffic.bytes || null }
  })

  const iocs: IocFinding[] = (advancedMetrics?.iocs ?? []).map((i) => {
    const ruleId = IOC_TO_RULE[i.type]
    const group = ruleId ? enriched.find((g) => g.ruleId === ruleId) : undefined
    return {
      ...i,
      ruleId,
      confidence: group?.confidence,
      occurrences: group?.occurrences,
      firstSeen: group?.firstSeen,
      lastSeen: group?.lastSeen,
      severity: iocSeverity(i, alerts),
      source: iocSource(i.type, alerts),
    }
  })

  // Alert-only IOCs: rules that fired but have no pre-seeded metric IOC entry.
  for (const g of enriched) {
    const type = IOC_RULE_TYPE[g.ruleId]
    if (!type) continue
    if (iocs.some((i) => i.type === type)) continue
    iocs.push({
      type,
      value: shortAlertName(g.signature),
      description: g.evidence,
      severity: g.severity,
      source: "CONFIRMED_ALERT",
      ruleId: g.ruleId,
      confidence: g.confidence,
      occurrences: g.occurrences,
      firstSeen: g.firstSeen,
      lastSeen: g.lastSeen,
    })
  }

  const mitre: MitreFinding[] = (advancedMetrics?.mitreMappings ?? []).map((m) => ({
    ...m,
    severity: mitreSeverity(m, alerts),
    source: mitreSource(m, alerts),
  }))

  // Alert-derived MITRE mappings for every fired rule's technique.
  const mitreIds = new Set(mitre.map((m) => m.id))
  for (const g of enriched) {
    const id = TECHNIQUE_ID[g.ruleId]
    if (!id || mitreIds.has(id)) continue
    const names = TECHNIQUE_NAMES[id] ?? { name: g.signature, desc: g.evidence }
    mitre.push({
      technique: names.name,
      id,
      description: names.desc,
      severity: g.severity,
      source: "CONFIRMED_ALERT",
    })
    mitreIds.add(id)
  }

  const recommendations = buildRecommendations(advancedMetrics, mitre, alerts)

  const alertTraffic = new Map<string, { packets: number | null; bytes: number | null }>()
  for (const a of alerts) alertTraffic.set(a.id, alertTrafficFor(a, flows))

  const emptyReasons = {
    files: http.length === 0
      ? "No HTTP file transfers detected."
      : http.every((h) => h.status === 304)
        ? "HTTP traffic present, but every response was 304 Not Modified — file bodies were never transmitted, so nothing to extract."
        : http.every((h) => h.status === 206)
          ? "HTTP traffic present, but every response was a partial 206 range — no complete file body crossed the wire, so nothing to extract."
          : "HTTP traffic present, but no downloadable files were identified.",
    credentials: "No supported cleartext authentication observed.",
    certificates: tls.length === 0
      ? "No TLS handshake packets captured."
      : tls.some((r) => /1\.3/.test(r.version))
        ? "TLS handshakes present, but no certificates were extracted — TLS 1.3 encrypts server certificates after the handshake (RFC 8446), so they are only visible if the session is decrypted."
        : "TLS handshakes present, but no certificate messages were captured (the handshakes likely completed before the capture started, or the capture missed the server's flight).",
  }

  const mode = jobInfo.isDemo
    ? "Local — demo dataset (browser analysis)"
    : "Local — browser analysis"

  let analysisDurationSec: number | undefined
  if (job?.completedAt && job.createdAt) {
    const d = (new Date(job.completedAt).getTime() - new Date(job.createdAt).getTime()) / 1000
    if (Number.isFinite(d) && d >= 0) analysisDurationSec = d
  }

  return {
    risk,
    alerts,
    groups: enriched,
    iocs,
    mitre,
    recommendations,
    timeline: buildTimeline(packets, timeline, durationSec ?? 0),
    bandwidth: buildBandwidth(packets, bandwidth, durationSec),
    alertTraffic,
    emptyReasons,
    metadata: {
      mode,
      schemaVersion: REPORT_SCHEMA_VERSION,
      analyzerVersion: jobInfo.analyzerVersion,
      ruleVersion: jobInfo.ruleVersion,
      riskSpecVersion: jobInfo.riskSpecVersion || RISK_SPEC_VERSION,
      analysisDurationSec,
      // Capture quality + rate availability (canonical metrics engine):
      // SINGLE_PACKET / ZERO_DURATION captures have null rates and the report
      // must render N/A, never a fabricated number.
      captureQuality: advancedMetrics?.rates?.quality,
      ratesAvailable: durationSec !== null,
    },
  }
}
