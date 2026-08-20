"use client"

import { useMemo, useState } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn, formatTime } from "@/lib/utils"
import { isPrivateIP, formatBytes } from "@/lib/map-data"
import { vendorLabel, displayMac, isUnicastMac } from "@/lib/oui"
import { riskLevel, riskColorClass, verdictLevel, RISK_CURVE_K } from "@/lib/risk"
import { analysisProblems } from "@/lib/analysis"
import { buildReportAnalysis, analystConclusion, portServiceName, talkerServicesOf, bandwidthStats, iocTypeLabel, shortAlertName, RISK_SPEC_VERSION, dnsLookupCount, dnsUniqueDomains, dnsNameOf, servicePortCounts, serviceEvidenceLabel, flowServiceEvidence, flowServiceName, osFromUserAgent, dltName, buildFlowsCsv, verdictLine, ownerOfDevices, localOwnedAddresses, endpointRowsOf, tcpHealthRttCaption, duplicateFrameCountOf, countryCountsByDst, sharePctLabel, escHtml as esc, mdInline as inline, binWidthSec, decodeRateOf, markdownToHtml, plural, flowTableRows, sessionTableRows, statusLabel, effectiveStatus, findingSourceLabel, summarizeStatuses, statusCountsLabel, reportDurationSec, flowInitiatorFlip, rstAttribution, credentialEventCount, type DetectionStatus } from "@/lib/report"
import { ANALYZER_VERSION, isNonUnicast, estimatedTcpLoss } from "@/lib/analysis"
import { formatDuration } from "@/lib/stats"
import { BUILD_INFO, BUILD_STAMP } from "@/lib/build-stamp"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Download, FileText, AlertTriangle, Globe, Shield, ShieldAlert, Monitor,
  Package, GitFork, MessagesSquare, FolderOpen, Key, Verified, BarChart3, History, Zap,
  Phone, Compass
} from "lucide-react"
import type { LucideIcon } from "lucide-react"
import type { AlertEntry } from "@/stores/analysis"


// Summary stat boxes rendered as a one-row table. Flex-wrapped divs print
// label and value as separate positioned glyph blocks that PDF extractors can
// interleave mid-word ("TLS0v1.3"); table cells extract as clean columns.
// print:inline merges each cell's stacked label/value divs into a single
// "label value" text run, so the extractor reads one contiguous line per cell
// even when the grid squeezes the table at print width (R2).
function StatGrid({ items, className, tint }: { items: { label: string; value: string; accent?: string; sub?: string }[]; className?: string; tint?: boolean }) {
  return (
    <table className={cn("w-full border-collapse text-xs break-inside-avoid", className)}>
      <tbody>
        <tr>
          {items.map((it) => (
            <td key={it.label} className={cn("border rounded p-3 text-center align-top", tint && "bg-muted/20")} title={it.sub || undefined}>
              <div className="text-muted-foreground whitespace-nowrap print:inline">{it.label}</div>
              <div className={cn("text-xl font-bold whitespace-nowrap print:inline", it.accent)}>{it.value}</div>
              {it.sub && <div className="text-[10px] text-muted-foreground mt-0.5 print:hidden">{it.sub}</div>}
            </td>
          ))}
        </tr>
      </tbody>
    </table>
  )
}

export function fmtClock(sec: number): string {
  // Round the TOTAL, not sec % 60 — rounding a component alone can emit the
  // impossible ":60" (59.7s rendered 00:00:60). Rounding first carries into
  // minutes/seconds correctly.
  const t = Math.max(0, Math.round(sec))
  const h = Math.floor(t / 3600)
  const m = Math.floor((t % 3600) / 60)
  const s = t % 60
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`
}

// Packet timestamps arrive as ISO strings or epoch seconds; normalize both
// and tolerate invalid values.
function packetDate(p: { timestamp: string | number }): Date | null {
  const t = typeof p.timestamp === "number" ? p.timestamp : Number(p.timestamp)
  const ms = Number.isFinite(t) ? (t > 1e12 ? t : t * 1000) : Date.parse(String(p.timestamp))
  return Number.isFinite(ms) ? new Date(ms) : null
}

function fmtDateTime(d: Date | null): string {
  if (!d) return "—"
  // The CSV exports UTC ISO-8601 while charts render local wall-clock time;
  // every display stamps its offset so the two can never be conflated (QA:
  // report showed 20:36:56 local vs 15:06:56Z in the CSV, unlabeled).
  const off = -d.getTimezoneOffset()
  const sign = off >= 0 ? "+" : "-"
  const abs = Math.abs(off)
  const tz = `UTC${sign}${Math.floor(abs / 60)}${abs % 60 ? ":" + String(abs % 60).padStart(2, "0") : ""}`
  return `${d.toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })} (${tz})`
}

// GeoIP breakdown messaging: a bare "Countries: 0" is misleading. Distinguish
// "no public IPs to geolocate" from "geolocation itself is unavailable".
function countriesLabel(countries: number, externalIps: number): string {
  if (countries > 0) return countries.toLocaleString()
  if (externalIps === 0) return "0 (no public IPs)"
  return "0 (no GeoIP DB)"
}

// Long IPv6 addresses compress to "2401:4900:…:308f" for the table; the full
// address stays available in the cell tooltip. IPv4 passes through untouched.
// Compressed (::) addresses are already short and MUST stay whole — truncating
// them collapses distinct hosts like 2606:50c0:8000::153 vs 2606:50c0:8002::153
// into the same "2606:50c0:…:153".
function shortIp(ip: string): string {
  if (!ip.includes(":")) return ip
  if (ip.includes("::")) return ip
  const g = ip.split(":")
  if (g.length <= 6) return ip
  return `${g.slice(0, 3).join(":")}:…:${g.slice(-3).join(":")}`
}

const PROTO_COLORS: Record<string, string> = { TCP: "bg-info", UDP: "bg-success", DNS: "bg-warning", TLS: "bg-chart-3" }

const sevLabel = (s: number) => s >= 5 ? "Critical" : s >= 4 ? "High" : s >= 3 ? "Medium" : "Low"

// "2 critical, 1 high" style breakdown for alert counts (severity 5 is
// Critical — previously lumped into "high").
const severityCounts = (alerts: { severity: number }[]) => {
  const c = alerts.filter((t) => t.severity >= 5).length
  const h = alerts.filter((t) => t.severity === 4).length
  const m = alerts.filter((t) => t.severity === 3).length
  const l = alerts.filter((t) => t.severity <= 2).length
  const parts: string[] = []
  if (c) parts.push(`${c} critical`)
  if (h) parts.push(`${h} high`)
  if (m) parts.push(`${m} medium`)
  if (l) parts.push(`${l} low`)
  return parts.length ? parts.join(", ") : "0 high"
}

const sourceBadge = (source: "CONFIRMED_ALERT" | "BEHAVIORAL_METRIC", status?: DetectionStatus) => (
  // The badge shows the DETECTION'S OWN status (legacy alerts count as
  // confirmed) — the IOC/MITRE layer never re-derives it from severity or
  // the existence of the finding (QA: SUSPECTED exfil read "Confirmed").
  <Badge variant={effectiveStatus({ status }) === "CONFIRMED" ? "default" : "outline"} className="text-[10px] whitespace-nowrap" title={status ? `Detection status: ${status}` : (source === "CONFIRMED_ALERT" ? "Derived from a confirmed signature alert" : "Derived from behavioral analysis of advanced metrics, not a signature alert")}>
    {findingSourceLabel(source, status)}
  </Badge>
)

function SectionTitle({ icon: Icon, title, sub }: { icon: LucideIcon; title: string; sub?: string }) {
  return (
    <div className="border-b pb-2 mb-4">
      <div className="flex items-center gap-2 text-xl font-bold">
        <Icon className="h-6 w-6 text-primary" />
        {title}
      </div>
      {sub && <div className="text-xs text-muted-foreground mt-1">{sub}</div>}
    </div>
  )
}

export default function ReportsPage() {
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const packets = useAnalysisStore((s) => s.packets)
  const flows = useAnalysisStore((s) => s.flows)
  const sessions = useAnalysisStore((s) => s.sessions)
  const dns = useAnalysisStore((s) => s.dns)
  const http = useAnalysisStore((s) => s.http)
  const tls = useAnalysisStore((s) => s.tls)
  const files = useAnalysisStore((s) => s.files)
  const calls = useAnalysisStore((s) => s.calls)
  const credentials = useAnalysisStore((s) => s.credentials)
  const certificates = useAnalysisStore((s) => s.certificates)
  const devices = useAnalysisStore((s) => s.devices)
  const alerts = useAnalysisStore((s) => s.alerts)
  const timeline = useAnalysisStore((s) => s.timeline)
  const bandwidth = useAnalysisStore((s) => s.bandwidth)
  const advancedMetrics = useAnalysisStore((s) => s.advancedMetrics)
  const burst = useAnalysisStore((s) => s.burst)
  const job = useAnalysisStore((s) => s.currentJob)
  const jobInfo = useAnalysisStore((s) => s.jobInfo)
  const stats = useAnalysisStore((s) => s.stats)
  const geoMap = useAnalysisStore((s) => s.geoMap)
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const decode = useAnalysisStore((s) => s.decode)
  const schemaVersion = useAnalysisStore((s) => s.schemaVersion)
  const validator = useAnalysisStore((s) => s.validator)
  const fileInfo = useAnalysisStore((s) => s.fileInfo)

  // Report credentials are masked by default, same as the Credentials page
  // (privacy); the section header carries the Show/Hide toggle.
  const [showPasswords, setShowPasswords] = useState(false)

  // Decode rate: how many packets actually yielded headers. Unsupported link
  // types (non-Ethernet encapsulation) parse lengths + timestamps only, so
  // the report must NOT issue a SAFE verdict on invisible traffic.
  const decodeRate = useMemo(() => decodeRateOf(decode, packets), [decode, packets])
  const undecodable = decodeRate < 0.05
  const linkTypes = useMemo(() => decode?.linkTypes || [], [decode])

  const ownerOf = useMemo(() => ownerOfDevices(devices), [devices])

  // Merged device identity (same rule as stats.ts): every address of a device
  // whose primary IP is private is INTERNAL, even when the address itself is a
  // Full local-ownership closure (B-72) — the same set the map uses. The old
  // rule-1-only set missed the router's public global 2401:…::1 (MAC-merged
  // with its private fe80::1), so its 9 ICMPv6 packets to the host's alias
  // were credited to "IN" India in Top Countries — pure LAN chatter, never
  // external traffic (QA: country attribution audit).
  const localOwned = useMemo(() => localOwnedAddresses(devices), [devices])

  const { totalBytes, avgPacketBytes, topProto, uniqueSrcIps, uniqueDstIps, topSrcIps, topDstIps, srcConns, dstConns, srcProtos, dstProtos, noSrcAddrCount, noDstAddrCount } = useMemo(() => {
    const totalBytes = packets.reduce((s, p) => s + p.length, 0)
    // Wire-size average: origLength is the on-wire size when the capture
    // truncated frames (snaplen), so the raw length would understate real
    // traffic (QA: avg packet size 465 B vs 485 B wire average).
    const avgPacketBytes = packets.length > 0 ? Math.round(packets.reduce((s, p) => s + (p.origLength ?? p.length), 0) / packets.length) : 0
    const protoCount: Record<string, number> = {}
    const srcIps = new Set<string>()
    const dstIps = new Set<string>()
    const srcCount: Record<string, { count: number; bytes: number }> = {}
    const dstCount: Record<string, { count: number; bytes: number }> = {}
    // Connection/protocol details are PACKET-direction counts (same pass as
    // the row's packet totals), not flow-level ones: the old flow key read
    // the local side as dst only for DNS flows, so the internal host showed
    // "1 conns · DNS" next to 13,865 destination packets (QA: top talkers).
    // A conversation is the 4-tuple (srcIp:srcPort ↔ dstIp:dstPort), the SAME
    // key on both sides: the source and destination views of the same
    // conversations must never disagree (QA: mamaji.pcapng — 8 Samsung
    // discovery conversations with different source ports showed "1 conns" on
    // the source side and "8 conns" on the destination side).
    const srcConns: Record<string, Set<string>> = {}
    const dstConns: Record<string, Set<string>> = {}
    const srcProtos: Record<string, Set<string>> = {}
    const dstProtos: Record<string, Set<string>> = {}
    let noSrcAddrCount = 0
    let noDstAddrCount = 0
    for (const p of packets) {
      protoCount[p.protocol] = (protoCount[p.protocol] || 0) + 1
      const hasSrc = !!p.srcIp && p.srcIp !== "\u2014"
      const hasDst = !!p.dstIp && p.dstIp !== "\u2014"
      if (!hasSrc) noSrcAddrCount += 1
      if (!hasDst) noDstAddrCount += 1
      const conv = hasSrc && hasDst && p.srcPort !== undefined && p.dstPort !== undefined ? `${p.srcIp}:${p.srcPort}↔${p.dstIp}:${p.dstPort}` : null
      // Undecodable packets carry the "—" placeholder, never a real address;
      // counting them would fabricate a phantom endpoint with every packet.
      if (hasSrc) {
        const src = ownerOf.get(p.srcIp!) ?? p.srcIp
        srcIps.add(src)
        const s = (srcCount[src] ||= { count: 0, bytes: 0 })
        s.count += 1
        s.bytes += p.length
        if (hasDst) (srcConns[src] ??= new Set()).add(conv ?? p.dstIp)
        if (p.protocol) (srcProtos[src] ??= new Set()).add(p.protocol)
      }
      if (hasDst) {
        const dst = ownerOf.get(p.dstIp!) ?? p.dstIp
        dstIps.add(dst)
        const d = (dstCount[dst] ||= { count: 0, bytes: 0 })
        d.count += 1
        d.bytes += p.length
        if (hasSrc) (dstConns[dst] ??= new Set()).add(conv ?? p.srcIp)
        if (p.protocol) (dstProtos[dst] ??= new Set()).add(p.protocol)
      }
    }
    return {
      totalBytes,
      avgPacketBytes,
      topProto: Object.entries(protoCount).sort((a, b) => b[1] - a[1]),
      uniqueSrcIps: srcIps.size,
      uniqueDstIps: dstIps.size,
      topSrcIps: Object.entries(srcCount).map(([ip, v]) => ({ ip, ...v })).sort((a, b) => b.count - a.count),
      topDstIps: Object.entries(dstCount).map(([ip, v]) => ({ ip, ...v })).sort((a, b) => b.count - a.count),
      srcConns, dstConns, srcProtos, dstProtos, noSrcAddrCount, noDstAddrCount,
    }
  }, [packets, ownerOf])

  // Rank ports by their SERVICE side — per-conversation, decided by PORT
  // (well-known/known service wins, else lower, P2P both-dynamic skipped),
  // never by packet direction: mid-session captures start on a server reply
  // and would otherwise dump whole flows onto the client's port (QA #2:
  // test.pcapng TCP/42224 295 + TCP/443 880 = 1,175).
  const allPorts = useMemo(() => servicePortCounts(packets), [packets])
  const topPorts = allPorts.slice(0, 8)
  const portTotal = allPorts.reduce((s, e) => s + e.count, 0)
  const displayedPortTotal = topPorts.reduce((s, e) => s + e.count, 0)
  // Packet attribution is exhaustive: every packet is either ports-attributed,
  // P2P dynamic-range (excluded from port attribution), or port-less
  // (ARP/ICMP/ICMPv6/IGMP/GRE/… — covered by Top Protocols). The coverage is
  // stated in the card note so the displayed rows can never be mistaken for
  // all analyzed packets (QA: my.pcapng 8,036 of 8,068 packets displayed).
  const otherPortTotal = portTotal - displayedPortTotal
  const p2pExcluded = useMemo(() => packets.reduce((s, p) => s + ((p.srcPort && p.dstPort) ? 1 : 0), 0) - portTotal, [packets, portTotal])
  const portlessPkts = packets.length - portTotal - p2pExcluded
  // Legacy jobs stored raw frames (dedupe absent): count on the stored set.
  // Fresh jobs record the removal in job.duplicateFrameCount and store the
  // ANALYZED set — the count then comes from the job, not a re-count. A fresh
  // job that removed NOTHING has rawPacketCount set but duplicateFrameCount
  // undefined — recounting the analyzed set would re-derive phantom "removed"
  // frames (QA: report said "2 consecutive duplicate frames removed" on a
  // capture that removed none — the recount matched byte-identical replies).
  const duplicateFrames = useMemo(() => duplicateFrameCountOf(job, packets), [job, packets])
  // Capture-quality grade from the duplicate ratio (double-capture artifact):
  // >=25% Poor, >=5% Degraded, else Good. Only when dedupe accounting exists.
  const dedupeGrade = useMemo(() => {
    const raw = job?.rawPacketCount
    if (typeof raw !== "number" || typeof job?.duplicateFrameCount !== "number" || raw === 0) return null
    const ratio = job.duplicateFrameCount / raw
    if (ratio >= 0.25) return { label: "POOR" as const, color: "text-danger" }
    if (ratio >= 0.05) return { label: "DEGRADED" as const, color: "text-warning" }
    return { label: "GOOD" as const, color: "text-success" }
  }, [job])

  const allCountries = useMemo(() =>
    [...countryCountsByDst(packets, geoMap, localOwned).entries()].sort((a, b) => b[1] - a[1]),
  [packets, geoMap, localOwned])
  const topCountries = allCountries.slice(0, 8)
  const countryTotal = allCountries.reduce((s, [, c]) => s + c, 0)

  const report = useMemo(() => buildReportAnalysis({
    job,
    jobInfo,
    alerts,
    packets,
    flows,
    sessions,
    tls,
    http,
    timeline,
    bandwidth,
    advancedMetrics,
  }), [job, jobInfo, alerts, packets, flows, sessions, tls, http, timeline, bandwidth, advancedMetrics])

  // The canonical AnalysisResult, rebuilt from the served slices + the
  // contract fields (schemaVersion/validator/fileInfo) the data API now
  // returns. Exports re-validate THIS object before producing anything —
  // an invalid result is not renderable/exportable (pipeline: engine →
  // full validation → only then → UI/HTML/PDF/JSON/API).
  const canonicalResult = useMemo(() => {
    if (!job || !validator) return null
    return {
      schemaVersion: schemaVersion ?? "",
      job: { ...job, status: "done" as const, progress: 100, stage: "complete" },
      packets,
      flows,
      sessions,
      dns,
      http,
      tls,
      files,
      calls,
      credentials,
      certificates,
      devices,
      threats: alerts,
      timeline,
      bandwidth,
      advancedMetrics: advancedMetrics ?? { rates: { quality: "EMPTY", durationSec: null, avgPacketsSec: null, avgBps: null, peakBps: null, peakBps100ms: null, bucketCount: 0, avgExceedsPeak: false } },
      fileInfo: fileInfo ?? { sha256: "", sha1: "", md5: "" },
      validator,
      decode: decode ?? { decoded: 0, total: 0, linkTypes: [] },
    } as unknown as import("@/lib/analysis").AnalysisResult
  }, [job, schemaVersion, validator, fileInfo, packets, flows, sessions, dns, http, tls, files, calls, credentials, certificates, alerts, timeline, bandwidth, advancedMetrics, decode])

  // Export guard: refuse to emit any report artifact from an invalid result.
  const requireValid = (): boolean => {
    if (!canonicalResult) return false
    const problems = analysisProblems(canonicalResult)
    if (problems.length > 0) {
      alert(`Export blocked: AnalysisResult failed validation (${problems.length} problems) — this is a pipeline bug, not a capture issue.`)
      console.error("Export blocked by validation:", problems)
      return false
    }
    return true
  }

  const risk = report.risk
  const mitre = report.mitre
  // The curve evaluated at the ACTUAL raw score, so the breakdown shows the
  // raw → normalized jump with the real numbers (raw 40 → 39.3 → 39/100),
  // instead of a template that hides the rounding.
  const riskCurve = risk ? 100 * (1 - Math.exp(-risk.rawScore / RISK_CURVE_K)) : null

  // The strongest finding's DETECTION status: a CRITICAL/HIGH verdict floored
  // by an unconfirmed (SUSPECTED/LIKELY) finding must never read as a
  // confirmed incident — the verdict header and risk card state the status
  // explicitly (QA: open.pcapng "53/100 CRITICAL" with "No findings were
  // confirmed" read as a confirmed critical incident).
  const highestSev = risk?.highestSeverity ?? job?.highestSeverity ?? 0
  const topUnconfirmedAlert = highestSev > 0
    ? alerts.find((a) => a.severity === highestSev && effectiveStatus(a) !== "CONFIRMED")
    : undefined
  const verdictStatusHint = topUnconfirmedAlert
    ? ` — unconfirmed (strongest finding: ${statusLabel(topUnconfirmedAlert.status ?? "SUSPECTED")})`
    : ""

  // Capture window from the actual packet timestamps (min/max — pcap files can
  // hold out-of-order packets), normalized from ISO or epoch-second shapes.
  const captureClock = useMemo(() => {
    let start: Date | null = null
    let end: Date | null = null
    for (const p of packets) {
      const t = packetDate(p)
      if (!t) continue
      if (!start || t < start) start = t
      if (!end || t > end) end = t
    }
    return { start, end }
  }, [packets])

  // Certificates are judged at capture end, not analysis time: job.createdAt
  // is the UPLOAD moment on real jobs (always after the capture), so a cert
  // valid during the capture would read "Expired" (QA: cert refTime drifted).
  const certRef = (captureClock.end ?? (job ? new Date(job.createdAt) : new Date())).getTime()

  // Map each alert to its timeline bin (capture start + bin index) so the
  // packet-activity table can flag intervals with detections. Bin edges
  // approximate the rebinner's bins; placement is best-effort.
  const { alertsByBin, alertDots } = useMemo(() => {
    const byBin = new Map<number, AlertEntry[]>()
    if (!job || report.timeline.length === 0) return { alertsByBin: byBin, alertDots: [] as { time: string; signature: string; name: string }[] }
    // Bin the alerts against the CAPTURE start. job.createdAt is the upload
    // time on real jobs, which is after the capture — every alert would land
    // at a negative offset and the dots never rendered (QA).
    const start = (captureClock.start?.getTime() ?? Date.parse(job.createdAt)) / 1000
    const binSec = Math.max(job.captureDuration / report.timeline.length, 0.001)
    for (const a of alerts) {
      const rel = new Date(a.timestamp).getTime() / 1000 - start
      const idx = Math.floor(rel / binSec)
      if (rel >= 0 && idx >= 0 && idx < report.timeline.length) {
        const arr = byBin.get(idx) || []
        arr.push(a)
        byBin.set(idx, arr)
      }
    }
    const dots = [...byBin.entries()]
      .sort((a, b) => a[0] - b[0])
      .flatMap(([idx, list]) => list.map((a) => ({ time: report.timeline[idx].time, signature: a.signature, name: shortAlertName(a.signature) })))
    return { alertsByBin: byBin, alertDots: dots }
  }, [job, alerts, report.timeline, captureClock])

  const bwStats = bandwidthStats(report.bandwidth)
  // Peak of per-second bandwidth (report.bandwidth is already in /s units);
  // advancedMetrics carries the same peak when present. A capture without a
  // time interval (single packet / zero duration) has NO rates — null, not 0.
  const peakBandwidth = report.bandwidth.length ? Math.max(...report.bandwidth.map((b) => b.in + b.out)) : (advancedMetrics?.throughputPeak ?? null)

  // Duration from the CANONICAL metrics engine (real min/max packet span);
  // null = no time interval (single packet / zero duration) — rates are N/A,
  // never a fabricated 0.001 s / 1 s denominator (QA: 1-SYN capture showed
  // 66 B/s average over a fake 1 s interval), and never a 0 divisor (legacy
  // jobs write captureDuration 0 → "Infinity B/s" would render).
  // Legacy jobs (pre-metrics) have no advancedMetrics: fall back to the job's
  // capture duration exactly like the report builder does, so the page and
  // the report never disagree on the window.
  const durationSec = reportDurationSec(advancedMetrics, job)
  const ratesAvailable = durationSec !== null

  // The label must describe the divisor the data was actually divided by:
  // clock-aligned 5-min buckets on long captures, binWidthSec rebins on
  // short ones (QA: a mid-5-min capture read "288-second" while values were
  // divided by 300).
  const bwInterval = job && report.bandwidth.length >= 2 && durationSec !== null
    ? (durationSec > 600 ? 300 : binWidthSec(durationSec))
    : null
  const bwIntervalLabel = bwInterval ? (Number.isInteger(bwInterval) ? `${bwInterval}-second` : `${bwInterval.toFixed(1)}-second`) : "capture"

  // Rate formatting: no time interval -> N/A, never a fabricated number.
  const rateLabel = (bps: number | null) => (bps === null ? "N/A" : formatBytes(bps) + "/s")
  const durLabel = (sec: number | null) => (sec === null ? "—" : formatDuration(sec))
  // ONE immutable export timestamp per page session: the printed PDF and the
  // HTML/markdown export stamped the same analysis with two independent
  // `new Date()` calls, so the artifacts of one export session disagreed
  // (QA: big.pcapng PDF 03:23:24 vs HTML 03:23:35 UTC).
  const exportTs = useMemo(() => new Date().toISOString().slice(0, 19).replace("T", " "), [])
  // Duration at the precision rates are computed from: formatDuration rounds
  // to whole seconds, so "Duration 48 s" next to "Avg Packets/s 584.0" (from
  // 48.17 s) would read as internally inconsistent (QA: mamaji.pcapng). Sub-
  // minute captures show the exact value; ≥ 1 min keeps the m/s format.
  const durPrecise = (sec: number | null) => (sec === null ? "—" : sec < 60 ? `${sec.toFixed(2).replace(/\.?0+$/, "")} s` : formatDuration(sec))

  // Query packets only (QR=0). Responses echo the question name in the header
  // and come back from the resolver, so they are packets, not queries.
  const dnsQueries = dns.filter((d) => !d.isResponse).length

  // QUIC/encryption visibility: QUIC Initial packets are the only decryptable
  // handshake window (they carry the ClientHello in a CRYPTO frame) — a
  // mid-session capture can hold 56k QUIC packets with ZERO Initials, which
  // must read as "encryption inferred, not decoded", never as payload
  // evidence (QA: big.pcapng — CSV said "payload" next to 0 handshakes).
  const { quicFlowCount, quicHandshakePkts, httpsPortPkts, encSharePct } = useMemo(() => {
    let quicFlows = 0
    for (const f of flows) if (f.appProtocol === "QUIC") quicFlows += 1
    let handshake = 0
    let enc = 0
    let https = 0
    for (const p of packets) {
      if (p.appProtocol === "QUIC") {
        if (p.appPayloadConfirmed) handshake += 1
        enc += 1
      } else if (p.appProtocol === "TLS" || p.appProtocol === "HTTPS") {
        https += 1
        enc += 1
      }
    }
    return { quicFlowCount: quicFlows, quicHandshakePkts: handshake, httpsPortPkts: https, encSharePct: packets.length > 0 ? (enc / packets.length) * 100 : 0 }
  }, [flows, packets])
  // Application-layer visibility is a SEPARATE dimension from capture quality
  // (frame completeness): a GOOD dedupe rate says nothing about whether
  // packet CONTENT could be inspected (QA: big.pcapng "Capture quality: GOOD"
  // next to 97.7% encrypted, zero decodable application payloads).
  const appVisibilityLabel = useMemo(() => {
    if (packets.length === 0) return "N/A — no packets"
    const pct = encSharePct.toFixed(0)
    if (encSharePct >= 50) return `LIMITED — ${pct}% of packets are associated with TCP/443 or UDP/443, treated as encrypted HTTPS/QUIC traffic (TCP/443 payload-verified only where a TLS handshake was captured; UDP/443 port-inferred where payload verification was unavailable); content-level inspection was not possible`
    if (encSharePct >= 25) return `PARTIAL — ${pct}% of packets are associated with TCP/443 or UDP/443, treated as encrypted HTTPS/QUIC traffic (UDP/443 port-inferred where payload verification was unavailable); content inspection applies to the decodable remainder`
    return `HIGH — only ${pct}% of packets are associated with TCP/443 or UDP/443 (treated as encrypted HTTPS/QUIC, port-inferred where payload verification was unavailable); most traffic carried decodable application content`
  }, [packets.length, encSharePct])

  // Per-talker remote services derive from flows, which carry both directions
  // per conversation. Aliases fold into their owner so the detail line lines
  // up with the folded Top Talkers row. (Connection counts and protocol mixes
  // come from the packet-direction pass in the top-talkers memo above.)
  const talkerFlows = useMemo(() => {
    // Port-derived "HTTP" is only a service if the decoder actually saw HTTP
    // on that endpoint (talkerServicesOf applies the same gate).
    const httpIps = new Set<string>()
    for (const h of http) { if (h.srcIp) httpIps.add(h.srcIp); if (h.dstIp) httpIps.add(h.dstIp) }
    return talkerServicesOf(flows, ownerOf, httpIps)
  }, [flows, ownerOf, http])

  // Talker service list for the report row: truncated at 4 WITH an overflow
  // count — a silent slice read as "these are all the services" (QA: local
  // host's XMPP vanished behind the cut).
  // Services are port-inferred (marked *) when no packet of the talker's
  // conversations was payload-verified for that service (QA: another.pcapng
  // listed "XMPP" next to payload-verified HTTPS/QUIC without distinction).
  const portInferredSvc = useMemo(() => {
    const map = new Map<string, Set<string>>()
    const confirmed = new Map<string, Set<string>>()
    for (const f of flows) {
      const ev = flowServiceEvidence(f, packets)
      const svc = flowServiceName(f.srcPort, f.dstPort, f.protocol)
      if (!svc || svc === "N/A" || svc === "Unknown service" || svc === "Dynamic/Ephemeral") continue
      const sIp = ownerOf.get(f.srcIp) ?? f.srcIp
      const dIp = ownerOf.get(f.dstIp) ?? f.dstIp
      for (const ip of [sIp, dIp]) {
        const target = ev === "payload" || ev === "mixed" ? confirmed : map
        const set = target.get(ip) ?? new Set<string>()
        set.add(svc)
        target.set(ip, set)
      }
    }
    for (const [ip, set] of confirmed) {
      const remove = map.get(ip)
      if (remove) for (const svc of set) remove.delete(svc)
    }
    return map
  }, [flows, packets, ownerOf])
  const svcList = (svcs?: Set<string>, ip?: string): { text: string; portInferred: boolean } => {
    if (!svcs || svcs.size === 0) return { text: "—", portInferred: false }
    const inferred = new Set(ip ? portInferredSvc.get(ip) ?? [] : [])
    const mark = (svc: string) => (inferred.has(svc) ? `${svc}*` : svc)
    const all = [...svcs].sort()
    return {
      text: all.length <= 4 ? all.map(mark).join(", ") : `${all.slice(0, 4).map(mark).join(", ")} +${all.length - 4} more`,
      portInferred: all.some((svc) => inferred.has(svc)),
    }
  }
  const talkersShowPortInferred = useMemo(() => [...topSrcIps.slice(0, 5), ...topDstIps.slice(0, 5)].some(({ ip }) => (portInferredSvc.get(ip)?.size ?? 0) > 0), [topSrcIps, topDstIps, portInferredSvc])

  const hostLabel = (ip: string) => {
    // 224.0.0.0/4, ff00::/8 etc. are multicast, not private LAN hosts —
    // labeling them "Internal Host" misattributes protocol chatter (QA).
    if (isNonUnicast(ip)) return "Multicast"
    if (isPrivateIP(ip) || localOwned.has(ip)) return "Internal Host"
    const cc = geoMap.get(ip)?.countryCode
    return cc && cc !== "??" && cc !== "LOC" ? `External · ${cc}` : "External (Country Unknown)"
  }

  // OUI lookup status must agree with the evidence: when any device actually
  // resolved a vendor, the appendix cannot claim "Vendor Lookup Unavailable".
  // Devices on raw-IP captures get a placeholder mac ("—"), which is not a
  // MAC: it must not flip the status to "no vendor match" (QA).
  const ouiStatus = jobInfo?.ouiVersion || (
    devices.some((d) => d.vendor)
      ? "Vendor Lookup Active (embedded OUI database)"
      : devices.some((d) => isUnicastMac(d.mac))
        ? "Vendor Lookup Active — no vendor match for captured MACs"
        : "embedded OUI database active — no MAC addresses present in this capture"
  )

  // §13 Endpoint table: drop unspecified/multicast placeholders (QA).
  const endpointRows = useMemo(() => endpointRowsOf(devices), [devices])
  const remoteEndpointCount = endpointRows.filter((d) => !isPrivateIP(d.ip)).length

  // Normal-activity observations, shown when there is nothing alarming to say
  // (a clean capture should still communicate what WAS seen).
  const observations = useMemo(() => {
    const obs: string[] = []
    // "HTTPS" is port-inferred (TCP/443) unless a ClientHello/ServerHello was
    // decoded — never imply verified TLS encryption when no handshake was
    // captured (QA: 0 handshakes but "TLS/HTTPS encrypted traffic").
    if (tls.length > 0) obs.push("TLS/HTTPS encrypted traffic")
    else if (packets.some((p) => p.appProtocol === "TLS" || p.appProtocol === "HTTPS")) obs.push("TCP/443 HTTPS traffic inferred from port — no TLS handshake captured")
    // STUN is the ICE handshake for real-time media; on its own it is NAT
    // traversal signaling, not a WebRTC session — wording must stay at
    // "consistent with", never "is" (§10, audit: WebRTC over-attribution).
    // The gate is STUN ONLY: QUIC shares UDP/443's neighborhood but is a
    // completely different protocol, and an appProtocol of QUIC must never
    // fabricate a STUN observation (QA: mamaji.pcapng reported "STUN traffic
    // detected" with zero STUN flows — the OR clause was the bug).
    if (packets.some((p) => p.appProtocol === "STUN")) obs.push("STUN traffic detected, consistent with NAT traversal/ICE activity — no WebRTC session was confirmed")
    else if (packets.some((p) => p.appProtocol === "QUIC")) obs.push(quicHandshakePkts > 0
      ? `QUIC traffic observed on UDP/443 (${plural(quicHandshakePkts, "payload-verified Initial handshake packet")}) — no STUN or WebRTC activity present; QUIC's TLS sessions remain encrypted`
      : "QUIC traffic observed on UDP/443 (port-inferred — no QUIC Initial handshake packets captured; QUIC carries TLS inside its CRYPTO frames, so session content was not decoded) — no STUN or WebRTC activity present")
    // Attribution honesty: a dominant external endpoint with no identity
    // evidence must be called an attribution gap, never silently folded into
    // a clean verdict (QA: big.pcapng — 185.165.242.20 carried 99.5% of
    // external packets yet nothing in the capture names it).
    const extByIp = new Map<string, number>()
    for (const p of packets) {
      const seen = new Set<string>()
      for (const ip of [p.srcIp, p.dstIp]) {
        if (!ip || ip === "\u2014" || seen.has(ip)) continue
        seen.add(ip)
        if (!isNonUnicast(ip) && !isPrivateIP(ip) && !localOwned.has(ip)) extByIp.set(ip, (extByIp.get(ip) ?? 0) + 1)
      }
    }
    const extTotal = [...extByIp.values()].reduce((a, b) => a + b, 0)
    const extTop = [...extByIp.entries()].sort((a, b) => b[1] - a[1])[0]
    if (extTop && extTotal > 0 && extTop[1] >= 1000 && (extTop[1] / extTotal) * 100 >= 70) {
      const identified = new Set<string>()
      for (const d of dns) if (d.answer && d.answer !== "\u2014") identified.add(d.answer)
      for (const t of tls) if (t.dstIp) identified.add(t.dstIp)
      for (const c of certificates) for (const san of c.san) if (!isNonUnicast(san) && !isPrivateIP(san)) identified.add(san)
      if (!identified.has(extTop[0])) {
        const cc = geoMap.get(extTop[0])?.countryCode
        obs.push(`External endpoint ${extTop[0]}${cc && cc !== "??" && cc !== "LOC" ? ` (${cc})` : ""} carries ${((extTop[1] / extTotal) * 100).toFixed(1)}% of external traffic (${extTop[1].toLocaleString()} packets) with no identity evidence — no DNS answer, TLS SNI or certificate names it, so its destination and purpose are unverified (an attribution gap, not a finding)`)
      }
    }
    // WhatsApp: STUN + XMPP (5222) + WhatsApp's chat/media domains together
    // are that app's signature (A3).
    const whatsappLike =
      packets.some((p) => p.dstPort === 5222 || p.appProtocol === "XMPP") &&
      (dns.some((d) => /mmx-ds\.whatsapp\.net|(^|\.)whatsapp\.(com|net)$/i.test(d.query)) ||
        tls.some((t) => /mmx-ds\.whatsapp\.net|(^|\.)whatsapp\.(com|net)$/i.test(t.sni || "")))
    if (whatsappLike) obs.push("WhatsApp-related endpoints and port-5222 traffic observed — the XMPP classification is port-inferred only, not payload-verified; STUN and WhatsApp chat/media domains also seen; no message or session content was reconstructed")
    if (packets.some((p) => (p.srcIp || "").includes(":") || (p.dstIp || "").includes(":"))) obs.push("IPv6 communication")
    // Multicast/broadcast requires DECODED addresses — undecodable packets
    // carry the "—" placeholder, which must not count as multicast (QA:
    // large/verylarge reported a fabricated multicast observation).
    if (!undecodable && packets.some((p) => p.dstIp && p.dstIp !== "\u2014" && isNonUnicast(p.dstIp))) obs.push("multicast/broadcast traffic")
    if (undecodable) obs.push(`capture payloads undecodable (${dltName(linkTypes)} — unsupported encapsulation); only lengths and timestamps parsed`)
    if (dnsQueries > 0) obs.push(`${dns.length.toLocaleString()} DNS packets — ${dnsQueries.toLocaleString()} queries + ${(dns.length - dnsQueries).toLocaleString()} responses, ${dnsLookupCount(dns).toLocaleString()} distinct name/type lookups for the capturing client, ${dnsUniqueDomains(dns).size.toLocaleString()} unique domain${dnsUniqueDomains(dns).size === 1 ? "" : "s"}`)
    // 0 DNS + any hostname-bearing traffic = the capture began mid-session:
    // the resolution phase predates the capture, so hostname↔IP correlation
    // and PTR lookups are unavailable (QA: login.pcapng talks to 4+ named
    // domains yet holds 0 DNS packets).
    if (dnsQueries === 0 && (http.length > 0 || tls.length > 0)) obs.push("0 DNS queries captured — capture likely began mid-session; hostname/IP correlation and PTR resolution unavailable")
    // An HTTP request and a decoded HTTP body are different things: only
    // requests whose body was captured AND decoded yield payloads/credentials.
    // "4 plaintext HTTP requests" next to "1 credential submission" read as a
    // counting error — name the relationship instead (QA: fufaji.pcapng).
    if (http.length > 0) obs.push(`${http.length} HTTP request${http.length === 1 ? "" : "s"} observed${credentials.length > 0 ? `; ${credentials.length} carried a decoded HTTP body containing credential field${credentials.length === 1 ? "" : "s"}` : ""}`)
    // HTTP User-Agents fingerprint client OSes even without MAC OUI data.
    // Microsoft-CryptoAPI/10.0 is a Windows component and must count as
    // Windows (its UA string never says "Windows").
    const uaOses = new Set<string>()
    for (const h of http) {
      const os = osFromUserAgent(h.userAgent || "")
      if (os) uaOses.add(os)
    }
    if (uaOses.size > 0) obs.push(`HTTP User-Agent${uaOses.size > 1 ? "s" : ""} consistent with ${[...uaOses].sort().join(", ")} (application/stack clue — the User-Agent is not a definitive OS fingerprint)`)
    // CRL/OCSP endpoints of Microsoft/DigiCert/Google trust stores: routine
    // background cert validation on Windows hosts, not suspicious activity.
    if (tls.some((t) => /(^|\.)ctldl\.windowsupdate\.com$|\.c\.lencr\.org$|(^|\.)crl\d*\.digicert\.com$|ocsp\.\w+\.(digicert\.com|pki\.goog|msocsp\.com)/i.test(t.sni || ""))) {
      obs.push("Windows certificate/CRL validation traffic (ctldl.windowsupdate.com, DigiCert/GlobalSign CRL & OCSP endpoints)")
    }
    // Network health must surface even when no detection rule fired: a SAFE
    // verdict next to 66.7% loss reads as "loss is fine" (QA). These are
    // observations, not findings — the verdict stays risk-based.
    const tcpFlowsAll = flows.filter((f) => f.protocol === "TCP")
    // Parity with the TCP Health card: "with measurements" = the subset that
    // captured a handshake or recorded at least one health signal — never
    // every TCP flow (QA: mic.pcapng showed "48 of 152" next to the card's
    // "150 flows with measurements", two denominators for one number).
    const measuredTcp = tcpFlowsAll.filter((f) => typeof f.rttMs === "number" || f.retrans || f.ooo || f.zeroWindow || f.rstCount)
    const lossyFlows = measuredTcp.filter((f) => (f.retrans ?? 0) > 0)
    if (lossyFlows.length > 0) {
      const worst = [...lossyFlows].sort((a, b) => (b.lossPct ?? 0) - (a.lossPct ?? 0))[0]
      const high = lossyFlows.filter((f) => (f.lossPct ?? 0) >= 20).length
      // The estimate and its confidence come from the CANONICAL loss function
      // (estimatedTcpLoss): retrans / data segments, confidence on the
      // data-segment sample — the worst flow's percentage is always
      // reproducible from the numbers printed next to it (QA: my.pcapng
      // "50%" read as 1/6 from the displayed 6 packets; the denominator was
      // 2 data segments).
      const worstEst = estimatedTcpLoss(worst)
      // The flow must be read initiator-first, exactly like the flows table,
      // the TCP Health table and the CSV — or the summary's worst flow and
      // the table's rows show opposite endpoint orders (QA: main.pcapng said
      // "worst 87.5% to 192.168.1.10" while the CSV row was
      // 192.168.1.10 → 185.199.110.133). "in flow A → B" claims no loss
      // direction: the retrans count sums both directions.
      const worstOrient = flowInitiatorFlip(worst, packets) ? `${worst.dstIp} → ${worst.srcIp}` : `${worst.srcIp} → ${worst.dstIp}`
      const unmeasured = tcpFlowsAll.length - measuredTcp.length
      obs.push(`Network health — retransmissions: ${lossyFlows.length} of ${measuredTcp.length} measured TCP flows (of ${tcpFlowsAll.length} TCP flows total; ${unmeasured} had no handshake and no observable health signal — no RTT, retransmission, out-of-order, zero-window or RST event — so loss cannot be measured on them) showed retransmissions. Worst flow: ${worstOrient} — Estimated retransmission ratio: ${worstEst.lossPct}% · Confidence: ${worstEst.confidence} · Sample: ${worstEst.dataSegments} data segment${worstEst.dataSegments === 1 ? "" : "s"} (of ${worstEst.totalPackets} packets in the flow; ${worstEst.retrans} retransmission${worstEst.retrans === 1 ? "" : "s"}). Interpretation: ${worstEst.dataSegments < 5 ? "insufficient evidence for an actual packet-loss measurement" : "an estimate from the observed data segments"}${high > 0 ? `. ${high} flow${high === 1 ? "" : "s"} ≥ 20% estimated loss` : ""}`)
      const rstFlows = tcpFlowsAll.filter((f) => (f.rstCount ?? 0) > 0)
      if (rstFlows.length > 0) {
        let rejected = 0
        let clientCancel = 0
        let serverClose = 0
        let unclassified = 0
        for (const rf of rstFlows) {
          const a = rstAttribution(rf, packets)
          rejected += a.rejected
          clientCancel += a.clientCancel
          serverClose += a.serverClose
          unclassified += a.unclassified
        }
        const rstRate = tcpFlowsAll.length > 0 ? rstFlows.length / tcpFlowsAll.length : 0
        const attrs = [
          ...(rejected > 0 ? [`${rejected} rejected connection${rejected === 1 ? "" : "s"} (RST in answer to a SYN before any SYN-ACK)`] : []),
          ...(clientCancel > 0 ? [`${clientCancel} client-initiated cancel${clientCancel === 1 ? "" : "s"} (RST sent by the connection initiator)`] : []),
          ...(serverClose > 0 ? [`${serverClose} server-side close${serverClose === 1 ? "" : "s"} (RST sent by the responder)`] : []),
          ...(unclassified > 0 ? [`${unclassified} unclassified`] : []),
        ]
        // An elevated RST share is common in browser/streaming traffic
        // (cancelled connections, short-lived flows, rejected connections,
        // capture timing) — it must be stated as informational, never as a
        // security finding, but a 30%+ reset share next to a clean verdict
        // reads as unexamined (QA: never_end.pcapng — 15 of 40 TCP flows
        // reset, "no detection rule triggered" only).
        obs.push(`Network health — resets: ${rstFlows.length} of ${tcpFlowsAll.length} TCP flows reset by RST${rstRate >= 0.3 ? " (elevated rate — informational, not treated as a security finding)" : ""} — attribution: ${attrs.join(", ")}. RSTs commonly follow cancelled connections, short-lived flows, rejected connections and capture timing; they are not evidence of malicious activity on their own.`)
      }
      obs.push("No security detection rule was triggered by these network-health observations")
    }
    // Consecutive identical frames are the double-capture signature — flow
    // counts can't see them (every packet is counted once) so the report
    // must (QA: frames #1/#3 and #2/#4 identical ACKs went unmentioned).
    // A substantial removal share is a capture-quality problem, not a win:
    // packet-rate, loss, retransmission and timing statistics come from the
    // analyzed set and must be read with that limitation in mind (QA:
    // minor.pcapng removed 27.1% of frames yet the verdict read like a
    // clean capture).
    if (duplicateFrames > 0) {
      const rawCount = typeof job?.rawPacketCount === "number" ? job.rawPacketCount : packets.length + duplicateFrames
      const dupPct = rawCount > 0 ? Math.round((duplicateFrames / rawCount) * 1000) / 10 : 0
      obs.push(`${duplicateFrames} consecutive duplicate frame${duplicateFrames === 1 ? "" : "s"} removed before analysis (double-capture artifact, ${dupPct}% of ${rawCount.toLocaleString()} raw frames) — detections and the risk score are computed on the analyzed set (${(rawCount - duplicateFrames).toLocaleString()} analyzed)${dupPct >= 25 ? "; capture quality POOR — interpret packet-rate, loss, retransmission and timing statistics cautiously" : dupPct >= 5 ? "; capture quality DEGRADED — interpret packet-rate and timing statistics cautiously" : ""}`)
    }
    return obs
  }, [packets, dns, http, tls, dnsQueries, undecodable, linkTypes, flows, duplicateFrames, job, credentials, geoMap, localOwned, certificates, quicHandshakePkts])
  const recs = useMemo(() => {
    type RecRow = { text: string; source: "CONFIRMED_ALERT" | "BEHAVIORAL_METRIC"; status?: DetectionStatus; priority?: "IMMEDIATE" | "INVESTIGATE" | "MONITOR" }
    const groups = { High: [] as RecRow[], Medium: [] as RecRow[], Low: [] as RecRow[] }
    for (const r of report.recommendations.sort((a, b) => b.severity - a.severity)) {
      groups[r.severity >= 4 ? "High" : r.severity >= 3 ? "Medium" : "Low"].push({ text: r.text, source: r.source, status: r.status, priority: r.priority })
    }
    if (undecodable) {
      groups.Medium.push({ text: `Capture not decodable (${dltName(linkTypes)}) — re-capture with an explicit DLT override (e.g. Wireshark: edit capture file settings or dumpcap -L) so headers can be parsed.`, source: "BEHAVIORAL_METRIC" })
    }
    return groups
  }, [report.recommendations, undecodable, linkTypes])

  if (!job) return null

  // Verdict gate: near-zero decode rate (unsupported encapsulation) means
  // the traffic is invisible — a 0/100 SAFE verdict would whitelist it. The
  // verdict must be UNKNOWN / INSUFFICIENT DATA instead (QA: large/verylarge).
  // The score displays its OWN numeric band (riskLevel) — never the floored
  // verdict level — so "53/100" reads as the MEDIUM band it is, while the
  // verdict badge still floors to CRITICAL from a 5/5 finding (QA:
  // open.pcapng "53/100 CRITICAL" conflated the score band with the finding
  // severity). The "Highest finding severity" row carries the 1–5 severity.
  const riskValue = (): string => undecodable
    ? "UNKNOWN / INSUFFICIENT DATA"
    : `${scoreVal}/100${scoreVal === 0 ? " — no detection rules triggered" : ` — ${riskLevel(scoreVal).label} score band`}`

  // job.riskScore is absent on legacy/malformed job records — a bare
  // undefined would render "undefined/100" in the verdict and conclusion.
  const jobScore = job.riskScore ?? 0
  const scoreVal = risk ? risk.normalizedScore : jobScore
  // Fallback path (no advanced metrics): same severity floor the report
  // builder applies — the verdict never reads lower than the strongest
  // finding, even when the score band alone would say SAFE/LOW.
  const fallbackVerdict = verdictLevel(riskLevel(job.riskScore), job.highestSeverity ?? 0)
  const levelLabel = undecodable ? "UNKNOWN" : (risk ? risk.levelLabel : fallbackVerdict.label)
  const levelColor = undecodable ? "text-muted-foreground" : (risk ? riskColorClass({ label: risk.levelLabel, color: risk.levelColor }) : riskColorClass(fallbackVerdict))
  const conclusionText = analystConclusion({
    undecodable,
    decodeRatePct: Math.round(decodeRate * 100),
    encapName: dltName(linkTypes),
    alerts: report.alerts,
    score: scoreVal,
    // Capture quality from the canonical metrics engine: a capture without a
    // measurable time interval (single packet / zero duration) yields an
    // INSUFFICIENT EVIDENCE verdict — never "clean" (QA: 1-SYN capture).
    quality: advancedMetrics?.rates?.quality,
    // A clean verdict on a mostly-encrypted capture must state the
    // visibility limit — 0/100 never means content was verified (QA:
    // big.pcapng 97.7% QUIC).
    encryptedSharePct: encSharePct,
  })

  const handleExport = () => {
    if (!requireValid()) return
    const t = document.title
    document.title = "PacketLens Report - " + job.filename
    setTimeout(() => {
      window.print()
      document.title = t
    }, 100)
  }

  const downloadText = (filename: string, content: string, mime = "text/plain") => {
    const blob = new Blob([content], { type: mime + ";charset=utf-8" })
    const a = document.createElement("a")
    a.href = URL.createObjectURL(blob)
    a.download = filename
    a.click()
    URL.revokeObjectURL(a.href)
  }

  const buildMarkdown = (): string => {
    let markdownPortInferred = false
    const mdTable = (header: string[], rows: string[][]) => [
      `| ${header.join(" | ")} |`,
      `| ${header.map(() => "---").join(" | ")} |`,
      ...rows.map((r) => `| ${r.join(" | ")} |`),
    ]
  // Top service names seen for a talker's conversations (flow-derived).
    const svcStr = (ip: string, side: "src" | "dst") => {
      const s = side === "src" ? talkerFlows.src.get(ip) : talkerFlows.dst.get(ip)
      const res = svcList(s, ip)
      if (res.portInferred) markdownPortInferred = true
      return res.text
    }
    const talkerRow = (ip: string, count: number, bytes: number, side: "src" | "dst") =>
      `| ${ip} | ${isNonUnicast(ip) ? "Multicast" : isPrivateIP(ip) || localOwned.has(ip) ? "Internal Host" : "External"} | ${count.toLocaleString()} | ${formatBytes(bytes)} | ${svcStr(ip, side)} |`

    const lines: string[] = [
      `# PacketLens Analysis Report — ${job.filename}`,
      "",
      "## Summary",
      ...mdTable(["Metric", "Value"], [
        ["Packets", stats.totalPackets.toLocaleString()],
        ["Flows", stats.totalFlows.toLocaleString()],
        ["Sessions (conversations)", stats.sessions.toLocaleString()],
        ["Local Devices", stats.devices.toLocaleString()],
        ["Duration", durPrecise(durationSec)],
        ["Risk score", riskValue()],
        // Severity is never hidden by the score: a HIGH finding is stated
        // next to a LOW numeric score, not swallowed by it. The 1–5 severity
        // scale is distinct from the 0–100 risk score, and an unconfirmed
        // finding is labeled as such (QA: open.pcapng "5/5 Critical" next to
        // "53/100" read as contradictory / confirmed).
        ["Highest finding severity (1–5)", highestSev > 0 ? `${sevLabel(highestSev)} (${highestSev}/5)${verdictStatusHint ? " · unconfirmed" : ""}` : "None"],
      ]),
      "",
      `## Capture Information`,
      `- **Analysis ID:** \`${job.id}\`${jobInfo?.isDemo ? " (Demo Dataset)" : ""}`,
      `- **Capture file:** \`${job.filename}\`` + (job.sha256 ? `\n- **SHA256:** \`${job.sha256}\`` : "") + (job.sha1 ? `\n- **SHA1:** \`${job.sha1}\`` : "") + (job.md5 ? `\n- **MD5:** \`${job.md5}\`` : ""),
      `- **File size:** ${formatBytes(job.fileSize)}`,
      `- **Packets:** ${stats.totalPackets.toLocaleString()}` + (typeof job?.rawPacketCount === "number" ? ` analyzed (raw ${job.rawPacketCount.toLocaleString()} · ${(job.duplicateFrameCount ?? 0).toLocaleString()} consecutive duplicates removed)` : "") + (undecodable ? ` · Undecodable traffic buckets: ${stats.totalFlows.toLocaleString()}` : ` · Flows: ${stats.totalFlows.toLocaleString()} · Sessions: ${stats.sessions.toLocaleString()} · Local Devices: ${stats.devices.toLocaleString()} (unique local hosts — MAC/IP aliases merged)`),
      `- **Duration:** ${durPrecise(durationSec)} · Risk score: ${riskValue()}`,
      `- **Alerts:** ${report.alerts.length} — Severity: ${severityCounts(report.alerts)} · Status: ${statusCountsLabel(summarizeStatuses(report.alerts))}${credentialEventCount(report.alerts) > 0 ? ` — covering ${credentialEventCount(report.alerts)} credential-submission event${credentialEventCount(report.alerts) === 1 ? "" : "s"}` : ""}`,
      "",
      "## Traffic",
      `- External IPs: ${stats.externalIps} · Countries: ${countriesLabel(stats.countries, stats.externalIps)} (unique GeoIP-resolved countries across external endpoints, either direction)`,
      `- Application-layer visibility: ${appVisibilityLabel} — a separate dimension from capture quality (frame completeness) and from the risk score.`,
      `- Source/destination IP counts are packet-direction counts (each endpoint counted once per side it appeared on). Flow and CSV rows are initiator-first: the Initiator column identifies the endpoint that initiated the conversation — so summing distinct CSV endpoints still yields different numbers by design. Sessions equal the conversation count: flows are already direction-agnostic (both directions merged into one flow), and each session is that conversation with its TCP state (ESTABLISHED / STATELESS / …) attached.`,
      `- DNS: ${dnsQueries} query packets + ${dns.length - dnsQueries} responses (${plural(dnsLookupCount(dns), "distinct lookup")}) · HTTP requests: ${http.length} · TCP/TLS handshakes: ${tls.length}${quicFlowCount > 0 ? ` · QUIC connections: ${quicFlowCount} · QUIC Initial packets decoded: ${quicHandshakePkts} — QUIC's TLS handshake lives in CRYPTO frames (never a TCP TLS handshake), so QUIC TLS/CRYPTO handshake visibility is ${quicHandshakePkts > 0 ? `partial (${quicHandshakePkts} decoded)` : "unavailable"}` : ""}`,
      ...(dnsQueries === 0 && (http.length > 0 || tls.length > 0) ? [`- **Note:** 0 DNS queries captured — the capture likely began mid-session; hostname↔IP correlation and PTR resolution are unavailable.`] : []),
      `- ${plural(files.length, "HTTP payload")} extracted · ${plural(credentials.length, "credential submission")} (credential submissions are the HTTP requests whose decoded body carried a username and/or password field — not every HTTP request) · ${plural(certificates.length, "unique certificate")} decoded (deduplicated by subject+serial across the capture)`,
      ...(report.notables.length ? [`- Notable destinations (neutral, not findings — these domains appeared in the capture's own TLS Server Name or HTTP Host fields, so the connection was made by a host inside the capture, not by PacketLens; presence alone is not a malicious indicator, and an absence of notable destinations is only a curated-list negative — it does not establish benignness or a clean reputation): ${report.notables.map((n) => `${n.domain} (${n.category})`).join(", ")}`] : [`- No notable destinations from the curated list — a curated-list negative only: it does not establish that the endpoints are benign or reputable.`]),
      ...(calls.length ? [`- VoIP calls: ${calls.length}`, ""] : []),
      "",
      ...(undecodable ? [`## Data Quality`, `- **WARNING:** only ${(decodeRate * 100).toFixed(0)}% of packets decoded (${linkTypes.length > 0 ? dltName(linkTypes) : "encapsulation unknown"}). Lengths and timestamps were parsed; headers were not. Verdict is UNKNOWN — re-capture with a decodable link type or explicit DLT override.`, ""] : []),
      "",
      "## Top Protocols",
      // Full protocol set — truncating here silently drops protocols the
      // on-page card still shows (IGMP vanished from the exported PDF while
      // the page listed six protocols) (QA #7).
      ...topProto.map(([p, c]) => `- ${p}: ${c} (${((c / packets.length) * 100).toFixed(1)}%)`),
      "",
      "## Top Ports",
      "| Protocol/Port | Service | Packets | Share |",
      "| --- | --- | --- | --- |",
      ...topPorts.map(({ protocol, port, count, confirmedFlows, flows }) => `| ${protocol}/${port} | ${serviceEvidenceLabel(portServiceName(port, protocol), confirmedFlows, flows)} | ${count.toLocaleString()} | ${sharePctLabel(count, portTotal)} |`),
      ...(otherPortTotal > 0 ? [`| — Other ports (${allPorts.length - topPorts.length} more services) | — | ${otherPortTotal.toLocaleString()} | ${sharePctLabel(otherPortTotal, portTotal)} |`] : []),
      `_Service-side attribution per conversation (well-known/known service port wins, else lower port); both-leg counts summed. Share is % of the ${portTotal.toLocaleString()} ports-attributable packets (of ${packets.length.toLocaleString()} analyzed): ${portlessPkts.toLocaleString()} packets have no ports (covered under Top Protocols) and ${p2pExcluded.toLocaleString()} are P2P dynamic-range (excluded), so the rows shown plus Other cover 100% of port attribution. Labels are payload-confirmed only when the decoder verified the protocol in the payload; evidence counts are FLOWS (conversations), never packets — the Packets column holds packet totals. A flow counts as having payload evidence when at least one of its packets was payload-verified, so a partially verified flow still counts (the CSV's "mixed" rows)._`,
      "",
      ...(observations.length ? ["## Observations", ...observations.map((o) => `- ${o}`), ""] : []),
      "## Top Talkers (source)",
      "| IP | Host | Packets | Bytes | Services |",
      "| --- | --- | --- | --- | --- |",
      ...topSrcIps.slice(0, 5).map(({ ip, count, bytes }) => talkerRow(ip, count, bytes, "src")),
      ...(noSrcAddrCount > 0 ? [`_${noSrcAddrCount.toLocaleString()} packet${noSrcAddrCount === 1 ? "" : "s"} with no decodable source address excluded from this table — not attributable to any host._`, ""] : [""]),
      "## Top Talkers (destination)",
      "| IP | Host | Packets | Bytes | Services |",
      "| --- | --- | --- | --- | --- |",
      ...topDstIps.slice(0, 5).map(({ ip, count, bytes }) => talkerRow(ip, count, bytes, "dst")),
      ...(noDstAddrCount > 0 ? [`_${noDstAddrCount.toLocaleString()} packet${noDstAddrCount === 1 ? "" : "s"} with no decodable destination address excluded from this table — not attributable to any host._`, ""] : []),
      ...(markdownPortInferred ? [`_* Service classification inferred from port usage only — no packet payload was payload-verified for that service (payload-verified services are unmarked)._`, ""] : []),
    ]
    if (report.alerts.length) {
      lines.push("## Alerts", ...report.alerts.slice(0, 20).map((t) => `- [${sevLabel(t.severity)}] ${t.signature} (${t.srcIp} → ${t.dstIp})`), "")
    }
    if (report.iocs.length) {
      lines.push("## Indicators & Affected Assets", ...report.iocs.slice(0, 20).map((i) => `- [${sevLabel(i.severity)}] ${i.type === "credential-theft" ? `Affected host: ${i.value}` : i.value} — ${i.description} (${findingSourceLabel(i.source, i.status)})`), "")
      if (report.iocs.some((i) => i.type === "credential-theft")) {
        lines.push("_The Plaintext Credential Exposure row lists the affected host (the machine that transmitted the credentials) and its destination — an affected host is the victim of the exposure, not an indicator of a known-malicious artifact. The capture proves the transmission, not theft, interception, or a malicious destination._", "")
      }
      if (report.iocs.some((i) => ["data-exfiltration", "beaconing", "dns-tunneling", "tor-vpn-proxy", "ja3", "port-scan", "syn-flood"].includes(i.type))) {
        lines.push("_Behavioral entries (e.g. Suspected Large Outbound Transfer, Beaconing, DNS Tunneling) are findings about observed traffic patterns, not indicators of a known-malicious artifact: the value describes the behavior itself, and the endpoints are not established as malicious._", "")
      }
    }
    if (calls.length) {
      lines.push("## VoIP / SIP Calls", ...mdTable(["Caller", "Callee", "Status", "Start", "Duration", "RTP Packets", "RTP Payload"], calls.map((c) => [c.from, c.to, c.status, formatTime(c.startTime), c.durationSec !== null ? fmtClock(c.durationSec) : "—", c.rtpPackets > 0 ? c.rtpPackets.toLocaleString() : "—", c.rtpPayloadType !== null ? `PT ${c.rtpPayloadType}` : "—"])), "")
    }
    if (mitre.length) {
      lines.push("## MITRE ATT&CK", ...mitre.map((m) => `- ${m.id} ${m.technique} (${sevLabel(m.severity)}) — ${m.description} (${findingSourceLabel(m.source, m.status)})`), "")
    } else if (report.alerts.length > 0) {
      lines.push("## MITRE ATT&CK", "- No techniques mapped — techniques attach only when the evidence demonstrates the technique was executed; SUSPECTED threshold findings and confirmed exposure-style findings (e.g. plaintext credential exposure) are deliberately unmapped, because exposure is a weakness or prerequisite, not observed adversary activity.", "")
    }
    const recLines: string[] = []
    // A SUSPECTED behavioral recommendation carries its INVESTIGATE action
    // priority in the export, so it never reads as a blocking mandate (QA:
    // long.pcapng "consider blocking suspicious destinations" for one
    // suspected STUN flow).
    const recLine = (r: { text: string; source: "CONFIRMED_ALERT" | "BEHAVIORAL_METRIC"; status?: DetectionStatus; priority?: "IMMEDIATE" | "INVESTIGATE" | "MONITOR" }) =>
      `- ${r.priority ? `**[${r.priority}]** ` : ""}${r.text} (${findingSourceLabel(r.source, r.status)})`
    if (recs.High.length) recLines.push("### High", ...recs.High.map(recLine))
    if (recs.Medium.length) recLines.push("### Medium", ...recs.Medium.map(recLine))
    if (recs.Low.length) recLines.push("### Low", ...recs.Low.map(recLine))
    if (recLines.length === 0) recLines.push("- No security detections triggered — no corrective security recommendations. Network-health observations above (retransmissions, estimated loss, RTT, RST) are informational network diagnostics, NOT security findings, and do not change this recommendation.")
    lines.push("## Recommendations", ...recLines)
    lines.push("", "## Analyst Conclusion", verdictLine(levelLabel, scoreVal, undecodable, verdictStatusHint), `- ${conclusionText}`)
    lines.push("", "## Appendix", `- Analysis completed: ${job.createdAt ? new Date(job.createdAt).toISOString().slice(0, 19).replace("T", " ") + " UTC" : "—"} · Export generated: ${exportTs} UTC · Mode: ${report.metadata.mode} · Schema: ${report.metadata.schemaVersion}`, `- Build: v${BUILD_INFO.version}${BUILD_INFO.isGit ? ` · Commit: ${BUILD_INFO.commit} (${BUILD_INFO.commitShort})` : ` · Source: build env (src:${BUILD_INFO.sourceHash || "unknown"})`} · Built: ${BUILD_INFO.builtAt}`, `- Analyzer: ${report.metadata.analyzerVersion || ANALYZER_VERSION} · Risk spec: ${report.metadata.riskSpecVersion || RISK_SPEC_VERSION} · Signature DB: ${report.metadata.ruleVersion || "Behavioral Detection Only"} · GeoIP (DB-IP City Lite): ${jobInfo?.geoDbVersion || "Lookup Unavailable"} · OUI: ${ouiStatus}`, `- Decoded: ${decode?.decoded.toLocaleString() ?? "—"} of ${(decode?.total ?? stats.totalPackets).toLocaleString()} packets${duplicateFrames > 0 ? ` · ${duplicateFrames.toLocaleString()} consecutive duplicate frames removed before analysis` : ""} · Encapsulation: ${linkTypes.length > 0 ? dltName(linkTypes) : "—"} · Application-layer visibility: ${appVisibilityLabel}`)
    return lines.join("\n")
  }

  const exportHtml = () => {
    if (!requireValid()) return
    downloadText(`${job.filename}-report.html`, markdownToHtml(buildMarkdown(), { jobId: job.id, jobFilename: job.filename, origin: window.location.origin }), "text/html")
  }

  const exportCsv = () => {
    if (!requireValid()) return
    downloadText(`${job.filename}-flows.csv`, buildFlowsCsv(flows, geoMap, packets), "text/csv")
  }

  const maxPkts = Math.max(...report.timeline.map((t) => t.packets), 1)
  const maxBw = Math.max(...report.bandwidth.map((b) => b.in + b.out), 1)

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          <div className="flex items-center justify-between no-print">
            <div>
              <h1 className="text-lg font-bold mb-1">Reports</h1>
              <p className="text-xs text-muted-foreground">Comprehensive analysis report — all sections</p>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" className="gap-2" onClick={exportHtml} title="Export report as standalone HTML">
                <Download className="h-4 w-4" /> HTML
              </Button>
              <Button variant="outline" size="sm" className="gap-2" onClick={exportCsv} title="Export flows as CSV">
                <Download className="h-4 w-4" /> CSV
              </Button>
              <Button variant="outline" size="sm" className="gap-2" onClick={handleExport}>
                <Download className="h-4 w-4" /> Export PDF
              </Button>
            </div>
          </div>

          <div className="print-only">
            <div style={{ textAlign: "center", padding: "80pt 0 24pt", pageBreakAfter: "always" }}>
              <div style={{ fontSize: "36pt", fontWeight: 800, color: "#1a1a2e", letterSpacing: "-0.02em", marginBottom: "8pt" }}>PacketLens</div>
              <div style={{ fontSize: "18pt", color: "#2563eb", fontWeight: 600, marginBottom: "32pt" }}>PCAP Analysis Report</div>
              <hr style={{ width: "80pt", border: "none", borderTop: "3px solid #2563eb", margin: "0 auto 32pt" }} />
              <table style={{ margin: "0 auto", fontSize: "10pt", color: "#444" }}>
                <tbody>
                  {jobInfo?.isDemo && <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>Type</td><td style={{ padding: "4pt 16pt", fontWeight: 600 }}>Demo Dataset</td></tr>}
                  <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>Analysis ID</td><td style={{ padding: "4pt 16pt", fontWeight: 600, fontFamily: "monospace" }}>{job.id}</td></tr>
                  <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>File</td><td style={{ padding: "4pt 16pt", fontWeight: 600 }}>{job.filename}</td></tr>
                  <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>Size</td><td style={{ padding: "4pt 16pt", fontWeight: 600 }}>{formatBytes(job.fileSize)}</td></tr>
                  {job.sha256 && <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>SHA256</td><td style={{ padding: "4pt 16pt", fontWeight: 600, fontFamily: "monospace", fontSize: "8pt" }}>{job.sha256}</td></tr>}
                  {job.sha1 && <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>SHA1</td><td style={{ padding: "4pt 16pt", fontWeight: 600, fontFamily: "monospace", fontSize: "8pt" }}>{job.sha1}</td></tr>}
                  {job.md5 && <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>MD5</td><td style={{ padding: "4pt 16pt", fontWeight: 600, fontFamily: "monospace", fontSize: "8pt" }}>{job.md5}</td></tr>}
                  <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>Packets</td><td style={{ padding: "4pt 16pt", fontWeight: 600 }}>{stats.totalPackets.toLocaleString()}</td></tr>
                  <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>Duration</td><td style={{ padding: "4pt 16pt", fontWeight: 600 }}>{durLabel(durationSec)}</td></tr>
                  <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>Risk Score</td><td style={{ padding: "4pt 16pt", fontWeight: 600 }}>{riskValue()}</td></tr>
                  <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>Analysis Completed</td><td style={{ padding: "4pt 16pt", fontWeight: 600 }}>{job.createdAt ? new Date(job.createdAt).toISOString().slice(0, 19).replace("T", " ") + " UTC" : "—"}</td></tr>
                  <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>Export Generated</td><td style={{ padding: "4pt 16pt", fontWeight: 600 }}>{new Date().toISOString().slice(0, 19).replace("T", " ")} UTC</td></tr>
                  <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>Build</td><td style={{ padding: "4pt 16pt", fontWeight: 600, fontFamily: "monospace", fontSize: "8pt" }}>v{BUILD_INFO.version} · {BUILD_INFO.isGit ? `commit:${BUILD_INFO.commitShort}` : `src:${BUILD_INFO.sourceHash || "unknown"}`} · {BUILD_INFO.builtAt}</td></tr>
                  {BUILD_INFO.isGit && <tr><td style={{ padding: "4pt 16pt", textAlign: "right", color: "#888" }}>Commit</td><td style={{ padding: "4pt 16pt", fontWeight: 600, fontFamily: "monospace", fontSize: "8pt" }}>{BUILD_INFO.commit}</td></tr>}
                </tbody>
              </table>
              <div style={{ marginTop: "40pt", fontSize: "8pt", color: "#aaa" }}>PacketLens Report &middot; Detection Engine: Behavioral &middot; Analyzer: {report.metadata.analyzerVersion || ANALYZER_VERSION} &middot; Generated By: PacketLens &middot; Generated {new Date().toISOString().slice(0, 10)} &middot; Build {BUILD_STAMP}</div>
            </div>
          </div>

          <div className="space-y-8">
            <section>
              <SectionTitle icon={FileText} title="1. Executive Summary" />
              <Card>
                <CardContent className="text-sm text-muted-foreground space-y-2 pt-6">
                  <p>Report generated for <strong>{job.filename}</strong>, containing <strong>{stats.totalPackets.toLocaleString()}</strong> packets over <strong>{durPrecise(durationSec)}</strong>. File: <strong>{formatBytes(job.fileSize)}</strong>, payload: <strong>{formatBytes(totalBytes)}</strong>.</p>
                  {undecodable ? (
                    <p><strong>{stats.totalFlows}</strong> undecodable traffic bucket{stats.totalFlows === 1 ? "" : "s"} — no endpoints were parsed (unsupported encapsulation).</p>
                  ) : (
                    <>
                    <p><strong>{plural(stats.totalFlows, "flow")}</strong>, <strong>{plural(stats.sessions, "session")}</strong>, <strong>{stats.devices} local device{stats.devices === 1 ? "" : "s"}</strong> (unique local hosts — MAC/IP aliases merged; {endpointRows.length} endpoints) across {uniqueSrcIps} source and {uniqueDstIps} destination IPs ({stats.externalIps} external, {countriesLabel(stats.countries, stats.externalIps)} countries/regions — unique GeoIP-resolved countries across external endpoints, either direction). Top protocol: <strong>{topProto[0]?.[0] || ""}</strong> ({packets.length === 0 ? "—" : ((topProto[0]?.[1] || 0) / packets.length * 100).toFixed(1) + "%"}).</p>
                    <p className="text-xs text-muted-foreground">Source/destination IP counts are packet-direction counts — each endpoint is counted once per side it appeared on. Flow and CSV rows are initiator-first: the Initiator column identifies the endpoint that initiated the conversation — so summing distinct CSV endpoints still yields different numbers from these counts by design. Sessions equal the conversation count: flows are already direction-agnostic (both directions merged into one flow), and each session is that conversation with its TCP state (ESTABLISHED / STATELESS / …) attached.</p>
                    </>
                  )}
                  {undecodable && (
                    <p className="text-danger font-medium">Data quality: only {(decodeRate * 100).toFixed(0)}% of packets decoded ({linkTypes.length > 0 ? dltName(linkTypes) + " encapsulation" : "encapsulation unknown"}). No headers were parsed — check the capture link type or re-capture with an explicit DLT override; the verdict below is UNKNOWN.</p>
                  )}
                  {(dnsQueries > 0 || http.length > 0 || tls.length > 0) && <p>DNS: <strong>{plural(dnsQueries, "query packet")}</strong> + <strong>{plural(dns.length - dnsQueries, "response")}</strong> ({plural(dnsLookupCount(dns), "distinct lookup")}), <strong>{plural(http.length, "HTTP request")}</strong>, <strong>{plural(tls.length, "TCP/TLS handshake")}</strong>{quicFlowCount > 0 ? <> — <strong>{plural(quicFlowCount, "QUIC connection")}</strong> (<strong>{plural(quicHandshakePkts, "QUIC Initial packet")}</strong> decoded; QUIC's TLS handshake is carried in CRYPTO frames, never a TCP TLS handshake, so QUIC TLS/CRYPTO handshake visibility is {quicHandshakePkts > 0 ? "partial" : "unavailable"})</> : null}.</p>}
                  {tls.length === 0 && (httpsPortPkts > 0 || quicFlowCount > 0) && (quicFlowCount > 0 && httpsPortPkts === 0
                    ? (quicHandshakePkts > 0
                      ? <p className="text-warning">QUIC traffic is present on UDP/443 — <strong>{plural(quicFlowCount, "connection")}</strong> with <strong>{plural(quicHandshakePkts, "payload-verified Initial handshake packet")}</strong> decoded; the TLS sessions inside QUIC are encrypted, and no ClientHello/ServerHello-style TLS metadata, SNI or certificates are extracted from its CRYPTO frames.</p>
                      : <p className="text-warning">QUIC traffic is present on UDP/443 (<strong>{plural(quicFlowCount, "connection")}</strong>, port-inferred — no QUIC Initial handshake packets captured, so the encryption is inferred, not decoded; the capture likely began mid-session). QUIC carries TLS inside its CRYPTO frames, and no handshake, SNI or certificate data was extracted.</p>)
                    : quicFlowCount > 0
                      ? <p className="text-warning">QUIC traffic is present on UDP/443 (<strong>{plural(quicFlowCount, "connection")}</strong>, port-inferred — no QUIC Initial handshake packets captured) alongside TCP/443 HTTPS (port-inferred) — the encryption is inferred, not decoded: no QUIC Initial handshake or TLS ClientHello/ServerHello packets were captured, so no handshake, SNI or certificate data was extracted from either.</p>
                      : <p className="text-warning">TCP/443 HTTPS traffic is present (inferred from port usage) — encryption is inferred, not decoded: no TLS ClientHello/ServerHello packets were captured (the capture likely started after session establishment).</p>)}
                  {files.length > 0 && <p><strong>{plural(files.length, "HTTP payload")}</strong> extracted ({formatBytes(files.reduce((s, f) => s + f.size, 0))}), <strong>{plural(credentials.length, "credential submission")}</strong> ({credentials.length > 0 ? "HTTP requests whose decoded body carried a username and/or password field — not every HTTP request" : "none of the HTTP requests carried credential fields"}), <strong>{plural(certificates.length, "unique certificate")}</strong> decoded.</p>}
                  {alerts.length > 0 ? (
                    <p><span className="text-danger font-medium">{plural(alerts.length, "alert")}</span> — Severity: {severityCounts(alerts)} · Status: {statusCountsLabel(summarizeStatuses(alerts))}. Risk score: <strong>{riskValue()}</strong>.</p>
                  ) : (
                    <p>No behavioral detection rules triggered. Risk score: <strong>{riskValue()}</strong>.</p>
                  )}
                  {alerts.length === 0 && observations.length > 0 && (
                    <p className="text-xs text-muted-foreground border-t border-border/30 pt-2">Observed normal activity: {observations.join(" · ")}.</p>
                  )}
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={Package} title="2. Traffic Summary" sub={`${stats.totalPackets.toLocaleString()} analyzed packets over ${durPrecise(durationSec)}`} />
              {typeof job?.rawPacketCount === "number" && (
                <div className="mb-3 text-[11px] text-muted-foreground space-y-1">
                  <p>
                    Raw frames: <strong>{job.rawPacketCount.toLocaleString()}</strong> · Consecutive duplicate frames removed: <strong>{job.duplicateFrameCount?.toLocaleString() ?? 0}</strong> · Analyzed: <strong>{stats.totalPackets.toLocaleString()}</strong>
                    {dedupeGrade && <span className={`ml-2 font-medium ${dedupeGrade.color}`}>Capture quality: {dedupeGrade.label}</span>}
                  </p>
                  <p>
                    Application-layer visibility: <strong>{appVisibilityLabel}</strong> — a separate dimension from capture quality (frame completeness): a clean dedupe rate does not mean packet content could be inspected.
                  </p>
                  <p>Every metric, detection and risk score is computed on the analyzed set — duplicate capture artifacts never inflate flows, SYN counts or rates.</p>
                </div>
              )}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[
                  { label: "Total Packets", value: stats.totalPackets.toLocaleString(), icon: Package, color: "text-info" },
                  { label: "Total Flows", value: stats.totalFlows.toLocaleString(), icon: GitFork, color: "text-chart-2" },
                  { label: "Sessions", value: stats.sessions.toLocaleString(), icon: MessagesSquare, color: "text-chart-3" },
                  { label: "Local Devices", value: stats.devices.toLocaleString(), icon: Monitor, color: "text-chart-1" },
                  { label: "Countries", value: countriesLabel(stats.countries, stats.externalIps), icon: Globe, color: stats.countries > 0 ? "text-warning" : "text-muted-foreground" },
                  { label: "External IPs", value: stats.externalIps.toLocaleString(), icon: Globe, color: "text-info" },
                  { label: "DNS Lookups", value: dnsLookupCount(dns).toLocaleString(), icon: Globe, color: "text-warning" },
                  { label: "HTTP Requests", value: http.length.toLocaleString(), icon: FileText, color: "text-info" },
                  { label: "TLS Handshakes", value: tls.length.toLocaleString(), icon: Shield, color: "text-chart-3" },
                  { label: "HTTP Payloads", value: files.length.toLocaleString(), icon: FolderOpen, color: "text-chart-1" },
                  { label: "VoIP Calls", value: calls.length.toLocaleString(), icon: Phone, color: "text-chart-2" },
                  { label: "Credential Submissions", value: credentials.length.toLocaleString(), icon: Key, color: "text-warning" },
                  { label: "Unique Certs", value: certificates.length.toLocaleString(), icon: Verified, color: "text-chart-2" },
                  { label: "Alerts", value: alerts.length.toLocaleString(), icon: AlertTriangle, color: "text-danger" },
                  { label: "Risk Score", value: riskValue(), icon: AlertTriangle, color: undecodable ? "text-muted-foreground" : (risk ? riskColorClass({ label: risk.levelLabel, color: risk.levelColor }) : riskColorClass(riskLevel(job.riskScore))) },
                  // Severity is surfaced ALONGSIDE the score — numeric
                  // normalization must never hide the strongest finding
                  // (a 39/100 LOW score with a HIGH finding reads as HIGH present).
                  { label: "Highest Finding", value: highestSev > 0 ? `${sevLabel(highestSev)} (${highestSev}/5)${verdictStatusHint ? " · unconfirmed" : ""}` : "None", icon: ShieldAlert, color: highestSev >= 4 ? "text-danger" : "text-muted-foreground" },
                  // Explicit measurement window (QA: long.pcapng peak labels).
                  { label: bwInterval ? `Peak ${bwIntervalLabel} rate` : "Peak rate (whole capture)", value: rateLabel(peakBandwidth), icon: BarChart3, color: "text-chart-2" },
                  { label: "Avg Packet Size", value: avgPacketBytes + " B", icon: Package, color: "text-muted-foreground" },
                ].map(({ label, value, color }) => (
                  <Card key={label}>
                    <CardHeader className="pb-2"><CardTitle className={cn("text-sm font-medium", color)}>{label}</CardTitle></CardHeader>
                    <CardContent><div className="text-2xl font-bold">{value}</div></CardContent>
                  </Card>
                ))}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                <Card>
                  <CardHeader><CardTitle className="text-sm">Protocol Distribution</CardTitle></CardHeader>
                  <CardContent className="space-y-3">
                    {topProto.map(([proto, count]) => (
                      <div key={proto} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <Badge variant="outline" className="text-[10px]">{proto}</Badge>
                          <span>{count.toLocaleString()} ({(count / packets.length * 100).toFixed(1)}%)</span>
                        </div>
                        <div className="h-2.5 bg-muted rounded-full overflow-hidden">
                          <div className={cn("h-full rounded-full transition-all", PROTO_COLORS[proto] || "bg-muted-foreground")} style={{ width: (count / packets.length * 100) + "%" }} />
                        </div>
                      </div>
                    ))}
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader><CardTitle className="text-sm">Traffic Details</CardTitle></CardHeader>
                  <CardContent>
                    <div className="space-y-2 text-xs">
                      {[
                        { label: "File", value: job.filename },
                        { label: "Size", value: formatBytes(job.fileSize) },
                        { label: "Duration", value: durPrecise(durationSec) },
                        { label: "Capture Start", value: fmtDateTime(captureClock.start) },
                        { label: "Capture End", value: fmtDateTime(captureClock.end) },
                        { label: "Total Bytes", value: formatBytes(totalBytes) },
                        { label: "Avg Packets/s", value: ratesAvailable ? (packets.length / durationSec).toFixed(1) : "N/A" },
                        { label: "Avg Throughput", value: advancedMetrics ? rateLabel(advancedMetrics.throughputAvg) : "N/A" },
                        { label: "Avg Packet Size", value: avgPacketBytes + " bytes" },
                        // Explicit measurement window: "Peak Bandwidth" alone
                        // never says what second-scale the peak is measured
                        // over (QA: long.pcapng peak labels).
                        { label: bwInterval ? `Peak ${bwIntervalLabel} rate` : "Peak rate (whole capture)", value: rateLabel(peakBandwidth) },
                        { label: "Source IPs", value: uniqueSrcIps.toLocaleString() },
                        { label: "Dest IPs", value: uniqueDstIps.toLocaleString() },
                      ].map(({ label, value }) => (
                        <div key={label} className="flex justify-between py-1 border-b border-border/30 last:border-0">
                          <span className="text-muted-foreground">{label}</span>
                          <span className="font-medium">{value}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </section>

            <section>
              <SectionTitle icon={Package} title="3. Packets" />
              <Card>
                <CardContent className="pt-6">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">#</th>
                          <th className="text-left py-2 pr-2">Time</th>
                          <th className="text-left py-2 pr-2">Source</th>
                          <th className="text-left py-2 pr-2">Destination</th>
                          <th className="text-left py-2 pr-2">Proto</th>
                          <th className="text-right py-2 pr-2">Len</th>
                          <th className="text-left py-2">Info</th>
                        </tr>
                      </thead>
                      <tbody>
                        {packets.slice(0, 20).map((p) => (
                          <tr key={p.num} className="border-b border-border/30 hover:bg-muted/20">
                            <td className="py-1.5 pr-2 font-mono text-muted-foreground">{p.num}</td>
                            <td className="py-1.5 pr-2 font-mono text-muted-foreground whitespace-nowrap hl-time">{formatTime(p.timestamp)}</td>
                            <td className="py-1.5 pr-2 font-mono whitespace-nowrap hl-src">{p.srcIp}</td>
                            <td className="py-1.5 pr-2 font-mono whitespace-nowrap">{p.dstIp}</td>
                            <td className="py-1.5 pr-2"><Badge variant="outline" className={cn("text-[10px] font-mono", p.protocol === "TCP" ? "bg-info/10" : p.protocol === "UDP" ? "bg-success/10" : p.protocol === "DNS" ? "bg-warning/10" : "bg-chart-3/10")}>{p.protocol}</Badge></td>
                            <td className="py-1.5 pr-2 text-right text-muted-foreground">{p.length}</td>
                            <td className="py-1.5 text-muted-foreground truncate max-w-[200px]">{p.info}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {packets.length > 20 && <p className="text-xs text-muted-foreground mt-2">... and {packets.length - 20} more packets</p>}
                  </div>
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={GitFork} title="4. Flows" />
              <Card>
                <CardContent className="pt-6">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">Initiator</th>
                          <th className="text-left py-2 pr-2">Responder</th>
                          <th className="text-left py-2 pr-2">Proto</th>
                          <th className="text-right py-2 pr-2">Packets</th>
                          <th className="text-right py-2 pr-2">Sent</th>
                          <th className="text-right py-2 pr-2">Recv</th>
                          <th className="text-right py-2">Duration</th>
                        </tr>
                      </thead>
                      <tbody>
                        {flowTableRows(flows, packets).slice(0, 15).map((f) => (
                          <tr key={f.srcIp + ":" + f.srcPort + "→" + f.dstIp + ":" + f.dstPort} className="border-b border-border/30">
                            <td className="py-1.5 pr-2 font-mono hl-src">{f.srcIp}:{f.srcPort}</td>
                            <td className="py-1.5 pr-2 font-mono">{f.dstIp}:{f.dstPort}</td>
                            <td className="py-1.5 pr-2"><Badge variant="outline" className="text-[10px] font-mono">{f.protocol}</Badge></td>
                            <td className="py-1.5 pr-2 text-right">{f.packets}</td>
                            <td className="py-1.5 pr-2 text-right text-muted-foreground">{f.directionUnknown ? "—" : formatBytes(f.bytesSent ?? 0)}</td>
                            <td className="py-1.5 pr-2 text-right text-muted-foreground">{f.directionUnknown ? "—" : formatBytes(f.bytesRecv ?? 0)}</td>
                            <td className="py-1.5 text-right text-muted-foreground">{f.duration}s</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {flows.length > 15 && <div className="text-[10px] text-muted-foreground mt-1">Showing the 15 largest flows of {flows.length.toLocaleString()} — the CSV export lists all flows.</div>}
                  <p className="text-[10px] text-muted-foreground mt-1">Initiator = the endpoint that sent the conversation&rsquo;s SYN (TCP) or its first observed packet — this table and the CSV export list the same endpoint first, and Sent/Recv are relative to the initiator. Detection always reads the original packet direction from the wire, never this display order.</p>
                  {/* TCP health mirrors the CSV export: per-flow RTT, retrans,
                      loss, OoO, zero-window and RST. Shows the worst flows —
                      a summary without rows reads as "nothing measured". */}
                  {(() => {
                    const tcp = flows.filter((f) => f.protocol === "TCP" && (typeof f.rttMs === "number" || f.retrans || f.ooo || f.zeroWindow || f.rstCount))
                    const worst = [...tcp].sort((a, b) => ((b.retrans ?? 0) + (b.ooo ?? 0) + (b.rstCount ?? 0)) - ((a.retrans ?? 0) + (a.ooo ?? 0) + (a.rstCount ?? 0))).slice(0, 10)
                    if (worst.length === 0) return null
                    const rtts = tcp.filter((f) => typeof f.rttMs === "number").map((f) => f.rttMs!) as number[]
                    const lossy = tcp.filter((f) => (f.retrans ?? 0) > 0).length
                    return (
                      <div className="mt-4">
                        <p className="text-xs font-medium mb-2" title="Subset: flows with a measured handshake (SYN/SYN-ACK captured in-window). Median/p95 — not the mean, which retransmit-backoff flows drag up.">
                          TCP Health — {tcp.length} flows with measurements · {lossy} with retransmissions · {tcpHealthRttCaption(rtts)}
                        </p>
                        <div className="overflow-x-auto">
                          <table className="w-full text-xs">
                            <thead>
                              <tr className="border-b text-muted-foreground">
                                <th className="text-left py-1.5 pr-2">Flow</th>
                                <th className="text-right py-1.5 pr-2">Pkts</th>
                                <th className="text-right py-1.5 pr-2">Data Seg</th>
                                <th className="text-right py-1.5 pr-2">RTT (ms)</th>
                                <th className="text-right py-1.5 pr-2">Retrans</th>
                                <th className="text-right py-1.5 pr-2">Est. Retrans Loss %</th>
                                <th className="text-right py-1.5 pr-2">Loss Conf</th>
                                <th className="text-right py-1.5 pr-2">OoO</th>
                                <th className="text-right py-1.5 pr-2">Zero Win</th>
                                <th className="text-right py-1.5">RST</th>
                              </tr>
                            </thead>
                            <tbody>
                              {worst.map((f) => {
                                // Same initiator-first orientation as the
                                // flows table and the CSV — the health table
                                // used to show the raw lexicographic order,
                                // so the same flow read as two flows (QA:
                                // main.pcapng 185.199.110.133 → 192.168.1.10
                                // in health vs 192.168.1.10 → 185.199.110.133
                                // in the CSV).
                                const o = flowInitiatorFlip(f, packets)
                                  ? { srcIp: f.dstIp, srcPort: f.dstPort, dstIp: f.srcIp, dstPort: f.srcPort }
                                  : { srcIp: f.srcIp, srcPort: f.srcPort, dstIp: f.dstIp, dstPort: f.dstPort }
                                return (
                                <tr key={f.id} className="border-b border-border/30">
                                  <td className="py-1.5 pr-2 font-mono truncate max-w-[200px]">{o.srcIp}:{o.srcPort} → {o.dstIp}:{o.dstPort}</td>
                                  <td className="py-1.5 pr-2 text-right font-mono">{f.packets}</td>
                                  <td className="py-1.5 pr-2 text-right font-mono">{f.dataSegments ?? "—"}</td>
                                  <td className="py-1.5 pr-2 text-right font-mono">{f.rttMs ? f.rttMs : "n/a"}</td>
                                  <td className="py-1.5 pr-2 text-right font-mono">{f.retrans ?? 0}</td>
                                  <td className="py-1.5 pr-2 text-right font-mono">{f.lossPct ?? "—"}</td>
                                  <td className="py-1.5 pr-2 text-right">{(() => { const e = estimatedTcpLoss(f); return e.confidence && <Badge variant={e.confidence === "HIGH" ? "default" : e.confidence === "MEDIUM" ? "warning" : "outline"} className="text-[9px]" title={`Loss confidence scales with the observed data-segment sample, never the total packet count — ${e.confidenceReason}; ${e.retrans} retransmission(s) over ${e.dataSegments} data segments of ${e.totalPackets} packets; control segments carry no loss evidence`}>{e.confidence}</Badge> })()}</td>
                                  <td className="py-1.5 pr-2 text-right font-mono">{f.ooo ?? 0}</td>
                                  <td className="py-1.5 pr-2 text-right font-mono">{f.zeroWindow ?? 0}</td>
                                  <td className="py-1.5 text-right font-mono">{f.rstCount ?? 0}</td>
                                </tr>
                                )
                              })}
                            </tbody>
                          </table>
                        </div>
                        <p className="text-[10px] text-muted-foreground mt-1">Endpoints are listed initiator-first, like the flows table and the CSV export. Est. Retrans Loss % = retransmissions &divide; observed data segments (both directions summed; a segment is a packet carrying TCP payload) — it is an ESTIMATE from the observed sample, never a measured packet-loss rate, and a flow&rsquo;s Pkts column also counts control segments (SYN/SYN-ACK/ACK/FIN/RST) that carry no loss evidence. The Data Seg column exposes the exact denominator so every displayed percentage is reproducible (&ldquo;1 retransmission / 10 data segments = 10%&rdquo;, never &ldquo;1 of 19 packets&rdquo;). Loss Conf scales with the data-segment sample (&ge;100 HIGH, 20&ndash;99 MED, &lt;20 LOW) — a 50% estimate from 2 data segments is far weaker than from 10,000, and 100 pure-ACK packets over 2 data segments still rate LOW. Retransmissions are summed over both directions and are not attributed to a side.</p>
                      </div>
                    )
                  })()}
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={MessagesSquare} title="5. Sessions" />
              <Card>
                <CardContent className="pt-6">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">Initiator</th>
                          <th className="text-left py-2 pr-2">Responder</th>
                          <th className="text-left py-2 pr-2">Proto</th>
                          <th className="text-right py-2 pr-2">Pkts</th>
                          <th className="text-right py-2 pr-2">Bytes</th>
                          <th className="text-left py-2">State</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sessionTableRows(sessions, packets).slice(0, 15).map((s) => (
                          <tr key={s.id} className="border-b border-border/30">
                            <td className="py-1.5 pr-2 font-mono hl-src">{s.srcIp}:{s.srcPort}</td>
                            <td className="py-1.5 pr-2 font-mono">{s.dstIp}:{s.dstPort}</td>
                            <td className="py-1.5 pr-2"><Badge variant="outline" className="text-[10px]">{s.protocol}</Badge></td>
                            <td className="py-1.5 pr-2 text-right">{s.packets}</td>
                            <td className="py-1.5 pr-2 text-right text-muted-foreground">{formatBytes(s.bytes)}</td>
                            <td className="py-1.5"><Badge variant="outline" className={"text-[10px] " + (s.state === "ESTABLISHED" ? "bg-success/10 text-success" : s.state === "CLOSED" ? "bg-muted text-muted-foreground" : s.state === "RESET" ? "bg-destructive/10 text-destructive" : "bg-warning/10 text-warning")}>{s.state}</Badge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {sessions.length > 15 && <div className="text-[10px] text-muted-foreground mt-1">Showing the 15 largest sessions of {sessions.length.toLocaleString()} — the Analysis page lists all sessions.</div>}
                  <p className="text-[10px] text-muted-foreground mt-1">Rows are initiator-first, like the CSV export: the side that sent the first SYN (or the first observed packet) is the Initiator, with its sent/received byte counts. Detection always reads the original packet direction from the wire, never this display order.</p>
                  <p className="text-xs text-muted-foreground mt-3">Sessions mirror flows one-to-one (one session per direction-normalized conversation; states come from the observed handshake — INITIATED = SYN seen but no completion, HALF_OPEN = SYN-ACK replied but never completed, ESTABLISHED = full handshake or mid-stream capture, RESET/CLOSED, STATELESS = non-TCP). Higher-level, multi-flow session reconstruction is not implemented.</p>
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={Globe} title="6. DNS Analysis" />
              <Card>
                <CardContent className="pt-6 space-y-4">
                  <div className="grid grid-cols-4 gap-4 text-xs">
                    <StatGrid items={[
                      { label: "DNS Messages", value: dns.length.toLocaleString(), sub: "queries + responses" },
                      { label: "Query Packets", value: dnsQueries.toLocaleString(), sub: "client-originated" },
                      { label: "Distinct Lookups", value: dnsLookupCount(dns).toLocaleString(), sub: "name+type, relay copies collapsed" },
                      { label: "Unique Domains", value: dnsUniqueDomains(dns).size.toLocaleString(), sub: "distinct names — case-insensitive, trailing dot stripped" },
                    ]} />
                  </div>
                  <div className="grid grid-cols-2 gap-4 text-xs">
                    <StatGrid tint items={[
                      { label: "Failed (NXDOMAIN)", value: dns.filter((d) => d.responseCode === "NXDOMAIN").length.toLocaleString() },
                      { label: "Resolution Source", value: dns.filter((d) => d.isResponse && (d.answer && d.answer !== '\u2014')).length.toLocaleString(), sub: "responses carrying an answer" },
                    ]} />
                  </div>
                  <p className="text-[10px] text-muted-foreground">Terminology: every decoded DNS message counts once (DNS Messages); of those, the messages carrying a question count as Query Packets; Distinct Lookups counts each name+type once for the capturing client — a LAN router relaying a query upstream is not counted as a second querier; Unique Domains counts each distinct queried name once (case-insensitive, trailing dots stripped — "Example.COM." and "example.com" are one domain). The four numbers therefore describe different scopes and should not be expected to agree{dns.length <= 15 ? " (the table below still lists every DNS message: queries and responses)" : ""}.</p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">Time</th>
                          <th className="text-left py-2 pr-2">Source</th>
                          <th className="text-left py-2 pr-2">Query</th>
                          <th className="text-left py-2 pr-2">Type</th>
                          <th className="text-left py-2">Response</th>
                        </tr>
                      </thead>
                      <tbody>
                        {dns.slice(0, 15).map((d) => (
                          <tr key={d.id} className="border-b border-border/30">
                            <td className="py-1.5 pr-2 font-mono text-muted-foreground whitespace-nowrap hl-time">{formatTime(d.timestamp)}</td>
                            <td className="py-1.5 pr-2 font-mono hl-src">{d.srcIp}</td>
                            <td className="py-1.5 pr-2 font-mono truncate max-w-[200px]">{d.query}</td>
                            <td className="py-1.5 pr-2"><Badge variant="outline" className="text-[10px]">{d.type}</Badge></td>
                            <td className="py-1.5"><Badge variant={d.responseCode === "NXDOMAIN" ? "destructive" : "success"} className="text-[10px]">{d.responseCode}</Badge></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {dns.length > 15 && <div className="text-[10px] text-muted-foreground mt-1">Showing the first 15 of {dns.length.toLocaleString()} DNS messages in capture order — the Analysis page lists all {dns.length.toLocaleString()}.</div>}
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={FileText} title="7. HTTP Analysis" />
              <Card>
                <CardContent className="pt-6 space-y-4">
                  <div className="grid grid-cols-4 gap-4 text-xs">
                    <StatGrid items={[
                      { label: "Requests", value: http.length.toLocaleString() },
                      { label: "Hosts", value: new Set(http.map((h) => dnsNameOf(h.host)).filter(Boolean)).size.toLocaleString() },
                      { label: "Errors (4xx/5xx)", value: http.filter((h) => h.status >= 400).length.toLocaleString() },
                      { label: "HTTP Bytes", value: formatBytes(http.reduce((s, h) => s + h.length, 0)), sub: "Total HTTP request+response bytes carried by the capture (headers and bodies) — distinct from downloadable file bodies, which section 10 reports separately." },
                    ]} />
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">Time</th>
                          <th className="text-left py-2 pr-2">Method</th>
                          <th className="text-left py-2 pr-2">URI</th>
                          <th className="text-left py-2 pr-2">Host</th>
                          <th className="text-left py-2 pr-2">Dest IP</th>
                          <th className="text-right py-2 pr-2">Status</th>
                          <th className="text-left py-2 pr-2">Content-Type</th>
                          <th className="text-left py-2">User-Agent</th>
                        </tr>
                      </thead>
                      <tbody>
                        {http.slice(0, 15).map((h) => (
                          <tr key={h.id} className="border-b border-border/30">
                            <td className="py-1.5 pr-2 font-mono text-muted-foreground whitespace-nowrap hl-time">{formatTime(h.timestamp)}</td>
                            <td className="py-1.5 pr-2"><Badge variant="outline" className="text-[10px]">{h.method}</Badge></td>
                            <td className="py-1.5 pr-2 font-mono truncate max-w-[160px]">{h.uri}</td>
                            <td className="py-1.5 pr-2 text-muted-foreground">{h.host}</td>
                            <td className="py-1.5 pr-2 font-mono">{h.dstIp}</td>
                            <td className="py-1.5 pr-2 text-right"><Badge variant="outline" className={"text-[10px] " + (h.status === 0 ? "bg-muted/40 text-muted-foreground" : h.status < 300 ? "bg-success/10 text-success" : h.status < 400 ? "bg-info/10 text-info" : "bg-danger/10 text-danger")}>{h.status}</Badge></td>
                            <td className="py-1.5 pr-2 text-muted-foreground truncate max-w-[120px]">{h.contentType}</td>
                            <td className="py-1.5 text-muted-foreground truncate max-w-[180px]">{h.userAgent}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {http.some((h) => h.status === 0) && (
                    <p className="text-[10px] text-muted-foreground">Status 0 = no HTTP response was captured for that request (capture ended before the response, the connection closed, or the response was not observed) — it does not mean the request failed.</p>
                  )}
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={Shield} title="8. TLS Analysis" />
              <Card>
                <CardContent className="pt-6 space-y-4">
                  <div className="grid grid-cols-4 gap-4 text-xs">
                    <StatGrid items={[
                      { label: "Handshakes", value: tls.length.toLocaleString() },
                      { label: "TLSv1.3", value: tls.filter((t) => t.version === "TLSv1.3" || t.version === "TLS 1.3").length.toLocaleString() },
                      { label: "TLSv1.2", value: tls.filter((t) => t.version === "TLSv1.2" || t.version === "TLS 1.2").length.toLocaleString() },
                      { label: "SNIs", value: new Set(tls.map((t) => dnsNameOf(t.sni)).filter(Boolean)).size.toLocaleString() },
                    ]} />
                  </div>
                  {tls.length === 0 && (
                    <div className="border border-muted rounded p-3 text-xs text-muted-foreground space-y-1">
                      <p className="font-medium text-foreground">No TLS ClientHello or ServerHello packets were observed.</p>
                      <p>Possible reasons:</p>
                      <ul className="list-disc pl-4 space-y-0.5">
                        <li>The capture started after TLS handshakes were established</li>
                        <li>Traffic was already encrypted when capture began</li>
                        <li>No TLS traffic was present in the capture</li>
                      </ul>
                    </div>
                  )}
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">Source</th>
                          <th className="text-left py-2 pr-2">SNI</th>
                          <th className="text-left py-2 pr-2">Version</th>
                          <th className="text-left py-2">Cipher Suite</th>
                        </tr>
                      </thead>
                      <tbody>
                        {tls.slice(0, 15).map((t) => (
                          <tr key={t.id} className="border-b border-border/30">
                            <td className="py-1.5 pr-2 font-mono hl-src">{t.srcIp}</td>
                            <td className="py-1.5 pr-2 font-mono truncate max-w-[150px]">{t.sni}</td>
                            <td className="py-1.5 pr-2"><Badge variant={t.version === "TLSv1.3" || t.version === "TLS 1.3" ? "success" : "default"} className="text-[10px]">{t.version}</Badge></td>
                            <td className="py-1.5 text-muted-foreground font-mono text-[10px] truncate max-w-[200px]">{t.cipherSuite}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {tls.length > 15 && <div className="text-[10px] text-muted-foreground mt-1">Showing the first 15 of {tls.length.toLocaleString()} TLS handshakes in capture order — the Analysis page lists all {tls.length.toLocaleString()}.</div>}
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={Compass} title="9. Notable Destinations" sub={`${report.notables.length.toLocaleString()} curated families — not security findings`} />
              <Card>
                <CardContent className="pt-6">
                  {report.notables.length === 0 ? (
                    <p className="text-xs text-muted-foreground">No destinations matched the curated notable families (threat-intelligence services, disposable/temporary email providers, DNS-over-HTTPS resolvers, Tor/anonymization projects, user-hosted github.io content) — a curated-list negative only: it does not establish that the endpoints are benign or reputable, and it says nothing about destinations outside the list.</p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="border-b text-muted-foreground">
                            <th className="text-left py-2 pr-2">Destination</th>
                            <th className="text-left py-2">Category</th>
                          </tr>
                        </thead>
                        <tbody>
                          {report.notables.map((n) => (
                            <tr key={n.domain} className="border-b border-border/30">
                              <td className="py-1.5 pr-2 font-mono text-[10px]">{n.domain}</td>
                              <td className="py-1.5"><Badge variant="outline" className="text-[10px]">{n.category}</Badge></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                  <p className="text-[10px] text-muted-foreground mt-2">Neutral context, never a finding: these destinations appear in both benign and malicious traffic (e.g. urlhaus-api.abuse.ch is a threat-intelligence lookup service — querying it does not mean the host is infected). The families are curated and not exhaustive; they are listed so notable traffic does not disappear into a SAFE verdict.</p>
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={FolderOpen} title="10. Extracted HTTP Payloads" />
              <Card>
                <CardContent className="pt-6">
                  <div className="grid grid-cols-3 gap-4 text-xs mb-4">
                    <StatGrid items={[
                      { label: "Total Payloads", value: files.length.toLocaleString() },
                      { label: "Total Size", value: formatBytes(files.reduce((s, f) => s + f.size, 0)) },
                      { label: "MIME Types", value: new Set(files.map((f) => (f.mimeType || "").toLowerCase()).filter(Boolean)).size.toLocaleString() },
                    ]} />
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">Kind</th>
                          <th className="text-left py-2 pr-2">Filename</th>
                          <th className="text-left py-2 pr-2">Type</th>
                          <th className="text-right py-2 pr-2">Size</th>
                          <th className="text-left py-2">MD5</th>
                        </tr>
                      </thead>
                      <tbody>
                        {files.slice(0, 20).map((f) => (
                          <tr key={f.id} className="border-b border-border/30">
                            <td className="py-1.5 pr-2 whitespace-nowrap">{f.kind === "file-transfer" ? "file upload" : "form body"}</td>
                            <td className="py-1.5 pr-2 font-mono truncate max-w-[200px]">{f.filename || '\u2014'}</td>
                            <td className="py-1.5 pr-2 text-muted-foreground">{f.mimeType}</td>
                            <td className="py-1.5 pr-2 text-right text-muted-foreground">{formatBytes(f.size)}</td>
                            <td className="py-1.5 font-mono text-[10px] text-muted-foreground">{f.md5}</td>
                          </tr>
                        ))}
                        {files.length > 20 && (
                          <tr><td colSpan={5} className="py-1.5 text-xs text-muted-foreground">… and {files.length - 20} more (see the Files page for the full list)</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  {files.length === 0 && (
                    <div className="border border-muted rounded p-3 text-xs text-muted-foreground space-y-1">
                      <p className="font-medium text-foreground">No downloadable file bodies were captured.</p>
                      <p>Reason: {report.emptyReasons.files}</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={Phone} title="11. VoIP / SIP Calls" sub={calls.length > 0 ? `${calls.length.toLocaleString()} SIP dialogs observed` : undefined} />
              <Card>
                <CardContent className="pt-6">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">Caller</th>
                          <th className="text-left py-2 pr-2">Callee</th>
                          <th className="text-left py-2 pr-2">Status</th>
                          <th className="text-left py-2 pr-2">Start</th>
                          <th className="text-right py-2 pr-2">Duration</th>
                          <th className="text-right py-2 pr-2">RTP Packets</th>
                          <th className="text-right py-2">RTP Payload</th>
                        </tr>
                      </thead>
                      <tbody>
                        {calls.slice(0, 20).map((c) => (
                          <tr key={c.id} className="border-b border-border/30">
                            <td className="py-1.5 pr-2 font-mono hl-from">{c.from}</td>
                            <td className="py-1.5 pr-2 font-mono text-muted-foreground hl-to">{c.to}</td>
                            <td className="py-1.5 pr-2"><Badge variant={c.status.includes("200") ? "success" : "outline"} className="text-[10px] hl-status">{c.status}</Badge></td>
                            <td className="py-1.5 pr-2 text-muted-foreground hl-start">{formatTime(c.startTime)}</td>
                            <td className="py-1.5 pr-2 text-right text-muted-foreground hl-dur">{c.durationSec !== null ? fmtClock(c.durationSec) : "—"}</td>
                            <td className="py-1.5 pr-2 text-right text-muted-foreground hl-rtp">{c.rtpPackets > 0 ? c.rtpPackets.toLocaleString() : "—"}</td>
                            <td className="py-1.5 text-right text-muted-foreground hl-pt">{c.rtpPayloadType !== null ? `PT ${c.rtpPayloadType}` : "—"}</td>
                          </tr>
                        ))}
                        {calls.length > 20 && (
                          <tr><td colSpan={7} className="py-1.5 text-xs text-muted-foreground">… and {calls.length - 20} more</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  {calls.length === 0 && (
                    <div className="border border-muted rounded p-3 text-xs text-muted-foreground space-y-1">
                      <p className="font-medium text-foreground">No VoIP traffic detected.</p>
                      <p>No SIP signalling (UDP/TCP 5060/5061 or a SIP start line) or RTP media (version-2 header, non-zero SSRC) was observed in the capture.</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </section>

            <section>
              <div className="flex items-center justify-between">
                <SectionTitle icon={Key} title="12. Credential Submissions" sub={credentials.length > 0 ? `${credentials.length.toLocaleString()} submission${credentials.length === 1 ? "" : "s"} · ${new Set(credentials.map((c) => c.username)).size.toLocaleString()} unique username${new Set(credentials.map((c) => c.username)).size === 1 ? "" : "s"}` : undefined} />
                {credentials.length > 0 && (
                  <Button variant="ghost" size="sm" onClick={() => setShowPasswords(!showPasswords)}>
                    {showPasswords ? "Hide passwords" : "Show passwords"}
                  </Button>
                )}
              </div>
              <Card>
                <CardContent className="pt-6">
                  <div className="grid grid-cols-3 gap-4 text-xs mb-4">
                    <StatGrid items={[
                      { label: "Submissions", value: credentials.length.toLocaleString() },
                      { label: "Unique Usernames", value: new Set(credentials.map((c) => c.username)).size.toLocaleString() },
                      { label: "Services", value: new Set(credentials.map((c) => c.service)).size.toLocaleString() },
                    ]} />
                  </div>
                  <p className="text-[10px] text-muted-foreground mb-3">
                    Each row is one HTTP request whose <strong>decoded body carried a username and/or password field</strong> —
                    a credential submission is not every HTTP payload, and the password value above is shown redacted by
                    default. The detection alert cites the exact request(s) and capture packet numbers in its Evidence.
                  </p>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">Source</th>
                          <th className="text-left py-2 pr-2">Username</th>
                          <th className="text-left py-2 pr-2">Password</th>
                          <th className="text-left py-2">Service</th>
                        </tr>
                      </thead>
                      <tbody>
                        {credentials.slice(0, 20).map((c) => (
                          <tr key={c.id} className="border-b border-border/30">
                            <td className="py-1.5 pr-2 font-mono hl-src">{c.srcIp}</td>
                            <td className="py-1.5 pr-2 text-warning font-medium hl-user">{c.username}</td>
                            <td className="py-1.5 pr-2 font-mono text-muted-foreground hl-pass">{showPasswords ? c.password : "••••••••"}</td>
                            <td className="py-1.5"><Badge variant="outline" className="text-[10px] hl-svc">{c.service}</Badge></td>
                          </tr>
                        ))}
                        {credentials.length > 20 && (
                          <tr><td colSpan={4} className="py-1.5 text-xs text-muted-foreground">… and {credentials.length - 20} more (see the Credentials page for the full list)</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  {credentials.length === 0 && (
                    <div className="border border-muted rounded p-3 text-xs text-muted-foreground space-y-1">
                      <p className="font-medium text-foreground">No credential submissions detected.</p>
                      <p>Reason: {report.emptyReasons.credentials}</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={Verified} title="13. Certificates" sub={`${certificates.length.toLocaleString()} unique certificate${certificates.length === 1 ? "" : "s"} — deduplicated by subject+serial across the capture; a session contributes a certificate only when its Certificate message was captured (resumed sessions and captures that begin mid-handshake contribute none)`} />
              <Card>
                <CardContent className="pt-6">
                  <div className="grid grid-cols-3 gap-4 text-xs mb-4">
                    <StatGrid items={[
                      { label: "Unique", value: certificates.length.toLocaleString() },
                      { label: "Expired", value: certificates.filter((c) => c.notAfter !== null && new Date(c.notAfter) < new Date(certRef)).length.toLocaleString() },
                      { label: "Valid", value: certificates.filter((c) => c.notAfter !== null && new Date(c.notAfter) >= new Date(certRef)).length.toLocaleString() },
                    ]} />
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">Subject</th>
                          <th className="text-left py-2 pr-2">Issuer</th>
                          <th className="text-left py-2 pr-2">Serial</th>
                          <th className="text-left py-2">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {certificates.slice(0, 20).map((c) => (
                          <tr key={c.id} className="border-b border-border/30">
                            <td className="py-1.5 pr-2 font-mono truncate max-w-[200px]">{c.subject}</td>
                            <td className="py-1.5 pr-2 text-muted-foreground truncate max-w-[200px]">{c.issuer}</td>
                            <td className="py-1.5 pr-2 font-mono text-[10px] text-muted-foreground truncate max-w-[160px]">{c.serial || "-"}</td>
                            <td className="py-1.5"><Badge variant={c.notAfter === null ? "outline" : new Date(c.notAfter) >= new Date(certRef) ? "success" : "destructive"} className="text-[10px]">{c.notAfter === null ? "Unknown" : new Date(c.notAfter) >= new Date(certRef) ? "Valid" : "Expired"}</Badge></td>
                          </tr>
                        ))}
                        {certificates.length > 20 && (
                          <tr><td colSpan={4} className="py-1.5 text-xs text-muted-foreground">… and {certificates.length - 20} more (see the Certificates page for the full list)</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  {certificates.length === 0 && (
                    <div className="border border-muted rounded p-3 text-xs text-muted-foreground space-y-1">
                      <p className="font-medium text-foreground">No certificates extracted.</p>
                      <p>Reason: {report.emptyReasons.certificates}</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={Monitor} title="14. Endpoints" sub={`${endpointRows.length.toLocaleString()} endpoints observed on the network`} />
              <Card>
                <CardContent className="pt-6">
                  <div className="grid grid-cols-4 gap-4 text-xs mb-4">
                    <StatGrid tint items={[
                      { label: "🖥 Local Devices", value: stats.devices.toLocaleString(), accent: "text-info", sub: "private IPs — remote services excluded" },
                      // External IPs and remote endpoints are distinct metrics
                      // (QA): externalIps counts every external IP seen in
                      // traffic, remote endpoints counts device rows without a
                      // local identity — an off-link peer that never ARPed
                      // (e.g. an IPv6 destination) has no MAC row, so it is an
                      // external IP without an endpoint entry. Both numbers on
                      // one card, footnote only when they actually differ.
                      { label: "🌐 Remote Endpoints", value: `${stats.externalIps} external IPs · ${remoteEndpointCount} remote endpoints`, accent: "text-info" },
                      { label: "🏭 Vendors", value: (() => { const known = new Set(devices.map((d) => d.vendor).filter(Boolean)); return known.size > 0 ? known.size.toLocaleString() : "—" })(), accent: "text-success" },
                      // sum of per-device packet totals double-counts (src+dst row each) — the
                      // honest number is the capture's unique packet count. 1049 must render
                      // "1.0k pkts", not "1.0 pkts" (k suffix was missing).
                      { label: "📦 Endpoint Packets", value: (packets.length >= 1000 ? (packets.length / 1000).toFixed(1) + "k" : String(packets.length)) + " pkts", accent: "text-muted-foreground", sub: `${packets.length.toLocaleString()} unique packets in the capture` },
                    ]} />
                  </div>
                  {stats.externalIps !== remoteEndpointCount && (
                    <p className="text-xs text-muted-foreground border border-border/40 rounded px-2 py-1.5 mb-3">
                      External IPs ({stats.externalIps}) and remote endpoints ({remoteEndpointCount}) differ: a peer that never ARPed — e.g. an off-link IPv6 destination — is counted as an external IP but has no MAC identity, so no endpoint row.
                    </p>
                  )}
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">Type</th>
                          <th className="text-left py-2 pr-2">IP</th>
                          <th className="text-left py-2 pr-2">MAC</th>
                          <th className="text-left py-2 pr-2">Hostname</th>
                          <th className="text-left py-2 pr-2">Vendor</th>
                          <th className="text-right py-2">Pkts</th>
                        </tr>
                      </thead>
                      <tbody>
                        {endpointRows.slice(0, 20).map((d) => {
                          // Off-link endpoints: the MAC/vendor columns describe
                          // the next-hop frame (the router's ARP answer), NOT the
                          // remote host — showing them as the remote's identity is
                          // fabricated (QA: Nokia/6c:22:f7 rows). Suppress both.
                          const offLink = !isPrivateIP(d.ip)
                          return (
                          <tr key={d.id} className="border-b border-border/30">
                            <td className="py-2 pr-2">
                              <span className={cn("inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold", isPrivateIP(d.ip) ? "bg-success/10 text-success border border-success/20" : "bg-info/10 text-info border border-info/20")}>
                                {isPrivateIP(d.ip) ? "💻 Local" : "🌐 Remote"}
                              </span>
                            </td>
                            <td className="py-2 pr-2 font-mono ip-addr" title={d.ip}>{shortIp(d.ip)}</td>
                            <td className="py-2 pr-2 font-mono text-muted-foreground">{offLink ? "—" : displayMac(d.mac)}</td>
                            <td className="py-2 pr-2">{d.hostname && d.hostname !== d.ip ? d.hostname : <span className="text-muted-foreground italic">Not resolved</span>}</td>
                            <td className="py-2 pr-2 text-muted-foreground">{offLink ? "—" : (vendorLabel(d.vendor, displayMac(d.mac)) || "—")}</td>
                            <td className="py-2 text-right">{d.packets.toLocaleString()}</td>
                          </tr>
                          )
                        })}
                        {endpointRows.length > 20 && (
                          <tr><td colSpan={6} className="py-1.5 text-xs text-muted-foreground">… and {endpointRows.length - 20} more (see the Devices page for the full list)</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={AlertTriangle} title="15. Threats & Alerts" sub={`${alerts.length.toLocaleString()} alerts · Severity: ${severityCounts(alerts)} · Status: ${statusCountsLabel(summarizeStatuses(alerts))}`} />
              <Card>
                <CardContent className="pt-6 space-y-4">
                  <div className="grid grid-cols-5 gap-4 text-xs">
                    <StatGrid tint items={[
                      { label: "⚠️ Total Alerts", value: alerts.length.toLocaleString(), accent: "text-danger" },
                      { label: "🔴 Critical", value: alerts.filter((t) => t.severity >= 5).length.toLocaleString(), accent: "text-danger" },
                      { label: "🟠 High", value: alerts.filter((t) => t.severity === 4).length.toLocaleString(), accent: "text-warning" },
                      { label: "🟡 Medium", value: alerts.filter((t) => t.severity === 3).length.toLocaleString(), accent: "text-warning" },
                      { label: "🟢 Low", value: alerts.filter((t) => t.severity <= 2).length.toLocaleString(), accent: "text-success" },
                    ]} />
                  </div>
                  {alerts.length === 0 && advancedMetrics && (advancedMetrics.beaconDetected || advancedMetrics.dnsTunnelingSuspected || advancedMetrics.dataExfiltrationSuspected || advancedMetrics.torVpnProxyDetected || advancedMetrics.ja3Suspicious) && (
                    <p className="text-xs text-muted-foreground border border-warning/30 bg-warning/5 rounded p-2">
                      No behavioral detection rules triggered, but the anomaly heuristics in the Risk Score section detected behavioral flags.
                      Behavioral rules and heuristic anomalies are computed independently; see sections 16-19 for the heuristic findings.
                    </p>
                  )}
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b text-muted-foreground">
                          <th className="text-left py-2 pr-2">Time</th>
                          <th className="text-left py-2 pr-2">Signature</th>
                          <th className="text-left py-2 pr-2">Src → Dst</th>
                          <th className="text-right py-2 pr-2">Pkts</th>
                          <th className="text-right py-2 pr-2">Bytes</th>
                          <th className="text-right py-2 pr-2">Conf</th>
                          <th className="text-left py-2 pr-2">Severity</th>
                          <th className="text-left py-2">Evidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.groups.map((g) => (
                          <tr key={g.ruleId + "::" + g.signature} className="border-b border-border/30">
                            <td className="py-1.5 pr-2 font-mono text-muted-foreground whitespace-nowrap hl-time text-xs">{g.occurrences > 1 ? `${formatTime(g.firstSeen)} – ${formatTime(g.lastSeen)}` : formatTime(g.firstSeen)}</td>
                            <td className="py-1.5 pr-2 text-xs">{g.signature} <span className="text-muted-foreground">×{g.occurrences}</span> <Badge variant={g.status === "CONFIRMED" ? "default" : g.status === "LIKELY" ? "warning" : "outline"} className="text-[9px]">{g.status ?? "CONFIRMED"}</Badge>{g.evidenceQuality && <Badge variant="outline" className="text-[9px] ml-1" title="Evidence quality — the strength of the underlying evidence, separate from the numeric confidence">Evidence {g.evidenceQuality}</Badge>}</td>
                            <td className="py-1.5 pr-2 font-mono text-xs">{g.srcHosts.join(", ")} → {g.dstHosts.join(", ")}</td>
                            <td className="py-1.5 pr-2 text-right text-muted-foreground" title={g.packets == null ? "Full capture packet rows were not retained for this flow" : undefined}>{g.packets == null ? "N/A" : g.packets.toLocaleString()}</td>
                            <td className="py-1.5 pr-2 text-right text-muted-foreground" title={g.bytes == null ? "Full capture packet rows were not retained for this flow" : undefined}>{g.bytes == null ? "N/A" : formatBytes(g.bytes)}</td>
                            <td className="py-1.5 pr-2 text-right">{g.confidence}%</td>
                            <td className="py-1.5"><Badge variant={g.severity >= 4 ? "destructive" : g.severity >= 3 ? "warning" : "default"} className="text-[10px]">{sevLabel(g.severity)}</Badge></td>
                            <td className="py-1.5 pr-2 text-xs text-muted-foreground">{g.evidence}{g.flowIds.length > 0 && <span className="font-mono text-[10px] text-muted-foreground/70"> · flows {g.flowIds.slice(0, 3).join(", ")}{g.flowIds.length > 3 ? "…" : ""}</span>}{g.packetRange && <span className="font-mono text-[10px] text-muted-foreground/70"> · packets {g.packetRange[0]}–{g.packetRange[1]}</span>}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {report.groups.some((g) => g.ruleId === "DATA-EXFIL-001") && (
                    <p className="text-[10px] text-muted-foreground border border-border/30 rounded p-2">
                      <strong>DATA-EXFIL-001</strong> fires on a directional byte-ratio rule: a local host sent more than
                      100&nbsp;KB with at least 5× more sent than received. The finding is <strong>behavior only</strong> — the
                      capture carries no payload evidence of what the bytes contained, retransmitted bytes are included in
                      the counts as captured, the destination is not established as malicious, and a normal upload, API call
                      or sync can match the same pattern.
                    </p>
                  )}
                  <div className="text-[10px] text-muted-foreground mt-1">Detection states come from evidence quality: CONFIRMED = payload-verified (e.g. cleartext credentials decoded from the wire); LIKELY = strong multi-indicator or high-evidence behavioral findings; SUSPECTED = a rule crossed its threshold on weaker evidence (scans, floods and behavioral heuristics can never reach CONFIRMED — the evidence is pattern-based, and the finding text says so). The Evidence badge (LOW/MEDIUM/HIGH) is the strength of that evidence — separate from the numeric confidence, which is the detector&rsquo;s calibration: payload-verified findings carry 100% and HIGH, a 24-port scan reads ~62% and MEDIUM. C2-beacon, exfil and DNS-tunnel rules that fire during a detected traffic burst get a bonus in the Risk Breakdown (e.g. 70% base can appear there as 85%), and behavioral detections state their measured basis in Evidence &mdash; see the risk contribution formula under &ldquo;Risk Breakdown&rdquo;. MITRE mappings are attached only to LIKELY/CONFIRMED detections. Pkts/Bytes read N/A when an alert spans multiple flows &mdash; the Evidence column then carries the measured numbers.</div>
                </CardContent>
              </Card>
            </section>

            <section>
              <SectionTitle icon={History} title="16. Timeline" sub={`${report.timeline.length.toLocaleString()} sampling intervals`} />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card>
                  <CardHeader><CardTitle className="text-sm">Packet Activity {report.timeline.length > 1 && <span className="text-muted-foreground font-normal">({report.timeline.length} intervals)</span>}</CardTitle></CardHeader>
                  <CardContent>
                    <table>
                      <tbody>
                        {report.timeline.map((t, i) => (
                          <tr key={t.time} className="align-middle">
                            <td className="w-24 font-mono whitespace-nowrap">{t.time}</td>
                            <td className="w-full">
                              <div className="h-3 bg-muted rounded-full overflow-hidden">
                                <div className="h-full bg-info rounded-full" style={{ width: (t.packets / maxPkts * 100) + "%" }} />
                              </div>
                            </td>
                            <td className="w-12 text-right font-mono whitespace-nowrap">{t.packets}</td>
                            <td className="w-4">
                              {alertsByBin.get(i)?.length ? (
                                <span className="inline-block h-2.5 w-2.5 rounded-full bg-danger align-middle" title={alertsByBin.get(i)!.map((a) => a.signature).join(", ")} />
                              ) : null}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {alertDots.length > 0 && (
                      <div className="mt-2 space-y-0.5">
                        {alertDots.map((d, i) => (
                          <div key={`${d.time}${d.signature}${i}`} className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                            <span className="inline-block h-2 w-2 rounded-full bg-danger" title={d.signature} />
                            <span className="font-mono">{d.time} {d.name}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader><CardTitle className="text-sm">Bandwidth</CardTitle></CardHeader>
                  <CardContent>
                    <table>
                      <tbody>
                        {report.bandwidth.map((b) => (
                          <tr key={b.time} className="align-middle">
                            <td className="w-24 font-mono whitespace-nowrap">{b.time}</td>
                            <td className="w-full">
                              <div className="h-3 bg-muted rounded-full overflow-hidden">
                                <div className="h-full bg-chart-2 rounded-full" style={{ width: ((b.in + b.out) / maxBw * 100) + "%" }} />
                              </div>
                            </td>
                            <td className="w-16 text-right font-mono whitespace-nowrap">{formatBytes(b.out + b.in)}/s</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </CardContent>
                </Card>
              </div>
            </section>

            <section>
              <SectionTitle icon={BarChart3} title="17. Top Talkers" />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card>
                  <CardHeader><CardTitle className="text-sm">Source IPs</CardTitle></CardHeader>
                  <CardContent className="space-y-2">
                    {topSrcIps.length === 0 && <p className="text-xs text-muted-foreground">No decodable addresses — capture encapsulation unsupported ({linkTypes.length > 0 ? dltName(linkTypes) : "unknown"}).</p>}
                    {topSrcIps.slice(0, 5).map(({ ip, count, bytes }) => {
                      const detail = talkerFlows.src.get(ip)
                      const conns = srcConns[ip]?.size ?? 0
                      const protos = srcProtos[ip] ? [...srcProtos[ip]!].sort().join(", ") : ""
                      return (
                        <div key={ip} className="flex justify-between gap-2 text-xs py-1 border-b border-border/30 last:border-0">
                          <div className="min-w-0">
                            <div className="font-mono truncate">{ip}</div>
                            <div className="text-[10px] text-muted-foreground">{hostLabel(ip)}</div>
                            {(detail || conns > 0) && <div className="text-[10px] text-muted-foreground">{[conns > 0 ? `${conns} conns` : null, protos || null, detail && detail.size > 0 ? `services: ${svcList(detail, ip).text}` : null].filter(Boolean).join(" · ")}</div>}
                          </div>
                          <div className="text-right text-muted-foreground whitespace-nowrap">
                            {count.toLocaleString()} pkts · {formatBytes(bytes)}
                            <div className="text-[10px]">({(count / packets.length * 100).toFixed(1)}%)</div>
                            <div className="text-[10px]">avg {ratesAvailable ? formatBytes(bytes / durationSec) + "/s" : "N/A"}</div>
                          </div>
                        </div>
                      )
                    })}
                    {noSrcAddrCount > 0 && <p className="text-[10px] text-muted-foreground pt-1">{noSrcAddrCount.toLocaleString()} packet{noSrcAddrCount === 1 ? "" : "s"} with no decodable source address excluded from this table — not attributable to any host.</p>}
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader><CardTitle className="text-sm">Destination IPs</CardTitle></CardHeader>
                  <CardContent className="space-y-2">
                    {topDstIps.length === 0 && <p className="text-xs text-muted-foreground">No decodable addresses — capture encapsulation unsupported ({linkTypes.length > 0 ? dltName(linkTypes) : "unknown"}).</p>}
                    {topDstIps.slice(0, 5).map(({ ip, count, bytes }) => {
                      const detail = talkerFlows.dst.get(ip)
                      const conns = dstConns[ip]?.size ?? 0
                      const protos = dstProtos[ip] ? [...dstProtos[ip]!].sort().join(", ") : ""
                      return (
                        <div key={ip} className="flex justify-between gap-2 text-xs py-1 border-b border-border/30 last:border-0">
                          <div className="min-w-0">
                            <div className="font-mono truncate">{ip}</div>
                            <div className="text-[10px] text-muted-foreground">{hostLabel(ip)}</div>
                            {(detail || conns > 0) && <div className="text-[10px] text-muted-foreground">{[conns > 0 ? `${conns} conns` : null, protos || null, detail && detail.size > 0 ? `services: ${svcList(detail, ip).text}` : null].filter(Boolean).join(" · ")}</div>}
                          </div>
                          <div className="text-right text-muted-foreground whitespace-nowrap">
                            {count.toLocaleString()} pkts · {formatBytes(bytes)}
                            <div className="text-[10px]">({(count / packets.length * 100).toFixed(1)}%)</div>
                            <div className="text-[10px]">avg {ratesAvailable ? formatBytes(bytes / durationSec) + "/s" : "N/A"}</div>
                          </div>
                        </div>
                      )
                    })}
                    {noDstAddrCount > 0 && <p className="text-[10px] text-muted-foreground pt-1">{noDstAddrCount.toLocaleString()} packet{noDstAddrCount === 1 ? "" : "s"} with no decodable destination address excluded from this table — not attributable to any host.</p>}
                    {talkersShowPortInferred && <p className="text-[10px] text-muted-foreground pt-1">* Service classification inferred from port usage only — no packet payload was payload-verified for that service (payload-verified services are unmarked).</p>}
                  </CardContent>
                </Card>
              </div>
            </section>

            {advancedMetrics && (
              <>
<section>
                  <SectionTitle icon={Shield} title="18. Risk Score" />
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                      { label: "Risk Score", value: riskValue(), color: undecodable ? "text-muted-foreground" : (risk ? riskColorClass({ label: risk.levelLabel, color: risk.levelColor }) : riskColorClass(riskLevel(job.riskScore))), icon: AlertTriangle, sub: !undecodable && scoreVal === 0 ? "no configured detection rule triggered — not a compromise probability" : (!undecodable && verdictStatusHint ? "rule-engine score, not a probability of compromise" : undefined) },
                      { label: "Avg rate (capture span)", value: rateLabel(advancedMetrics.throughputAvg), color: "text-info", icon: BarChart3 },
                      { label: "Peak 100-ms rate", value: rateLabel(advancedMetrics.throughputPeak100ms ?? null), color: "text-chart-2", icon: BarChart3 },
                       { label: "Burst", value: advancedMetrics.burst?.detected ? "Detected" : "Not Detected", color: advancedMetrics.burst?.detected ? "text-danger" : "text-success", icon: Zap, sub: advancedMetrics.burst?.detected ? `${advancedMetrics.burst.ratio.toFixed(1)}× average · ${advancedMetrics.burst.duration.toFixed(1)} s` : undefined },
                    ].map(({ label, value, color, icon: Icon, sub }) => (
                      <Card key={label}>
                        <CardHeader className="pb-2"><CardTitle className={cn("text-sm font-medium", color)}><Icon className="h-4 w-4 inline mr-1" />{label}</CardTitle></CardHeader>
                        <CardContent><div className="text-2xl font-bold">{value}</div>{sub && <div className="text-[10px] text-muted-foreground mt-1">{sub}</div>}</CardContent>
                      </Card>
                    ))}
                  </div>
                  <div className="flex flex-wrap gap-2 mt-4">
                    {advancedMetrics.beaconDetected || advancedMetrics.dnsTunnelingSuspected || advancedMetrics.dataExfiltrationSuspected || advancedMetrics.torVpnProxyDetected || advancedMetrics.ja3Suspicious ? (
                      <>
                        {advancedMetrics.beaconDetected && <Badge variant="destructive">Beaconing Detected</Badge>}
                        {advancedMetrics.dnsTunnelingSuspected && <Badge variant="destructive">DNS Tunneling Suspected</Badge>}
                        {advancedMetrics.dataExfiltrationSuspected && <Badge variant="destructive">Suspected Large Outbound Transfer</Badge>}
                        {advancedMetrics.torVpnProxyDetected && <Badge variant="warning">TOR/VPN/Proxy Detected</Badge>}
                        {advancedMetrics.ja3Suspicious && <Badge variant="destructive">Suspicious JA3</Badge>}
                      </>
                    ) : advancedMetrics.burst?.detected ? (
                      <Badge variant="outline" className="text-info">Traffic burst detected (informational — no anomaly rules fired)</Badge>
                    ) : (
                      <Badge variant="success">No anomalies detected</Badge>
                    )}
                    {advancedMetrics.burst?.detected && risk && !risk.burstApplied && (
                      <p className="text-[10px] text-muted-foreground border border-border/30 rounded p-2 mt-2 w-full">
                        The traffic burst is <strong>not itself evidence of exfiltration</strong> and contributed no
                        confidence bonus to any rule (the burst bonus applies only to C2-beacon, exfil and DNS-tunnel rules
                        — here: <strong>No</strong>). Short high-rate bursts are consistent with normal web, streaming or
                        update traffic.
                      </p>
                    )}
                  </div>

                  <Card className="mt-4">
                    <CardHeader><CardTitle className="text-sm">Throughput Statistics</CardTitle></CardHeader>
                    <CardContent className="space-y-1 text-xs">
                      {[
                        { label: "Average", value: rateLabel(advancedMetrics.throughputAvg) },
                        { label: "Peak (1 s interval)", value: rateLabel(advancedMetrics.throughputPeak) },
                        { label: `Minimum (${bwIntervalLabel} interval)`, value: bwStats.min === null ? "—" : formatBytes(bwStats.min) + "/s" },
                        { label: `Median (${bwIntervalLabel} interval)`, value: bwStats.median === null ? "—" : formatBytes(bwStats.median) + "/s" },
                        { label: `95th percentile (${bwIntervalLabel} interval)`, value: bwStats.p95 === null ? "—" : formatBytes(bwStats.p95) + "/s" },
                      ].map(({ label, value }) => (
                        <div key={label} className="flex justify-between py-0.5">
                          <span className="text-muted-foreground">{label}</span>
                          <span className="font-mono">{value}</span>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                  
                  {risk && (
                    <Card className="mt-4">
                      <CardHeader><CardTitle className="text-sm">Risk Score Breakdown</CardTitle></CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          <div className="border rounded p-3 bg-muted/30">
                            <div className="font-mono text-xs space-y-1">
                              <div className="flex justify-between"><span className="text-muted-foreground">Raw score</span><span className="font-medium">{Math.round(risk.rawScore * 10) / 10}</span></div>
                              <div className="flex justify-between"><span className="text-muted-foreground">Normalization formula</span><span className="font-medium whitespace-nowrap">100 × (1 − exp(−{risk.rawScore} / {RISK_CURVE_K})) ≈ {riskCurve !== null ? riskCurve.toFixed(1) : "—"} → {risk.normalizedScore}/100</span></div>
                              <div className="flex justify-between"><span className="text-muted-foreground">Burst bonus applied <span title="Only C2-beacon, exfil and DNS-tunnel rules receive the burst confidence bonus; a bare burst with nothing to boost shows No.">(C2/exfil/DNS rules only)</span></span><span className="font-medium">{risk.burstApplied ? "Yes" : "No"}</span></div>
                              <div className="flex justify-between"><span className="text-muted-foreground">Normalized score</span><span className="text-foreground font-bold">{undecodable ? "N/A — insufficient data" : `${risk.normalizedScore}/100 ${risk.levelLabel === "SAFE" ? "— no configured detections" : risk.levelLabel}`}{!undecodable && verdictStatusHint && <span className="text-xs text-muted-foreground font-normal">{verdictStatusHint}</span>}</span></div>
                              <div className="flex justify-between"><span className="text-muted-foreground">Assessment confidence</span><span className="font-medium">{undecodable ? "None — undecodable capture" : encSharePct >= 50 ? `Limited — ${Math.round(encSharePct)}% of packets on TCP/443 or UDP/443, treated as encrypted HTTPS/QUIC (port-inferred where payload verification was unavailable); content not decodable` : encSharePct >= 25 ? `Partial — ${Math.round(encSharePct)}% of packets on TCP/443 or UDP/443, treated as encrypted HTTPS/QUIC (port-inferred where payload verification was unavailable)` : "Full — most packets carried decodable application content"}</span></div>
                              <div className="border-t border-border/30 pt-2 mt-2">
                                <div className="font-semibold mb-1 text-xs">Contributions (sorted by impact):</div>
                                {risk.items.length === 0 ? (
                                  <p className="text-xs text-muted-foreground">No rules contributed to the risk score.</p>
                                ) : (
                                <div className="table-wrap">
                                  <table>
                                    <thead>
                                      <tr>
                                        <th>Rule</th>
                                        <th className="text-right">Severity</th>
                                        <th className="text-right">Confidence</th>
                                        <th className="text-right">Weight</th>
                                        <th className="text-right">Contribution (raw pts)</th>
                                        <th className="text-right">Formula</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {[...risk.items].sort((a, b) => b.contribution - a.contribution).map((item) => (
                                        <tr key={item.ruleId + item.srcIp + item.dstIp}>
                                          <td title={item.ruleId}>
                                            <span className={item.effectiveConfidence >= 80 ? "text-danger font-medium" : item.effectiveConfidence >= 50 ? "text-warning font-medium" : ""}>{item.ruleName}</span>
                                          </td>
                                          <td className="text-right">{sevLabel(item.severity)} ({item.severity})</td>
                                          <td className="text-right">{item.effectiveConfidence}%{item.effectiveConfidence !== item.confidence && <span className="text-muted-foreground" title="burst confidence bonus"> (+{item.effectiveConfidence - item.confidence})</span>}</td>
                                          <td className="text-right" title={`${item.severityWeight}wt severity + ${item.ruleWeight}wt rule`}>{item.severityWeight + item.ruleWeight}wt</td>
                                          <td className="text-right font-mono">+{Math.round(item.contribution)}</td>
                                          <td className="text-right font-mono whitespace-nowrap">({item.severityWeight}+{item.ruleWeight}) × {item.confidenceMult.toFixed(1)}</td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                                )}
                                <div className="text-[10px] text-muted-foreground mt-1">contribution = (severity weight + rule weight) × confidence multiplier — &lt;50% ×0.5, 50–79% ×1.0, ≥80% ×1.5. Each rule&rsquo;s contribution is raw pre-normalization points; the contributions sum to the <strong>Raw score</strong> ({risk.rawScore.toFixed(1)}), which the curve maps to the <strong>Normalized score</strong> ({risk.normalizedScore}/100).</div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  )}
                  
                  <div className="flex flex-wrap gap-2 mt-4">
                <Card>
                  <CardHeader><CardTitle className="text-sm">Top Ports</CardTitle></CardHeader>
                  <CardContent className="space-y-2">
                    {topPorts.length > 0 && <p className="text-[10px] text-muted-foreground">Service-side attribution per conversation (well-known/known service port wins, else lower port); both-leg counts summed. Conversations between two dynamic-range ports (P2P) are excluded ({p2pExcluded.toLocaleString()} pkts). Port-less protocols (ICMP, GRE, ESP…) appear under Top Protocols. Labels are payload-confirmed only when the decoder verified the protocol in the payload; evidence counts are FLOWS (conversations), never packets — the Count column holds packet totals. A flow counts as having payload evidence when at least one of its packets was payload-verified, so a partially verified flow still counts (the CSV's "mixed" rows). Share is % of the {portTotal.toLocaleString()} ports-attributable packets (of {packets.length.toLocaleString()} analyzed): {portlessPkts.toLocaleString()} packets have no ports and {p2pExcluded.toLocaleString()} are P2P dynamic-range, so the rows shown plus the Other row cover 100% of port attribution — they never imply coverage of all analyzed packets.</p>}
                    {topPorts.length === 0 && (
                      <p className="text-xs text-muted-foreground">{undecodable ? `No port data — payloads undecodable (${dltName(linkTypes)}), so ports were not parsed` : "No port data"}</p>
                    )}
                    {/* Table, not flex rows: the PDF text extractor splits flex
                        label/value pairs into separate columns (R3). */}
                    {topPorts.length > 0 && (
                      // break-inside-avoid: an 8-row card must not straddle a
                      // page break, or the printed PDF repeats the header
                      // row mid-table (QA #4).
                      <table className="w-full text-xs break-inside-avoid">
                        <thead>
                          <tr className="border-b text-muted-foreground">
                            <th className="text-left py-1.5 pr-2 font-medium">Port</th>
                            <th className="text-left py-1.5 pr-2 font-medium">Service</th>
                            <th className="text-left py-1.5 pr-2 font-medium">Share</th>
                            <th className="text-right py-1.5 font-medium">Count</th>
                          </tr>
                        </thead>
                        <tbody>
                          {topPorts.map(({ protocol, port, count, confirmedFlows, flows }) => (
                            <tr key={protocol + "/" + port} className="border-b border-border/30">
                              <td className="py-1.5 pr-2 font-mono whitespace-nowrap">{protocol}/{port}</td>
                              <td className="py-1.5 pr-2 text-muted-foreground">
                                {serviceEvidenceLabel(portServiceName(port, protocol), confirmedFlows, flows)}
                              </td>
                              <td className="py-1.5 pr-2 whitespace-nowrap">
                                <span className="text-[10px] text-muted-foreground mr-1">{sharePctLabel(count, portTotal)}</span>
                                <div className="inline-block h-2.5 align-middle bg-muted rounded-full overflow-hidden max-w-[120px]">
                                  <div className="h-full bg-chart-3 rounded-full" style={{ width: (count / topPorts[0].count * 100) + "%" }} />
                                </div>
                              </td>
                              <td className="py-1.5 text-right text-muted-foreground whitespace-nowrap">{count.toLocaleString()}</td>
                            </tr>
                          ))}
                          {otherPortTotal > 0 && (
                            <tr className="border-b border-border/30">
                              <td className="py-1.5 pr-2 font-mono whitespace-nowrap text-muted-foreground">Other ports</td>
                              <td className="py-1.5 pr-2 text-muted-foreground">{allPorts.length - topPorts.length} more service{allPorts.length - topPorts.length === 1 ? "" : "s"}</td>
                              <td className="py-1.5 pr-2 whitespace-nowrap">
                                <span className="text-[10px] text-muted-foreground mr-1">{sharePctLabel(otherPortTotal, portTotal)}</span>
                              </td>
                              <td className="py-1.5 text-right text-muted-foreground whitespace-nowrap">{otherPortTotal.toLocaleString()}</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    )}
                    {topPorts.length < allPorts.length && <p className="text-[10px] text-muted-foreground pt-1">+{allPorts.length - topPorts.length} more services (top {topPorts.length} shown)</p>}
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader><CardTitle className="text-sm">Top Countries (packet-direction: by each packet&rsquo;s destination)</CardTitle></CardHeader>
                  <CardContent className="space-y-2">
                    {topCountries.length === 0 && <p className="text-xs text-muted-foreground">{stats.externalIps === 0 ? "Countries resolved: 0 — no public IP addresses found (nothing to geolocate)" : jobInfo?.geoDbVersion ? "Countries resolved: 0 — captured public IPs have no location entries in the installed database" : "Countries resolved: 0 — GeoIP database unavailable. Install the bundled DB-IP City Lite database to enable country analysis"}</p>}
                    {topCountries.length > 0 && (
                      <table className="w-full text-xs break-inside-avoid">
                        <thead>
                          <tr className="border-b text-muted-foreground">
                            <th className="text-left py-1.5 pr-2 font-medium">Country</th>
                            <th className="text-left py-1.5 pr-2 font-medium">Share</th>
                            <th className="text-right py-1.5 font-medium">Packets</th>
                          </tr>
                        </thead>
                        <tbody>
                          {topCountries.map(([cc, count]) => (
                            <tr key={cc} className="border-b border-border/30">
                              <td className="py-1.5 pr-2 font-mono whitespace-nowrap">{cc}</td>
                              <td className="py-1.5 pr-2 whitespace-nowrap">
                                <span className="text-[10px] text-muted-foreground mr-1">{sharePctLabel(count, countryTotal)}</span>
                                <div className="inline-block h-2.5 align-middle bg-muted rounded-full overflow-hidden max-w-[120px]">
                                  <div className="h-full bg-warning rounded-full" style={{ width: (count / topCountries[0][1] * 100) + "%" }} />
                                </div>
                              </td>
                              <td className="py-1.5 text-right text-muted-foreground whitespace-nowrap">{count.toLocaleString()}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                    {topCountries.length < allCountries.length && <p className="text-[10px] text-muted-foreground pt-1">+{allCountries.length - topCountries.length} more countries (top {topCountries.length} shown)</p>}
                    <p className="text-[10px] text-muted-foreground pt-1">{countryTotal < packets.length ? `Shares are of the ${countryTotal.toLocaleString()} packets attributable to a country (${((countryTotal / packets.length) * 100).toFixed(1)}% of the ${packets.length.toLocaleString()} captured packets) — the remaining packets have no GeoIP mapping and cannot be country-attributed. ` : ""}Methodology: each packet is counted once, by its destination address&rsquo;s country (the destination leg of each conversation). The CSV export&rsquo;s dstCountry column totals whole conversations including both directions, so its country sums are larger than these packet counts by design — the two artifacts are not directly comparable.</p>
                  </CardContent>
                </Card>
              </div>
             </section>

             {!advancedMetrics && burst && (
               <section>
                 <SectionTitle icon={Zap} title="Traffic Burst" />
                 <Card>
                   <CardContent className="pt-4">
                      {burst.detected ? (
                        <div className="space-y-2 text-xs">
                          <div className="flex items-center gap-2"><span className="text-danger font-semibold">Detected</span><span className="text-muted-foreground">·</span><span className="font-mono">{burst.ratio.toFixed(1)}× average</span></div>
                         <div className="grid grid-cols-2 gap-2">
                           <div><span className="text-muted-foreground">Peak</span><div className="font-mono">{formatBytes(burst.peakThroughput)}/s</div></div>
                           <div><span className="text-muted-foreground">Average</span><div className="font-mono">{formatBytes(burst.averageThroughput)}/s</div></div>
                           <div><span className="text-muted-foreground">Duration</span><div className="font-mono">{burst.duration.toFixed(1)} s</div></div>
                           <div><span className="text-muted-foreground">Occurred</span><div className="font-mono">{fmtClock(burst.start)} – {fmtClock(burst.end)}</div></div>
                         </div>
                       </div>
                     ) : (
                       <span className="text-success text-xs font-medium">Not Detected</span>
                     )}
                   </CardContent>
                 </Card>
               </section>
             )}

             <section>
                <SectionTitle icon={AlertTriangle} title="19. Indicators & Affected Assets" />
                  <Card>
                    <CardContent className="pt-6">
                      {report.iocs.length > 0 && report.iocs.length !== alerts.length && (
                        <p className="text-xs text-muted-foreground border border-border/30 rounded p-2 mb-3">
                          Indicator rows may exceed confirmed alerts: behavioral indicators (DNS tunneling, beaconing, exfiltration) are
                          derived from advanced metrics, while confirmed alerts come from signature rules. Each row is labeled
                          with its source below.
                        </p>
                      )}
                      {report.iocs.some((i) => i.type === "credential-theft") && (
                        <p className="text-xs text-muted-foreground border border-border/30 rounded p-2 mb-3">
                          The Plaintext Credential Exposure row lists the <strong>affected host</strong> (the machine
                          that transmitted the credentials) and its destination — an affected host is the <strong>victim
                          of the exposure</strong>, not an indicator of a known-malicious artifact. The capture proves
                          the transmission, not theft, interception, or a malicious destination.
                        </p>
                      )}
                      {report.iocs.some((i) => ["data-exfiltration", "beaconing", "dns-tunneling", "tor-vpn-proxy", "ja3", "port-scan", "syn-flood"].includes(i.type)) && (
                        <p className="text-xs text-muted-foreground border border-border/30 rounded p-2 mb-3">
                          Behavioral entries (e.g. Suspected Large Outbound Transfer, Beaconing, DNS Tunneling) are
                          <strong> findings about observed traffic patterns, not indicators of a known-malicious artifact</strong>:
                          the value describes the behavior itself, and the endpoints are not established as malicious.
                        </p>
                      )}
                      {report.iocs.length === 0 ? (
                        <p className="text-sm text-muted-foreground">No malicious indicators detected — the Notable Destinations section is curated context, not indicators.</p>
                      ) : (
                        <div className="overflow-x-auto">
                          <table className="w-full text-xs">
                            <thead>
                              <tr className="border-b text-muted-foreground">
                                <th className="text-left py-2 pr-2">Type</th>
                                <th className="text-left py-2 pr-2">Value</th>
                                <th className="text-left py-2 pr-2">Description</th>
                                <th className="text-left py-2 pr-2">Severity</th>
                                <th className="text-left py-2">Source</th>
                              </tr>
                            </thead>
                            <tbody>
                              {report.iocs.map((ioc, i) => (
                                <tr key={i} className="border-b border-border/30">
                                  <td className="py-1.5 pr-2 text-muted-foreground">{iocTypeLabel(ioc.type)}</td>
                                  <td className="py-1.5 pr-2 font-mono">{ioc.type === "credential-theft" ? `Affected host: ${ioc.value}` : ioc.value}</td>
                                  <td className="py-1.5 pr-2 text-muted-foreground">{ioc.description}</td>
                                  <td className="py-1.5 pr-2"><Badge variant={ioc.severity >= 4 ? "destructive" : ioc.severity >= 3 ? "warning" : "default"} className="text-[10px]">{sevLabel(ioc.severity)}</Badge></td>
                                  <td className="py-1.5">{sourceBadge(ioc.source, ioc.status)}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </section>

                <section>
                  <SectionTitle icon={Shield} title="20. MITRE ATT&CK Mapping" />
                  <Card>
                    <CardContent className="pt-6">
                      {mitre.length === 0 ? (
                        <div>
                          <p className="text-sm text-muted-foreground">No MITRE ATT&CK techniques mapped</p>
                          {alerts.length > 0 && (
                            <p className="text-xs text-muted-foreground border border-border/30 rounded p-2 mt-2">
                              Techniques are attached only when the evidence <strong>demonstrates the technique was
                              executed</strong> (LIKELY/CONFIRMED detections with matching activity). SUSPECTED
                              findings — rules that crossed a threshold on pattern evidence (e.g. the directional
                              byte-ratio exfiltration rule) — deliberately receive no mapping, and confirmed
                              exposure-style findings (e.g. plaintext credential exposure) are unmapped too: exposure
                              is a weakness or prerequisite, not observed adversary activity.
                            </p>
                          )}
                        </div>
                      ) : (
                        <div className="space-y-4">
                          {(["High", "Medium", "Low"] as const).map((sev) => {
                            const rows = mitre.filter((m) => sevLabel(m.severity) === sev)
                            if (rows.length === 0) return null
                            return (
                              <div key={sev}>
                                <h3 className={cn("text-xs font-bold uppercase tracking-wide mb-2", sev === "High" ? "text-danger" : sev === "Medium" ? "text-warning" : "text-muted-foreground")}>{sev} Severity</h3>
                                <div className="space-y-2">
                                  {rows.map((m, i) => (
                                    <div key={i} className="border rounded-lg p-3">
                                      <div className="flex items-center justify-between gap-2">
                                        <span className="font-mono text-xs text-primary">{m.id}</span>
                                        <span className="text-sm font-medium">{m.technique}</span>
                                        <Badge variant={m.severity >= 4 ? "destructive" : m.severity >= 3 ? "warning" : "default"} className="shrink-0">{sevLabel(m.severity)}</Badge>
                                      </div>
                                      <p className="text-xs text-muted-foreground mt-1">{m.description}</p>
                                      <div className="text-xs mt-1.5 flex items-center gap-1.5">Source: {sourceBadge(m.source, m.status)}</div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )
                          })}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </section>

                <section>
                  <SectionTitle icon={FileText} title="21. Recommendations" />
                  <Card>
                    <CardContent className="pt-6 space-y-4">
                      {recs.High.length === 0 && recs.Medium.length === 0 && recs.Low.length === 0 && (
                        <p className="text-sm text-muted-foreground">
                          {alerts.length === 0
                            ? "No security detections triggered. Any network-health observations in this report (retransmissions, estimated retransmission-based loss, RTT, RST, out-of-order, zero-window) are informational network diagnostics, not security findings — a 0/100 risk score never means the network is loss-free. Continue routine monitoring."
                            : "No specific recommendations at this time. Continue monitoring network traffic for anomalies."}
                        </p>
                      )}
                      {recs.High.length > 0 && (
                        <div>
                          <h3 className="text-xs font-bold uppercase tracking-wide text-danger mb-2">High Priority</h3>
                          <div className="space-y-2">
                            {recs.High.map((r, i) => (
                              <div key={i} className="flex gap-2 text-sm">
                                <AlertTriangle className="h-4 w-4 text-danger shrink-0 mt-0.5" />
                                <span>{r.priority && <Badge variant="warning" className="mr-1.5 align-middle text-[10px]">{r.priority}</Badge>}{r.text} <span className="text-[10px] text-muted-foreground whitespace-nowrap">({findingSourceLabel(r.source, r.status)})</span></span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {recs.Medium.length > 0 && (
                        <div>
                          <h3 className="text-xs font-bold uppercase tracking-wide text-warning mb-2">Medium Priority</h3>
                          <div className="space-y-2">
                            {recs.Medium.map((r, i) => (
                              <div key={i} className="flex gap-2 text-sm">
                                <AlertTriangle className="h-4 w-4 text-warning shrink-0 mt-0.5" />
                                <span>{r.priority && <Badge variant="warning" className="mr-1.5 align-middle text-[10px]">{r.priority}</Badge>}{r.text} <span className="text-[10px] text-muted-foreground whitespace-nowrap">({findingSourceLabel(r.source, r.status)})</span></span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {recs.Low.length > 0 && (
                        <div>
                          <h3 className="text-xs font-bold uppercase tracking-wide text-muted-foreground mb-2">Low Priority</h3>
                          <div className="space-y-2">
                            {recs.Low.map((r, i) => (
                              <div key={i} className="flex gap-2 text-sm">
                                <AlertTriangle className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />
                                <span>{r.priority && <Badge variant="warning" className="mr-1.5 align-middle text-[10px]">{r.priority}</Badge>}{r.text} <span className="text-[10px] text-muted-foreground whitespace-nowrap">({findingSourceLabel(r.source, r.status)})</span></span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </section>
              </>
            )}

                <section>
                  <SectionTitle icon={BarChart3} title="22. Appendix" />
                  <Card>
                    <CardContent className="pt-6 text-xs text-muted-foreground space-y-3">
                      <p><strong>Analysis ID:</strong> <span className="font-mono">{job.id}</span></p>
                      {jobInfo?.isDemo && <Badge variant="outline" className="mb-2 text-xs inline-block">Demo Dataset</Badge>}
                      <p><strong>Capture file:</strong> {job.filename} ({formatBytes(job.fileSize)})</p>
                      {job.sha256 && <p><strong>SHA256:</strong> <span className="font-mono text-xs break-all">{job.sha256}</span></p>}
                      {job.sha1 && <p><strong>SHA1:</strong> <span className="font-mono text-xs break-all">{job.sha1}</span></p>}
                      {job.md5 && <p><strong>MD5:</strong> <span className="font-mono text-xs">{job.md5}</span></p>}
                      <p><strong>Packets:</strong> {stats.totalPackets.toLocaleString()} · <strong>Flows:</strong> {stats.totalFlows.toLocaleString()} · <strong>Sessions:</strong> {stats.sessions.toLocaleString()} · <strong>Local Devices:</strong> {stats.devices.toLocaleString()}</p>
                      <p><strong>Duration:</strong> {durLabel(durationSec)} · <strong>External IPs:</strong> {stats.externalIps} · <strong>Countries:</strong> {countriesLabel(stats.countries, stats.externalIps)}</p>
                      <p><strong>Decoded:</strong> {decode ? `${decode.decoded.toLocaleString()} of ${decode.total.toLocaleString()} packets (${(decodeRate * 100).toFixed(0)}%)` : "—"}{duplicateFrames > 0 ? <> · <strong>{duplicateFrames.toLocaleString()} consecutive duplicate frames</strong> removed before analysis</> : null} · <strong>Encapsulation:</strong> {linkTypes.length > 0 ? dltName(linkTypes) : "—"} · <strong>Application-layer visibility:</strong> {appVisibilityLabel}</p>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <h4 className="font-semibold mb-2">Report Metadata</h4>
                          <p><strong>Tool:</strong> PacketLens v{ANALYZER_VERSION} (Web) — {beginnerMode ? "Beginner" : "Expert"}</p>
                          <p><strong>Generation Mode:</strong> {report.metadata.mode}</p>
                          <p><strong>Report Schema Version:</strong> {report.metadata.schemaVersion}</p>
                          <p><strong>Analyzer Version:</strong> {report.metadata.analyzerVersion || ANALYZER_VERSION}</p>
                          <p><strong>Build:</strong> v{BUILD_INFO.version} · {BUILD_INFO.isGit ? <>Commit: <span className="font-mono">{BUILD_INFO.commit}</span></> : <>Source: build env <span className="font-mono">(src:{BUILD_INFO.sourceHash || "unknown"})</span></>} · Built: {BUILD_INFO.builtAt}</p>
                          {BUILD_INFO.isGit && <p><strong>Commit (short):</strong> <span className="font-mono">{BUILD_INFO.commitShort}</span></p>}
                          <p><strong>Signature DB Version:</strong> {report.metadata.ruleVersion || "Behavioral Detection Only"}</p>
                          <p><strong>Risk Spec Version:</strong> {report.metadata.riskSpecVersion || RISK_SPEC_VERSION}</p>
                          <p><strong>GeoIP DB (DB-IP City Lite):</strong> {jobInfo?.geoDbVersion || "Lookup Unavailable"}</p>
                          <p><strong>OUI DB Version:</strong> {ouiStatus}</p>
                          {report.metadata.analysisDurationSec != null && <p><strong>Analysis Duration:</strong> {formatDuration(report.metadata.analysisDurationSec)}</p>}
                        </div>
                        <div>
                          <h4 className="font-semibold mb-2">Threat Summary</h4>
                          <p><strong>Alerts:</strong> {alerts.length} — Severity: {severityCounts(alerts)} · Status: {statusCountsLabel(summarizeStatuses(alerts))}</p>
                          <p><strong>Indicators:</strong> {report.iocs.length} — Status: {statusCountsLabel(summarizeStatuses(report.iocs))}</p>
                          <p><strong>MITRE Mappings:</strong> {report.mitre.length}</p>
                          <p><strong>Risk Score:</strong> {riskValue()}</p>
                          {risk && <p><strong>Raw Score:</strong> {Math.round(risk.rawScore * 10) / 10}</p>}
                          {burst && <p><strong>Burst Detected:</strong> {formatBytes(burst.peakThroughput)}/s peak</p>}
                        </div>
                      </div>
                      <p><strong>Analysis completed:</strong> {job.createdAt ? new Date(job.createdAt).toISOString().slice(0, 19).replace("T", " ") + " UTC" : "—"} · <strong>Export generated:</strong> {exportTs} UTC · <strong>Build:</strong> {BUILD_STAMP}</p>
                    </CardContent>
                  </Card>
                </section>

                <section>
                  <SectionTitle icon={Shield} title="23. Analyst Conclusion" />
                  <Card>
                    <CardContent className="pt-6 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Shield className={cn("h-5 w-5", levelColor)} />
                        <span className={cn("text-lg font-bold", levelColor)}>{levelLabel === "SAFE" ? "NO DETECTIONS" : levelLabel}</span>
                        {levelLabel === "SAFE" && <span className="text-xs text-muted-foreground">— no configured detection rule triggered (not a proof of a clean network)</span>}
                        {levelLabel !== "SAFE" && verdictStatusHint && <span className="text-xs text-muted-foreground">{verdictStatusHint}</span>}
                        <span className="text-xs text-muted-foreground">Final verdict · Risk score {riskValue()}</span>
                      </div>
                      <p className="text-sm text-muted-foreground">{conclusionText}</p>
                      <p className="text-xs text-muted-foreground">{levelLabel === "SAFE" ? "NO DETECTIONS means no configured detection rule triggered" : `The ${levelLabel} verdict reflects the configured detection rules only${verdictStatusHint ? " — the level is floored by the strongest finding's rule severity (1–5), which is NOT the same scale as the 0–100 risk score" : ""}`} — it is not proof that the capture is universally safe or clean.</p>
                    </CardContent>
                  </Card>
                </section>
          </div>
        </main>
      </div>
    </div>
  )
}
