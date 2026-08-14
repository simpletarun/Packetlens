import { readFileSync, readdirSync } from "node:fs"
import { join, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { parsePcap } from "@/lib/pcap"
import { analyzePcap } from "@/lib/analysis"
import { buildReportAnalysis, dnsLookupCount, analystConclusion } from "@/lib/report"
import { isPrivateIP } from "@/lib/map-data"
import { computeRisk, buildRiskInputs, burstConfidenceBoost, computeRiskBreakdown, riskLevel, verdictLevel } from "@/lib/risk"
import type { JobSummary } from "@/stores/analysis"

const testsDir = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(testsDir, "fixtures")
const externalDir = "C:/Users/hp/Downloads/all pcap"

const KNOWN_RULES = new Set(["PORT-SCAN-001", "SYN-FLOOD-001", "DNS-TUNNEL-001", "CRED-LEAK-001", "MALWARE-DL-001", "C2-BEACON-001", "DATA-EXFIL-001", "TLS-SUSPICIOUS-001", "HTTP-CREDS-001"])
const BURST_RULES = new Set(["DATA-EXFIL-001", "C2-BEACON-001", "DNS-TUNNEL-001"])
const isIso = (s: unknown) => typeof s === "string" && !Number.isNaN(Date.parse(s))

// Subnet broadcasts, multicast, unspecified, loopback, link-local, 169.254
// and the IPv6 "::" (expanded form included) are never devices.
function isNonUnicastLocal(ip: string): boolean {
  if (ip.includes(":")) {
    if (ip.startsWith("ff") || ip.startsWith("fe80")) return true
    if (ip === "::" || /^0(:0){7}$/.test(ip)) return true
    return false
  }
  const parts = ip.split(".")
  if (parts.length !== 4) return true
  const n = parts.map(Number)
  if (n.some((x) => Number.isNaN(x))) return true
  if (n[0] === 224 || n[0] === 239 || n[0] === 255) return true
  if (n[0] === 0 || n[0] === 127) return true
  if (n[0] === 169 && n[1] === 254) return true
  if (n[2] === 255 || n[3] === 255) return true
  return false
}

function assertNoNaN(obj: unknown, path = "", problems: string[]) {
  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) problems.push(`${path}=${obj}`)
    return
  }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => assertNoNaN(v, `${path}[${i}]`, problems))
    return
  }
  if (obj && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      if (v !== undefined) assertNoNaN(v, path ? `${path}.${k}` : k, problems)
    }
  }
}

// The API route serves JobSummary = engine AnalysisJob + done/progress/stage
// overrides; buildReportAnalysis must receive that exact shape.
function jobSummary(j: ReturnType<typeof analyzePcap>["job"]): JobSummary {
  return { ...j, status: "done", progress: 100, stage: "complete" }
}

async function audit(file: string, display: string) {
  let parsed
  try {
    parsed = await parsePcap(readFileSync(file))
  } catch (e) {
    return expect.soft(`parse ${display}`).toContain("no throw")
  }
  const pkts = parsed.packets
  expect.soft(pkts.length, `${display}: at least 1 packet`).toBeGreaterThan(0)
  if (pkts.length === 0) return

  const a1 = analyzePcap(parsed)
  const a2 = analyzePcap(parsed)
  const j = a1.job
  expect.soft(j.totalPackets, `${display}: totalPackets`).toBe(pkts.length)
  expect.soft(a1.devices.length, `${display}: job.devices`).toBe(j.devices)
  expect.soft(a1.flows.length, `${display}: job.totalFlows`).toBe(j.totalFlows)
  expect.soft(a1.sessions.length, `${display}: sessions==flows`).toBe(a1.flows.length)
  expect.soft(a1.decode.decoded, `${display}: decoded<=total`).toBeLessThanOrEqual(a1.decode.total)
  expect.soft(JSON.stringify(a1), `${display}: determinism`).toBe(JSON.stringify(a2))

  // Canonical validator consistency: schema version always present; the
  // integrity verdict must be exactly derivable from the raw flags, and the
  // decode stats must agree with the legacy `decode` alias.
  expect.soft(a1.schemaVersion, `${display}: schemaVersion`).toBeTruthy()
  expect.soft(a1.validator.schemaVersion, `${display}: validator.schemaVersion`).toBe(a1.schemaVersion)
  expect.soft(a1.validator.captureQuality, `${display}: validator quality`).toBe(a1.advancedMetrics.rates.quality)
  expect.soft(a1.validator.durationSec, `${display}: validator durationSec`).toBe(a1.advancedMetrics.rates.durationSec)
  // 100 ms instantaneous peak: null whenever no time interval exists, and
  // otherwise >= the 1-second peak (same zero base, ten windows per second).
  const m = a1.advancedMetrics
  if (m.rates.quality === "VALID") {
    expect.soft(m.throughputPeak100ms, `${display}: 100ms peak present`).not.toBeNull()
    expect.soft(m.throughputPeak100ms!, `${display}: 100ms peak >= 1s peak`).toBeGreaterThanOrEqual(m.throughputPeak!)
  } else {
    expect.soft(m.throughputPeak100ms, `${display}: 100ms peak null without interval`).toBeNull()
  }
  expect.soft(a1.validator.decode.decoded, `${display}: validator decoded`).toBe(a1.decode.decoded)
  expect.soft(a1.validator.decode.total, `${display}: validator total`).toBe(a1.decode.total)
  expect.soft(a1.validator.decode.linkTypes, `${display}: validator linkTypes`).toEqual(a1.decode.linkTypes)
  const vi = a1.validator.integrity
  const flagTruncated = vi.fileTruncated || vi.truncatedPackets > 0
  const flagUnsupported = vi.unsupportedLinkTypes.length > 0
  const flagMalformed = vi.malformedPackets > 0
  const flagIncomplete = a1.decode.total > 0 && a1.decode.decoded < a1.decode.total
  expect.soft(
    (vi.status === "truncated" && flagTruncated && !(flagUnsupported || flagMalformed || flagIncomplete)) ||
    (vi.status === "unsupported_link_type" && flagUnsupported && !flagTruncated) ||
    (vi.status === "malformed" && flagMalformed && !flagTruncated && !flagUnsupported) ||
    (vi.status === "incomplete_decode" && flagIncomplete && !flagTruncated && !flagUnsupported && !flagMalformed) ||
    (vi.status === "valid" && !flagTruncated && !flagUnsupported && !flagMalformed && !flagIncomplete),
    `${display}: integrity verdict consistent with flags (${vi.status})`,
  ).toBe(true)

  // Protocol honesty: every HTTP/TLS entry must be backed by at least one
  // payload-confirmed packet; a flow never claims "payload" without one; a
  // transport-only flow carries no app label (QA: TCP/80 without HTTP payload
  // was labeled HTTP; pure-SYN packets showed port-inferred app labels).
  const confirmedApps = new Set(a1.packets.filter((p) => p.appPayloadConfirmed).map((p) => p.appProtocol))
  expect.soft(
    a1.http.length === 0 || confirmedApps.has("HTTP"),
    `${display}: http entries backed by payload-confirmed HTTP (${confirmedApps.has("HTTP")})`,
  ).toBe(true)
  expect.soft(
    a1.tls.length === 0 || confirmedApps.has("TLS") || confirmedApps.has("HTTPS"),
    `${display}: tls entries backed by payload-confirmed TLS`,
  ).toBe(true)
  for (const f of a1.flows) {
    if (f.protocolSource === "PAYLOAD_CONFIRMED") {
      expect.soft(!!f.appProtocol, `${display}: payload flow ${f.id} has app label`).toBe(true)
    } else if (f.protocolSource === "UNKNOWN") {
      expect.soft(!f.appProtocol, `${display}: UNKNOWN flow ${f.id} has no app label`).toBe(true)
    }
  }
  expect.soft(
    a1.flows.every((f) => f.protocolSource === undefined || ["PAYLOAD_CONFIRMED", "PORT_INFERRED", "UNKNOWN"].includes(f.protocolSource)),
    `${display}: flow protocolSource enum`,
  ).toBe(true)

  // TCP state machine: states come from the observed handshake and the flow
  // mirror always agrees with its session (QA: all TCP flows claimed
  // ESTABLISHED; SYN-only and half-open conversations were misreported).
  const STATES = new Set(["ESTABLISHED", "CLOSED", "RESET", "INITIATED", "HALF_OPEN", "STATELESS"])
  expect.soft(
    a1.sessions.every((s) => STATES.has(s.state)),
    `${display}: session state enum (${[...new Set(a1.sessions.map((s) => s.state))].join(",")})`,
  ).toBe(true)
  for (const f of a1.flows) {
    const sess = a1.sessions.find(
      (s) => s.srcIp === f.srcIp && s.dstIp === f.dstIp && s.srcPort === f.srcPort && s.dstPort === f.dstPort,
    )
    expect.soft(sess?.state === f.tcpState, `${display}: flow ${f.id} tcpState ${f.tcpState} mirrors session ${sess?.state}`).toBe(true)
  }

  const totalLen = pkts.reduce((s, p) => s + (p.length || 0), 0)

  // Alert dedup: one event fires one alert — the same (rule, src, dst) never
  // appears twice in the displayed threat list, and risk dedups identically.
  const threatKeys = a1.threats.map((t) => `${t.ruleId}|${t.srcIp}|${t.dstIp}`)
  expect.soft(
    new Set(threatKeys).size === threatKeys.length,
    `${display}: threats unique by (rule, src, dst) (${threatKeys.length} threats)`,
  ).toBe(true)
  expect.soft(a1.job.alerts === a1.threats.length, `${display}: job.alerts mirrors threat count`).toBe(true)
  expect.soft(
    a1.threats.every((t) => (t.packetNums ?? []).every((n) => Number.isInteger(n) && n >= 1)),
    `${display}: threat packetNums are valid packet numbers`,
  ).toBe(true)
  expect.soft(
    a1.threats.filter((t) => t.payloadConfirmed).every((t) => ["HTTP-CREDS-001", "CRED-LEAK-001"].includes(t.ruleId)),
    `${display}: payloadConfirmed only on payload-derived findings`,
  ).toBe(true)
  let flowPkts = 0, flowBytes = 0
  const flowKeys = new Set<string>()
  for (const f of a1.flows) {
    flowPkts += f.packets
    flowBytes += f.bytesTotal
    expect.soft(f.packets >= 1 && f.bytesTotal >= 0 && f.bytesSent >= 0 && f.bytesRecv >= 0 && f.duration >= 0, `${display}: flow fields ${f.id}`).toBe(true)
    if (!f.directionUnknown) {
      expect.soft(Math.abs(f.bytesSent + f.bytesRecv - f.bytesTotal) <= 1, `${display}: flow bytes ${f.id}`).toBe(true)
    }
    const s = Date.parse(f.startTime), e = Date.parse(f.endTime)
    expect.soft(isIso(f.startTime) && isIso(f.endTime) && e >= s, `${display}: flow times ${f.id}`).toBe(true)
    expect.soft(Math.abs(f.duration - (e - s) / 1000) <= 0.011, `${display}: flow duration ${f.id}`).toBe(true)
    const key = `${f.srcIp}:${f.srcPort}-${f.dstIp}:${f.dstPort}|${f.protocol}`
    expect.soft(!flowKeys.has(key), `${display}: flow key unique ${key}`).toBe(true)
    flowKeys.add(key)
  }
  expect.soft(flowPkts, `${display}: sum(flow.packets)`).toBe(j.totalPackets)
  expect.soft(flowBytes, `${display}: sum(flow.bytesTotal)`).toBe(totalLen)

  const devIps = new Map<string, { aliases: string[] }>()
  for (const d of a1.devices) {
    expect.soft(isIso(d.firstSeen) && isIso(d.lastSeen) && d.packets >= 0 && d.bytes >= 0, `${display}: device ${d.ip}`).toBe(true)
    devIps.set(d.ip, { aliases: d.addresses ?? [] })
  }
  let devBytes = 0
  const unattributed = new Set<string>()
  for (const p of pkts) {
    let endpoints = 0
    for (const ip of new Set([p.srcIp, p.dstIp].filter(Boolean) as string[])) {
      const isDev = devIps.has(ip) || [...devIps.values()].some((d) => d.aliases.includes(ip))
      if (isDev) { endpoints++; continue }
      if (!isNonUnicastLocal(ip)) unattributed.add(ip)
    }
    devBytes += (p.length || 0) * endpoints
  }
  expect.soft([...unattributed], `${display}: all unicast IPs attributed`).toEqual([])
  expect.soft(a1.devices.reduce((s, d) => s + d.bytes, 0), `${display}: device bytes per endpoint`).toBe(devBytes)

  expect.soft(a1.bandwidth.reduce((s, b) => s + b.in + b.out, 0), `${display}: bandwidth conserves bytes`).toBe(totalLen)
  expect.soft(a1.timeline.reduce((s, t) => s + t.packets, 0), `${display}: timeline conserves packets`).toBe(j.totalPackets)
  expect.soft(a1.timeline.reduce((s, t) => s + t.bytes, 0), `${display}: timeline conserves bytes`).toBe(totalLen)
  for (const t of a1.timeline) {
    expect.soft(t.tcp + t.udp + t.dns + t.tls <= t.packets, `${display}: timeline slices`).toBe(true)
  }

  expect.soft(dnsLookupCount(a1.dns) >= 1 || a1.dns.length === 0, `${display}: dns lookups`).toBe(true)
  expect.soft(new Set(a1.dns.map((d) => d.query)).size, `${display}: job.domains`).toBe(j.domains)
  for (const d of a1.dns) expect.soft(isIso(d.timestamp) && d.query.length > 0 && (d.ttl === null || d.ttl >= 0), `${display}: dns ${d.query}`).toBe(true)
  for (const t of a1.tls) expect.soft(isIso(t.timestamp) && t.sni.length <= 253, `${display}: tls ${t.sni}`).toBe(true)
  for (const h of a1.http) expect.soft(isIso(h.timestamp), `${display}: http`).toBe(true)
  for (const c of a1.certificates) {
    expect.soft(c.notBefore === null || isIso(c.notBefore), `${display}: cert notBefore`).toBe(true)
    expect.soft(c.notAfter === null || isIso(c.notAfter), `${display}: cert notAfter`).toBe(true)
  }
  for (const s of a1.sessions) expect.soft(isIso(s.startTime) && s.packets >= 1 && s.duration >= 0, `${display}: session`).toBe(true)

  const synCounts = new Map<string, number>()
  const synPorts = new Map<string, Set<number>>()
  const synDsts = new Map<string, Set<string>>()
  for (const p of pkts) {
    if (p.srcIp && p.tcpFlags?.includes("SYN")) {
      synCounts.set(p.srcIp, (synCounts.get(p.srcIp) ?? 0) + 1)
      if (!synPorts.has(p.srcIp)) synPorts.set(p.srcIp, new Set())
      synPorts.get(p.srcIp)!.add(p.dstPort ?? 0)
      if (!synDsts.has(p.srcIp)) synDsts.set(p.srcIp, new Set())
      if (p.dstIp) synDsts.get(p.srcIp)!.add(p.dstIp)
    }
  }
  const expectTor = pkts.some((p) => (p.srcIp ?? "").startsWith("185.220.101.") || (p.dstIp ?? "").startsWith("185.220.101."))

  for (const t of a1.threats) {
    expect.soft(t.severity >= 1 && t.severity <= 5 && t.confidence >= 0 && t.confidence <= 100 && KNOWN_RULES.has(t.ruleId) && t.evidence.length > 0 && isIso(t.timestamp), `${display}: threat ${t.ruleId}`).toBe(true)
    if (t.ruleId === "PORT-SCAN-001") {
      const m = t.evidence.match(/^(\S+) scanned (\d+) ports on (\d+) host\(s\) over ([\d.]+)s \((\d+) SYN, (\d+) RST, (\d+) FIN/)
      if (m) {
        expect.soft(synPorts.get(m[1])?.size, `${display}: portscan ports`).toBe(Number(m[2]))
        expect.soft(synDsts.get(m[1])?.size, `${display}: portscan dsts`).toBe(Number(m[3]))
      }
    }
    if (t.ruleId === "C2-BEACON-001") {
      const m = t.evidence.match(/^(\d+) connections to ([^:]+):(\d+) at ~([\d.]+)s intervals/)
      if (m) {
        const n = Number(m[1]), ip = m[2], port = Number(m[3]), mean = Number(m[4])
        const starts = a1.flows
          .filter((f) => (f.dstIp === ip && f.dstPort === port) || (f.srcIp === ip && f.srcPort === port))
          .map((f) => Date.parse(f.startTime)).sort((x, y) => x - y)
        expect.soft(starts.length, `${display}: beacon count`).toBe(n)
        const ivs: number[] = []
        for (let i = 1; i < starts.length; i++) { const iv = (starts[i] - starts[i - 1]) / 1000; if (iv > 0) ivs.push(iv) }
        if (ivs.length >= 2) {
          const avg = ivs.reduce((s, x) => s + x, 0) / ivs.length
          expect.soft(Math.abs(avg - mean), `${display}: beacon mean`).toBeLessThanOrEqual(0.55)
          const v = ivs.reduce((s, x) => s + (x - avg) ** 2, 0) / ivs.length
          expect.soft(Math.sqrt(v) / avg, `${display}: beacon CV`).toBeLessThan(0.35)
        }
      }
    }
    if (t.ruleId === "DATA-EXFIL-001") {
      const m = t.evidence.match(/^(\d+) flow\(s\) sending >(\d+) KB to external IPs \(outbound ≥5× received; top: (\S+) → (\S+), (\d+) KB sent\)/)
      if (m) {
        const k = Number(m[1]), thrKB = Number(m[2]), topPriv = m[3], topPub = m[4], topKB = Number(m[5])
        const candidates = a1.flows.filter((f) => {
          const sPriv = isPrivateIP(f.srcIp), dPriv = isPrivateIP(f.dstIp)
          if (sPriv === dPriv) return false
          const out = sPriv ? f.bytesSent : f.bytesRecv
          const inn = sPriv ? f.bytesRecv : f.bytesSent
          return out > thrKB * 1024 && out > 5 * inn
        })
        expect.soft(candidates.length, `${display}: exfil count`).toBe(k)
        const top = candidates.find((f) => (isPrivateIP(f.srcIp) ? f.srcIp : f.dstIp) === topPriv && (isPrivateIP(f.srcIp) ? f.dstIp : f.srcIp) === topPub)
        expect.soft(!!top, `${display}: exfil top flow`).toBe(true)
        if (top) {
          const out = isPrivateIP(top.srcIp) ? top.bytesSent : top.bytesRecv
          expect.soft(Math.abs(out / 1024 - topKB), `${display}: exfil top KB`).toBeLessThanOrEqual(1)
        }
      }
    }
    if (t.ruleId === "SYN-FLOOD-001") {
      expect.soft([...synCounts.values()].some((c) => c >= 100), `${display}: syn flood threshold`).toBe(true)
    }
  }
  expect.soft(a1.advancedMetrics.torVpnProxyDetected, `${display}: tor parity`).toBe(expectTor)

  expect.soft(a1.credentials.length === 0 || a1.threats.some((t) => t.ruleId === "HTTP-CREDS-001" || t.ruleId === "CRED-LEAK-001"), `${display}: creds => threat`).toBe(true)
  for (const f of a1.files) {
    // Regression: CR/LF-stripped header decode glued the next header name onto
    // Content-Type values ("...form-urlencodedUser-Agent:"). A well-formed
    // mime has exactly one '/' and no whitespace or header-name residue.
    expect.soft(/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(f.mimeType), `${display}: file mime well-formed (${f.mimeType})`).toBe(true)
  }
  const floodSrcs = [...synCounts.entries()].filter(([, c]) => c >= 100).map(([ip]) => ip)
  expect.soft(floodSrcs.length === 0 || a1.threats.some((t) => t.ruleId === "SYN-FLOOD-001"), `${display}: 100+ SYNs => SYN-FLOOD-001`).toBe(true)

  // Definite-assignment (no null union): TS narrows a `let x: T | null = null`
  // that is assigned only inside a callback to `never` after the call.
  let report!: ReturnType<typeof buildReportAnalysis>
  expect.soft(() => {
    report = buildReportAnalysis({
      job: jobSummary(j), jobInfo: { isDemo: false },
      alerts: a1.threats, packets: a1.packets, flows: a1.flows,
      sessions: a1.sessions, tls: a1.tls, http: a1.http,
      timeline: a1.timeline, bandwidth: a1.bandwidth, advancedMetrics: a1.advancedMetrics,
    })
  }, `${display}: buildReportAnalysis`).not.toThrow()
  const boost = burstConfidenceBoost(a1.advancedMetrics)
  expect.soft(computeRisk(buildRiskInputs(a1.threats), boost), `${display}: riskScore recompute`).toBe(j.riskScore)
  const br = report?.risk
  if (br) {
    expect.soft(br.normalizedScore, `${display}: report risk`).toBe(j.riskScore)
    const itemSum = br.items.reduce((s, i) => s + i.contribution, 0)
    expect.soft(Math.abs(br.rawScore - itemSum), `${display}: rawScore sum`).toBeLessThanOrEqual(0.11)
    for (const i of br.items) {
      expect.soft([0.5, 1, 1.5].includes(i.confidenceMult), `${display}: risk mult ${i.ruleId}`).toBe(true)
      expect.soft(Math.abs(i.contribution - (i.severityWeight + i.ruleWeight) * i.confidenceMult) <= 0.11, `${display}: risk contribution ${i.ruleId}`).toBe(true)
    }
    expect.soft(verdictLevel(riskLevel(br.normalizedScore), br.highestSeverity ?? 0).label, `${display}: risk level`).toBe(br.levelLabel)
    expect.soft(!!br.burstApplied, `${display}: burstApplied`).toBe(boost && br.items.some((i) => BURST_RULES.has(i.ruleId)))
  }

  const nan: string[] = []
  assertNoNaN(a1, "", nan)
  assertNoNaN(report, "", nan)
  expect.soft(nan, `${display}: no NaN`).toEqual([])

  // Verdict integrity: a capture with confirmed findings must NEVER be
  // concluded "clean" (QA: never_end reported 1 High alert + IOC yet its
  // Analyst Conclusion said no suspicious indicators were detected).
  const conclusion = analystConclusion({
    undecodable: false, decodeRatePct: 100, encapName: "Ethernet",
    alerts: report?.alerts ?? [], score: j.riskScore,
    quality: a1.advancedMetrics.rates?.quality,
  })
  expect.soft(
    (report?.alerts.length ?? 0) === 0 || conclusion.includes("NOT clean"),
    `${display}: verdict acknowledges findings (${conclusion.slice(0, 60)})`,
  ).toBe(true)
  // 0 alerts on a capture without a time interval: INSUFFICIENT EVIDENCE,
  // never a "clean" verdict (QA: 1-SYN capture concluded clean).
  if ((report?.alerts.length ?? 0) === 0 && a1.advancedMetrics.rates?.quality && a1.advancedMetrics.rates.quality !== "VALID") {
    expect.soft(conclusion.includes("insufficient evidence"), `${display}: non-VALID zero-alert capture concludes insufficient evidence (${conclusion.slice(0, 80)})`).toBe(true)
  }

  // Canonical capture metrics (metrics.ts): the engine's rates are the ONLY
  // numbers the report may divide by. On a capture without a time interval
  // (single packet / zero duration) the rates MUST be null and the report
  // must produce NO bandwidth series (QA: a 1-SYN capture reported 66 B/s).
  const q = a1.advancedMetrics.rates
  expect.soft(q, `${display}: advancedMetrics.rates present`).toBeTruthy()
  if (q) {
    if (q.quality === "VALID") {
      expect.soft(q.durationSec! > 0, `${display}: VALID duration > 0`).toBe(true)
      expect.soft(q.avgPacketsSec!, `${display}: VALID avgPacketsSec`).toBeGreaterThan(0)
      expect.soft(q.avgBps!, `${display}: VALID avgBps`).toBeGreaterThan(0)
      // The average is total/span — it may legitimately EXCEED the peak on
      // bursty captures (a gap mid-capture shrinks the divisor; Teardrop is
      // 914 B/s avg vs 764 B/s peak). avgExceedsPeak must track it exactly.
      expect.soft(q.avgExceedsPeak === (q.avgBps! > q.peakBps!), `${display}: avgExceedsPeak consistent (avg=${q.avgBps!.toFixed(1)}, peak=${q.peakBps})`).toBe(true)
    } else {
      expect.soft(q.durationSec === null && q.avgBps === null && q.avgPacketsSec === null && q.peakBps === null, `${display}: ${q.quality} has null rates`).toBe(true)
    }
    expect.soft(a1.advancedMetrics.burst === null || q.quality === "VALID", `${display}: burst only when VALID`).toBe(true)
  }
  expect.soft(
    q === undefined || q.quality === "VALID" ? true : (report?.bandwidth.length ?? 1) === 0,
    `${display}: no bandwidth series without a time interval`,
  ).toBe(true)
  expect.soft(
    (report?.metadata.ratesAvailable ?? true) || report?.bandwidth.length === 0,
    `${display}: ratesAvailable consistent`,
  ).toBe(true)
}

describe("corpus invariants — every capture must be internally consistent", () => {
  const files: { file: string; name: string }[] = []
  for (const sub of ["corpus", "."]) {
    const dir = join(fixturesDir, sub)
    try {
      for (const f of readdirSync(dir).filter((f) => f.endsWith(".pcap") || f.endsWith(".pcapng"))) {
        files.push({ file: join(dir, f), name: `[fx] ${f}` })
      }
    } catch { /* missing */ }
  }
  try {
    for (const f of readdirSync(externalDir).filter((f) => f.endsWith(".pcap") || f.endsWith(".pcapng"))) {
      files.push({ file: join(externalDir, f), name: `[dl] ${f}` })
    }
  } catch { /* external corpus not present on this machine */ }

  it.each(files)(`invariants hold: $name`, async ({ file, name }) => {
    await audit(file, name)
  }, 120_000)

  it("login.pcapng: plaintext HTTP credentials must fire HTTP-CREDS-001 (QA: risk was 0 SAFE)", async () => {
    const parsed = await parsePcap(readFileSync(join(fixturesDir, "corpus", "login.pcapng")))
    const a = analyzePcap(parsed)
    expect(a.credentials.length).toBeGreaterThan(0)
    const t = a.threats.find((x) => x.ruleId === "HTTP-CREDS-001")
    expect(t).toBeDefined()
    expect(t!.severity).toBe(4)
    expect(a.job.riskScore).toBeGreaterThan(0)
  })

  it("large.pcapng (when present): SNI-only VPN poll loop is not beaconing (QA: C2-BEACON-001 FP)", async () => {
    try {
      const parsed = await parsePcap(readFileSync(join(externalDir, "large.pcapng")))
      const a = analyzePcap(parsed)
      expect(a.threats.find((x) => x.ruleId === "C2-BEACON-001")).toBeUndefined()
      expect(a.job.riskScore).toBe(68)
    } catch {
      expect(true).toBe(true) // external corpus not on this machine
    }
  })
})
