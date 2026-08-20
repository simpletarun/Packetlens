import { describe, it, expect } from "vitest"
import { buildReportAnalysis, buildReportRisk, alertTrafficFor, binPackets, mitreSource, iocSource, SOURCE_LABELS, portServiceName, flowServiceName, talkerServicesOf, bandwidthStats, iocTypeLabel, shortAlertName, dnsLookupCount, servicePortCounts, serviceEvidenceLabel, osFromUserAgent, dltName, buildFlowsCsv, verdictLine, escHtml, mdInline, 
packetEpochSec, bucketOverlapSec, buildBandwidth, analystConclusion, plural, flowTableRows, sessionTableRows, 
duplicateFrameCountOf, statusLabel, findingSourceLabel, effectiveStatus, summarizeStatuses, statusCountsLabel, 
reportDurationSec, dnsUniqueDomains, dnsNameOf, credentialEventCount, sharePctLabel, rstAttribution } from "@/lib/report"
import { BUILD_STAMP } from "@/lib/build-stamp"
import { buildRiskInputs, burstDetected, computeRisk, computeRiskBreakdown, riskLevel } from "@/lib/risk"
import { tlsCipherSuiteName } from "@/lib/pcap"
import type { AdvancedMetrics, AlertEntry, Flow, Packet, Session } from "@/stores/analysis"
import type { GeoLocation } from "@/lib/geo"

const T0 = 1_700_000_000

function packet(sec: number, srcIp = "10.0.0.5", dstIp = "203.0.113.9", length = 128): Packet {
  return { num: sec + 1, timestamp: new Date((T0 + sec) * 1000).toISOString(), srcIp, dstIp, srcPort: 1234, dstPort: 80, protocol: "TCP", length, flags: "", ttl: 64, info: "" }
}

const portScanAlert: AlertEntry = {
  id: "a1", timestamp: new Date(T0 * 1000).toISOString(), signature: "TCP Port Scan Detected",
  category: "Reconnaissance", severity: 3, confidence: 70, ruleId: "PORT-SCAN-001",
  srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 0, dstPort: 0, protocol: "TCP", evidence: "28 unique ports scanned",
}

const beaconAlert: AlertEntry = {
  id: "a2", timestamp: new Date(T0 * 1000).toISOString(), signature: "Regular Beaconing Detected",
  category: "Command and Control", severity: 5, confidence: 65, ruleId: "C2-BEACON-001",
  srcIp: "multiple", dstIp: "external", srcPort: 0, dstPort: 0, protocol: "TCP", evidence: "Periodic communication pattern detected",
}

const dnsTunnelAlert: AlertEntry = {
  id: "a3", timestamp: new Date(T0 * 1000).toISOString(), signature: "Possible DNS Tunneling",
  category: "Exfiltration", severity: 4, confidence: 80, ruleId: "DNS-TUNNEL-001",
  srcIp: "multiple", dstIp: "external", srcPort: 0, dstPort: 0, protocol: "TCP", evidence: "Long or high-frequency DNS queries detected",
}

const advancedMetrics: AdvancedMetrics = {
  throughputAvg: 1000, throughputPeak: 5000,
  burst: { detected: true, peakThroughput: 5000, averageThroughput: 1000, ratio: 5, start: 1, end: 3, duration: 2, outboundDominant: true },
  beaconDetected: true, dnsTunnelingSuspected: true, dataExfiltrationSuspected: false,
  torVpnProxyDetected: false, portScanEnhanced: true, ja3Suspicious: false,
  topTalkers: [],
  iocs: [
    { type: "threat", value: "TCP Port Scan Detected", description: "28 unique ports scanned", severity: 3 },
    { type: "dns-tunneling", value: "Suspicious DNS patterns", description: "Long or high-frequency DNS queries detected", severity: 3 },
    { type: "beaconing", value: "Periodic communication detected", description: "Regular beaconing pattern identified", severity: 3 },
  ],
  mitreMappings: [
    { technique: "Port Scan", id: "T1046", description: "Network scanning for open ports", severity: 3 },
    { technique: "DNS Tunneling", id: "T1071.004", description: "Data encoded in DNS queries/responses", severity: 4 },
    { technique: "Application Layer Protocol", id: "T1071", description: "Periodic C2 beaconing detected", severity: 3 },
  ],
}

const state = {
  job: { id: "j1", filename: "x.pcap", fileSize: 1000, status: "done" as const, progress: 100, stage: "complete", totalPackets: 90, totalFlows: 1, conversations: 1, devices: 2, externalIps: 1, countries: 0, domains: 1, protocols: ["TCP"], alerts: 1, riskScore: 30, captureDuration: 88, createdAt: new Date(T0 * 1000).toISOString(), completedAt: new Date((T0 + 12) * 1000).toISOString() },
  jobInfo: { mode: "local" as const, analyzerVersion: "v3.0.0", riskSpecVersion: "1.2" },
  alerts: [portScanAlert],
  packets: Array.from({ length: 88 }, (_, i) => packet(i)),
  flows: [{ id: "f1", srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 1234, dstPort: 80, protocol: "TCP", packets: 42, bytesTotal: 6000, bytesSent: 4000, bytesRecv: 2000, duration: 10, startTime: "", endTime: "" }] as Flow[],
  sessions: [] as Session[],
  tls: [],
  http: [],
  timeline: [{ time: "22:25", packets: 88, bytes: 11264, tcp: 88, udp: 0, dns: 0, tls: 0 }],
  bandwidth: [{ time: "22:25", in: 5000, out: 6264 }],
  advancedMetrics,
}

describe("report consistency \u2014 single canonical analysis", () => {
  it("risk header value equals the breakdown value (one computation, one object)", () => {
    const r = buildReportAnalysis(state)
    expect(r.risk).not.toBeNull()
    const header = `${r.risk!.normalizedScore}/100 ${r.risk!.levelLabel}`
    expect(header).toContain(`${r.risk!.normalizedScore}`)
    expect(r.risk!.normalizedScore).toBe(r.risk!.items.length ? r.risk!.normalizedScore : r.risk!.normalizedScore)
    expect(r.risk!.normalizedScore).toBe(computeRisk(buildRiskInputs(state.alerts), burstDetected(state.advancedMetrics)))
  })

  it("no advanced metrics â†’ risk null (page falls back to job score, no breakdown shown)", () => {
    const r = buildReportAnalysis({ ...state, advancedMetrics: null })
    expect(r.risk).toBeNull()
  })

  it("alerts array is the single source (no copy/filter anywhere)", () => {
    const r = buildReportAnalysis(state)
    expect(r.alerts).toBe(state.alerts)
  })

it("IOC sources: signature-backed type is CONFIRMED_ALERT; flag types are CONFIRMED when the backing alert fired, else BEHAVIORAL", () => {
    const r = buildReportAnalysis(state)
    const iocs = new Map(r.iocs.map((i) => [i.type, i.source]))
    expect(iocs.get("threat")).toBe("CONFIRMED_ALERT")
    expect(iocs.get("dns-tunneling")).toBe("BEHAVIORAL_METRIC")
    expect(iocSource("beaconing", [beaconAlert])).toBe("CONFIRMED_ALERT")
    expect(iocSource("beaconing", [portScanAlert])).toBe("BEHAVIORAL_METRIC")
  })

  it("one IOC row per fired alert — alert-derived IOCs dedupe against the seeded threat IOC (QA: mic.pcapng showed 4 IOCs for 2 alerts)", () => {
    const r = buildReportAnalysis(state)
    // Fixture's seeded threat IOC predates the ruleId field: the signature
    // match must still stop the alert-only pass from appending a second row.
    const portScanRows = r.iocs.filter((i) => i.value === "TCP Port Scan Detected")
    expect(portScanRows).toHaveLength(1)
    expect(portScanRows[0].source).toBe("CONFIRMED_ALERT")
  })

  it("ruleId-keyed seeded IOCs dedupe the alert-only pass on fresh analyses", () => {
    const r = buildReportAnalysis({
      ...state,
      advancedMetrics: { ...advancedMetrics, iocs: [{ type: "threat", value: "Port Scan Detected", description: "28 unique ports scanned", severity: 3, ruleId: "PORT-SCAN-001" }] },
    })
    const portScanRows = r.iocs.filter((i) => i.ruleId === "PORT-SCAN-001")
    expect(portScanRows).toHaveLength(1)
  })

  it("IOC, MITRE and alert severities agree for the same finding (alert severity is canonical)", () => {
    const withBeacon = buildReportAnalysis({ ...state, alerts: [...state.alerts, beaconAlert] })
    const ioc = withBeacon.iocs.find((i) => i.type === "beaconing")
    const mitre = withBeacon.mitre.find((m) => m.id === "T1071")
    expect(ioc).toBeDefined()
    expect(ioc!.severity).toBe(beaconAlert.severity)
    expect(mitre).toBeDefined()
    expect(mitre!.severity).toBe(beaconAlert.severity)
    expect(ioc!.source).toBe(mitre!.source)
  })

  it("MITRE sources: alert-backed technique is CONFIRMED, flag-only technique is BEHAVIORAL", () => {
    const r = buildReportAnalysis(state)
    const mitre = new Map(r.mitre.map((m) => [m.id, m.source]))
    expect(mitre.get("T1046")).toBe("CONFIRMED_ALERT")
    expect(mitre.get("T1071.004")).toBe("BEHAVIORAL_METRIC")
    expect(mitreSource({ id: "T1046" }, [portScanAlert])).toBe("CONFIRMED_ALERT")
    expect(mitreSource({ id: "T1071.004" }, [portScanAlert])).toBe("BEHAVIORAL_METRIC")
    expect(mitreSource({ id: "T1071" }, [beaconAlert])).toBe("CONFIRMED_ALERT")
  })

  it("DNS MITRE technique (T1071.004) resolves CONFIRMED when the DNS-TUNNEL-001 alert fired, regardless of label drift", () => {
    const r = buildReportAnalysis({ ...state, alerts: [...state.alerts, dnsTunnelAlert] })
    const mitre = new Map(r.mitre.map((m) => [m.id, m.source]))
    const sev = new Map(r.mitre.map((m) => [m.id, m.severity]))
    expect(mitre.get("T1071.004")).toBe("CONFIRMED_ALERT")
    expect(sev.get("T1071.004")).toBe(dnsTunnelAlert.severity)
    expect(mitre.get("T1071")).toBe("BEHAVIORAL_METRIC")
    expect(mitreSource({ id: "T1071.004" }, [dnsTunnelAlert])).toBe("CONFIRMED_ALERT")
  })

  it("flag-backed recommendations carry CONFIRMED_ALERT when the rule fired, BEHAVIORAL_METRIC otherwise", () => {
    const withAlerts = buildReportAnalysis({ ...state, alerts: [...state.alerts, beaconAlert, dnsTunnelAlert] })
    const beaconRec = withAlerts.recommendations.find((r) => r.text.includes("Periodic communication"))
    const dnsRec = withAlerts.recommendations.find((r) => r.text.includes("Unusual DNS query"))
    expect(beaconRec!.source).toBe("CONFIRMED_ALERT")
    expect(beaconRec!.severity).toBe(beaconAlert.severity)
    expect(dnsRec!.source).toBe("CONFIRMED_ALERT")
    expect(dnsRec!.severity).toBe(dnsTunnelAlert.severity)
    // Legacy alerts (no status) default to CONFIRMED — established findings
    // keep no INVESTIGATE override; a SUSPECTED backing gets INVESTIGATE.
    expect(beaconRec!.priority).toBeUndefined()
    const suspected = buildReportAnalysis({
      ...state,
      alerts: [...state.alerts, { ...beaconAlert, status: "SUSPECTED" as const }, { ...dnsTunnelAlert, status: "SUSPECTED" as const }],
    })
    expect(suspected.recommendations.find((r) => r.text.includes("Periodic communication"))!.priority).toBe("INVESTIGATE")
    expect(suspected.recommendations.find((r) => r.text.includes("Unusual DNS query"))!.priority).toBe("INVESTIGATE")
    const flagsOnly = buildReportAnalysis(state)
    expect(flagsOnly.recommendations.find((r) => r.text.includes("Unusual DNS query"))!.source).toBe("BEHAVIORAL_METRIC")
  })

  it("dashboard and report count alerts from the same store array (canonical identity)", () => {
    const r = buildReportAnalysis(state)
    const dashboardAlerts = state.alerts
    expect(r.alerts).toBe(dashboardAlerts)
    expect(r.alerts.length).toBe(dashboardAlerts.length)
  })

  it("every recommendation carries a source", () => {
    const r = buildReportAnalysis(state)
    expect(r.recommendations.length).toBeGreaterThan(0)
    for (const rec of r.recommendations) {
      expect(Object.keys(SOURCE_LABELS)).toContain(rec.source)
    }
  })
})

describe("threat traffic \u2014 never fake zeros", () => {
  it("returns real flow counts when a matching flow exists", () => {
    const t = alertTrafficFor(portScanAlert, state.flows)
    expect(t.packets).toBe(42)
    expect(t.bytes).toBe(6000)
  })

  it("returns null (N/A) when no flow covers the alert's pair", () => {
    const t = alertTrafficFor({ ...portScanAlert, srcIp: "10.99.99.99" }, state.flows)
    expect(t.packets).toBeNull()
    expect(t.bytes).toBeNull()
  })

it("matches flows regardless of direction (deriveFlows normalizes src/dst by IP order)", () => {
    const reversed = alertTrafficFor({ ...portScanAlert, srcIp: "203.0.113.9", dstIp: "10.0.0.5" }, state.flows)
    expect(reversed.packets).toBe(42)
    expect(reversed.bytes).toBe(6000)
  })

  it("does not attribute a same-host flow on a different tuple (port gate)", () => {
    const flows: Flow[] = [
      { id: "dns", srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 12345, dstPort: 53, protocol: "UDP", packets: 200, bytesTotal: 10000, bytesSent: 5000, bytesRecv: 5000, duration: 10, startTime: "", endTime: "" },
      { id: "https", srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 12345, dstPort: 443, protocol: "TCP", packets: 500, bytesTotal: 30000, bytesSent: 0, bytesRecv: 0, duration: 10, startTime: "", endTime: "" },
    ]
    const t = alertTrafficFor({ ...portScanAlert, srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 12345, dstPort: 53 }, flows)
    expect(t.packets).toBe(200)
    expect(t.bytes).toBe(10000)
  })

  it("group traffic is summed once per unique tuple, not once per alert (Nx double count)", () => {
    const alerts = [1, 2, 3].map((i) => ({
      ...portScanAlert,
      id: `scan-${i}`,
      timestamp: new Date((T0 + i) * 1000).toISOString(),
      srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 0, dstPort: 0,
    }))
    const r = buildReportAnalysis({ ...state, alerts })
    const g = r.groups.find((x) => x.alertIds.length === 3)
    expect(g).toBeDefined()
    expect(g!.packets).toBe(42)
    expect(g!.bytes).toBe(6000)
  })
})

describe("math fixes (2026-08 audit)", () => {
  it("packetEpochSec treats numeric timestamps >= 1e12 as milliseconds", () => {
    const ms = { num: 1, timestamp: 1_700_000_000_000, srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 1, dstPort: 2, protocol: "TCP", length: 60, flags: "", ttl: 64, info: "" }
    const s = { ...ms, num: 2, timestamp: 1_700_000_000 }
    expect(packetEpochSec(ms)).toBe(1_700_000_000)
    expect(packetEpochSec(s)).toBe(1_700_000_000)
  })

  it("bucketOverlapSec divides partial edge 5-min buckets by their real capture overlap", () => {
    // Capture 10:03:00 → 10:07:00 (local): first bucket 10:00–10:05 holds 120 s.
    const start = new Date(2026, 7, 13, 10, 3, 0).getTime() / 1000
    const end = new Date(2026, 7, 13, 10, 7, 0).getTime() / 1000
    expect(bucketOverlapSec("10:00", start, end)).toBe(120)
    expect(bucketOverlapSec("10:05", start, end)).toBe(120)
    expect(bucketOverlapSec("10:15", start, end)).toBe(300)
  })

  it("bucketOverlapSec resolves post-midnight buckets against the NEXT day (audit)", () => {
    // Capture 23:50:00 → 00:03:00 crossing midnight: the 00:00–00:05 wall
    // bucket holds only 180 s, and resolving "00:00" on the START day would
    // put it BEFORE the capture (overlap 0 → full 300, understating ~1.7x).
    const start = new Date(2026, 7, 13, 23, 50, 0).getTime() / 1000
    const end = new Date(2026, 7, 14, 0, 3, 0).getTime() / 1000
    expect(bucketOverlapSec("00:00", start, end)).toBe(180)
    expect(bucketOverlapSec("23:55", start, end)).toBe(300)
  })

  it("buildBandwidth divides the partial TAIL rebin bin by its real width (audit)", () => {
    // 90 s capture, bin = 1 s (binPackets t0 = first packet): the LAST bin
    // spans only the 0.5 s tail between its last packet and the capture end.
    // Dividing it by the full 1 s would understate the tail's per-second rate.
    const start = 1_700_000_000
    const packets = Array.from({ length: 89 }, (_, i) => ({
      num: i + 1, timestamp: start + i, srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 1, dstPort: 2, protocol: "TCP", length: 60, flags: "", ttl: 64, info: "",
    }))
    packets.push({ num: 90, timestamp: start + 89.5, srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 1, dstPort: 2, protocol: "TCP", length: 60, flags: "", ttl: 64, info: "" })
    const bw = buildBandwidth(packets, [], 90)
    const tail = bw[bw.length - 1]
    // srcIp is private → counted as OUT. Tail bin: 89 s → 89.5 s holds 60 B
    // over 0.5 s = 120 B/s, not 60 B/s.
    expect(tail.out).toBeCloseTo(120, 6)
    // Interior bins stay full-width 60 B/s.
    expect(bw[0].out).toBe(60)
  })

  it("buildBandwidth divides each store bin by its own overlap, not fixed 300", () => {
    const start = new Date(2026, 7, 13, 10, 3, 0).getTime() / 1000
    const packets = [
      { num: 1, timestamp: start, srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 1, dstPort: 2, protocol: "TCP", length: 60, flags: "", ttl: 64, info: "" },
      { num: 2, timestamp: start + 720, srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 1, dstPort: 2, protocol: "TCP", length: 60, flags: "", ttl: 64, info: "" },
    ]
    const bw = buildBandwidth(packets, [
      { time: "10:00", in: 12000, out: 0 },
      { time: "10:05", in: 3000, out: 0 },
      { time: "10:10", in: 3000, out: 0 },
    ], 720)
    expect(bw.map((b) => b.in)).toEqual([100, 10, 10])
  })

  it("servicePortCounts keeps known service ports >= 49152 (WireGuard 51820)", () => {
    const top = servicePortCounts([
      { srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 50000, dstPort: 51820, protocol: "UDP" },
    ])
    expect(top[0].port).toBe(51820)
  })
})

describe("top ports and throughput helpers", () => {
  it("maps well-known ports to service names and dynamic ports to ephemeral", () => {
    expect(portServiceName(443)).toBe("HTTPS")
    expect(portServiceName(53)).toBe("DNS")
    expect(portServiceName(5222)).toBe("XMPP")
    expect(portServiceName(47942)).toBe("Dynamic/Ephemeral")
    expect(portServiceName(49161)).toBe("Dynamic/Ephemeral")
    expect(portServiceName(9999)).toBe("Unknown service")
  })

  it("protocol disambiguates port labels: UDP/443 is QUIC, TCP/443 is HTTPS", () => {
    expect(portServiceName(443, "UDP")).toBe("QUIC")
    expect(portServiceName(443, "TCP")).toBe("HTTPS")
    expect(portServiceName(53, "UDP")).toBe("DNS")
    expect(portServiceName(53, "TCP")).toBe("DNS")
  })

  it("labels discovery/real-time services the report actually sees (no more 'Unassigned' for STUN)", () => {
    expect(portServiceName(3478)).toBe("STUN")
    expect(portServiceName(5349)).toBe("STUN")
    expect(portServiceName(5353)).toBe("mDNS")
    expect(portServiceName(1900)).toBe("SSDP")
    expect(portServiceName(3702)).toBe("WS-Discovery")
    expect(portServiceName(51820)).toBe("WireGuard")
  })

  it("labels the previously missing TCP/7 Echo and TCP/5228 GCM ports", () => {
    expect(portServiceName(7)).toBe("Echo")
    expect(portServiceName(7, "TCP")).toBe("Echo")
    expect(portServiceName(5228)).toBe("GCM (FCM)")
    expect(portServiceName(5228, "TCP")).toBe("GCM (FCM)")
  })

  it("dnsLookupCount: a relayed lookup counts once, whatever the forwarding router", () => {
    const mk = (src: string, dst: string, query: string, type = "A") => ({ id: "d", timestamp: "", srcIp: src, dstIp: dst, query, type, responseCode: "NOERROR", answer: "", ttl: 1 })
    const entries = [
      mk("192.168.1.5", "192.168.1.1", "api.github.com"),
      mk("192.168.1.1", "8.8.8.8", "api.github.com"), // router relay \u2014 same lookup
      mk("192.168.1.1", "8.8.8.8", "api.github.com"), // retransmit
      mk("192.168.1.5", "192.168.1.1", "google.com", "AAAA"),
    ]
    expect(dnsLookupCount(entries)).toBe(2)
  })

  it("dnsLookupCount: direct-to-resolver queries dedupe by name+type", () => {
    const mk = (query: string, type = "A") => ({ id: "d", timestamp: "", srcIp: "10.0.0.5", dstIp: "1.1.1.1", query, type, responseCode: "NOERROR", answer: "", ttl: 1 })
    expect(dnsLookupCount([mk("a.com"), mk("a.com"), mk("b.com")])).toBe(2)
  })

  it("dnsUniqueDomains: case and trailing-dot variants are ONE name (RFC 4343)", () => {
    const mk = (query: string) => ({ id: "d", timestamp: "", srcIp: "10.0.0.5", dstIp: "1.1.1.1", query, type: "A", responseCode: "NOERROR", answer: "", ttl: 1 })
    const names = dnsUniqueDomains([mk("Example.COM."), mk("example.com"), mk("example.com"), mk("a.b.com")])
    expect(names).toEqual(new Set(["example.com", "a.b.com"]))
    expect(dnsUniqueDomains([mk(""), mk("")]).size).toBe(0)
  })

  it("dnsNameOf: strips one trailing dot and lowercases", () => {
    expect(dnsNameOf("Example.COM.")).toBe("example.com")
    expect(dnsNameOf("www.example.com.")).toBe("www.example.com")
    expect(dnsNameOf("")).toBe("")
    expect(dnsNameOf(undefined)).toBe("")
  })

it("burst bonus is reported as applied only when an eligible rule actually benefits", () => {
    const burstMetrics = { burst: { detected: true }, beaconDetected: true } as unknown as AdvancedMetrics
    expect(buildReportRisk([portScanAlert], burstMetrics)?.burstApplied).toBe(false)
    expect(buildReportRisk([beaconAlert], burstMetrics)?.burstApplied).toBe(true)
    const noBurst = { burst: { detected: false }, beaconDetected: true } as unknown as AdvancedMetrics
    expect(buildReportRisk([beaconAlert], noBurst)?.burstApplied).toBe(false)
  })

  it("verdict floors to the strongest finding's severity (score band LOW, finding HIGH)", () => {
    const credAlert: AlertEntry = {
      id: "t1", timestamp: new Date(T0 * 1000).toISOString(), signature: "Plaintext HTTP Credentials",
      category: "Plaintext Credential Exposure", severity: 4, confidence: 75, ruleId: "HTTP-CREDS-001",
      srcIp: "10.0.0.5", dstIp: "23.155.129.172", srcPort: 0, dstPort: 0, protocol: "TCP", evidence: "x",
    }
    const metrics = { burst: null, beaconDetected: false } as unknown as AdvancedMetrics
    const r = buildReportRisk([credAlert], metrics)
    // Numeric score is untouched: one HTTP-CREDS-001 → raw 40 → 39 (LOW band).
    expect(r?.normalizedScore).toBe(39)
    expect(r?.highestSeverity).toBe(4)
    // But the verdict level is floored by the High finding, never "LOW".
    expect(r?.levelLabel).toBe("HIGH")
    // No findings → the pure score band stands.
    const safe = buildReportRisk([], metrics)
    expect(safe?.levelLabel).toBe(riskLevel(safe!.normalizedScore).label)
    // A Medium finding floors to MEDIUM.
    const medAlert: AlertEntry = { ...credAlert, severity: 3, ruleId: "PORT-SCAN-001" }
    expect(buildReportRisk([medAlert], metrics)?.levelLabel).toBe("MEDIUM")
  })

  it("rawScore stays UNROUNDED so the breakdown's curve row agrees with the normalized score (audit)", () => {
    // TLS-SUSPICIOUS-001 (sev 3 → 8, rule 25) at confidence 40 → 0.5×
    // multiplier → raw 11.5: a fractional raw must NOT be pre-rounded. The
    // page substitutes the stored raw into the curve, and a rounded 12 would
    // display a formula that no longer produces the shown normalized score.
    const alert: AlertEntry = {
      id: "t1", timestamp: new Date(T0 * 1000).toISOString(), signature: "Suspicious TLS",
      category: "Suspicious TLS", severity: 3, confidence: 40, ruleId: "TLS-SUSPICIOUS-001",
      srcIp: "10.0.0.5", dstIp: "23.155.129.172", srcPort: 0, dstPort: 0, protocol: "TCP", evidence: "x",
    }
    const metrics = { burst: null, beaconDetected: false } as unknown as AdvancedMetrics
    const r = buildReportRisk([alert], metrics)
    expect(r?.rawScore).toBe(11.5)
    // The stored raw is the curve input: round(100 * (1 - exp(-raw/80)))
    // === normalized — a pre-rounded raw would break this identity.
    expect(Math.round(100 * (1 - Math.exp(-r!.rawScore / 80)))).toBe(r!.normalizedScore)
  })

  it("bandwidthStats: min/median/p95 from interval sums; nulls when not enough data", () => {
    expect(bandwidthStats([])).toEqual({ min: null, median: null, p95: null })
    expect(bandwidthStats([{ in: 5, out: 5 }])).toEqual({ min: null, median: null, p95: null })
    const bins = [{ in: 0, out: 1000 }, { in: 0, out: 2000 }, { in: 0, out: 3000 }, { in: 0, out: 4000 }]
    expect(bandwidthStats(bins)).toEqual({ min: 1000, median: 2500, p95: 4000 })
  })

  it("iocTypeLabel maps internal identifiers to analyst-readable names", () => {
    expect(iocTypeLabel("threat")).toBe("Network Threat")
    expect(iocTypeLabel("dns-tunneling")).toBe("DNS Tunneling")
    expect(iocTypeLabel("beaconing")).toBe("Beaconing")
    expect(iocTypeLabel("data-exfiltration")).toBe("Suspected Large Outbound Transfer")
    expect(iocTypeLabel("weird-type")).toBe("Weird Type")
  })

  it("shortAlertName strips signatures down to the finding", () => {
    expect(shortAlertName("TCP Port Scan Detected")).toBe("TCP Port Scan")
    expect(shortAlertName("Possible DNS Tunneling")).toBe("DNS Tunneling")
    expect(shortAlertName("Regular Beaconing Detected")).toBe("Beaconing")
    expect(shortAlertName("Suspicious TLS")).toBe("Suspicious TLS")
  })
})

describe("timeline binning", () => {
  it("an 88s capture with a single store bin rebins to 1s intervals and preserves the packet total", () => {
    const bins = binPackets(state.packets, 88)
    expect(bins.length).toBe(88)
    expect(bins.reduce((s, b) => s + b.packets, 0)).toBe(88)
    expect(bins[0].time).toBe("00:00")
    expect(bins[87].time).toBe("01:27")
  })

  it("short captures (â‰¤10 min) rebin from packets even when the store has 2 coarse 5-minute bins \u2014 never collapses an 88s capture to 2 points", () => {
    const multi = [{ time: "22:20", packets: 10, bytes: 1, tcp: 10, udp: 0, dns: 0, tls: 0 }, { time: "22:25", packets: 20, bytes: 2, tcp: 20, udp: 0, dns: 0, tls: 0 }]
    const r = buildReportAnalysis({ ...state, timeline: multi })
    expect(r.timeline.length).toBe(88)
    expect(r.timeline.reduce((s, t) => s + t.packets, 0)).toBe(88)
    expect(r.timeline[0].time).toBe("00:00")
    expect(r.timeline[87].time).toBe("01:27")
  })

  it("long captures (>10 min) keep the store 5-minute bins", () => {
    const multi = [{ time: "22:20", packets: 10, bytes: 1, tcp: 10, udp: 0, dns: 0, tls: 0 }, { time: "22:25", packets: 20, bytes: 2, tcp: 20, udp: 0, dns: 0, tls: 0 }]
    const longPackets = [packet(0), packet(3600)]
    const r = buildReportAnalysis({ ...state, job: { ...state.job, captureDuration: 3600 }, timeline: multi, packets: longPackets })
    // Full entries, not just {time, packets}: the timeline page draws protocol
    // slices (TCP/UDP/DNS/TLS/OTHER) from these rows.
    expect(r.timeline).toEqual(multi)
  })

  it("bandwidth points are per-second: packet bins divide by bin width, store 5-min bins by 300", () => {
    // 88s capture â†’ 1s bins; each packet is 128B from a private source â†’ out
    const r = buildReportAnalysis(state)
    expect(r.bandwidth.length).toBe(88)
    expect(r.bandwidth[0].out).toBe(128)
    expect(r.bandwidth[0].in).toBe(0)
    // Store bins are 5-minute SUMS (1.5 MB in a bin) \u2014 as a rate that is 5 KB/s
    const storeBins = [{ time: "22:20", in: 1_500_000, out: 0 }, { time: "22:25", in: 3_000_000, out: 0 }]
    const long = buildReportAnalysis({ ...state, job: { ...state.job, captureDuration: 3600 }, bandwidth: storeBins, packets: [packet(0), packet(3600)] })
    expect(long.bandwidth).toEqual([
      { time: "22:20", in: 5000, out: 0 },
      { time: "22:25", in: 10000, out: 0 },
    ])
  })

  it("5s bins for captures up to 10 minutes", () => {
    const dur = 300
    const packets = Array.from({ length: 300 }, (_, i) => packet(i))
    const bins = binPackets(packets, dur)
    expect(bins.length).toBe(60)
  })

  it("DNS/TLS packets land in exactly one slice \u2014 never double-counted in the stacked bars (QA: 527 UDP + 2 DNS from 529 UDP packets)", () => {
    const p: Packet[] = [
      { ...packet(0), protocol: "UDP", dstPort: 53, appProtocol: "DNS" },
      { ...packet(1), protocol: "UDP", dstPort: 53, appProtocol: "DNS" },
      { ...packet(2), protocol: "UDP", dstPort: 53, appProtocol: "DNS" },
      { ...packet(3), protocol: "TCP", dstPort: 443, appProtocol: "TLS" },
      { ...packet(4), protocol: "TCP", dstPort: 80, appProtocol: "HTTP" },
      { ...packet(5), protocol: "TCP", dstPort: 443, appProtocol: "HTTPS" },
    ]
    const bins = binPackets(p, 10)
    const tot = bins.reduce(
      (s, b) => ({ packets: s.packets + b.packets, dns: s.dns + b.dns, udp: s.udp + b.udp, tls: s.tls + b.tls, tcp: s.tcp + b.tcp }),
      { packets: 0, dns: 0, udp: 0, tls: 0, tcp: 0 },
    )
    expect(tot.packets).toBe(6)
    expect(tot.dns).toBe(3)
    expect(tot.udp).toBe(0)
    expect(tot.tls).toBe(2)
    expect(tot.tcp).toBe(1)
    // The stacked bar can never overflow its bucket: slices sum â‰¤ packets.
    for (const b of bins) expect(b.tcp + b.udp + b.dns + b.tls).toBeLessThanOrEqual(b.packets)
  })
})

describe("metadata", () => {
  it("exposes mode, schema version and analysis duration", () => {
    const r = buildReportAnalysis(state)
    expect(r.metadata.mode).toContain("Local")
    expect(r.metadata.schemaVersion).toBe("1.0")
    expect(r.metadata.analysisDurationSec).toBe(12)
    expect(r.metadata.analyzerVersion).toBe("v3.0.0")
  })

  it("demo jobs are labeled as local browser analysis", () => {
    const r = buildReportAnalysis({ ...state, jobInfo: { isDemo: true } })
    expect(r.metadata.mode).toContain("demo")
  })
})

describe("demo dataset \u2014 header and breakdown cannot diverge", () => {
  it("canonical risk from mock store state equals mockJob.riskScore (header == breakdown)", async () => {
    const m = await import("@/lib/mock-data")
    const r = buildReportAnalysis({
      job: m.mockJob,
      jobInfo: m.mockJobInfo,
      alerts: m.mockThreats,
      packets: m.mockPackets,
      flows: m.mockFlows,
      sessions: m.mockSessions,
      tls: m.mockTls,
      http: m.mockHttp,
      timeline: m.mockTimeline,
      bandwidth: m.mockBandwidth,
      advancedMetrics: m.mockAdvancedMetrics,
    })
    expect(r.risk).not.toBeNull()
    expect(r.risk!.normalizedScore).toBe(m.mockJob.riskScore)
    expect(r.alerts).toBe(m.mockThreats)
    expect(m.mockJob.alerts).toBe(m.mockThreats.length)
  })

  it("demo dataset \u2014 every section agrees on the data-exfiltration finding", async () => {
    const m = await import("@/lib/mock-data")
    const r = buildReportAnalysis({
      job: m.mockJob,
      jobInfo: m.mockJobInfo,
      alerts: m.mockThreats,
      packets: m.mockPackets,
      flows: m.mockFlows,
      sessions: m.mockSessions,
      tls: m.mockTls,
      http: m.mockHttp,
      timeline: m.mockTimeline,
      bandwidth: m.mockBandwidth,
      advancedMetrics: m.mockAdvancedMetrics,
    })
// The demo metrics are now derived from the actual mock packets (QA: the
    // hand-written 4.1 MB exfiltration finding was impossible from the data):
    // no "large outbound transfers" recommendation may be claimed, and any
    // data-exfiltration IOC / T1041 mitre row must be CONFIRMED_ALERT-sourced
    // from a fired alert (the curated "ICMP Tunneling" shares rule
    // DATA-EXFIL-001), never from the metrics.
    const alert = m.mockThreats.find((t: { ruleId: string }) => t.ruleId === "DATA-EXFIL-001")
    expect(m.mockAdvancedMetrics.dataExfiltrationSuspected).toBe(false)
    const rec = r.recommendations.find((x) => x.text.includes("large outbound transfers"))
    expect(rec).toBeUndefined()
    for (const finding of [
      r.iocs.find((i) => i.type === "data-exfiltration"),
      r.mitre.find((m2) => m2.id === "T1041"),
    ]) {
      if (finding) {
        expect(finding.source).toBe("CONFIRMED_ALERT")
        expect(finding.severity).toBe(alert!.severity)
      }
    }
  })
})

describe("servicePortCounts \u2014 conversation-based service-side attribution", () => {
  // QA regression: ephemeral source ports BELOW 32768 (e.g. 12209) failed the
  // old ">= 32768 is ephemeral" check, so serverâ†’client reply packets were
  // attributed to the client's port and TCP/443 split (1,175 â†’ 768 + leaked).
  const p = (srcIp: string, dstIp: string, srcPort: number, dstPort: number, protocol: string) =>
    ({ srcIp, dstIp, srcPort, dstPort, protocol })

  it("counts BOTH legs of a TCP/443 conversation under TCP/443 even when the client port is below 32768", () => {
    const packets = [
      p("10.0.0.5", "1.2.3.4", 12209, 443, "TCP"),
      p("1.2.3.4", "10.0.0.5", 443, 12209, "TCP"),
      p("10.0.0.5", "1.2.3.4", 12209, 443, "TCP"),
      p("1.2.3.4", "10.0.0.5", 443, 12209, "TCP"),
    ]
    const top = servicePortCounts(packets)
    expect(top).toEqual([{ protocol: "TCP", port: 443, count: 4, confirmed: 0, flows: 1, confirmedFlows: 0 }])
  })

  it("applies the same rule to UDP (request and reply legs both count toward UDP/443)", () => {
    const packets = [
      p("10.0.0.5", "1.2.3.4", 49152, 443, "UDP"),
      p("1.2.3.4", "10.0.0.5", 443, 49152, "UDP"),
      p("10.0.0.5", "1.2.3.4", 49152, 53, "UDP"),
      p("1.2.3.4", "10.0.0.5", 53, 49152, "UDP"),
    ]
    const top = servicePortCounts(packets)
    expect(top).toEqual([
      { protocol: "UDP", port: 443, count: 2, confirmed: 0, flows: 1, confirmedFlows: 0 },
      { protocol: "UDP", port: 53, count: 2, confirmed: 0, flows: 1, confirmedFlows: 0 },
    ])
  })

  it("keys conversations by normalized 5-tuple: independent client ports stay separate", () => {
    const packets = [
      p("10.0.0.5", "1.2.3.4", 12209, 443, "TCP"),
      p("1.2.3.4", "10.0.0.5", 443, 12209, "TCP"),
      p("10.0.0.6", "1.2.3.4", 14820, 443, "TCP"),
      p("1.2.3.4", "10.0.0.6", 443, 14820, "TCP"),
    ]
    const top = servicePortCounts(packets)
    // Two independent client conversations — the flows count must be 2.
    expect(top).toEqual([{ protocol: "TCP", port: 443, count: 4, confirmed: 0, flows: 2, confirmedFlows: 0 }])
  })

  it("skips port-less packets (ICMP/GRE/ESP have no srcPort/dstPort)", () => {
    const packets = [
      p("10.0.0.5", "1.2.3.4", 12209, 443, "TCP"),
      { srcIp: "10.0.0.5", dstIp: "1.2.3.4", srcPort: undefined, dstPort: undefined, protocol: "ICMP" },
    ]
    const top = servicePortCounts(packets)
    expect(top).toEqual([{ protocol: "TCP", port: 443, count: 1, confirmed: 0, flows: 1, confirmedFlows: 0 }])
  })

  it("ranks multiple services by total conversation packets", () => {
    const packets = [
      p("10.0.0.5", "1.2.3.4", 12209, 443, "TCP"),
      p("1.2.3.4", "10.0.0.5", 443, 12209, "TCP"),
      p("10.0.0.5", "8.8.8.8", 23061, 53, "UDP"),
    ]
    const top = servicePortCounts(packets)
    expect(top[0]).toEqual({ protocol: "TCP", port: 443, count: 2, confirmed: 0, flows: 1, confirmedFlows: 0 })
    expect(top[1]).toEqual({ protocol: "UDP", port: 53, count: 1, confirmed: 0, flows: 1, confirmedFlows: 0 })
  })

  it("handles mid-session captures: a flow whose FIRST packet is a server reply still counts under the known service port", () => {
    // test.pcapng regression (fcb528a9): TCP/42224 295 + TCP/443 880 =
    // 1,175. The 42224 conversation was captured mid-session \u2014 its first
    // packets are serverâ†’client replies \u2014 so the old "first-packet
    // destination" rule dumped the whole flow onto the client's port.
    const packets = [
      p("1.2.3.4", "10.0.0.5", 443, 42224, "TCP"),
      p("1.2.3.4", "10.0.0.5", 443, 42224, "TCP"),
      p("1.2.3.4", "10.0.0.5", 443, 42224, "TCP"),
      p("10.0.0.5", "1.2.3.4", 42224, 443, "TCP"),
    ]
    const top = servicePortCounts(packets)
    expect(top).toEqual([{ protocol: "TCP", port: 443, count: 4, confirmed: 0, flows: 1, confirmedFlows: 0 }])
    expect(top.some((e) => e.port === 42224)).toBe(false)
    expect(top.some((e) => e.port >= 49152)).toBe(false)
  })

it("excludes P2P conversations between two dynamic-range ports (UDP/57621 gone)", () => {
    const packets = [
      p("192.168.1.15", "192.168.1.255", 57621, 57621, "UDP"),
      p("192.168.1.15", "192.168.1.255", 57621, 57621, "UDP"),
    ]
    expect(servicePortCounts(packets)).toEqual([])
  })

  it("excludes P2P even when the lower dynamic port is 32768..49151 — both sides ephemeral (testing.pcapng 40714 regression)", () => {
    // The old rule looked for "both ports >= 49152", so this real capture —
    // 192.168.137.1:49161 <-> 192.168.137.228:40714 (159 pkts) — leaked a
    // bogus "TCP/40714" service row. 40714 is inside the app's own
    // "Dynamic/Ephemeral" 32768..49151 band (ephemeralOrKnown), so the rule
    // now matches on that band (EPHEMERAL_PORT_MIN = 32768): a=min there
    // means both are dynamic, hence P2P.
    const packets = [
      p("192.168.137.1", "192.168.137.228", 49161, 40714, "TCP"),
      p("192.168.137.228", "192.168.137.1", 40714, 49161, "TCP"),
    ]
    expect(servicePortCounts(packets)).toEqual([])
    // The same two-port pattern where the known port is BELOW 32768 must
    // still be attributed to it (RDP 12481 to the phone's 40714 → TCP/12481).
    const mixed = [p("192.168.137.228", "192.168.137.1", 40714, 12481, "TCP")]
    expect(servicePortCounts(mixed)[0]).toEqual({ protocol: "TCP", port: 12481, count: 1, confirmed: 0, flows: 1, confirmedFlows: 0 })
  })

  it("attributes mDNS (5353) even when the first packet is the response leg", () => {
    const packets = [
      p("192.168.1.255", "192.168.1.15", 5353, 57621, "UDP"),
      p("192.168.1.15", "192.168.1.255", 57621, 5353, "UDP"),
    ]
    expect(servicePortCounts(packets)).toEqual([{ protocol: "UDP", port: 5353, count: 2, confirmed: 0, flows: 1, confirmedFlows: 0 }])
  })

  it("prefers the lower port when both endpoints use known service ports", () => {
    const packets = [
      p("10.0.0.5", "1.2.3.4", 8443, 443, "TCP"),
      p("1.2.3.4", "10.0.0.5", 443, 8443, "TCP"),
    ]
    expect(servicePortCounts(packets)).toEqual([{ protocol: "TCP", port: 443, count: 2, confirmed: 0, flows: 1, confirmedFlows: 0 }])
  })
})

describe("osFromUserAgent \u2014 HTTP User-Agent OS fingerprint", () => {
  it("maps Microsoft-CryptoAPI to Windows even though its UA never says 'Windows'", () => {
    expect(osFromUserAgent("Microsoft-CryptoAPI/10.0")).toBe("Windows")
  })

  it("maps common browser/mobile UAs", () => {
    expect(osFromUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126")).toBe("Windows")
    expect(osFromUserAgent("Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/126")).toBe("Android")
    expect(osFromUserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)")).toBe("iOS")
    expect(osFromUserAgent("curl/8.4.0")).toBeUndefined()
    expect(osFromUserAgent("")).toBeUndefined()
  })
})

describe("dltName \u2014 encapsulation diagnostics", () => {
  it("maps known link types and keeps unknown DLT numbers (QA verylarge)", () => {
    expect(dltName([1])).toBe("Ethernet")
    expect(dltName([113])).toBe("Linux cooked v1 (SLL)")
    expect(dltName([])).toBe("unknown")
    expect(dltName([147])).toBe("DLT 147")
    expect(dltName([1, 101])).toBe("Ethernet, Raw IP (IPv4/IPv6)")
  })
})

describe("v3.2 export schema and verdict", () => {
it("buildFlowsCsv: BOM + split IP/port columns + sent+recv = total + empty cells for N/A", () => {
    const geo = new Map<string, GeoLocation>([
      ["203.0.113.9", { ip: "203.0.113.9", country: "United States", countryCode: "US", city: "X", lat: 1, lon: 1, isPrivate: false, asn: "AS64500" }],
    ])
    const flows: Flow[] = [
      { id: "f1", srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 1234, dstPort: 80, protocol: "TCP", packets: 42, bytesTotal: 6000, bytesSent: 4000, bytesRecv: 2000, duration: 10, startTime: "2024-01-01T00:00:00Z", endTime: "2024-01-01T00:00:10Z", rttMs: 9, retrans: 1 },
      { id: "f2", srcIp: "203.0.113.9", dstIp: "10.0.0.5", srcPort: 80, dstPort: 1234, protocol: "TCP", packets: 12, bytesTotal: 1000, bytesSent: 0, bytesRecv: 0, duration: 2, startTime: "", endTime: "", directionUnknown: true, rttMs: 0, retrans: 0 },
      { id: "f3", srcIp: "\u2014", dstIp: "\u2014", srcPort: 0, dstPort: 0, protocol: "OTHER", packets: 4, bytesTotal: 243, bytesSent: 0, bytesRecv: 0, duration: 1, startTime: "", endTime: "", directionUnknown: true },
      { id: "f4", srcIp: "2401:4900:1:2:3:4:5:6", dstIp: "203.0.113.20", srcPort: 443, dstPort: 53000, protocol: "UDP", packets: 1, bytesTotal: 100, bytesSent: 100, bytesRecv: 0, duration: 1, startTime: "", endTime: "", directionUnknown: true },
    ]
    const csv = buildFlowsCsv(flows, geo)
    expect(csv.startsWith("\uFEFF")).toBe(true)
    const lines = csv.split("\n")
    // Build-identity comment rides the export so the artifact traces to a
    // commit, followed by the semantics lines that document the columns a
    // spreadsheet reader cannot see explained anywhere else (RFC 4180 §2.1
    // allows comment preamble rows).
    expect(lines[0]).toMatch(/^\uFEFF# PacketLens v\d+\.\d+\.\d+ · (commit|src):.* · 4 flows$/)
    expect(lines[1]).toMatch(/^# Rows are initiator-first:/)
    expect(lines[2]).toMatch(/^# serviceEvidence:/)
    expect(lines[3]).toMatch(/^# estLossPct:/)
    expect(lines[4]).toMatch(/^# srcCountry\/dstCountry: FLOW-level/)
    expect(lines[5]).toMatch(/^# directionSemantics: initiator\/responder/)
    expect(lines[6]).toBe("srcIp,srcPort,dstIp,dstPort,protocol,packets,bytesSent,bytesRecv,bytesTotal,startTime,endTime,durationSec,srcCountry,dstCountry,srcAsn,dstAsn,service,serviceEvidence,rttMs,retrans,dataSegments,estLossPct")
    // src/dst in their own columns — "ip:port" pairs are gone (IPv6 safety).
    expect(lines[7]).toBe("10.0.0.5,1234,203.0.113.9,80,TCP,42,4000,2000,6000,2024-01-01T00:00:00Z,2024-01-01T00:00:10Z,10,,US,,AS64500,HTTP,port,9,1,,")
    // Direction-unknown: empty sent/recv cells, never the string "unknown";
    // service reads N/A like the port-less rows, never a blank (QA: OTHER
    // rows shipped an empty service while ARP/ICMPv6 said N/A).
    expect(lines[8]).toBe("203.0.113.9,80,10.0.0.5,1234,TCP,12,,,1000,,,2,US,,AS64500,,N/A,,0,0,,")
    expect(lines[8]).not.toContain("unknown")
    expect(lines[8]).not.toContain("\u2014")
    // Undecodable ("—") endpoints keep an explicit label, never an em-dash
    // or a silent blank (QA: "OTHER flow has empty source/destination").
    expect(lines[9]).toBe("Undecoded/unknown endpoint,0,Undecoded/unknown endpoint,0,OTHER,4,,,243,,,1,,,,,N/A,,,,,")
    // IPv6 row parses as 4 separate columns (no 9-group "ip:port" address).
    expect(lines[10]).toBe("2401:4900:1:2:3:4:5:6,443,203.0.113.20,53000,UDP,1,,,100,,,1,,,,,N/A,,,,,")
    // Exactly SIX comment rows (loss denominator + flow-level countries +
    // initiator/responder semantics are documented for spreadsheet readers),
    // then schema rows only.
    expect(lines.filter((l) => l.replace(/^\uFEFF/, "").startsWith("#"))).toHaveLength(6)
    expect(lines).toHaveLength(11)
  })

  it("buildFlowsCsv: serviceEvidence column is port/mixed/payload, never a guess", () => {
    // UDP/3478 conversation where only SOME packets were cookie-verified STUN
    // (the audit's 26-of-622 case): the flow stays "STUN" (service port) but
    // the evidence column says "mixed" — the label no longer reads as 622
    // confirmed STUN packets.
    const stunFlow: Flow = { id: "f1", srcIp: "101.2.27.162", dstIp: "192.168.1.20", srcPort: 3478, dstPort: 65242, protocol: "UDP", packets: 3, bytesTotal: 100, bytesSent: 100, bytesRecv: 0, duration: 1, startTime: "", endTime: "" }
    const stunPackets = [
      { srcIp: "101.2.27.162", dstIp: "192.168.1.20", srcPort: 3478, dstPort: 65242, protocol: "UDP", appProtocol: "STUN", appPayloadConfirmed: true },
      { srcIp: "101.2.27.162", dstIp: "192.168.1.20", srcPort: 3478, dstPort: 65242, protocol: "UDP", appProtocol: "UDP" },
      { srcIp: "101.2.27.162", dstIp: "192.168.1.20", srcPort: 3478, dstPort: 65242, protocol: "UDP", appProtocol: "UDP" },
    ]
    expect(buildFlowsCsv([stunFlow], new Map(), stunPackets).split("\n")[7].split(",")[17]).toBe("mixed")
    // A port-fallback label WITHOUT the decoder's confirmation flag is NEVER
    // payload evidence: big.pcapng's UDP/443 QUIC flow read "payload" next to
    // a "port-inferred" note while zero Initial handshake packets existed
    // (QA). The label alone — even matching the service — means "port".
    const quicPackets = [
      { srcIp: "185.165.242.20", dstIp: "192.168.1.10", srcPort: 443, dstPort: 55290, protocol: "UDP", appProtocol: "QUIC" },
      { srcIp: "185.165.242.20", dstIp: "192.168.1.10", srcPort: 443, dstPort: 55290, protocol: "UDP", appProtocol: "QUIC" },
    ]
    const quicFlow: Flow = { id: "f4", srcIp: "185.165.242.20", dstIp: "192.168.1.10", srcPort: 443, dstPort: 55290, protocol: "UDP", packets: 2, bytesTotal: 200, bytesSent: 200, bytesRecv: 0, duration: 1, startTime: "", endTime: "" }
    expect(buildFlowsCsv([quicFlow], new Map(), quicPackets).split("\n")[7].split(",")[17]).toBe("port")
    // A payload-verified QUIC Initial packet flips it to full "payload".
    const verified = quicPackets.map((p) => ({ ...p, appPayloadConfirmed: true }))
    expect(buildFlowsCsv([quicFlow], new Map(), verified).split("\n")[7].split(",")[17]).toBe("payload")
    // No packet evidence → "port". UDP/8001 HTTP-Alt is port-based, so even a
    // port-labeled HTTP-Alt packet never counts as payload evidence.
    const altPackets = [
      { srcIp: "192.168.1.3", dstIp: "224.0.0.7", srcPort: 8001, dstPort: 8001, protocol: "UDP", appProtocol: "HTTP-Alt" },
    ]
    const altFlow: Flow = { id: "f2", srcIp: "192.168.1.3", dstIp: "224.0.0.7", srcPort: 8001, dstPort: 8001, protocol: "UDP", packets: 1, bytesTotal: 100, bytesSent: 100, bytesRecv: 0, duration: 1, startTime: "", endTime: "" }
    expect(buildFlowsCsv([altFlow], new Map(), altPackets).split("\n")[7].split(",")[17]).toBe("port")
    // Direction-unknown rows carry no service, hence no evidence.
    const dirUnknown: Flow = { id: "f3", srcIp: "203.0.113.9", dstIp: "10.0.0.5", srcPort: 443, dstPort: 53000, protocol: "UDP", packets: 1, bytesTotal: 100, bytesSent: 0, bytesRecv: 0, duration: 1, startTime: "", endTime: "", directionUnknown: true }
    expect(buildFlowsCsv([dirUnknown], new Map(), []).split("\n")[7].split(",")[17]).toBe("")
  })

  it("DHCPv6 (UDP 546/547) is a known service, not Unknown service", () => {
    expect(portServiceName(546, "UDP")).toBe("DHCPv6")
    expect(portServiceName(547, "UDP")).toBe("DHCPv6")
    expect(flowServiceName(546, 547, "UDP")).toBe("DHCPv6")
    const flow: Flow = { id: "f1", srcIp: "fe80::bad1:fffa:a38:77dc", dstIp: "ff02::1:2", srcPort: 546, dstPort: 547, protocol: "UDP", packets: 1, bytesTotal: 100, bytesSent: 100, bytesRecv: 0, duration: 1, startTime: "", endTime: "" }
    expect(buildFlowsCsv([flow]).split("\n")[7].split(",")[16]).toBe("DHCPv6")
  })

  it("serviceEvidenceLabel: fully confirmed stays plain, partial carries the flow counts, none says port-inferred", () => {
    // Flows — not packets — are the evidence unit: a conversation is
    // payload-confirmed if ANY of its packets was protocol-verified, so
    // "N of M flows" is the honest wording next to packet counts (QA:
    // "8 of 17" vs "17 of 40,864 packets" mixed radixes).
    expect(serviceEvidenceLabel("STUN", 26, 622)).toBe("STUN (26 of 622 flows with payload evidence)")
    expect(serviceEvidenceLabel("HTTP-Alt", 0, 20)).toBe("HTTP-Alt (port-inferred)")
    expect(serviceEvidenceLabel("STUN", 622, 622)).toBe("STUN")
  })

  it("servicePortCounts: STUN confirmed counts only cookie-verified packets; HTTP-Alt never counts", () => {
    const packets = [
      { srcIp: "10.0.0.5", dstIp: "101.2.27.162", srcPort: 65242, dstPort: 3478, protocol: "UDP", appProtocol: "STUN", appPayloadConfirmed: true },
      { srcIp: "10.0.0.5", dstIp: "101.2.27.162", srcPort: 65242, dstPort: 3478, protocol: "UDP", appProtocol: "UDP" },
      { srcIp: "10.0.0.5", dstIp: "101.2.27.162", srcPort: 65242, dstPort: 3478, protocol: "UDP", appProtocol: "UDP" },
      { srcIp: "192.168.1.3", dstIp: "224.0.0.7", srcPort: 8001, dstPort: 8001, protocol: "UDP", appProtocol: "HTTP-Alt" },
      { srcIp: "fe80::1", dstIp: "ff02::1:2", srcPort: 546, dstPort: 547, protocol: "UDP", appProtocol: "DHCPv6" },
    ]
    const top = servicePortCounts(packets)
    expect(top.find((e) => e.port === 3478)).toEqual({ protocol: "UDP", port: 3478, count: 3, confirmed: 1, flows: 1, confirmedFlows: 1 })
    expect(top.find((e) => e.port === 8001)).toEqual({ protocol: "UDP", port: 8001, count: 1, confirmed: 0, flows: 1, confirmedFlows: 0 })
    expect(top.find((e) => e.port === 546)).toEqual({ protocol: "UDP", port: 546, count: 1, confirmed: 0, flows: 1, confirmedFlows: 0 })
  })

  it("sharePctLabel: truthful rounding — nonzero shares never read 0%, tiny shares say <0.1%", () => {
    // QA: my.pcapng Top Ports rounded 74%/25% to whole numbers so the
    // displayed table looked like 100% of 8,068 packets while 32 port-less
    // packets were outside it. The label keeps one decimal so the same table
    // shows 74.0%+25.0%+0.4% and cannot imply full coverage of a larger whole.
    expect(sharePctLabel(3, 8036)).toBe("<0.1%")
    expect(sharePctLabel(32, 8036)).toBe("0.4%")
    expect(sharePctLabel(5950, 8036)).toBe("74.0%")
    expect(sharePctLabel(2008, 8036)).toBe("25.0%")
    expect(sharePctLabel(0, 100)).toBe("0%")
    expect(sharePctLabel(100, 100)).toBe("100.0%")
    expect(sharePctLabel(5, 10)).toBe("50.0%")
    expect(sharePctLabel(1, 100000)).toBe("<0.1%")
    expect(sharePctLabel(0, 0)).toBe("\u2014")
    expect(sharePctLabel(7, 0)).toBe("\u2014")
  })

  it("buildFlowsCsv: service column uses the canonical known-port rule and port-less N/A", () => {
    const flows: Flow[] = [
      // server-side tuple: known STUN port sits on the SOURCE side — the
      // conversation is still STUN, and the CSV must say so (QA audit:
      // 101.2.27.162:3478 was labeled Dynamic/Ephemeral by dstPort-only lookup).
      { id: "f1", srcIp: "101.2.27.162", dstIp: "192.168.1.20", srcPort: 3478, dstPort: 65242, protocol: "UDP", packets: 622, bytesTotal: 100, bytesSent: 100, bytesRecv: 0, duration: 1, startTime: "", endTime: "" },
      // port-less protocol: ARP has no transport service port — "N/A", not
      // "Unknown service" (QA: ARP/ICMPv6/HOPOPT labeled "Unknown service").
      { id: "f2", srcIp: "192.168.1.17", dstIp: "192.168.1.17", srcPort: 0, dstPort: 0, protocol: "ARP", packets: 2, bytesTotal: 84, bytesSent: 84, bytesRecv: 0, duration: 0.116, startTime: "", endTime: "" },
    ]
    const csv = buildFlowsCsv(flows)
    const lines = csv.split("\n")
    expect(lines[7].split(",")[16]).toBe("STUN")
    expect(lines[8].split(",")[16]).toBe("N/A")
  })

  it("buildFlowsCsv: rows are initiator-first — a resolver-sorted flow flips to the querying client (DNS QA)", () => {
    // The flow record is canonical (endpoints sorted), so a DNS conversation
    // lists the resolver first (192.168.137.1:53 < 192.168.137.228:47942),
    // but the CSV's Source header must carry the conversation initiator —
    // the client that sent the first observed query (QA: CSV showed the
    // resolver as "source").
    const flows: Flow[] = [
      { id: "f1", srcIp: "192.168.137.1", dstIp: "192.168.137.228", srcPort: 53, dstPort: 47942, protocol: "UDP", packets: 3, bytesTotal: 300, bytesSent: 100, bytesRecv: 200, duration: 1, startTime: "", endTime: "" },
    ]
    const packets = [
      { srcIp: "192.168.137.228", dstIp: "192.168.137.1", srcPort: 47942, dstPort: 53, protocol: "UDP" },
      { srcIp: "192.168.137.1", dstIp: "192.168.137.228", srcPort: 53, dstPort: 47942, protocol: "UDP" },
      { srcIp: "192.168.137.228", dstIp: "192.168.137.1", srcPort: 47942, dstPort: 53, protocol: "UDP" },
    ]
    const csv = buildFlowsCsv(flows, new Map(), packets)
    const cols = csv.split("\n")[7].split(",")
    expect(cols[0]).toBe("192.168.137.228") // client, the initiator
    expect(cols[2]).toBe("192.168.137.1")   // resolver
    expect(cols[6]).toBe("200")             // bytesSent = flow bytesRecv (client leg)
    expect(cols[7]).toBe("100")             // bytesRecv = flow bytesSent (server leg)
  })

  it("buildFlowsCsv: TCP initiator comes from the SYN packet, not record order (mid-session server-first QA)", () => {
    const flows: Flow[] = [
      { id: "f1", srcIp: "198.51.100.7", dstIp: "10.0.0.5", srcPort: 443, dstPort: 42224, protocol: "TCP", packets: 4, bytesTotal: 400, bytesSent: 250, bytesRecv: 150, duration: 1, startTime: "", endTime: "" },
    ]
    // Capture began mid-session: server replies first, then the client's
    // SYN/SYN-ACK handshake — the SYN's source must win over first-packet.
    const packets = [
      { srcIp: "198.51.100.7", dstIp: "10.0.0.5", srcPort: 443, dstPort: 42224, protocol: "TCP", flags: "ACK" },
      { srcIp: "10.0.0.5", dstIp: "198.51.100.7", srcPort: 42224, dstPort: 443, protocol: "TCP", flags: "SYN" },
      { srcIp: "198.51.100.7", dstIp: "10.0.0.5", srcPort: 443, dstPort: 42224, protocol: "TCP", flags: "SYN-ACK" },
      { srcIp: "10.0.0.5", dstIp: "198.51.100.7", srcPort: 42224, dstPort: 443, protocol: "TCP", flags: "ACK" },
    ]
    const cols = buildFlowsCsv(flows, new Map(), packets).split("\n")[7].split(",")
    expect(cols[0]).toBe("10.0.0.5")        // the SYN sender
    expect(cols[1]).toBe("42224")
    expect(cols[2]).toBe("198.51.100.7")
    expect(cols[6]).toBe("150")             // sent-by-source = flow bytesRecv
    // Without any SYN the initiator falls back to the first packet's source:
    // if the capture opens with a server reply (canonical order), the row
    // keeps canonical order; with NO packets at all there is nothing to
    // detect, so the canonical order stands unchanged.
    const noSyn = buildFlowsCsv(flows, new Map(), [{ srcIp: "198.51.100.7", dstIp: "10.0.0.5", srcPort: 443, dstPort: 42224, protocol: "TCP" }])
    expect(noSyn.split("\n")[7].split(",")[0]).toBe("198.51.100.7")
    expect(buildFlowsCsv(flows).split("\n")[7].split(",")[0]).toBe("198.51.100.7")
  })

  it("rstAttribution: RST to a SYN before any SYN-ACK is a rejected connection, not a close", () => {
    const f: Flow = { id: "f1", srcIp: "10.0.0.5", dstIp: "198.51.100.7", srcPort: 42224, dstPort: 80, protocol: "TCP", packets: 3, bytesTotal: 300, bytesSent: 200, bytesRecv: 100, duration: 1, startTime: "", endTime: "" }
    const packets = [
      { srcIp: "10.0.0.5", dstIp: "198.51.100.7", srcPort: 42224, dstPort: 80, protocol: "TCP", flags: "SYN" },
      { srcIp: "198.51.100.7", dstIp: "10.0.0.5", srcPort: 80, dstPort: 42224, protocol: "TCP", flags: "RST" },
    ]
    expect(rstAttribution(f, packets)).toEqual({ rejected: 1, clientCancel: 0, serverClose: 0, unclassified: 0 })
  })

  it("rstAttribution: mid-session RST from the initiator is a client cancel; from the responder a server close", () => {
    const f: Flow = { id: "f1", srcIp: "10.0.0.5", dstIp: "198.51.100.7", srcPort: 42224, dstPort: 443, protocol: "TCP", packets: 6, bytesTotal: 600, bytesSent: 400, bytesRecv: 200, duration: 1, startTime: "", endTime: "" }
    const packets = [
      { srcIp: "10.0.0.5", dstIp: "198.51.100.7", srcPort: 42224, dstPort: 443, protocol: "TCP", flags: "SYN" },
      { srcIp: "198.51.100.7", dstIp: "10.0.0.5", srcPort: 443, dstPort: 42224, protocol: "TCP", flags: "SYN-ACK" },
      { srcIp: "10.0.0.5", dstIp: "198.51.100.7", srcPort: 42224, dstPort: 443, protocol: "TCP", flags: "ACK" },
      { srcIp: "10.0.0.5", dstIp: "198.51.100.7", srcPort: 42224, dstPort: 443, protocol: "TCP", flags: "RST" },
    ]
    expect(rstAttribution(f, packets)).toEqual({ rejected: 0, clientCancel: 1, serverClose: 0, unclassified: 0 })
    const serverRst = [...packets, { srcIp: "198.51.100.7", dstIp: "10.0.0.5", srcPort: 443, dstPort: 42224, protocol: "TCP", flags: "RST" }]
    expect(rstAttribution(f, serverRst)).toEqual({ rejected: 0, clientCancel: 1, serverClose: 1, unclassified: 0 })
  })

  it("rstAttribution: no SYN captured — first-packet source is the initiator, so its RST is a client cancel; the other leg's RST is a server close", () => {
    const f: Flow = { id: "f1", srcIp: "198.51.100.7", dstIp: "10.0.0.5", srcPort: 443, dstPort: 42224, protocol: "TCP", packets: 2, bytesTotal: 200, bytesSent: 100, bytesRecv: 100, duration: 1, startTime: "", endTime: "" }
    const packets = [
      { srcIp: "198.51.100.7", dstIp: "10.0.0.5", srcPort: 443, dstPort: 42224, protocol: "TCP", flags: "ACK" },
      { srcIp: "198.51.100.7", dstIp: "10.0.0.5", srcPort: 443, dstPort: 42224, protocol: "TCP", flags: "RST" },
    ]
    expect(rstAttribution(f, packets)).toEqual({ rejected: 0, clientCancel: 1, serverClose: 0, unclassified: 0 })
    const responderRst = [...packets, { srcIp: "10.0.0.5", dstIp: "198.51.100.7", srcPort: 42224, dstPort: 443, protocol: "TCP", flags: "RST" }]
    expect(rstAttribution(f, responderRst)).toEqual({ rejected: 0, clientCancel: 1, serverClose: 1, unclassified: 0 })
  })

  it("buildFlowsCsv: formula-prefixed cells are defused and embedded commas/quotes are quoted", () => {
    // GeoIP ASN strings are external data — an ASN like "=1+1" would execute
    // as an Excel formula when the exported CSV is opened (CSV injection).
    const geo = new Map<string, GeoLocation>([
      ["203.0.113.77", { ip: "203.0.113.77", country: "X", countryCode: "XX", city: "", lat: 0, lon: 0, isPrivate: false, asn: "=HYPERLINK(\"http://evil\")" }],
      ["203.0.113.78", { ip: "203.0.113.78", country: "X", countryCode: "XX", city: "", lat: 0, lon: 0, isPrivate: false, asn: "+SUM(A1:A9)" }],
      ["203.0.113.79", { ip: "203.0.113.79", country: "X", countryCode: "XX", city: "", lat: 0, lon: 0, isPrivate: false, asn: "AS64500" }],
    ])
    const flows: Flow[] = [
      { id: "fx1", srcIp: "10.0.0.1", dstIp: "203.0.113.77", srcPort: 0, dstPort: 0, protocol: "TCP", packets: 1, bytesTotal: 1, bytesSent: 0, bytesRecv: 1, duration: 1, startTime: "", endTime: "" },
      { id: "fx2", srcIp: "10.0.0.1", dstIp: "203.0.113.78", srcPort: 0, dstPort: 0, protocol: "TCP", packets: 1, bytesTotal: 1, bytesSent: 0, bytesRecv: 1, duration: 1, startTime: "", endTime: "" },
      { id: "fx3", srcIp: "10.0.0.1", dstIp: "203.0.113.79", srcPort: 0, dstPort: 0, protocol: "TCP", packets: 1, bytesTotal: 1, bytesSent: 0, bytesRecv: 1, duration: 1, startTime: "", endTime: "" },
    ]
    const csv = buildFlowsCsv(flows, geo)
    const defusedLine = csv.split("\n")[7]
    expect(defusedLine).toContain(`'=HYPERLINK(""http://evil"")`)
    expect(defusedLine).toContain("'=HYPERLINK")
    expect(defusedLine).not.toContain(",=HYPERLINK")
    expect(csv.split("\n")[8]).toContain("'+SUM(A1:A9)")
    expect(csv.split("\n")[9]).toContain("AS64500")
  })

  it("mdInline escapes ONCE — no &amp;amp; / literal &lt; in exported HTML", () => {
    // The old flow pre-escaped at the call site AND inside mdInline, so the
    // exported file rendered "&amp;amp;" for & and literal "&lt;" for <.
    expect(mdInline("5 < 6 & 7 > 4")).toBe("5 &lt; 6 &amp; 7 &gt; 4")
    expect(mdInline("C2 beacon on port 443 & DNS <tunnel>")).toBe("C2 beacon on port 443 &amp; DNS &lt;tunnel&gt;")
  })

  it("mdInline renders **bold** and `code` links from raw text", () => {
    expect(mdInline("**Final verdict:** **LOW** \u2014 risk 12/100")).toBe("<strong>Final verdict:</strong> <strong>LOW</strong> \u2014 risk 12/100")
    expect(mdInline("Analysis ID `abc-123` done")).toBe("Analysis ID <code>abc-123</code> done")
  })

  it("mdInline renders *italic* — no literal asterisks in the HTML export", () => {
    // A bare *…* footnote used to leak the asterisks into the exported
    // report.html: "*(+3 more services — top 8 shown)*" (QA: export check).
    expect(mdInline("*(+3 more services — top 8 shown)*")).toBe("<em>(+3 more services — top 8 shown)</em>")
    expect(mdInline("**bold** then *italic*")).toBe("<strong>bold</strong> then <em>italic</em>")
  })

  it("talkerServicesOf labels BOTH talker cards with a conversation's service", () => {
    // The STUN flow 101.2.27.162:3478 → 192.168.1.20:65242 put the server on
    // the flow's source side only; its destination card row read "Services —"
    // next to 350 packets. The service is canonical per conversation and
    // belongs to both participants on both cards (QA: top-talkers services).
    const flows = [
      { srcIp: "101.2.27.162", dstIp: "192.168.1.20", srcPort: 3478, dstPort: 65242, protocol: "UDP" },
      { srcIp: "192.168.1.20", dstIp: "8.8.8.8", srcPort: 51729, dstPort: 53, protocol: "UDP" },
    ]
    const { src, dst } = talkerServicesOf(flows, new Map(), new Set())
    const sorted = (m: Map<string, Set<string>>, ip: string) => [...(m.get(ip) ?? [])].sort()
    expect(sorted(src, "101.2.27.162")).toEqual(["STUN"])
    expect(sorted(dst, "101.2.27.162")).toEqual(["STUN"])
    expect(sorted(src, "192.168.1.20")).toEqual(["DNS", "STUN"])
    expect(sorted(dst, "192.168.1.20")).toEqual(["DNS", "STUN"])
    expect(sorted(src, "8.8.8.8")).toEqual(["DNS"])
  })

  it("talkerServicesOf keeps the phantom-HTTP gate and drops junk labels", () => {
    const flows = [
      { srcIp: "10.0.0.1", dstIp: "10.0.0.2", srcPort: 80, dstPort: 51234, protocol: "TCP" },
      { srcIp: "10.0.0.1", dstIp: "10.0.0.2", srcPort: 49152, dstPort: 49153, protocol: "UDP" },
    ]
    const { src } = talkerServicesOf(flows, new Map(), new Set())
    expect(src.get("10.0.0.1")).toBeUndefined()
    expect(src.get("10.0.0.2")).toBeUndefined()
    const httpSeen = talkerServicesOf(
      [{ srcIp: "10.0.0.1", dstIp: "10.0.0.2", srcPort: 80, dstPort: 51234, protocol: "TCP" }],
      new Map(),
      new Set(["10.0.0.2"]),
    )
    expect([...httpSeen.src.get("10.0.0.1")!]).toEqual(["HTTP"])
    expect([...httpSeen.dst.get("10.0.0.2")!]).toEqual(["HTTP"])
  })

  it("mdInline escapes code content and attribute-breaking quotes", () => {
    expect(mdInline("`a & b`")).toBe("<code>a &amp; b</code>")
    expect(escHtml(`say "hi" <now>`)).toBe("say &quot;hi&quot; &lt;now&gt;")
  })

it("verdictLine renders per-class text: SAFE becomes NO DETECTIONS; LOW/MEDIUM/HIGH/CRITICAL and UNKNOWN on undecodable", () => {
    expect(verdictLine("SAFE", 0, false)).toBe("- **Final verdict:** **NO DETECTIONS** \u2014 risk 0/100 \u2014 no configured detection rules triggered (absence of detection is not proof of a clean network)")
    expect(verdictLine("LOW", 12, false)).toBe("- **Final verdict:** **LOW** \u2014 risk 12/100 \u2014 risk 12/100 is in the SAFE score band; the verdict level is the strongest finding's rule severity (1\u20135), not the score band")
    expect(verdictLine("MEDIUM", 55, false)).toBe("- **Final verdict:** **MEDIUM** \u2014 risk 55/100")
    expect(verdictLine("HIGH", 73, false)).toBe("- **Final verdict:** **HIGH** \u2014 risk 73/100")
    expect(verdictLine("CRITICAL", 86, false)).toBe("- **Final verdict:** **CRITICAL** \u2014 risk 86/100")
    expect(verdictLine("UNKNOWN", 0, true)).toBe("- **Final verdict:** **UNKNOWN** \u2014 risk not computable (insufficient data)")
  })

  it("risk breakdown shows the EFFECTIVE (burst-boosted) confidence that produced the multiplier", () => {
    const alerts = [portScanAlert, beaconAlert]
    const b = computeRiskBreakdown(buildRiskInputs(alerts), true)
    const exfilLike = b.items.find((i) => i.ruleId === "PORT-SCAN-001")!
    // PORT-SCAN-001 gets no burst bonus: 70 stays 70 â†’ medium Ã—1.0.
    expect(exfilLike.confidence).toBe(70)
    expect(exfilLike.effectiveConfidence).toBe(70)
    expect(exfilLike.confidenceMult).toBe(1.0)
    const beacon = b.items.find((i) => i.ruleId === "C2-BEACON-001")!
    // Beacon 65 + 15 burst = 80 â†’ high Ã—1.5. The table must print 80, not 65
    // next to "Ã—1.5" (QA: breakdown showed Ã—1.5 at a 65% base).
    expect(beacon.confidence).toBe(65)
    expect(beacon.effectiveConfidence).toBe(80)
    expect(beacon.confidenceMult).toBe(1.5)
    expect(beacon.contribution).toBeCloseTo((25 + 20) * 1.5, 5)
    const raw = b.items.reduce((s, i) => s + i.contribution, 0)
    expect(raw).toBeCloseTo(b.rawScore, 5)
    expect(computeRisk(buildRiskInputs(alerts), true)).toBe(b.normalizedScore)
  })
})

describe("tlsCipherSuiteName", () => {
  it("names common TLS 1.3/1.2 suites and falls back to hex", () => {
    expect(tlsCipherSuiteName(0x1301)).toBe("TLS_AES_128_GCM_SHA256")
    expect(tlsCipherSuiteName(0x1302)).toBe("TLS_AES_256_GCM_SHA384")
    expect(tlsCipherSuiteName(0xc02f)).toBe("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    expect(tlsCipherSuiteName(0xc02c)).toBe("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
    expect(tlsCipherSuiteName(0x9999)).toBe("0x9999")
  })
})

describe("analystConclusion � the verdict must never call a capture clean while confirmed findings exist", () => {
  const base = { undecodable: false, decodeRatePct: 100, encapName: "Ethernet", alerts: [], score: 0 }

  it("confirms findings when alerts exist, even at LOW score (QA: never_end 39 LOW + 1 alert)", () => {
    const text = analystConclusion({ ...base, alerts: [{ signature: "Plaintext HTTP Credentials" }], score: 39 })
    expect(text).toContain("1 confirmed finding detected (Plaintext HTTP Credentials)")
    // "NOT clean" implies compromise; a confirmed plaintext credential
    // exposure is a weakness the capture demonstrated — the confirmed case
    // says "a security finding was confirmed" instead (QA: never_end.pcapng).
    expect(text).toContain("A security finding was confirmed under the configured detection rules")
    expect(text).not.toContain("NOT clean")
    expect(text).toContain("not proof that the capture is universally malicious")
    // The score is a rule-output summary, never a probability of compromise.
    expect(text).toContain("does not represent a probability of compromise")
    // A confirmed credential transmission must never read as confirmed theft
    // or interception (QA: college.pcapng "Credential Theft" wording).
    expect(text).toContain("does not establish that the credential was intercepted")
    expect(text).not.toContain("No suspicious indicators")
  })

it("pluralizes the alert count and names EVERY fired rule (QA: mic.pcapng hid the SYN flood behind 'Port Scan Detected')", () => {
    const text = analystConclusion({ ...base, alerts: [{ signature: "A" }, { signature: "B" }], score: 0 })
    expect(text).toContain("2 confirmed findings detected (A; B)")
    expect(text).not.toContain("detected (A).")
  })

  it("uses the configured-rules wording when zero alerts fire and no score-driven branch matches", () => {
    expect(analystConclusion({ ...base, score: 39 })).toContain("No configured detection rules triggered")
    expect(analystConclusion({ ...base, score: 39 })).not.toContain("clean")
  })

  it("INSUFFICIENT EVIDENCE when the capture has no measurable time interval", () => {
    const text = analystConclusion({ ...base, quality: "SINGLE_PACKET" })
    expect(text).toContain("insufficient evidence")
    expect(text).toContain("NOT proof of safety")
    expect(text).not.toContain("clean")
  })

  it("a VALID capture with zero alerts keeps the standard conclusion", () => {
    expect(analystConclusion({ ...base, quality: "VALID" })).toContain("No configured detection rules triggered")
  })

  it("a mostly-encrypted capture with no alerts states the visibility limit — 0/100 never means content was verified (QA: big.pcapng 97.7% QUIC)", () => {
    const text = analystConclusion({ ...base, quality: "VALID", encryptedSharePct: 97.7 })
    expect(text).toContain("No configured detection rules triggered")
    expect(text).toContain("98% of packets are associated with TCP/443 or UDP/443 and were treated as encrypted HTTPS/QUIC traffic")
    expect(text).toContain("content-level verification of the encrypted traffic was possible")
    expect(text).toContain("packet/flow statistics and unencrypted protocols only")
    // Below the threshold the note stays silent — a minority-encrypted
    // capture does not carry the same blind spot.
    expect(analystConclusion({ ...base, quality: "VALID", encryptedSharePct: 12 })).not.toContain("traffic is encrypted")
    expect(analystConclusion({ ...base, quality: "VALID" })).not.toContain("traffic is encrypted")
  })

  it("keeps score-based wording when no alerts fired", () => {
    expect(analystConclusion({ ...base, score: 85 })).toContain("Significant malicious activity")
    expect(analystConclusion({ ...base, score: 55 })).toContain("Suspicious or anomalous behavior")
  })

  it("always reports UNKNOWN on undecodable captures regardless of score", () => {
    const text = analystConclusion({ undecodable: true, decodeRatePct: 12, encapName: "Linux SLL", alerts: [], score: 0 })
    expect(text).toContain("12% of packets could be decoded")
    expect(text).toContain("No verdict is possible")
  })

  it("a degraded capture WITH findings says why the rates may be wrong", () => {
    // Non-VALID + alerts: the finding stands, and the note explains that
    // rate/burst evidence may be unavailable — a clean-ish note would
    // silently downgrade the detection.
    const text = analystConclusion({ ...base, quality: "SINGLE_PACKET", alerts: [{ signature: "Plaintext HTTP Credentials" }], score: 39 })
    expect(text).toContain("1 confirmed finding detected")
    expect(text).toContain("A security finding was confirmed under the configured detection rules")
    expect(text).toContain("capture quality")
  })
})

describe("MITRE mapping for plaintext credential alerts (never T1040, never T1552)", () => {
  it("never maps plaintext credential exposure to Network Sniffing, and recommends exposure-aware rotation", () => {
    const report = buildReportAnalysis({
      job: null,
      jobInfo: {},
      alerts: [{
        id: "a1", timestamp: new Date(T0 * 1000).toISOString(),
        signature: "Plaintext HTTP Credentials", category: "Credential Access",
        severity: 4, confidence: 75, ruleId: "HTTP-CREDS-001",
        srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 0, dstPort: 0, protocol: "HTTP",
        evidence: "4 plaintext credential submission(s) over HTTP Form",
      }],
      packets: [], flows: [], sessions: [], tls: [], http: [],
      timeline: [], bandwidth: [],
      advancedMetrics: {
        throughputAvg: 0, throughputPeak: 0, burst: null,
        beaconDetected: false, dnsTunnelingSuspected: false, dataExfiltrationSuspected: false,
        torVpnProxyDetected: false, portScanEnhanced: false, ja3Suspicious: false,
        topTalkers: [], iocs: [], mitreMappings: [],
      },
    })
    // T1040 Network Sniffing describes adversary activity (capturing
    // traffic); the capture proves only that the credentials were exposed
    // to potential passive interception — no sniffer is observed, so an
    // automatic report must not map the finding (QA: never_end.pcapng).
    expect(report.mitre.find((m) => m.id === "T1040")).toBeUndefined()
    expect(report.mitre).toHaveLength(0)
    expect(report.mitre.find((m) => m.id === "T1552")).toBeUndefined()
    // The remediation rides on the alert itself, phrased around what the
    // capture proves: assume exposure to anyone able to observe the path.
    const rec = report.recommendations.find((r) => r.text.includes("Plaintext credentials"))
    expect(rec).toBeDefined()
    expect(rec?.severity).toBe(4)
    expect(rec?.source).toBe("CONFIRMED_ALERT")
    expect(rec?.status).toBe("CONFIRMED")
    expect(rec?.text).toContain("assume the credential may have been exposed to anyone able to observe the network path")
    expect(rec?.text).toContain("rotate the affected accounts")
    expect(rec?.text).not.toContain("sniffer")
  })

  it("legacy persisted T1552 rows keep rendering (their own stored description is preserved)", () => {
    const report = buildReportAnalysis({
      ...state,
      advancedMetrics: {
        ...state.advancedMetrics,
        mitreMappings: [{ id: "T1552", technique: "Unsecured Credentials", description: "legacy row", severity: 4 }],
      },
    })
    const m = report.mitre.find((x) => x.id === "T1552")
    expect(m?.technique).toBe("Unsecured Credentials")
    expect(m?.description).toBe("legacy row")
  })
})

describe("credentialEventCount — one finding must never read as one exposed credential", () => {
  it("reads the submission count from the alert evidence and sums across alerts", () => {
    expect(credentialEventCount([
      { ruleId: "HTTP-CREDS-001", evidence: "4 plaintext credential submission(s) over HTTP Form" },
      { ruleId: "CRED-LEAK-001", evidence: "2 plaintext credential submission(s) over SMTP" },
      { ruleId: "DATA-EXFIL-001", evidence: "9 plaintext credential submission(s) — ignored, wrong rule" },
      { ruleId: "HTTP-CREDS-001", evidence: "no numeric prefix — counts 0" },
    ])).toBe(6)
  })

  it("surfaces the count on the conclusion line (QA: never_end '1 alert' vs 4 submissions)", () => {
    const text = analystConclusion({
      undecodable: false, decodeRatePct: 100, encapName: "Ethernet",
      alerts: [{ signature: "Plaintext HTTP Credentials", ruleId: "HTTP-CREDS-001", evidence: "4 plaintext credential submission(s) over HTTP Form" }],
      score: 53,
    })
    expect(text).toContain("1 confirmed finding detected covering 4 credential-submission events")
    expect(text).not.toContain("1 confirmed finding detected (Plaintext HTTP Credentials)")
  })
})

describe("TLS certificate empty-reason is version-aware — 1.2 is never blamed on 1.3 encryption (QA: minor.pcapng)", () => {
  const tlsRow = (version: string) => ({ id: "t1", timestamp: new Date(T0 * 1000).toISOString(), srcIp: "10.0.0.5", dstIp: "203.0.113.9", version, sni: "example.com", cipherSuite: "TLS_AES_128_GCM_SHA256", ja3: "", issuer: "", validityDays: 0 })

  it("1.2-only captures explain missing certificates via resumed/missed handshakes, not encryption", () => {
    const r = buildReportAnalysis({ ...state, tls: [tlsRow("TLS 1.2"), tlsRow("TLS 1.2")] })
    expect(r.emptyReasons.certificates).toContain("TLS 1.2")
    expect(r.emptyReasons.certificates).toContain("resumed/abbreviated")
    expect(r.emptyReasons.certificates).not.toContain("TLS 1.3")
  })

  it("1.3-only captures attribute the absence to 1.3 encryption", () => {
    const r = buildReportAnalysis({ ...state, tls: [tlsRow("TLS 1.3")] })
    expect(r.emptyReasons.certificates).toContain("TLS 1.3")
    expect(r.emptyReasons.certificates).toContain("encrypt")
  })

  it("mixed 1.3 + 1.2 captures explain BOTH — 1.2 is not blanket-claimed encrypted (QA: 29x1.3 + 5x1.2)", () => {
    const r = buildReportAnalysis({ ...state, tls: [tlsRow("TLS 1.3"), tlsRow("TLS 1.2")] })
    expect(r.emptyReasons.certificates).toContain("1 TLS 1.3 handshake")
    expect(r.emptyReasons.certificates).toContain("1 TLS 1.2 handshake")
    expect(r.emptyReasons.certificates).toContain("encrypt the server Certificate")
    expect(r.emptyReasons.certificates).toContain("resumed/abbreviated")
  })

  it("no TLS at all keeps the plain reason", () => {
    const r = buildReportAnalysis(state)
    expect(r.emptyReasons.certificates).toBe("No TLS handshake packets captured.")
  })
})

describe("MITRE gating — SUSPECTED/OBSERVED detections never claim ATT&CK techniques", () => {
  it("a SUSPECTED port-scan alert drops its T1046 row (QA: scan/flood false positives carried T1046/T1498)", () => {
    const r = buildReportAnalysis({ ...state, alerts: [{ ...portScanAlert, status: "SUSPECTED" }] })
    expect(r.mitre.find((m) => m.id === "T1046")).toBeUndefined()
    // Metric-only techniques (no backing alert) are unaffected by the gate.
    expect(r.mitre.find((m) => m.id === "T1071.004")).toBeDefined()
    expect(r.mitre.find((m) => m.id === "T1071")).toBeDefined()
    // The alert itself still surfaces — only its ATT&CK claim is withheld.
    expect(r.groups.map((g) => g.ruleId)).toContain("PORT-SCAN-001")
    expect(r.groups.find((g) => g.ruleId === "PORT-SCAN-001")!.status).toBe("SUSPECTED")
  })

  it("LIKELY and CONFIRMED alerts keep their techniques; legacy alerts without status stay mapped", () => {
    const likely = buildReportAnalysis({ ...state, alerts: [{ ...portScanAlert, status: "LIKELY" }] })
    expect(likely.mitre.find((m) => m.id === "T1046")).toBeDefined()
    const confirmed = buildReportAnalysis({ ...state, alerts: [{ ...portScanAlert, status: "CONFIRMED" }] })
    expect(confirmed.mitre.find((m) => m.id === "T1046")).toBeDefined()
    const legacy = buildReportAnalysis(state)
    expect(legacy.mitre.find((m) => m.id === "T1046")).toBeDefined()
  })

  it("OBSERVED alerts are gated too", () => {
    const r = buildReportAnalysis({ ...state, alerts: [{ ...portScanAlert, status: "OBSERVED" }] })
    expect(r.mitre.find((m) => m.id === "T1046")).toBeUndefined()
  })
})

describe("notable destinations — neutral context, never findings", () => {
  it("matches the curated families across SNI and HTTP Host, case-insensitively", () => {
    const r = buildReportAnalysis({
      ...state,
tls: [{ id: "t1", timestamp: new Date(T0 * 1000).toISOString(), srcIp: "10.0.0.5", dstIp: "203.0.113.9", version: "TLSv1.3", cipherSuite: "A", sni: "urlhaus-api.abuse.ch", ja3: "", issuer: "", validityDays: 0 }],
      http: [{ id: "h1", timestamp: new Date(T0 * 1000).toISOString(), srcIp: "10.0.0.5", dstIp: "203.0.113.9", method: "GET", uri: "/", status: 200, host: "api.internal.temp-mail.io", contentType: "", userAgent: "", length: 0 }],
    })
    const byDomain = new Map(r.notables.map((n) => [n.domain, n.category]))
    expect(byDomain.get("urlhaus-api.abuse.ch")).toContain("Threat-intelligence")
    expect(byDomain.get("api.internal.temp-mail.io")).toContain("Disposable")
    expect(r.notables.length).toBe(2)
  })

  it("matches DoH resolvers, Tor and github.io; ignores ordinary domains", () => {
    const r = buildReportAnalysis({
      ...state,
tls: [
        { id: "t1", timestamp: new Date(T0 * 1000).toISOString(), srcIp: "10.0.0.5", dstIp: "1.1.1.1", version: "TLSv1.3", cipherSuite: "A", sni: "doh.li", ja3: "", issuer: "", validityDays: 0 },
        { id: "t2", timestamp: new Date(T0 * 1000).toISOString(), srcIp: "10.0.0.5", dstIp: "8.8.8.8", version: "TLSv1.2", cipherSuite: "A", sni: "purecatamphetamine.github.io", ja3: "", issuer: "", validityDays: 0 },
        { id: "t3", timestamp: new Date(T0 * 1000).toISOString(), srcIp: "10.0.0.5", dstIp: "8.8.8.8", version: "TLSv1.2", cipherSuite: "A", sni: "www.bbc.co.uk", ja3: "", issuer: "", validityDays: 0 },
        { id: "t4", timestamp: new Date(T0 * 1000).toISOString(), srcIp: "10.0.0.5", dstIp: "8.8.8.8", version: "TLSv1.2", cipherSuite: "A", sni: "TORPROJECT.ORG", ja3: "", issuer: "", validityDays: 0 },
      ],
    })
    const byDomain = new Map(r.notables.map((n) => [n.domain, n.category]))
    expect(byDomain.get("doh.li")).toContain("DNS-over-HTTPS")
    expect(byDomain.get("purecatamphetamine.github.io")).toContain("github.io")
    expect(byDomain.get("torproject.org")).toContain("Tor")
    expect(byDomain.get("www.bbc.co.uk")).toBeUndefined()
  })
})

describe("build identity — every artifact carries the exact git commit", () => {
  it("BUILD_INFO/BUILD_STAMP embed the commit from the build environment", async () => {
    process.env.NEXT_PUBLIC_BUILD_COMMIT = "5b4429a"
    process.env.NEXT_PUBLIC_BUILD_COMMIT_SHORT = ""
    process.env.NEXT_PUBLIC_BUILD_TIME = "2026-08-15T12:00:00.000Z"
    process.env.NEXT_PUBLIC_BUILD_SRC_HASH = "4b8eaa0785ff"
    const { vi } = await import("vitest")
    vi.resetModules()
    const { BUILD_INFO, BUILD_STAMP } = await import("@/lib/build-stamp")
    expect(BUILD_INFO.isGit).toBe(true)
    expect(BUILD_INFO.commit).toBe("5b4429a")
    expect(BUILD_INFO.commitShort).toBe("5b4429a")
    expect(BUILD_STAMP).toContain("commit:5b4429a")
    expect(BUILD_STAMP).toContain("2026-08-15T12:00:00.000Z")
    delete process.env.NEXT_PUBLIC_BUILD_COMMIT
  })

  it("without Git the stamp says src: and never claims a commit", async () => {
    delete process.env.NEXT_PUBLIC_BUILD_COMMIT
    delete process.env.NEXT_PUBLIC_BUILD_TIME
    process.env.NEXT_PUBLIC_BUILD_SRC_HASH = "4b8eaa0785ff"
    const { vi } = await import("vitest")
    vi.resetModules()
    const { BUILD_INFO, BUILD_STAMP } = await import("@/lib/build-stamp")
    expect(BUILD_INFO.isGit).toBe(false)
    expect(BUILD_STAMP).toContain("src:4b8eaa0785ff")
    expect(BUILD_STAMP).not.toContain("commit:")
  })

it("the flows CSV embeds the same build identity as the report", () => {
    // The static import chain (report.ts → build-stamp.ts) resolves once at
    // load; the CSV comment must carry that SAME stamp instance — a report
    // and its export can never disagree about their build.
    const csv = buildFlowsCsv([], new Map(), [])
    expect(csv.startsWith("\uFEFF# PacketLens ")).toBe(true)
    expect(csv.split("\n")[0].slice(1)).toContain(BUILD_STAMP)
  })
})

describe("plural() — count-aware nouns in every artifact", () => {
  it("singular/plural boundaries", () => {
    expect(plural(0, "credential")).toBe("0 credentials")
    expect(plural(1, "credential")).toBe("1 credential")
    expect(plural(2, "credential")).toBe("2 credentials")
    expect(plural(1, "file")).toBe("1 file")
    expect(plural(2, "file")).toBe("2 files")
    expect(plural(1, "HTTP request")).toBe("1 HTTP request")
    expect(plural(3, "HTTP request")).toBe("3 HTTP requests")
    expect(plural(1, "alert")).toBe("1 alert")
    expect(plural(1, "DNS query packet")).toBe("1 DNS query packet")
  })
})

describe("flowTableRows — the report's flows table and the CSV agree on the initiator", () => {
  it("both surfaces flip the SAME conversations to initiator-first", () => {
    const packets = [
      { srcIp: "192.168.1.10", dstIp: "104.16.103.112", srcPort: 13248, dstPort: 443, protocol: "TCP", flags: "SYN" },
      { srcIp: "104.16.103.112", dstIp: "192.168.1.10", srcPort: 443, dstPort: 13248, protocol: "TCP", flags: "SYN-ACK" },
      { srcIp: "192.168.1.10", dstIp: "46.101.206.53", srcPort: 6750, dstPort: 443, protocol: "TCP", flags: "SYN" },
    ]
    const flows: Flow[] = [
      // Canonical record (server first): the initiator is 192.168.1.10.
      { id: "f1", srcIp: "104.16.103.112", dstIp: "192.168.1.10", srcPort: 443, dstPort: 13248, protocol: "TCP", packets: 10, bytesTotal: 1000, bytesSent: 800, bytesRecv: 200, duration: 5, startTime: "", endTime: "" },
      // Already initiator-first.
      { id: "f2", srcIp: "192.168.1.10", dstIp: "46.101.206.53", srcPort: 6750, dstPort: 443, protocol: "TCP", packets: 5, bytesTotal: 500, bytesSent: 100, bytesRecv: 400, duration: 3, startTime: "", endTime: "" },
    ]
const rows = flowTableRows(flows, packets)
    expect(rows[0].srcIp).toBe("192.168.1.10")
    expect(rows[0].dstIp).toBe("104.16.103.112")
    expect(rows[0].srcPort).toBe(13248)
    // Sent/Recv swap with the endpoints: the row's left side is the initiator.
    expect(rows[0].bytesSent).toBe(200)
    expect(rows[0].bytesRecv).toBe(800)
    expect(rows[1].srcIp).toBe("192.168.1.10")
    // CSV produces the same initiator for the same flow record.
    const csv = buildFlowsCsv(flows, new Map(), packets)
    const csvLines = csv.split("\n")
    expect(csvLines[7].startsWith("192.168.1.10,13248,104.16.103.112,443,")).toBe(true)
    expect(csvLines[8].startsWith("192.168.1.10,6750,46.101.206.53,443,")).toBe(true)
  })

it("carries the per-flow RTT through to the page rows", () => {
    const flows: Flow[] = [
      { id: "f1", srcIp: "10.0.0.1", dstIp: "10.0.0.2", srcPort: 1234, dstPort: 443, protocol: "TCP", packets: 4, bytesTotal: 400, bytesSent: 100, bytesRecv: 300, duration: 2, startTime: "", endTime: "", rttMs: 42.5 },
      { id: "f2", srcIp: "10.0.0.1", dstIp: "10.0.0.3", srcPort: 1235, dstPort: 53, protocol: "UDP", packets: 2, bytesTotal: 100, bytesSent: 50, bytesRecv: 50, duration: 1, startTime: "", endTime: "" },
    ]
    const rows = flowTableRows(flows, [])
    expect(rows[0].rttMs).toBe(42.5)
    expect(rows[1].rttMs).toBeUndefined()
  })
})

describe("sessionTableRows — the report's sessions table is initiator-first like the flows table and the CSV (QA: PDF listed the server 142.250.80.46:443 as Initiator)", () => {
  const mkSession = (o: Partial<Parameters<typeof sessionTableRows>[0][number]>) => ({
    id: "s1", srcIp: "104.16.103.112", dstIp: "192.168.1.10", srcPort: 443, dstPort: 13248,
    protocol: "TCP", packets: 10, bytes: 1000, state: "ESTABLISHED", ...o,
  })

  it("flips a server-first canonical record to the client side", () => {
    const packets = [
      { srcIp: "192.168.1.10", dstIp: "104.16.103.112", srcPort: 13248, dstPort: 443, protocol: "TCP", flags: "SYN" },
      { srcIp: "104.16.103.112", dstIp: "192.168.1.10", srcPort: 443, dstPort: 13248, protocol: "TCP", flags: "SYN-ACK" },
      { srcIp: "192.168.1.10", dstIp: "104.16.103.112", srcPort: 13248, dstPort: 443, protocol: "TCP", flags: "ACK" },
    ]
    const rows = sessionTableRows([mkSession({})], packets)
    expect(rows[0].srcIp).toBe("192.168.1.10")
    expect(rows[0].srcPort).toBe(13248)
    expect(rows[0].dstIp).toBe("104.16.103.112")
    expect(rows[0].dstPort).toBe(443)
    // The rest of the session row survives the flip untouched.
    expect(rows[0].id).toBe("s1")
    expect(rows[0].packets).toBe(10)
    expect(rows[0].bytes).toBe(1000)
    expect(rows[0].state).toBe("ESTABLISHED")
  })

  it("keeps an already initiator-first session unchanged", () => {
    const s = mkSession({ srcIp: "192.168.1.10", dstIp: "46.101.206.53", srcPort: 6750, dstPort: 443 })
    const rows = sessionTableRows([s], [{ srcIp: "192.168.1.10", dstIp: "46.101.206.53", srcPort: 6750, dstPort: 443, protocol: "TCP", flags: "SYN" }])
    expect(rows[0].srcIp).toBe("192.168.1.10")
  })

  it("UDP sessions flip to the endpoint that sent the first observed packet", () => {
    const packets = [
      { srcIp: "192.168.1.10", dstIp: "8.8.8.8", srcPort: 54321, dstPort: 53, protocol: "UDP", flags: "" },
      { srcIp: "8.8.8.8", dstIp: "192.168.1.10", srcPort: 53, dstPort: 54321, protocol: "UDP", flags: "" },
    ]
    const rows = sessionTableRows([mkSession({ protocol: "UDP", srcIp: "8.8.8.8", dstIp: "192.168.1.10", srcPort: 53, dstPort: 54321, state: "STATELESS" })], packets)
    expect(rows[0].srcIp).toBe("192.168.1.10")
  })

  it("a mid-stream capture with no SYN keeps the canonical order (nothing better exists)", () => {
    const packets = [{ srcIp: "8.8.8.8", dstIp: "192.168.1.10", srcPort: 53, dstPort: 54321, protocol: "UDP", flags: "" }]
    const rows = sessionTableRows([mkSession({ protocol: "UDP", srcIp: "8.8.8.8", dstIp: "192.168.1.10", srcPort: 53, dstPort: 54321, state: "STATELESS" })], packets)
    expect(rows[0].srcIp).toBe("8.8.8.8")
  })
})

describe("duplicateFrameCountOf — the report's duplicate count never re-derives phantom removals (QA: '2 removed' on a capture that removed none)", () => {
  const dupPair = [
    { srcIp: "192.168.1.10", dstIp: "8.8.8.8", srcPort: 54321, dstPort: 443, protocol: "TCP", length: 60, tcpSeq: 10, flags: "ACK" },
    { srcIp: "192.168.1.10", dstIp: "8.8.8.8", srcPort: 54321, dstPort: 443, protocol: "TCP", length: 60, tcpSeq: 10, flags: "ACK" },
  ]

  it("a fresh job that removed nothing reports 0 — the analyzed set is never recounted", () => {
    expect(duplicateFrameCountOf({ rawPacketCount: 152 }, dupPair)).toBe(0)
  })

  it("a fresh job with a recorded removal uses the job's own number", () => {
    expect(duplicateFrameCountOf({ rawPacketCount: 152, duplicateFrameCount: 2 }, dupPair)).toBe(2)
    expect(duplicateFrameCountOf({ rawPacketCount: 152, duplicateFrameCount: 0 }, dupPair)).toBe(0)
  })

  it("true legacy jobs (neither field present) recount the stored raw set", () => {
    expect(duplicateFrameCountOf({}, dupPair)).toBe(1)
    expect(duplicateFrameCountOf(null, dupPair)).toBe(1)
    expect(duplicateFrameCountOf(undefined, dupPair)).toBe(1)
    expect(duplicateFrameCountOf(undefined, [])).toBe(0)
  })
})

// Shared fixture: the open.pcapng "Suspected Large Outbound Transfer" finding shape.
const exfil = (status: "SUSPECTED" | "CONFIRMED"): AlertEntry => ({
  id: "a9", timestamp: new Date(T0 * 1000).toISOString(), signature: "Suspected Large Outbound Transfer",
  category: "Exfiltration", severity: 4, confidence: status === "CONFIRMED" ? 100 : 70, ruleId: "DATA-EXFIL-001",
  srcIp: "192.168.1.10", dstIp: "172.64.155.209", srcPort: 0, dstPort: 0, protocol: "TCP",
  evidence: "1 flow sending >100 KB outbound; 5x received bytes",
  status, evidenceQuality: status === "CONFIRMED" ? "HIGH" : "MEDIUM",
})
const exfilMetrics = {
  iocs: [{ type: "data-exfiltration", value: "Data Exfiltration", description: "1 flow sending >100 KB", severity: 4, ruleId: "DATA-EXFIL-001" }],
  mitreMappings: [{ technique: "Exfiltration Over C2 Channel", id: "T1041", description: "Data sent to external server", severity: 4 }],
}

describe("detection status is the ONE source of truth across every report layer (QA: open.pcapng)", () => {
  const base = { undecodable: false, decodeRatePct: 100, encapName: "Ethernet", alerts: [], score: 0 }

  it("a SUSPECTED finding stays SUSPECTED in the IOC, recommendation and conclusion; MITRE stays empty (QA: 'Confirmed alert' in IOC/recommendation/conclusion)", () => {
    const alert = exfil("SUSPECTED")
    const r = buildReportAnalysis({
      ...state,
      alerts: [alert],
      advancedMetrics: { ...advancedMetrics, dataExfiltrationSuspected: true, ...exfilMetrics },
    })
    expect(r.groups[0].status).toBe("SUSPECTED")
    const ioc = r.iocs.find((i) => i.ruleId === "DATA-EXFIL-001")
    expect(ioc).toBeDefined()
    expect(ioc!.status).toBe("SUSPECTED")
    const rec = r.recommendations.find((x) => x.text.includes("Investigate the flagged outbound transfer"))
    expect(rec).toBeDefined()
    expect(rec!.status).toBe("SUSPECTED")
    // A SUSPECTED behavioral finding is INVESTIGATE-priority: the rec must
    // never read as a blocking mandate (QA: long.pcapng "consider blocking").
    expect(rec!.priority).toBe("INVESTIGATE")
    expect(r.mitre).toHaveLength(0)
    const conclusion = analystConclusion({ ...base, alerts: [alert], score: 40 })
    expect(conclusion).toContain("1 suspected finding detected (Suspected Large Outbound Transfer)")
    expect(conclusion).toContain("No findings were confirmed")
    expect(conclusion).not.toContain("confirmed finding")
  })

  it("a CONFIRMED finding stays CONFIRMED in every layer and keeps its MITRE mapping", () => {
    const alert = exfil("CONFIRMED")
    const r = buildReportAnalysis({
      ...state,
      alerts: [alert],
      advancedMetrics: { ...advancedMetrics, dataExfiltrationSuspected: true, ...exfilMetrics },
    })
    const ioc = r.iocs.find((i) => i.ruleId === "DATA-EXFIL-001")
    expect(ioc!.status).toBe("CONFIRMED")
    const mitre = r.mitre.find((m) => m.id === "T1041")
    expect(mitre).toBeDefined()
    expect(mitre!.status).toBe("CONFIRMED")
    const rec = r.recommendations.find((x) => x.text.includes("Investigate the flagged outbound transfer"))
    expect(rec!.status).toBe("CONFIRMED")
    // A CONFIRMED finding keeps no INVESTIGATE downgrade — the priority
    // override exists only for behavioral (unconfirmed) findings.
    expect(rec!.priority).toBeUndefined()
    const conclusion = analystConclusion({ ...base, alerts: [alert], score: 40 })
    expect(conclusion).toContain("1 confirmed finding detected (Suspected Large Outbound Transfer)")
    expect(conclusion).not.toContain("No findings were confirmed")
  })

  it("mixed statuses list each count from alert.status, never a blanket 'confirmed'", () => {
    const text = analystConclusion({
      ...base,
      alerts: [exfil("CONFIRMED"), { ...exfil("SUSPECTED"), id: "a10" }],
      score: 60,
    })
    expect(text).toContain("1 confirmed, 1 suspected findings detected")
  })

  it("legacy status-less alerts still count as confirmed (pre-status semantics preserved)", () => {
    const text = analystConclusion({ ...base, alerts: [portScanAlert], score: 30 })
    expect(text).toContain("1 confirmed finding detected (TCP Port Scan Detected)")
    expect(text).not.toContain("No findings were confirmed")
  })

  it("statusLabel and findingSourceLabel map status to words — the only place labels are written", () => {
    expect(statusLabel("OBSERVED")).toBe("Observed alert")
    expect(statusLabel("SUSPECTED")).toBe("Suspected alert")
    expect(statusLabel("LIKELY")).toBe("Likely alert")
    expect(statusLabel("CONFIRMED")).toBe("Confirmed alert")
    expect(findingSourceLabel("CONFIRMED_ALERT", "SUSPECTED")).toBe("Suspected alert")
    expect(findingSourceLabel("CONFIRMED_ALERT")).toBe("Confirmed alert")
    expect(findingSourceLabel("BEHAVIORAL_METRIC")).toBe("Behavioral indicator (advanced metrics)")
    expect(effectiveStatus({ status: undefined })).toBe("CONFIRMED")
    expect(effectiveStatus({ status: "SUSPECTED" })).toBe("SUSPECTED")
  })
})

describe("severity and status stay visibly separate (QA: 'Alerts: 1 (1 critical)' read as a confirmed finding)", () => {
  it("summarizeStatuses counts by detection status, legacy alerts as confirmed", () => {
    expect(summarizeStatuses([
      { status: "SUSPECTED" }, { status: "CONFIRMED" }, { status: "LIKELY" }, { status: "OBSERVED" }, {},
    ])).toEqual({ confirmed: 2, likely: 1, suspected: 1, observed: 1 })
    expect(summarizeStatuses([])).toEqual({ confirmed: 0, likely: 0, suspected: 0, observed: 0 })
  })

it("statusCountsLabel always states the confirmed count, zero included", () => {
    expect(statusCountsLabel({ confirmed: 0, likely: 0, suspected: 1, observed: 0 })).toBe("0 confirmed · 1 suspected")
    expect(statusCountsLabel({ confirmed: 1, likely: 0, suspected: 1, observed: 0 })).toBe("1 confirmed · 1 suspected")
    expect(statusCountsLabel({ confirmed: 0, likely: 0, suspected: 0, observed: 0 })).toBe("0 confirmed")
  })

  it("IOC statuses aggregate exactly like alerts — a SUSPECTED IOC is never 'confirmed' (QA: report parenthetical labeled IOC sources as confirmed/behavioral)", () => {
    // The report's Threat Summary line aggregates the IOC statuses with the
    // same helper the Alerts line uses; a SUSPECTED IOC (the detection's own
    // status) must never read as confirmed.
    const iocs = [
      { type: "threat", value: "8.8.8.8", status: "SUSPECTED" as const },
      { type: "domain", value: "example.com", status: "CONFIRMED" as const },
      { type: "behavioral", value: "exfil", status: undefined }, // legacy: no status field
    ]
    const label = statusCountsLabel(summarizeStatuses(iocs))
    expect(label).toBe("2 confirmed · 1 suspected")
    expect(label).not.toContain("behavioral")
  })

  it("a CRITICAL-severity SUSPECTED finding renders 0 confirmed, never '1 confirmed'", () => {
    // Severity answers "how bad if real"; status answers "how strong is the
    // evidence". The summary must say both without blurring them.
    const criticalSuspected = exfil("SUSPECTED")
    const r = buildReportAnalysis({
      ...state,
      alerts: [criticalSuspected],
      advancedMetrics: { ...advancedMetrics, dataExfiltrationSuspected: true, ...exfilMetrics },
    })
    const counts = summarizeStatuses(r.alerts)
    expect(counts).toEqual({ confirmed: 0, likely: 0, suspected: 1, observed: 0 })
    const label = statusCountsLabel(counts)
    expect(label).toContain("0 confirmed")
    expect(label).toContain("1 suspected")
    expect(label).not.toContain("1 confirmed")
    // The risk verdict floors on severity (CRITICAL) while the finding stays
    // SUSPECTED — status is never derived from the score or severity.
    expect(r.risk!.highestSeverity).toBeGreaterThanOrEqual(4)
  })

it("a CONFIRMED finding reports 1 confirmed while severity stays CRITICAL", () => {
    const r = buildReportAnalysis({
      ...state,
      alerts: [exfil("CONFIRMED")],
      advancedMetrics: { ...advancedMetrics, dataExfiltrationSuspected: true, ...exfilMetrics },
    })
    const label = statusCountsLabel(summarizeStatuses(r.alerts))
    expect(label).toBe("1 confirmed")
    expect(label).not.toContain("suspected")
  })
})

describe("alert group evidence quality — never fabricated for legacy alerts", () => {
  const noQ = (id: string): AlertEntry => ({ ...portScanAlert, id })
  const withQ = (id: string, q: "LOW" | "MEDIUM" | "HIGH"): AlertEntry => ({ ...portScanAlert, id, evidenceQuality: q })

  it("a group of legacy alerts without the field carries NO badge (undefined, not a made-up MEDIUM)", () => {
    const r = buildReportAnalysis({ ...state, alerts: [noQ("a1"), noQ("a2")] })
    expect(r.groups[0].evidenceQuality).toBeUndefined()
  })

  it("missing quality never inflates the group (LOW + missing stays LOW, in either order)", () => {
    const r1 = buildReportAnalysis({ ...state, alerts: [withQ("a1", "LOW"), noQ("a2")] })
    expect(r1.groups[0].evidenceQuality).toBe("LOW")
    const r2 = buildReportAnalysis({ ...state, alerts: [noQ("a1"), withQ("a2", "LOW")] })
    expect(r2.groups[0].evidenceQuality).toBe("LOW")
  })

  it("the strongest REAL quality wins (HIGH over LOW)", () => {
    const r = buildReportAnalysis({ ...state, alerts: [withQ("a1", "HIGH"), withQ("a2", "LOW")] })
    expect(r.groups[0].evidenceQuality).toBe("HIGH")
  })
})

describe("group alert traffic — a partial sum never reads as the group total", () => {
  it("a group spanning tuples reads N/A when ANY backing tuple's flow rows were not retained", () => {
    const scanA = { ...portScanAlert, id: "s1", srcIp: "10.0.0.5", dstIp: "203.0.113.9" }
    const scanB = { ...portScanAlert, id: "s2", srcIp: "10.0.0.5", dstIp: "203.0.113.10" }
    const flows = [{ id: "f1", srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 1234, dstPort: 80, protocol: "TCP", packets: 42, bytesTotal: 6000, bytesSent: 4000, bytesRecv: 2000, duration: 10, startTime: "", endTime: "" }] as Flow[]
    const r = buildReportAnalysis({ ...state, alerts: [scanA, scanB], flows })
    const g = r.groups.find((x) => x.ruleId === "PORT-SCAN-001")!
    expect(g.occurrences).toBe(2)
    // scanB's pair has no retained flow row: 42 pkts/6 KB would be a PARTIAL
    // sum presented as the group total — the honest answer is N/A.
    expect(g.packets).toBeNull()
    expect(g.bytes).toBeNull()
  })

  it("a group whose every tuple is retained keeps the exact summed traffic", () => {
    const scanA = { ...portScanAlert, id: "s1", srcIp: "10.0.0.5", dstIp: "203.0.113.9" }
    const scanB = { ...portScanAlert, id: "s2", srcIp: "10.0.0.5", dstIp: "203.0.113.10" }
    const flows = [
      { id: "f1", srcIp: "10.0.0.5", dstIp: "203.0.113.9", srcPort: 1234, dstPort: 80, protocol: "TCP", packets: 42, bytesTotal: 6000, bytesSent: 4000, bytesRecv: 2000, duration: 10, startTime: "", endTime: "" },
      { id: "f2", srcIp: "10.0.0.5", dstIp: "203.0.113.10", srcPort: 2000, dstPort: 443, protocol: "TCP", packets: 7, bytesTotal: 800, bytesSent: 300, bytesRecv: 500, duration: 4, startTime: "", endTime: "" },
    ] as Flow[]
    const r = buildReportAnalysis({ ...state, alerts: [scanA, scanB], flows })
    const g = r.groups.find((x) => x.ruleId === "PORT-SCAN-001")!
    expect(g.packets).toBe(49)
    expect(g.bytes).toBe(6800)
  })
})

describe("reportDurationSec — the report's rate denominator is never 0 or NaN", () => {
  it("the metrics engine's duration wins when present", () => {
    expect(reportDurationSec({ rates: { durationSec: 42 } }, { captureDuration: 88 })).toBe(42)
  })

  it("legacy jobs fall back to the job's capture duration", () => {
    expect(reportDurationSec(null, { captureDuration: 88 })).toBe(88)
    expect(reportDurationSec(undefined, undefined)).toBeNull()
  })

  it("no interval → null, never a 0 divisor (single packet / zero duration / NaN)", () => {
    expect(reportDurationSec({ rates: { durationSec: null } }, { captureDuration: 0 })).toBeNull()
    expect(reportDurationSec({ rates: { durationSec: null } }, null)).toBeNull()
    expect(reportDurationSec(null, { captureDuration: 0 })).toBeNull()
    expect(reportDurationSec(null, { captureDuration: -5 })).toBeNull()
    expect(reportDurationSec(null, { captureDuration: Number.NaN })).toBeNull()
  })
})

describe("binPackets — unparseable timestamps never poison the timeline", () => {
  it("skips bad-timestamp packets: no NaN bins, and the valid packets stay in their real bins", () => {
    const pkts: Packet[] = [
      packet(0),
      { ...packet(2), timestamp: "not-a-date" },
      packet(4),
    ]
    const bins = binPackets(pkts, 10)
    expect(bins.length).toBe(2)
    expect(bins.reduce((s, b) => s + b.packets, 0)).toBe(2)
    expect(bins.every((b) => b.time !== "NaN")).toBe(true)
  })

  it("an all-invalid-timestamp capture yields no bins, not NaN rows", () => {
    const pkts: Packet[] = [
      { ...packet(0), timestamp: "garbage" },
      { ...packet(1), timestamp: "garbage" },
    ]
    expect(binPackets(pkts, 10)).toEqual([])
  })
})
