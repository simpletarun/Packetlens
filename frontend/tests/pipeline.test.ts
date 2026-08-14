import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { parsePcap } from "@/lib/pcap"
import { analyzePcap } from "@/lib/analysis"
import { computeRisk, buildRiskInputs, burstConfidenceBoost } from "@/lib/risk"
import { computeStats } from "@/lib/stats"
import { dnsLookupCount, portServiceName } from "@/lib/report"
import { isPrivateIP } from "@/lib/map-data"

// Regression fixture: the user's testing.pcapng (1-minute Android capture).
// The review demanded: no DNS-tunneling / beaconing false positives, no
// UDP-as-port-scan false positive, packet-only alert timestamps, no MACs on
// remote hosts, explainable risk, deterministic output.
const fixture = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "testing.pcapng")

describe("end-to-end pipeline on testing.pcapng", () => {
  it("produces a deterministic, explainable report with zero false positives", async () => {
    const buf = readFileSync(fixture)
    const parsed = await parsePcap(buf)
    const analysis = analyzePcap(parsed)

    const captureStart = Math.min(...parsed.packets.map((p) => p.timestamp))
    const captureEnd = Math.max(...parsed.packets.map((p) => p.timestamp))

    // 1. No DNS-tunneling / beaconing false positives on normal browser traffic.
    expect(analysis.advancedMetrics.dnsTunnelingSuspected).toBe(false)
    expect(analysis.advancedMetrics.beaconDetected).toBe(false)

    // 2. No UDP-chatter-as-port-scan false positive (no TCP SYN probes present).
    expect(analysis.threats.some((t) => t.ruleId === "PORT-SCAN-001")).toBe(false)
    expect(analysis.threats.some((t) => t.ruleId === "DNS-TUNNEL-001")).toBe(false)
    expect(analysis.threats.some((t) => t.ruleId === "C2-BEACON-001")).toBe(false)

    // 3. Every alert timestamp lies inside the capture window (never generation time).
    for (const t of analysis.threats) {
      const sec = new Date(t.timestamp).getTime() / 1000
      expect(sec).toBeGreaterThanOrEqual(captureStart - 1)
      expect(sec).toBeLessThanOrEqual(captureEnd + 1)
    }

    // 4. Remote (public) IPs never carry a MAC; private ones may.
    const privateHosts = analysis.devices.filter((d) => d.ip.startsWith("192.168.") || d.ip.startsWith("10."))
    const remote = analysis.devices.filter((d) => !d.ip.startsWith("192.168.") && !d.ip.startsWith("10.") && !d.ip.startsWith("fe80:") && !d.ip.startsWith("ff"))
    for (const d of remote) expect(d.mac, `${d.ip} must not show a MAC`).toBe("\u2014")
    expect(privateHosts.length).toBeGreaterThan(0)

    // 5. Risk is a pure, explainable function of alerts (parity with the risk table).
    expect(analysis.job.riskScore).toBe(computeRisk(buildRiskInputs(analysis.threats), burstConfidenceBoost(analysis.advancedMetrics)))
    // No alerts on benign traffic => risk 0. Every alert the report shows is present here.
    expect(analysis.job.riskScore).toBe(0)

    // 6. Deterministic: two runs produce identical threat sets.
    const again = analyzePcap(parsed)
    expect(again.threats).toEqual(analysis.threats)
    expect(again.job.riskScore).toBe(analysis.job.riskScore)
  }, 60000)

  it("reports the true capture duration, distinct DNS lookups, local device count and one throughput number", async () => {
    const buf = readFileSync(fixture)
    const parsed = await parsePcap(buf)
    const analysis = analyzePcap(parsed)

    const captureStart = Math.min(...parsed.packets.map((p) => p.timestamp))
    const captureEnd = Math.max(...parsed.packets.map((p) => p.timestamp))
    const duration = captureEnd - captureStart

    // Duration: the summary must match the real min..max packet span (the old
    // first/last-of-file span and a rounded job value showed "1 min" for an
    // 87.6s capture), and no flow may outlast the capture beyond rounding.
    expect(analysis.job.captureDuration).toBeCloseTo(duration, 1)
    const maxFlow = Math.max(...analysis.flows.map((f) => f.duration))
    expect(maxFlow).toBeLessThanOrEqual(Math.round(duration) + 1)

    // DNS: all 54 DNS messages are kept (responses carry rcode/answers), but
    // only the 27 client queries are queries — the 27 rows from the router
    // are responses, never queriers — and the 11 distinct lookups collapse
    // the duplicates.
    expect(analysis.dns.length).toBe(54)
    const dnsQueries = analysis.dns.filter((d) => !d.isResponse).length
    expect(dnsQueries).toBe(27)
    expect(dnsLookupCount(analysis.dns)).toBe(11)
    expect(analysis.dns.some((d) => d.isResponse)).toBe(true)

    // DNS TTL: responses here carry TTL 0 ON THE WIRE (the Xiaomi connectivity
    // resolver answers from cache), so the rows must surface 0 — the "TTL
    // always 0s" QA finding is honest parsing, not a bug (the synthetic
    // buildDnsPcap(false) fixture demonstrates a real 300 s TTL survives).
    const responseTtls = analysis.dns.filter((d) => d.isResponse).map((d) => d.ttl)
    expect(responseTtls.length).toBeGreaterThan(0)
    expect(responseTtls.every((t) => t === 0)).toBe(true)
    // ...and answers themselves are still captured from the wire.
    expect(analysis.dns.filter((d) => d.isResponse).some((d) => d.answer && d.answer !== '\u2014')).toBe(true)

    // Devices: report count = LOCAL devices only (3 local rows on this LAN —
    // the client, the router, and one cross-subnet host the router forwards
    // for; v3.2 F-04 QA fixed same-MAC merges to respect subnet boundaries,
    // so the forwarded 192.168.1.10 row is no longer folded into the router),
    // while the endpoint list keeps all 29 (26 external services).
    expect(analysis.devices.length).toBe(29)
    const localDevices = analysis.devices.filter((d) => isPrivateIP(d.ip)).length
    expect(localDevices).toBe(3)
    const routerRow = analysis.devices.find((d) => d.ip === "192.168.137.1")
    expect(routerRow?.addresses ?? []).not.toContain("192.168.1.10")
    const stats = computeStats({
      job: { ...analysis.job, status: "done" } as Parameters<typeof computeStats>[0]["job"], packets: analysis.packets, flows: analysis.flows,
      sessions: analysis.sessions, dns: analysis.dns, devices: analysis.devices,
      alerts: analysis.threats, geo: new Map(),
    })
    expect(stats.devices).toBe(localDevices)

    // Throughput: the engine's canonical avg divides total bytes by the rate
    // window = max(real span, covered seconds), so it can never exceed the
    // peak bucket (QA: Teardrop 914 B/s avg vs 764 B/s peak on dense short
    // captures). This is the single number the report page renders.
    const total = analysis.packets.reduce((s, p) => s + p.length, 0)
    const rates = analysis.advancedMetrics.rates
    const rateWindow = Math.max(rates.durationSec ?? duration, rates.bucketCount)
    expect(Math.abs(total / rateWindow - (analysis.advancedMetrics.throughputAvg ?? 0))).toBeLessThan(1)
    expect(analysis.advancedMetrics.throughputAvg!).toBeLessThanOrEqual(analysis.advancedMetrics.throughputPeak!)

    // Port services: previously-unlabeled well-known ports resolve.
    expect(portServiceName(7, "TCP")).toBe("Echo")
    expect(portServiceName(5228, "TCP")).toBe("GCM (FCM)")
    expect(portServiceName(443, "UDP")).toBe("QUIC")
  }, 60000)
})
