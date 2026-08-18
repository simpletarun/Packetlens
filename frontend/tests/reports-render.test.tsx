import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import { render, cleanup, screen, fireEvent } from "@testing-library/react"
import { useAnalysisStore } from "@/stores/analysis"
import type { AlertEntry, JobSummary } from "@/stores/analysis"
import { ANALYSIS_SCHEMA_VERSION } from "@/lib/analysis"

vi.mock("next/navigation", () => ({
  useParams: () => ({ jobId: "key-test" }),
  usePathname: () => "/analysis/key-test/reports",
}))
vi.mock("next-themes", () => ({
  useTheme: () => ({ theme: "light", setTheme: () => {} }),
}))

import ReportsPage, { fmtClock } from "@/app/analysis/[jobId]/reports/page"

function seedStore() {
  const job: JobSummary = {
    id: "key-test", filename: "dup-alert.pcap", fileSize: 1024,
    status: "done", progress: 100, stage: "complete",
    totalPackets: 2, totalFlows: 1, conversations: 1,
    devices: 2, externalIps: 1, countries: 0, domains: 0,
    protocols: ["TCP"], alerts: 2, riskScore: 10,
    highestSeverity: 4, captureQuality: "VALID", captureDuration: 1,
    createdAt: "2024-01-01T00:00:00.000Z",
    completedAt: "2024-01-01T00:00:02.000Z",
  }
  // Two alerts with the SAME timestamp and signature land in the same
  // timeline bin, so the alert-dot key "time + signature" would collide.
  // Different sources keep the event-dedup contract (ruleId|srcIp|dstIp).
  const mkAlert = (id: string, srcIp: string, dstIp: string): AlertEntry => ({
    id, timestamp: "2024-01-01T00:00:01.000Z", signature: "SYN Flood Attempt",
    category: "DoS", severity: 4, confidence: 90, ruleId: "SYN-FLOOD-001",
    srcIp, dstIp, srcPort: 12345, dstPort: 80,
    protocol: "TCP", evidence: "test",
  })
  useAnalysisStore.getState().setAllData({
    job,
    packets: [
      { num: 1, timestamp: "2024-01-01T00:00:00.100Z", srcIp: "192.168.1.1", dstIp: "10.0.0.1", srcPort: 12345, dstPort: 80, protocol: "TCP", length: 64, flags: "SYN", ttl: 64, info: "" },
      { num: 2, timestamp: "2024-01-01T00:00:01.100Z", srcIp: "10.0.0.1", dstIp: "192.168.1.1", srcPort: 80, dstPort: 12345, protocol: "TCP", length: 60, flags: "ACK", ttl: 64, info: "" },
    ],
    flows: [
      { id: "f1", srcIp: "192.168.1.1", dstIp: "10.0.0.1", srcPort: 12345, dstPort: 80, protocol: "TCP", packets: 2, bytesTotal: 124, bytesSent: 64, bytesRecv: 60, duration: 1, startTime: "2024-01-01T00:00:00.100Z", endTime: "2024-01-01T00:00:01.100Z", retrans: 0, appProtocol: "HTTP", protocolSource: "PORT_INFERRED", tcpState: "INITIATED" },
    ],
    sessions: [
      { id: "s1", srcIp: "192.168.1.1", dstIp: "10.0.0.1", srcPort: 12345, dstPort: 80, protocol: "TCP", packets: 2, bytes: 124, startTime: "2024-01-01T00:00:00.100Z", endTime: "2024-01-01T00:00:01.100Z", duration: 1, state: "INITIATED" },
    ],
    dns: [], http: [], tls: [], files: [],
    credentials: [], certificates: [], devices: [], alerts: [mkAlert("a1", "192.168.1.1", "10.0.0.1"), mkAlert("a2", "10.0.0.5", "203.0.113.9")],
    timeline: [
      { time: "00:00", packets: 1, bytes: 64, tcp: 1, udp: 0, dns: 0, tls: 0 },
      { time: "00:30", packets: 1, bytes: 60, tcp: 1, udp: 0, dns: 0, tls: 0 },
    ],
    bandwidth: [
      { time: "00:00", in: 64, out: 0 },
      { time: "00:30", in: 60, out: 0 },
    ],
advancedMetrics: {
        rates: { quality: "VALID", durationSec: 1, avgPacketsSec: 2, avgBps: 124, peakBps: 124, peakBps100ms: 124, bucketCount: 1, avgExceedsPeak: false },
        burst: null,
        throughputAvg: 124, throughputPeak: 124, throughputPeak100ms: 124,
      beaconDetected: false, dnsTunnelingSuspected: false, dataExfiltrationSuspected: false,
      torVpnProxyDetected: false, portScanEnhanced: false, ja3Suspicious: false,
      topTalkers: [], iocs: [], mitreMappings: [],
    },
    burst: null,
    schemaVersion: ANALYSIS_SCHEMA_VERSION,
    validator: {
      schemaVersion: ANALYSIS_SCHEMA_VERSION,
      captureQuality: "VALID",
      durationSec: 1,
      decode: { decoded: 2, total: 2, linkTypes: [1], decodeRatePct: 100 },
      integrity: { status: "valid", truncatedPackets: 0, fileTruncated: false, malformedPackets: 0, unsupportedLinkTypes: [] },
    },
    decode: { decoded: 2, total: 2, linkTypes: [1] },
    fileInfo: { sha256: "", sha1: "", md5: "" },
  })
}

describe("Reports page render", () => {
  beforeEach(() => {
    useAnalysisStore.getState().resetAnalysis()
  })
  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
  })

  it("renders alert dots without duplicate-key warnings when two alerts share a bin and signature", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {})
    seedStore()
    render(<ReportsPage />)
    const dupKeyWarnings = spy.mock.calls.filter((args) => String(args[0]).includes("same key"))
    expect(dupKeyWarnings).toHaveLength(0)
  })

  it("gates an undecodable capture: UNKNOWN verdict, N/A breakdown, undecodable bucket wording (QA verylarge)", () => {    const job: JobSummary = {
      id: "key-test", filename: "verylarge.pcapng", fileSize: 17355742,
      status: "done", progress: 100, stage: "complete",
      totalPackets: 23253, totalFlows: 1, conversations: 1,
      devices: 0, externalIps: 0, countries: 0, domains: 0,
      protocols: ["OTHER"], alerts: 1, riskScore: 0,
      captureDuration: 198, createdAt: "2024-01-01T00:00:00.000Z",
      completedAt: "2024-01-01T00:03:18.000Z",
    }
    const mkAlert = (): AlertEntry => ({
      id: "a1", timestamp: "2024-01-01T00:00:01.000Z", signature: "SYN Flood Attempt",
      category: "DoS", severity: 4, confidence: 90, ruleId: "SYN-FLOOD-001",
      srcIp: "\u2014", dstIp: "\u2014", srcPort: 0, dstPort: 0,
      protocol: "OTHER", evidence: "test",
    })
    const dash = "\u2014"
    useAnalysisStore.getState().setAllData({
      job,
      packets: [
        { num: 1, timestamp: "2024-01-01T00:00:00.100Z", srcIp: dash, dstIp: dash, srcPort: 0, dstPort: 0, protocol: "OTHER", length: 146, flags: "", ttl: 0, info: "IP packet #1" },
        { num: 2, timestamp: "2024-01-01T00:00:00.200Z", srcIp: dash, dstIp: dash, srcPort: 0, dstPort: 0, protocol: "OTHER", length: 79, flags: "", ttl: 0, info: "IP packet #2" },
      ],
      flows: [{ id: "flow-1", srcIp: dash, dstIp: dash, srcPort: 0, dstPort: 0, protocol: "OTHER", packets: 23253, bytesTotal: 17355742, bytesSent: 0, bytesRecv: 0, duration: 198, startTime: "2024-01-01T00:00:00.000Z", endTime: "2024-01-01T00:03:18.000Z", directionUnknown: true }],
      sessions: [], dns: [], http: [], tls: [], files: [],
      credentials: [], certificates: [], devices: [], alerts: [mkAlert()],
      timeline: [
        { time: "00:00", packets: 11627, bytes: 8677871, tcp: 0, udp: 0, dns: 0, tls: 0 },
        { time: "00:03", packets: 11626, bytes: 8677871, tcp: 0, udp: 0, dns: 0, tls: 0 },
      ],
      bandwidth: [
        { time: "00:00", in: 8677871, out: 0 },
        { time: "00:03", in: 8677871, out: 0 },
      ],
      advancedMetrics: {
        throughputAvg: 0, throughputPeak: 0, burst: null,
        beaconDetected: false, dnsTunnelingSuspected: false, dataExfiltrationSuspected: false,
        torVpnProxyDetected: false, portScanEnhanced: false, ja3Suspicious: false,
        topTalkers: [], iocs: [], mitreMappings: [],
      },
      burst: null,
      decode: { decoded: 0, total: 23253, linkTypes: [] },
    })
    render(<ReportsPage />)
    // Verdict gate: the card + cover must say UNKNOWN, never 0/100 SAFE.
    expect(screen.getAllByText("UNKNOWN / INSUFFICIENT DATA").length).toBeGreaterThan(0)
    expect(screen.queryByText(/0\/100 SAFE/)).toBeNull()
    // Risk breakdown must not contradict the headline.
    expect(screen.getByText("N/A — insufficient data")).toBeTruthy()
    // Exec summary calls it an undecodable traffic bucket, not flows+IPs.
    expect(screen.getByText(/undecodable traffic bucket/)).toBeTruthy()
    // Data-quality warning.
    expect(screen.getByText(/only 0% of packets decoded/)).toBeTruthy()
  })

  it("talkers label a local device's IPv6 alias Internal, not External (merged identity)", () => {
    const job: JobSummary = {
      id: "key-test", filename: "v6-alias.pcapng", fileSize: 1024,
      status: "done", progress: 100, stage: "complete",
      totalPackets: 3, totalFlows: 2, conversations: 2,
      devices: 1, externalIps: 1, countries: 0, domains: 0,
      protocols: ["TCP"], alerts: 0, riskScore: 5,
      captureDuration: 60, createdAt: "2024-01-01T00:00:00.000Z",
      completedAt: "2024-01-01T00:00:02.000Z",
    }
    const v6 = "2401:4900:8910:1:2:3:4:308f"
    useAnalysisStore.getState().setAllData({
      job,
      packets: [
        { num: 1, timestamp: "2024-01-01T00:00:00.100Z", srcIp: v6, dstIp: "192.168.1.20", srcPort: 54321, dstPort: 443, protocol: "TCP", length: 64, flags: "SYN", ttl: 64, info: "" },
        { num: 2, timestamp: "2024-01-01T00:00:01.100Z", srcIp: "192.168.1.20", dstIp: v6, srcPort: 443, dstPort: 54321, protocol: "TCP", length: 60, flags: "ACK", ttl: 64, info: "" },
        { num: 3, timestamp: "2024-01-01T00:00:02.100Z", srcIp: "192.168.1.20", dstIp: "8.8.8.8", srcPort: 53, dstPort: 53, protocol: "UDP", length: 80, flags: "", ttl: 64, info: "" },
      ],
      flows: [], sessions: [], dns: [], http: [], tls: [], files: [],
      credentials: [], certificates: [],
      devices: [{ id: "d1", ip: "192.168.1.20", mac: "00:1b:21:aa:bb:cc", hostname: "DESKTOP-X", vendor: "Intel", os: "Windows", firstSeen: "2024-01-01T00:00:00.100Z", lastSeen: "2024-01-01T00:00:02.100Z", packets: 3, bytes: 204, addresses: [v6] }],
      alerts: [],
      timeline: [
        { time: "00:00", packets: 2, bytes: 124, tcp: 2, udp: 0, dns: 0, tls: 0 },
        { time: "00:01", packets: 1, bytes: 80, tcp: 0, udp: 1, dns: 1, tls: 0 },
      ],
      bandwidth: [
        { time: "00:00", in: 124, out: 0 },
        { time: "00:01", in: 80, out: 0 },
      ],
      advancedMetrics: null,
      burst: null,
    })
    render(<ReportsPage />)
    // The MAC-merged v6 alias of local .20 must read Internal — before the
    // fix it showed as a second "External (Country Unknown)" talker row.
    expect(screen.getAllByText("External (Country Unknown)")).toHaveLength(1)
  })

  it("suppresses MAC+vendor on off-link remote endpoint rows (QA Nokia next-hop)", () => {
    const job: JobSummary = {
      id: "key-test", filename: "macs.pcap", fileSize: 1024,
      status: "done", progress: 100, stage: "complete",
      totalPackets: 2, totalFlows: 1, conversations: 1,
      devices: 2, externalIps: 1, countries: 0, domains: 0,
      protocols: ["TCP"], alerts: 0, riskScore: 5,
      captureDuration: 60, createdAt: "2024-01-01T00:00:00.000Z",
      completedAt: "2024-01-01T00:00:02.000Z",
    }
    useAnalysisStore.getState().setAllData({
      job,
      packets: [
        { num: 1, timestamp: "2024-01-01T00:00:00.100Z", srcIp: "192.168.1.20", dstIp: "8.8.8.8", srcPort: 42315, dstPort: 443, protocol: "TCP", length: 64, flags: "SYN", ttl: 64, info: "" },
        { num: 2, timestamp: "2024-01-01T00:00:01.100Z", srcIp: "8.8.8.8", dstIp: "192.168.1.20", srcPort: 443, dstPort: 42315, protocol: "TCP", length: 60, flags: "ACK", ttl: 64, info: "" },
      ],
      flows: [], sessions: [], dns: [], http: [], tls: [], files: [],
      credentials: [], certificates: [],
      devices: [
        { id: "d1", ip: "192.168.1.20", mac: "00:1b:21:aa:bb:cc", hostname: "", vendor: "Intel", os: "Windows", firstSeen: "2024-01-01T00:00:00.100Z", lastSeen: "2024-01-01T00:00:01.100Z", packets: 2, bytes: 124 },
        { id: "d2", ip: "8.8.8.8", mac: "6e:22:f7:11:22:33", hostname: "", vendor: "Nokia", os: "", firstSeen: "2024-01-01T00:00:00.100Z", lastSeen: "2024-01-01T00:00:01.100Z", packets: 2, bytes: 124 },
      ],
      alerts: [],
      timeline: [
        { time: "00:00", packets: 1, bytes: 64, tcp: 1, udp: 0, dns: 0, tls: 0 },
        { time: "00:01", packets: 1, bytes: 60, tcp: 1, udp: 0, dns: 0, tls: 0 },
      ],
      bandwidth: [
        { time: "00:00", in: 64, out: 0 },
        { time: "00:01", in: 60, out: 0 },
      ],
      advancedMetrics: null,
      burst: null,
    })
    render(<ReportsPage />)
    // The remote row's MAC/vendor describe the next-hop frame, not the remote
    // host — both must be suppressed; the LOCAL row keeps its real values.
    expect(screen.queryByText("Nokia")).toBeNull()
    expect(screen.queryByText("6e:22:f7:11:22:33")).toBeNull()
    expect(screen.getAllByText("Intel")).toHaveLength(1)
    // §13 remote-endpoint card: external IPs and remote endpoints on one card
    // (they coincide here, so no difference footnote appears).
    expect(screen.getByText("1 external IPs · 1 remote endpoints")).toBeTruthy()
    expect(screen.queryByText(/External IPs \(\d+\) and remote endpoints \(\d+\) differ/)).toBeNull()
  })

  it("says 'no handshakes captured' when TCP health flows exist without RTT (mid-stream)", () => {
    const job: JobSummary = {
      id: "key-test", filename: "tcp-health.pcap", fileSize: 1024,
      status: "done", progress: 100, stage: "complete",
      totalPackets: 2, totalFlows: 1, conversations: 1,
      devices: 0, externalIps: 1, countries: 0, domains: 0,
      protocols: ["TCP"], alerts: 0, riskScore: 5,
      captureDuration: 60, createdAt: "2024-01-01T00:00:00.000Z",
      completedAt: "2024-01-01T00:00:02.000Z",
    }
    useAnalysisStore.getState().setAllData({
      job,
      packets: [
        { num: 1, timestamp: "2024-01-01T00:00:00.100Z", srcIp: "192.168.1.20", dstIp: "8.8.8.8", srcPort: 42315, dstPort: 443, protocol: "TCP", length: 64, flags: "", ttl: 64, info: "" },
      ],
      flows: [{ id: "f1", srcIp: "192.168.1.20", dstIp: "8.8.8.8", srcPort: 42315, dstPort: 443, protocol: "TCP", packets: 5, bytesTotal: 600, bytesSent: 300, bytesRecv: 300, duration: 9, startTime: "2024-01-01T00:00:00.100Z", endTime: "2024-01-01T00:00:09.100Z", retrans: 2 }],
      sessions: [], dns: [], http: [], tls: [], files: [],
      credentials: [], certificates: [], devices: [], alerts: [],
      timeline: [
        { time: "00:00", packets: 1, bytes: 64, tcp: 1, udp: 0, dns: 0, tls: 0 },
      ],
      bandwidth: [
        { time: "00:00", in: 64, out: 0 },
      ],
      advancedMetrics: null,
      burst: null,
    })
    render(<ReportsPage />)
    // No SYN captured ⇒ no handshake RTT — the old "avg handshake RTT —"
    // read as a silent gap; it must say why there is no number.
    expect(screen.getByText(/no handshakes captured \(mid-session flows\)/)).toBeTruthy()
  })

  it("fmtClock carries fractional seconds into minutes — never a :60 field (QA 59.7s)", () => {
    expect(fmtClock(59.7)).toBe("00:01:00")
    expect(fmtClock(59.4)).toBe("00:00:59")
    expect(fmtClock(3599.7)).toBe("01:00:00")
    expect(fmtClock(0.4)).toBe("00:00:00")
  })

  it("exports a REAL HTML report: http origin deep link, no double-escape, verdict class, tables", async () => {
    seedStore()
    let captured: Blob | null = null
    vi.spyOn(URL, "createObjectURL").mockImplementation((b) => { captured = b as Blob; return "blob:mock" })
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {})
    render(<ReportsPage />)
    fireEvent.click(screen.getByTitle("Export report as standalone HTML"))
    const html = await captured!.text()
    // Real file header + our schema/style
    expect(html.startsWith("<!doctype html>")).toBe(true)
    expect(html).toContain("PacketLens Report — dup-alert.pcap")
    // Deep link uses the page's actual origin (http in jsdom), never a
    // hardcoded https:// that breaks localhost deployments.
    expect(html).toContain(`<a href="http://localhost:3000/analysis/key-test">View in PacketLens</a>`)
    // Backtick spans became real <code>; the Analysis ID links into the app.
    expect(html).toContain(`<code><a href="http://localhost:3000/analysis/key-test">key-test</a></code>`)
    expect(html).not.toContain("`key-test`")
    // Verdict carries its level class (report risk recomputed from the two
    // sev-4 alerts: 71/100 HIGH — the seed's job.riskScore is only a
    // fallback when advancedMetrics are absent).
    expect(html).toContain(`<strong class="lv-high">HIGH</strong>`)
    // No double-escaping anywhere in the artifact.
    expect(html).not.toContain("&amp;amp;")
    // Markdown tables became real tables with a header row (cells are
    // emitted one per line, so assert structurally, not on one long string).
    expect(html).toContain("<table><thead><tr>")
    expect(html).toContain("<th>Metric</th>")
    expect(html).toContain("<th>Value</th>")
  })

  it("exports a REAL flows CSV: BOM + header + one row per flow", async () => {
    const job: JobSummary = {
      id: "key-test", filename: "csv-export.pcap", fileSize: 1024,
      status: "done", progress: 100, stage: "complete",
      totalPackets: 8, totalFlows: 2, conversations: 2,
      devices: 0, externalIps: 1, countries: 0, domains: 0,
      protocols: ["TCP"], alerts: 0, riskScore: 5,
      highestSeverity: 0, captureQuality: "VALID", captureDuration: 1,
      createdAt: "2024-01-01T00:00:00.000Z",
      completedAt: "2024-01-01T00:00:02.000Z",
    }
    // The export guard re-validates the canonical result, so the fixture
    // must reconcile: 8 packets, Σ bytes 1000 = flows 600 + 400.
    const packetLens = [120, 120, 120, 120, 120, 133, 133, 134]
    useAnalysisStore.getState().setAllData({
      job,
      packets: packetLens.map((length, i) => ({
        num: i + 1, timestamp: `2024-01-01T00:00:00.${(i + 1) * 100}Z`,
        srcIp: i < 5 ? "192.168.1.20" : "8.8.8.8", dstIp: i < 5 ? "8.8.8.8" : "192.168.1.20",
        srcPort: i < 5 ? 42315 : 443, dstPort: i < 5 ? 443 : 42315,
        protocol: "TCP", length, flags: "ACK", ttl: 64, info: "",
      })),
      flows: [
        { id: "f1", srcIp: "192.168.1.20", dstIp: "8.8.8.8", srcPort: 42315, dstPort: 443, protocol: "TCP", packets: 5, bytesTotal: 600, bytesSent: 300, bytesRecv: 300, duration: 9, startTime: "2024-01-01T00:00:00.100Z", endTime: "2024-01-01T00:00:09.100Z", retrans: 2, tcpState: "ESTABLISHED" },
        { id: "f2", srcIp: "8.8.8.8", dstIp: "192.168.1.20", srcPort: 443, dstPort: 42315, protocol: "TCP", packets: 3, bytesTotal: 400, bytesSent: 0, bytesRecv: 400, duration: 8, startTime: "2024-01-01T00:00:00.200Z", endTime: "2024-01-01T00:00:08.200Z", retrans: 0, directionUnknown: true, tcpState: "ESTABLISHED" },
      ],
      sessions: [
        { id: "s1", srcIp: "192.168.1.20", dstIp: "8.8.8.8", srcPort: 42315, dstPort: 443, protocol: "TCP", packets: 5, bytes: 600, startTime: "2024-01-01T00:00:00.100Z", endTime: "2024-01-01T00:00:09.100Z", duration: 9, state: "ESTABLISHED" },
        { id: "s2", srcIp: "8.8.8.8", dstIp: "192.168.1.20", srcPort: 443, dstPort: 42315, protocol: "TCP", packets: 3, bytes: 400, startTime: "2024-01-01T00:00:00.200Z", endTime: "2024-01-01T00:00:08.200Z", duration: 8, state: "ESTABLISHED" },
      ],
      dns: [], http: [], tls: [], files: [],
      credentials: [], certificates: [], devices: [], alerts: [],
      timeline: [{ time: "00:00", packets: 8, bytes: 1000, tcp: 8, udp: 0, dns: 0, tls: 0 }],
      bandwidth: [{ time: "00:00", in: 400, out: 600 }],
      advancedMetrics: {
        rates: { quality: "VALID", durationSec: 1, avgPacketsSec: 8, avgBps: 1000, peakBps: 1000, peakBps100ms: 1000, bucketCount: 1, avgExceedsPeak: false },
        burst: null,
        throughputAvg: 1000, throughputPeak: 1000, throughputPeak100ms: 1000,
        beaconDetected: false, dnsTunnelingSuspected: false, dataExfiltrationSuspected: false,
        torVpnProxyDetected: false, portScanEnhanced: false, ja3Suspicious: false,
        topTalkers: [], iocs: [], mitreMappings: [],
      },
      burst: null,
      schemaVersion: ANALYSIS_SCHEMA_VERSION,
      validator: {
        schemaVersion: ANALYSIS_SCHEMA_VERSION,
        captureQuality: "VALID",
        durationSec: 1,
        decode: { decoded: 8, total: 8, linkTypes: [1], decodeRatePct: 100 },
        integrity: { status: "valid", truncatedPackets: 0, fileTruncated: false, malformedPackets: 0, unsupportedLinkTypes: [] },
      },
      decode: { decoded: 8, total: 8, linkTypes: [1] },
      fileInfo: { sha256: "", sha1: "", md5: "" },
    })
    let captured: Blob | null = null
    vi.spyOn(URL, "createObjectURL").mockImplementation((b) => { captured = b as Blob; return "blob:mock" })
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {})
    render(<ReportsPage />)
    fireEvent.click(screen.getByTitle("Export flows as CSV"))
    const csv = await captured!.text()
    const lines = csv.split("\n")
    // Build-identity comment + semantics lines ride the export (jsdom's
    // Blob.text() strips the BOM, so the round-tripped artifact starts at
    // the comment lines); one data row per flow follows.
    expect(lines[0]).toMatch(/^# PacketLens v\d+\.\d+\.\d+ · (commit|src):.* · 2 flows$/)
    expect(lines[1]).toMatch(/^# Rows are initiator-first:/)
    expect(lines[5]).toBe("srcIp,srcPort,dstIp,dstPort,protocol,packets,bytesSent,bytesRecv,bytesTotal,startTime,endTime,durationSec,srcCountry,dstCountry,srcAsn,dstAsn,service,serviceEvidence,rttMs,retrans,dataSegments,estLossPct")
    expect(lines).toHaveLength(8)
    expect(lines[6]).toContain("192.168.1.20,42315,8.8.8.8,443,TCP,5,300,300,600")
    expect(lines[7]).toContain("8.8.8.8,443,192.168.1.20,42315,TCP,3,,,400")
  })
})

  it("a CRITICAL-severity SUSPECTED alert renders '0 confirmed · 1 suspected' — never '1 confirmed' (QA: temp.pcapng)", () => {
    seedStore()
    const criticalSuspected: AlertEntry = {
      ...useAnalysisStore.getState().alerts[0],
      id: "a9",
      signature: "Suspected Large Outbound Transfer",
      category: "Exfiltration",
      severity: 5,
      confidence: 70,
      ruleId: "DATA-EXFIL-001",
      status: "SUSPECTED",
      evidenceQuality: "MEDIUM",
    }
    useAnalysisStore.getState().setAlerts([criticalSuspected])
    render(<ReportsPage />)
    const summary = screen.getByText("1 alert").closest("p")?.textContent ?? ""
    expect(summary).toContain("1 critical")
    expect(summary).toContain("0 confirmed")
    expect(summary).toContain("1 suspected")
    expect(summary).not.toContain("1 confirmed")
  })
