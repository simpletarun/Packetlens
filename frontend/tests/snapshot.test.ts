import { describe, it, expect } from "vitest"
import { analyzePcap, ANALYSIS_SCHEMA_VERSION, ANALYZER_VERSION } from "@/lib/analysis"
import { buildReportAnalysis } from "@/lib/report"
import { riskLevel, verdictLevel } from "@/lib/risk"
import type { ParsedPacket } from "@/lib/pcap"

// Golden snapshot of the CANONICAL Analysis JSON: any shape change to the
// engine's output (schemaVersion bump, new validator field, flow field
// rename…) must fail here loudly — the report/export/UI consumers regenerate
// from this exact object, so the snapshot IS the contract.
// Deterministic by construction: timestamps are UTC ISO, no timeline or
// bandwidth labels (those use the local timezone), and the capture is
// hand-built (no geo, no RNG).
function makePacket(overrides: Partial<ParsedPacket> = {}): ParsedPacket {
  return {
    num: 1, timestamp: 1_700_000_000, length: 64, origLength: 64,
    srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 52000, dstPort: 80,
    protocol: "TCP", tcpFlags: "ACK", payload: "",
    ...overrides,
  }
}

const capture = () =>
  analyzePcap({
    packets: [
      // TCP/80 pure SYN — port-inferred HTTP, INITIATED conversation.
      makePacket({ num: 1, timestamp: 1_700_000_000, tcpFlags: "SYN", appProtocol: "HTTP" }),
      // Payload-confirmed GET → HTTP entry + credential + payload provenance.
      makePacket({
        num: 2, timestamp: 1_700_000_001, tcpFlags: "PSH ACK", appProtocol: "HTTP", appPayloadConfirmed: true, httpMethod: "GET",
        payload: Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcjpzM2NyZXQ=\r\n\r\n", "latin1").toString("hex"),
      }),
      // Completing ACK — the handshake closes: ESTABLISHED.
      makePacket({ num: 3, timestamp: 1_700_000_002, tcpFlags: "ACK" }),
      // DNS query over UDP.
      makePacket({ num: 4, timestamp: 1_700_000_003, protocol: "UDP", tcpFlags: undefined, srcPort: 53000, dstPort: 53, dnsQuery: "example.com", dnsQtype: 1 }),
    ],
    stats: {
      totalPackets: 4, totalBytes: 256, duration: 3, startTime: 1_700_000_000, endTime: 1_700_000_003,
      protocols: { TCP: 3, UDP: 1 }, linkTypes: [1], decodedPackets: 4,
    },
  })

describe("canonical Analysis JSON snapshot (schema contract)", () => {
  it("matches the pinned golden model", () => {
    const a = capture()
    const model = {
      schemaVersion: a.schemaVersion,
      analyzerVersion: a.job.analyzerVersion,
      job: {
        totalPackets: a.job.totalPackets,
        totalFlows: a.job.totalFlows,
        alerts: a.job.alerts,
        riskScore: a.job.riskScore,
        captureQuality: a.job.captureQuality,
        captureDuration: a.job.captureDuration,
      },
      validator: a.validator,
      flows: a.flows.map((f) => ({
        srcIp: f.srcIp, dstIp: f.dstIp, srcPort: f.srcPort, dstPort: f.dstPort,
        protocol: f.protocol, packets: f.packets, bytesTotal: f.bytesTotal,
        appProtocol: f.appProtocol, protocolSource: f.protocolSource, tcpState: f.tcpState,
      })),
      sessions: a.sessions.map((s) => ({ state: s.state, packets: s.packets })),
      threats: a.threats.map((t) => ({
        ruleId: t.ruleId, severity: t.severity, confidence: t.confidence,
        srcIp: t.srcIp, dstIp: t.dstIp, packetNums: t.packetNums, payloadConfirmed: t.payloadConfirmed,
      })),
      dns: a.dns.map((d) => ({ query: d.query, type: d.type, responseCode: d.responseCode, isResponse: d.isResponse })),
      http: a.http.map((h) => ({ method: h.method, uri: h.uri, status: h.status })),
      credentials: a.credentials.map((c) => ({ username: c.username, service: c.service, packetNum: c.packetNum })),
    }
    expect(JSON.stringify(model, null, 2)).toMatchInlineSnapshot(`
      "{
        "schemaVersion": "1.1.0",
        "analyzerVersion": "3.4.0",
        "job": {
          "totalPackets": 4,
          "totalFlows": 2,
          "alerts": 1,
          "riskScore": 39,
          "captureQuality": "VALID",
          "captureDuration": 3
        },
        "validator": {
          "schemaVersion": "1.1.0",
          "captureQuality": "VALID",
          "durationSec": 3,
          "decode": {
            "decoded": 4,
            "total": 4,
            "linkTypes": [
              1
            ],
            "decodeRatePct": 100
          },
          "integrity": {
            "status": "valid",
            "truncatedPackets": 0,
            "fileTruncated": false,
            "malformedPackets": 0,
            "unsupportedLinkTypes": []
          }
        },
        "flows": [
          {
            "srcIp": "192.168.1.5",
            "dstIp": "8.8.8.8",
            "srcPort": 52000,
            "dstPort": 80,
            "protocol": "TCP",
            "packets": 3,
            "bytesTotal": 192,
            "appProtocol": "HTTP",
            "protocolSource": "PAYLOAD_CONFIRMED",
            "tcpState": "INITIATED"
          },
          {
            "srcIp": "192.168.1.5",
            "dstIp": "8.8.8.8",
            "srcPort": 53000,
            "dstPort": 53,
            "protocol": "UDP",
            "packets": 1,
            "bytesTotal": 64,
            "protocolSource": "UNKNOWN",
            "tcpState": "STATELESS"
          }
        ],
        "sessions": [
          {
            "state": "INITIATED",
            "packets": 3
          },
          {
            "state": "STATELESS",
            "packets": 1
          }
        ],
        "threats": [
          {
            "ruleId": "HTTP-CREDS-001",
            "severity": 4,
            "confidence": 75,
            "srcIp": "192.168.1.5",
            "dstIp": "8.8.8.8",
            "packetNums": [
              2
            ],
            "payloadConfirmed": true
          }
        ],
        "dns": [
          {
            "query": "example.com",
            "type": "A",
            "responseCode": "NOERROR",
            "isResponse": false
          }
        ],
        "http": [
          {
            "method": "GET",
            "uri": "/",
            "status": 0
          }
        ],
        "credentials": [
          {
            "username": "user",
            "service": "HTTP Basic",
            "packetNum": 2
          }
        ]
      }"
    `)
  })

  it("schemaVersion and analyzerVersion are pinned and reported", () => {
    const a = capture()
    expect(a.schemaVersion).toBe(ANALYSIS_SCHEMA_VERSION)
    expect(a.job.analyzerVersion).toBe(ANALYZER_VERSION)
  })

  it("the report builder consumes the canonical validator (duration + quality)", () => {
    const a = capture()
    expect(a.advancedMetrics.rates.durationSec).toBe(3)
    expect(a.validator.durationSec).toBe(3)
    const r = buildReportAnalysis({
      job: { ...a.job, status: "done", progress: 100, stage: "complete", createdAt: "2024-01-01T00:00:00.000Z", completedAt: "2024-01-01T00:00:05.000Z" },
      jobInfo: { isDemo: false },
      alerts: a.threats, packets: a.packets, flows: a.flows,
      sessions: a.sessions, tls: a.tls, http: a.http,
      timeline: a.timeline, bandwidth: a.bandwidth, advancedMetrics: a.advancedMetrics,
    })
    expect(r.metadata.analysisDurationSec).toBe(5)
    expect(r.metadata.captureQuality).toBe(a.validator.captureQuality)
    expect(r.metadata.ratesAvailable).toBe(a.validator.durationSec !== null)
    expect(r.risk!.normalizedScore).toBe(a.job.riskScore)
    // The verdict level is the score band floored by the strongest finding —
    // this capture has a confirmed High finding under a LOW score band.
    expect(r.risk!.levelLabel).toBe(verdictLevel(riskLevel(a.job.riskScore), a.job.highestSeverity).label)
    expect(r.risk!.highestSeverity).toBe(4)
  })
})
