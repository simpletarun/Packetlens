import { describe, it, expect } from "vitest"
import { analyzePcap, analysisProblems, assertValidAnalysisResult } from "@/lib/analysis"
import type { AnalysisResult } from "@/lib/analysis"
import type { PCAPResult, ParsedPacket } from "@/lib/pcap"

// ── Conservation invariants (byte/packet conservation) ─────────────────────
// The pipeline is: PCAP → engine → canonical result → FULL VALIDATION → only
// then → UI/HTML/PDF/JSON/API. Every analyzePcap() call self-validates; these
// tests prove the engine never emits (and the validator never accepts) a
// result where bytes or packets are created, dropped, or double-counted.

function makePacket(overrides: Partial<ParsedPacket> = {}): ParsedPacket {
  return {
    num: 1,
    timestamp: 1000000,
    length: 64,
    origLength: 64,
    srcIp: "192.168.1.1",
    dstIp: "10.0.0.1",
    srcPort: 12345,
    dstPort: 80,
    protocol: "TCP",
    tcpFlags: "ACK",
    payload: "",
    ...overrides,
  }
}

function run(packets: ParsedPacket[]): AnalysisResult {
  return analyzePcap({
    packets,
    stats: {
      totalPackets: packets.length,
      totalBytes: packets.reduce((s, p) => s + p.length, 0),
      duration: 1, startTime: 1000000, endTime: 1000001,
      protocols: { TCP: packets.length },
      linkTypes: [1], decodedPackets: packets.length,
    },
  })
}

describe("engine conservation — analyzePcap output always self-validates", () => {
  it("mixed capture: Σ flow packets = packets, Σ flow bytes = Σ packet bytes, legs reconcile", () => {
    const a = run([
      makePacket({ num: 1, tcpFlags: "SYN", length: 60 }),
      makePacket({ num: 2, srcIp: "10.0.0.1", dstIp: "192.168.1.1", srcPort: 80, dstPort: 12345, tcpFlags: "SYN ACK", length: 60 }),
      makePacket({ num: 3, tcpFlags: "ACK", length: 54 }),
      makePacket({ num: 4, tcpFlags: "PSH ACK", length: 200, appProtocol: "HTTP", appPayloadConfirmed: true, httpMethod: "GET" }),
      makePacket({ num: 5, protocol: "UDP", srcIp: "192.168.1.1", srcPort: 5353, dstIp: "224.0.0.251", dstPort: 5353, tcpFlags: undefined, length: 80 }),
    ])
    expect(analysisProblems(a)).toEqual([])
    const flowPackets = a.flows.reduce((s, f) => s + f.packets, 0)
    const flowBytes = a.flows.reduce((s, f) => s + f.bytesTotal, 0)
    const packetBytes = a.packets.reduce((s, p) => s + p.length, 0)
    expect(flowPackets).toBe(a.packets.length)
    expect(flowBytes).toBe(packetBytes)
    for (const f of a.flows) expect(f.bytesSent + f.bytesRecv).toBe(f.bytesTotal)
    const sessionPackets = a.sessions.reduce((s, x) => s + x.packets, 0)
    expect(sessionPackets).toBe(flowPackets)
    expect(a.job.alerts).toBe(a.threats.length)
    expect(a.job.highestSeverity).toBe(a.threats.reduce((m, t) => Math.max(m, t.severity), 0))
  })

  it("self-flows (ARP srcIp == dstIp) count each packet exactly once", () => {
    const a = run([
      makePacket({ num: 1, srcIp: "192.168.1.17", dstIp: "192.168.1.17", srcPort: 0, dstPort: 0, protocol: "ARP", tcpFlags: undefined }),
      makePacket({ num: 2, srcIp: "192.168.1.17", dstIp: "192.168.1.17", srcPort: 0, dstPort: 0, protocol: "ARP", tcpFlags: undefined }),
    ])
    expect(analysisProblems(a)).toEqual([])
    const f = a.flows[0]
    expect(f.bytesSent + f.bytesRecv).toBe(f.bytesTotal)
    expect(f.bytesTotal).toBe(2 * 64)
  })

  it("undecodable packets conserve on one leg — never doubled, never lost", () => {
    const undecodable = (n: number, length: number): ParsedPacket => ({
      num: n, timestamp: 1000000 + n, length, origLength: length,
      srcIp: undefined, dstIp: undefined, srcPort: 0, dstPort: 0,
      protocol: "OTHER", tcpFlags: undefined, payload: "",
    })
    const a = run([undecodable(1, 100), undecodable(2, 200), undecodable(3, 300)])
    expect(analysisProblems(a)).toEqual([])
    const f = a.flows[0]
    expect(f.directionUnknown).toBe(true)
    expect(f.bytesSent + f.bytesRecv).toBe(f.bytesTotal)
    expect(f.bytesTotal).toBe(600)
  })
})

describe("validator — analysisProblems rejects any inconsistency", () => {
  const hex = (s: string) => Buffer.from(s, "latin1").toString("hex")
  const base = run([
    makePacket({ num: 1, timestamp: 1000000, tcpFlags: "SYN" }),
    makePacket({ num: 2, timestamp: 1000001, srcIp: "10.0.0.1", dstIp: "192.168.1.1", srcPort: 80, dstPort: 12345, tcpFlags: "SYN ACK" }),
    makePacket({ num: 3, timestamp: 1000002, tcpFlags: "ACK" }),
    makePacket({ num: 4, timestamp: 1000003, tcpFlags: "PSH ACK", appProtocol: "HTTP", appPayloadConfirmed: true, httpMethod: "GET", payload: hex("GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcjpzM2NyZXQ=\r\n") }),
    makePacket({ num: 5, timestamp: 1000004, srcIp: "192.168.1.1", srcPort: 5353, dstIp: "224.0.0.251", dstPort: 5353, protocol: "UDP", tcpFlags: undefined }),
  ])
  expect(base.threats.length).toBeGreaterThan(0)
  const tamper = (mutate: (a: AnalysisResult) => void): string[] => {
    const copy = structuredClone(base)
    mutate(copy)
    return analysisProblems(copy)
  }

  it("accepts the engine's own output", () => {
    expect(analysisProblems(base)).toEqual([])
  })

  it("rejects flows whose legs do not sum to their total", () => {
    const tcp = base.flows.find((f) => f.protocol === "TCP")!
    const problems = tamper((a) => {
      const f = a.flows.find((x) => x.id === tcp.id)!
      f.bytesSent += 1
    })
    expect(problems.some((p) => p.includes("bytesSent") && p.includes("bytesTotal"))).toBe(true)
  })

  it("rejects Σ flow bytes != Σ packet bytes", () => {
    const problems = tamper((a) => { a.packets[0].length += 5 })
    expect(problems.some((p) => p.includes("Σ flow bytes") || p.includes("flow bytes"))).toBe(true)
  })

  it("rejects Σ flow packets != packet count", () => {
    const tcp = base.flows.find((f) => f.protocol === "TCP")!
    const problems = tamper((a) => {
      const f = a.flows.find((x) => x.id === tcp.id)!
      f.packets += 1
    })
    expect(problems.some((p) => p.includes("flow packets"))).toBe(true)
  })

  it("rejects a threat citing a nonexistent flowId", () => {
    const problems = tamper((a) => { a.threats[0].flowId = "nope" })
    expect(problems.some((p) => p.includes("flowId nope does not exist"))).toBe(true)
  })

  it("rejects a credential citing a packet outside 1..N", () => {
    const problems = tamper((a) => { a.credentials[0].packetNum = 999 })
    expect(problems.some((p) => p.includes("out of range"))).toBe(true)
  })

  it("rejects payloadConfirmed without decoder payload evidence", () => {
    const problems = tamper((a) => {
      const t = a.threats.find((x) => x.payloadConfirmed)!
      const num = t.packetNums![0]
      const p = a.packets.find((x) => x.num === num)!
      p.appPayloadConfirmed = false
    })
    expect(problems.some((p) => p.includes("no decoder payload evidence"))).toBe(true)
  })

  it("rejects duplicate alert events (ruleId|srcIp|dstIp)", () => {
    const problems = tamper((a) => {
      a.threats.push({ ...a.threats[0], id: "copy" })
    })
    expect(problems.some((p) => p.includes("duplicate threat event"))).toBe(true)
  })

  it("rejects flow/session state disagreement and non-TCP STATELESS misuse", () => {
    // The 3-way handshake completed, so the session is ESTABLISHED — a flow
    // claiming CLOSED while its session says ESTABLISHED must be rejected.
    const problems = tamper((a) => {
      const flow = a.flows.find((f) => f.protocol === "TCP")!
      flow.tcpState = "CLOSED"
    })
    expect(problems.some((p) => p.includes("tcpState") || p.includes("session state"))).toBe(true)
    const nonTcp = tamper((a) => {
      const f = a.flows.find((x) => x.protocol === "UDP")!
      f.tcpState = "ESTABLISHED"
    })
    expect(nonTcp.some((p) => p.includes("STATELESS"))).toBe(true)
  })

  it("rejects job summary mismatches and captureQuality/rates drift", () => {
    const p1 = tamper((a) => { a.job.totalPackets += 1 })
    expect(p1.some((x) => x.includes("job.totalPackets"))).toBe(true)
    const p2 = tamper((a) => { a.job.captureQuality = "EMPTY" })
    expect(p2.some((x) => x.includes("captureQuality"))).toBe(true)
    const p3 = tamper((a) => { a.job.highestSeverity = 1 })
    expect(p3.some((x) => x.includes("highestSeverity"))).toBe(true)
  })

  it("rejects avgExceedsPeak lying about avg vs peak", () => {
    const problems = tamper((a) => {
      a.advancedMetrics.rates!.avgExceedsPeak = !a.advancedMetrics.rates!.avgExceedsPeak
    })
    expect(problems.some((p) => p.includes("avgExceedsPeak"))).toBe(true)
  })

  it("rejects non-VALID captures carrying rates", () => {
    const problems = tamper((a) => {
      const r = a.advancedMetrics.rates!
      r.quality = "SINGLE_PACKET"
    })
    expect(problems.some((p) => p.includes("must have null rates"))).toBe(true)
  })

  it("assertValidAnalysisResult throws with a problem count", () => {
    const copy = structuredClone(base)
    const tcp = copy.flows.find((f) => f.protocol === "TCP")!
    tcp.bytesRecv += 9
    expect(() => assertValidAnalysisResult(copy)).toThrow(/failed validation \(\d+\)/)
  })
})

describe("validator — undecodable-only and zero-duration captures stay honest", () => {
  it("ZERO_DURATION: three packets, one timestamp — no rates, no burst", () => {
    const same = makePacket({ num: 1, timestamp: 1000000 })
    const a = run([same, { ...same, num: 2 }, { ...same, num: 3 }])
    expect(analysisProblems(a)).toEqual([])
    expect(a.advancedMetrics.rates.quality).toBe("ZERO_DURATION")
    expect(a.advancedMetrics.rates.avgBps).toBeNull()
    expect(a.advancedMetrics.rates.durationSec).toBeNull()
    expect(a.advancedMetrics.burst).toBeNull()
    expect(a.job.captureDuration).toBe(0)
    expect(a.job.captureQuality).toBe("ZERO_DURATION")
  })
})
