import { describe, it, expect } from "vitest"
import { analyzePcap } from "@/lib/analysis"
import type { PCAPResult, ParsedPacket } from "@/lib/pcap"

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

describe("Regression tests", () => {
  it("handles packets with missing srcIp", () => {
    const packets = [makePacket({ srcIp: undefined, dstIp: "10.0.0.1" })]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 1, totalBytes: 64, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 1 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.packets[0].srcIp).toBe("\u2014")
  })

  it("handles packets with missing dstIp", () => {
    const packets = [makePacket({ dstIp: undefined })]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 1, totalBytes: 64, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 1 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.packets[0].dstIp).toBe("\u2014")
  })

  it("handles unknown protocol", () => {
    const packets = [makePacket({ protocol: "ICMP" })]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 1, totalBytes: 64, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { ICMP: 1 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.packets[0].protocol).toBe("ICMP")
  })

  it("handles zero-length capture", () => {
    const result: PCAPResult = {
      packets: [],
      stats: { totalPackets: 0, totalBytes: 0, duration: 0, startTime: 0, endTime: 0, protocols: {} },
    }
    const analysis = analyzePcap(result)
    expect(analysis.job.totalPackets).toBe(0)
    expect(analysis.job.riskScore).toBe(0)
  })

  it("handles single packet capture", () => {
    const packets = [makePacket()]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 1, totalBytes: 64, duration: 0, startTime: 1000000, endTime: 1000000, protocols: { TCP: 1 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.job.totalPackets).toBe(1)
    expect(analysis.flows.length).toBe(1)
  })

  it("handles large packet count without crashing", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 10000; i++) {
      packets.push(makePacket({ num: i + 1 }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 3600, startTime: 1000000, endTime: 1360000, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.job.totalPackets).toBe(10000)
    expect(analysis.packets.length).toBe(10000)
  })

  it("handles DNS queries without response", () => {
    const packets = [makePacket({ dnsQuery: "example.com", protocol: "UDP", srcPort: 53, dstPort: 53 })]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 1, totalBytes: 64, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { UDP: 1 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.dns.length).toBe(1)
    expect(analysis.dns[0].query).toBe("example.com")
  })

  it("handles HTTP requests without Host header", () => {
    const packets = [makePacket({ httpMethod: "GET", httpUri: "/", httpHost: "", protocol: "TCP", srcPort: 49152, dstPort: 80 })]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 1, totalBytes: 64, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 1 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.http.length).toBe(1)
    expect(analysis.http[0].method).toBe("GET")
  })

  it("risk score caps at 100", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 50; i++) {
      packets.push(makePacket({ num: i + 1, dstPort: 1000 + i }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 10, startTime: 1000000, endTime: 1000010, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.job.riskScore).toBeLessThanOrEqual(100)
  })

  it("undecodable capture (no IPs): decode stats reported, flow direction unknown, no phantom sent/recv legs", () => {
    // Regression: large/verylarge reported bytesSent = bytesRecv = total on a
    // phantom "—" flow — every undecodable packet was counted in BOTH legs.
    const undecoded = (n: number): ParsedPacket => ({
      num: n, timestamp: 1000000 + n, length: 400, origLength: 400, payload: "",
    })
    const packets = [undecoded(1), undecoded(2), undecoded(3)]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 3, totalBytes: 1200, duration: 3, startTime: 1000001, endTime: 1000003, protocols: { OTHER: 3 }, linkTypes: [12], decodedPackets: 0 },
    }
    const analysis = analyzePcap(result)
    expect(analysis.decode).toEqual({ decoded: 0, total: 3, linkTypes: [12] })
    const flow = analysis.flows[0]
    expect(flow.srcIp).toBe("\u2014")
    expect(flow.directionUnknown).toBe(true)
    expect(flow.bytesSent).toBe(0)
    expect(flow.bytesRecv).toBe(0)
    expect(flow.bytesTotal).toBe(1200)
  })

  it("decodable capture: decode stats reflect full decode, flow has real directions", () => {
    const result: PCAPResult = {
      packets: [makePacket()],
      stats: { totalPackets: 1, totalBytes: 64, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 1 }, linkTypes: [1], decodedPackets: 1 },
    }
    const analysis = analyzePcap(result)
    expect(analysis.decode).toEqual({ decoded: 1, total: 1, linkTypes: [1] })
    expect(analysis.flows[0].directionUnknown).toBe(false)
  })
})