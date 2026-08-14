import { describe, it, expect } from "vitest"
import { analyzePcap } from "@/lib/analysis"
import { isPrivateIP } from "@/lib/map-data"
import { enrichDeviceVendors } from "@/lib/oui-server"
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

describe("protocol honesty — flow protocolSource (payload vs port_inferred)", () => {
  function run(packets: ParsedPacket[]) {
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

  it("TCP/80 with no HTTP payload is port_inferred, never payload", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, timestamp: 1000000, dstIp: "8.8.8.8", dstPort: 80, tcpFlags: "SYN", appProtocol: "HTTP" }),
      makePacket({ num: 2, timestamp: 1000001, dstIp: "8.8.8.8", dstPort: 80, tcpFlags: "ACK", appProtocol: "HTTP" }),
    ]
    const f = run(packets).flows[0]
    expect(f.protocolSource).toBe("port_inferred")
    expect(f.appProtocol).toBe("HTTP")
  })

  it("a GET payload makes the flow payload-confirmed HTTP", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, timestamp: 1000000, dstIp: "8.8.8.8", dstPort: 80, tcpFlags: "PSH ACK", appProtocol: "HTTP", appPayloadConfirmed: true, httpMethod: "GET" }),
      makePacket({ num: 2, timestamp: 1000001, dstIp: "8.8.8.8", dstPort: 80, tcpFlags: "ACK", appProtocol: "HTTP" }),
    ]
    const f = run(packets).flows[0]
    expect(f.protocolSource).toBe("payload")
    expect(f.appProtocol).toBe("HTTP")
  })

  it("bare transport with no app label is transport_only", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, timestamp: 1000000, dstIp: "8.8.8.8", dstPort: 3389, tcpFlags: "SYN" }),
    ]
    const f = run(packets).flows[0]
    expect(f.protocolSource).toBe("transport_only")
    expect(f.appProtocol).toBeUndefined()
  })

  it("a payload-confirmed label wins over port-inferred labels in a mixed flow", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, timestamp: 1000000, dstIp: "8.8.8.8", dstPort: 80, tcpFlags: "SYN", appProtocol: "HTTP" }),
      makePacket({ num: 2, timestamp: 1000001, dstIp: "8.8.8.8", dstPort: 80, tcpFlags: "PSH ACK", appProtocol: "HTTP", appPayloadConfirmed: true, httpMethod: "POST" }),
    ]
    const f = run(packets).flows[0]
    expect(f.protocolSource).toBe("payload")
  })

  it("packets surface the appPayloadConfirmed flag", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, timestamp: 1000000, dstIp: "8.8.8.8", dstPort: 443, appProtocol: "TLS", appPayloadConfirmed: true, tlsSni: "example.com" }),
    ]
    const a = run(packets)
    expect(a.packets[0].appPayloadConfirmed).toBe(true)
  })
})

describe("TCP state machine — honest handshake states on flows and sessions", () => {
  function run(packets: ParsedPacket[]) {
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

  // Client 192.168.1.1:12345 → server 10.0.0.1:80; reverse for server→client.
  const SYN: ParsedPacket = { ...makePacket(), num: 1, tcpFlags: "SYN" }
  const SYNACK: ParsedPacket = { ...makePacket({ num: 2, timestamp: 1000001, srcIp: "10.0.0.1", dstIp: "192.168.1.1", srcPort: 80, dstPort: 12345 }), tcpFlags: "SYN ACK" }
  const ACK: ParsedPacket = { ...makePacket({ num: 3, timestamp: 1000002 }), tcpFlags: "ACK" }
  const RST: ParsedPacket = { ...makePacket({ num: 4, timestamp: 1000003 }), tcpFlags: "RST" }
  const FIN: ParsedPacket = { ...makePacket({ num: 5, timestamp: 1000004 }), tcpFlags: "FIN ACK" }

  it("SYN only (failed/partial handshake) is INITIATED", () => {
    const a = run([SYN, { ...makePacket({ num: 6, timestamp: 1000005 }), tcpFlags: "SYN" }])
    expect(a.sessions[0].state).toBe("INITIATED")
    expect(a.flows[0].tcpState).toBe("INITIATED")
  })

  it("SYN + SYN-ACK with no completing ACK is HALF_OPEN, not ESTABLISHED", () => {
    const a = run([SYN, SYNACK])
    expect(a.sessions[0].state).toBe("HALF_OPEN")
    expect(a.flows[0].tcpState).toBe("HALF_OPEN")
  })

  it("SYN + SYN-ACK + ACK completes the handshake: ESTABLISHED", () => {
    const a = run([SYN, SYNACK, ACK])
    expect(a.sessions[0].state).toBe("ESTABLISHED")
    expect(a.flows[0].tcpState).toBe("ESTABLISHED")
  })

  it("the final ACK must come AFTER the SYN-ACK (order-sensitive)", () => {
    // ACK seen before the SYN-ACK (out-of-order capture) never completes it.
    const a = run([SYN, ACK, SYNACK])
    expect(a.sessions[0].state).toBe("HALF_OPEN")
  })

  it("RST overrides everything: RESET", () => {
    const a = run([SYN, SYNACK, ACK, RST])
    expect(a.sessions[0].state).toBe("RESET")
  })

  it("clean FIN close is CLOSED", () => {
    const a = run([SYN, SYNACK, ACK, FIN])
    expect(a.sessions[0].state).toBe("CLOSED")
  })

  it("mid-stream capture without a SYN is ESTABLISHED (honest guess)", () => {
    const a = run([ACK, ACK])
    expect(a.sessions[0].state).toBe("ESTABLISHED")
  })

  it("UDP sessions and flows are STATELESS", () => {
    const udp: ParsedPacket = { ...makePacket({ num: 1, protocol: "UDP", tcpFlags: undefined }) }
    const a = run([udp])
    expect(a.sessions[0].state).toBe("STATELESS")
    expect(a.flows[0].tcpState).toBe("STATELESS")
  })

  it("flow and session states always agree (mirror invariant)", () => {
    const a = run([SYN, SYNACK, ACK, FIN])
    for (const f of a.flows) {
      const sess = a.sessions.find((s) => s.srcIp === f.srcIp && s.dstIp === f.dstIp && s.srcPort === f.srcPort && s.dstPort === f.dstPort)
      expect(sess?.state).toBe(f.tcpState)
    }
  })
})

describe("Analysis engine", () => {
  it("analyzes an empty capture", () => {
    const result: PCAPResult = {
      packets: [],
      stats: { totalPackets: 0, totalBytes: 0, duration: 0, startTime: 0, endTime: 0, protocols: {} },
    }
    const analysis = analyzePcap(result)
    expect(analysis.job.totalPackets).toBe(0)
    expect(analysis.packets.length).toBe(0)
    expect(analysis.flows.length).toBe(0)
    expect(analysis.threats.length).toBe(0)
    // EMPTY capture: no time interval -> canonical rates are null (N/A).
    expect(analysis.advancedMetrics.rates.quality).toBe("EMPTY")
    expect(analysis.advancedMetrics.throughputAvg).toBeNull()
    expect(analysis.advancedMetrics.iocs.length).toBe(0)
  })

  it("emits the canonical validator: quality, decode stats, integrity", () => {
    const result: PCAPResult = {
      packets: [],
      stats: { totalPackets: 0, totalBytes: 0, duration: 0, startTime: 0, endTime: 0, protocols: {}, linkTypes: [], decodedPackets: 0 },
    }
    const analysis = analyzePcap(result)
    expect(analysis.schemaVersion).toBeTruthy()
    expect(analysis.validator.schemaVersion).toBe(analysis.schemaVersion)
    expect(analysis.validator.captureQuality).toBe("EMPTY")
    expect(analysis.validator.durationSec).toBeNull()
    expect(analysis.validator.integrity.status).toBe("valid")
    expect(analysis.validator.integrity.truncatedPackets).toBe(0)
    expect(analysis.validator.integrity.malformedPackets).toBe(0)
    expect(analysis.validator.integrity.fileTruncated).toBe(false)
    expect(analysis.validator.decode.decodeRatePct).toBe(100)
  })

  it("validator: truncated integrity status wins over decode issues", () => {
    const packets: ParsedPacket[] = [makePacket({ num: 1, timestamp: 1000000 }), makePacket({ num: 2, timestamp: 1000001 })]
    const analysis = analyzePcap({
      packets,
      stats: {
        totalPackets: 2, totalBytes: 128, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 2 },
        linkTypes: [1], decodedPackets: 1, truncatedPackets: 2, fileTruncated: true,
      },
    })
    expect(analysis.validator.integrity.status).toBe("truncated")
    expect(analysis.validator.integrity.fileTruncated).toBe(true)
    expect(analysis.validator.integrity.truncatedPackets).toBe(2)
    expect(analysis.validator.decode.decodeRatePct).toBe(50)
  })

  it("validator: unsupported link type beats malformed/incomplete", () => {
    const packets: ParsedPacket[] = [makePacket({ num: 1, timestamp: 1000000, length: 64, origLength: 64 })]
    const analysis = analyzePcap({
      packets,
      stats: {
        totalPackets: 1, totalBytes: 64, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { OTHER: 1 },
        linkTypes: [999], decodedPackets: 0, malformedPackets: 0,
      },
    })
    expect(analysis.validator.integrity.status).toBe("unsupported_link_type")
    expect(analysis.validator.integrity.unsupportedLinkTypes).toEqual([999])
  })

  it("validator: malformed frames are their own status on a supported link type", () => {
    const packets: ParsedPacket[] = [makePacket({ num: 1, timestamp: 1000000 })]
    const analysis = analyzePcap({
      packets,
      stats: {
        totalPackets: 1, totalBytes: 64, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 1 },
        linkTypes: [1], decodedPackets: 1, malformedPackets: 3,
      },
    })
    expect(analysis.validator.integrity.status).toBe("malformed")
    expect(analysis.validator.integrity.malformedPackets).toBe(3)
  })

  it("validator: incomplete decode is reported when supported DLTs miss packets", () => {
    const packets: ParsedPacket[] = [makePacket({ num: 1, timestamp: 1000000 }), makePacket({ num: 2, timestamp: 1000001 })]
    const analysis = analyzePcap({
      packets,
      stats: {
        totalPackets: 2, totalBytes: 128, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 2 },
        linkTypes: [1], decodedPackets: 1,
      },
    })
    expect(analysis.validator.integrity.status).toBe("incomplete_decode")
  })

  it("validator: valid capture keeps valid status and full decode", () => {
    const packets: ParsedPacket[] = [makePacket({ num: 1, timestamp: 1000000 }), makePacket({ num: 2, timestamp: 1000001 })]
    const analysis = analyzePcap({
      packets,
      stats: {
        totalPackets: 2, totalBytes: 128, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 2 },
        linkTypes: [1], decodedPackets: 2,
      },
    })
    expect(analysis.validator.integrity.status).toBe("valid")
    expect(analysis.validator.integrity.unsupportedLinkTypes).toEqual([])
    expect(analysis.validator.captureQuality).toBe("VALID")
  })

  it("detects port scans from TCP SYN probes", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 21; i++) {
      packets.push(makePacket({ num: i + 1, dstPort: 1000 + i, tcpFlags: "SYN" }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 10, startTime: 1000000, endTime: 1000010, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.threats.length).toBeGreaterThan(0)
    expect(analysis.threats[0].signature).toBe("Port Scan Detected")
  })

  it("derives device hostnames from DNS answers in the capture", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcIp: "10.0.0.5", dstIp: "10.0.0.1", dnsAnswers: [{ name: "router.lan", ip: "10.0.0.1" }] }),
      makePacket({ num: 2, srcIp: "10.0.0.9", dstIp: "10.0.0.5", dnsAnswers: [{ name: "phone.lan", ip: "10.0.0.9" }] }),
      makePacket({ num: 3, srcIp: "10.0.0.9", dstIp: "10.0.0.5" }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 10, startTime: 1000000, endTime: 1000010, protocols: { UDP: packets.length } },
    }
    const analysis = analyzePcap(result)
    const byIp = new Map(analysis.devices.map((d) => [d.ip, d]))
    expect(byIp.get("10.0.0.1")?.hostname).toBe("router.lan")
    expect(byIp.get("10.0.0.9")?.hostname).toBe("phone.lan")
    expect(byIp.get("10.0.0.5")?.hostname).toBe("10.0.0.5")
  })

  it("enriches device vendors from the bundled OUI table", () => {
    const packets: ParsedPacket[] = [makePacket({ num: 1, srcIp: "10.0.0.5", dstIp: "10.0.0.1", srcMac: "8c:90:2d:ca:b4:d5" })]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    const enriched = enrichDeviceVendors(analysis.devices)
    expect(enriched.find((d) => d.ip === "10.0.0.5")?.vendor).toContain("TP-Link")
  })

  it("calculates throughput", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 10; i++) {
      // WAN crossing (private→public): throughput is the LAN↔internet rate;
      // LAN↔LAN chatter is not internet throughput and must not inflate it.
      packets.push(makePacket({ num: i + 1, timestamp: 1000000 + i, length: 1000, dstIp: "8.8.8.8", dstPort: 443 }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 10, startTime: 1000000, endTime: 1000010, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.advancedMetrics.throughputAvg).toBeGreaterThan(0)
  })

  it("detects data exfiltration", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 5; i++) {
      packets.push(makePacket({ num: i + 1, srcIp: "192.168.1.1", dstIp: "203.0.113.5", length: 50000 }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 10, startTime: 1000000, endTime: 1000010, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.advancedMetrics.dataExfiltrationSuspected).toBe(true)
  })

  it("maps MITRE techniques for port scans", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 21; i++) {
      packets.push(makePacket({ num: i + 1, dstPort: 1000 + i, tcpFlags: "SYN" }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 10, startTime: 1000000, endTime: 1000010, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.advancedMetrics.mitreMappings.some(m => m.id === "T1046")).toBe(true)
  })

  it("calculates risk score with advanced metrics", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 21; i++) {
      packets.push(makePacket({ num: i + 1, dstPort: 1000 + i, tcpFlags: "SYN" }))
    }
    for (let i = 0; i < 5; i++) {
      packets.push(makePacket({ num: 16 + i, srcIp: "192.168.1.1", dstIp: "203.0.113.5", length: 50000 }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 10, startTime: 1000000, endTime: 1000010, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.job.riskScore).toBeGreaterThan(0)
  })

  it("port scan evidence lists probed ports, SYN/RST/FIN and window", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 24; i++) {
      packets.push(makePacket({
        num: i + 1,
        dstPort: 1000 + i,
        tcpFlags: "SYN",
        timestamp: 1000000 + i,
      }))
    }
    for (let i = 0; i < 3; i++) {
      packets.push(makePacket({ num: 30 + i, dstPort: 1000 + i, tcpFlags: "RST", timestamp: 1000030 + i }))
    }
    packets.push(makePacket({ num: 40, dstPort: 1005, tcpFlags: "RST,FIN", timestamp: 1000040 }))
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 41, startTime: 1000000, endTime: 1000041, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    const scan = analysis.threats.find((t) => t.signature === "Port Scan Detected")
    expect(scan).toBeDefined()
    expect(scan!.evidence).toContain("24 ports")
    expect(scan!.evidence).toContain("24 SYN, 4 RST, 1 FIN")
    expect(scan!.evidence).toContain("e.g. 1000, 1001")
    expect(scan!.timestamp).toBe(new Date(1000040 * 1000).toISOString())
  })

  it("does NOT flag UDP-only traffic to many ports as a port scan", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 28; i++) {
      packets.push(makePacket({ num: i + 1, protocol: "UDP", dstPort: 4000 + i, timestamp: 1000000 + i, tcpFlags: undefined }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 28, startTime: 1000000, endTime: 1000028, protocols: { UDP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.threats.some((t) => t.ruleId === "PORT-SCAN-001")).toBe(false)
  })

  it("does NOT flag ordinary dotted DNS queries as tunneling", () => {
    const packets: ParsedPacket[] = []
    const names = ["www.google.com", "api.github.com", "clientservices.googleapis.com", "login.microsoftonline.com", "edge.microsoft.com"]
    for (let i = 0; i < 30; i++) {
      packets.push(makePacket({ num: i + 1, protocol: "UDP", dstPort: 53, timestamp: 1000000 + i * 2, dnsQuery: names[i % names.length] }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 60, startTime: 1000000, endTime: 1000060, protocols: { UDP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.advancedMetrics.dnsTunnelingSuspected).toBe(false)
    expect(analysis.threats.some((t) => t.ruleId === "DNS-TUNNEL-001")).toBe(false)
  })

  it("flags tunneling-like DNS queries and stamps the alert with capture end", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 6; i++) {
      packets.push(makePacket({
        num: i + 1, protocol: "UDP", dstPort: 53, timestamp: 1000000 + i,
        dnsQuery: `${"q8zXw3kL".repeat(6).slice(0, 45)}.tunnel.example.com`,
      }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 5, startTime: 1000000, endTime: 1000005, protocols: { UDP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.advancedMetrics.dnsTunnelingSuspected).toBe(true)
    const alert = analysis.threats.find((t) => t.ruleId === "DNS-TUNNEL-001")
    expect(alert).toBeDefined()
    expect(alert!.evidence).toContain("6 tunneling-like queries")
    expect(alert!.timestamp).toBe(new Date(1000005 * 1000).toISOString())
  })

  it("does NOT flag one sustained connection as beaconing", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 20; i++) {
      packets.push(makePacket({ num: i + 1, dstIp: "203.0.113.9", dstPort: 443, timestamp: 1000000 + i * 2, length: 1200 }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 40, startTime: 1000000, endTime: 1000040, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.advancedMetrics.beaconDetected).toBe(false)
  })

  it("flags a regular connection cadence to one host as beaconing", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 6; i++) {
      packets.push(makePacket({ num: i + 1, srcPort: 40000 + i, dstIp: "203.0.113.9", dstPort: 443, timestamp: 1000000 + i * 5, length: 800 }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 30, startTime: 1000000, endTime: 1000030, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.advancedMetrics.beaconDetected).toBe(true)
    const alert = analysis.threats.find((t) => t.ruleId === "C2-BEACON-001")
    expect(alert).toBeDefined()
    expect(alert!.evidence).toContain("6 connections to 203.0.113.9:443")
    expect(alert!.evidence).toContain("CV 0.000")
    expect(alert!.timestamp).toBe(new Date(1000025 * 1000).toISOString())
  })

  it("assigns MACs only to private IPs (public IPs show the router, not a device)", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcMac: "aa:bb:cc:dd:ee:ff", srcIp: "192.168.1.5", dstIp: "8.8.8.8", dstPort: 443 }),
      makePacket({ num: 2, srcIp: "192.168.1.5", dstIp: "8.8.8.8", dstPort: 443, srcMac: "aa:bb:cc:dd:ee:ff" }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    const local = analysis.devices.find((d) => d.ip === "192.168.1.5")
    const remote = analysis.devices.find((d) => d.ip === "8.8.8.8")
    expect(local?.mac).toBe("aa:bb:cc:dd:ee:ff")
    expect(remote?.mac).toBe("\u2014")
  })

  it("does NOT flag STUN keepalive cadence as beaconing", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 6; i++) {
      packets.push(makePacket({ num: i + 1, protocol: "UDP", srcPort: 40000 + i, dstIp: "203.0.113.9", dstPort: 3478, timestamp: 1000000 + i * 5, length: 120 }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 30, startTime: 1000000, endTime: 1000030, protocols: { UDP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.advancedMetrics.beaconDetected).toBe(false)
    expect(analysis.threats.find((t) => t.ruleId === "C2-BEACON-001")).toBeUndefined()
  })

  it("does NOT flag SSDP multicast discovery chatter as beaconing", () => {
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 6; i++) {
      packets.push(makePacket({ num: i + 1, protocol: "UDP", srcPort: 30000 + i, dstIp: "239.255.255.250", dstPort: 1900, timestamp: 1000000 + i * 5, length: 300 }))
    }
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 30, startTime: 1000000, endTime: 1000030, protocols: { UDP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.advancedMetrics.beaconDetected).toBe(false)
  })

  it("merges v4+v6 of one NIC into a single device and skips multicast", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcMac: "aa:bb:cc:dd:ee:ff", srcIp: "192.168.1.5", dstIp: "8.8.8.8" }),
      makePacket({ num: 2, srcMac: "aa:bb:cc:dd:ee:ff", srcIp: "fd00::5", dstIp: "8.8.8.8" }),
      makePacket({ num: 3, srcMac: "aa:bb:cc:dd:ee:ff", srcIp: "192.168.1.5", dstIp: "239.255.255.250", dstPort: 1900 }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 10, startTime: 1000000, endTime: 1000010, protocols: { UDP: packets.length } },
    }
    const analysis = analyzePcap(result)
    const merged = analysis.devices.filter((d) => d.mac === "aa:bb:cc:dd:ee:ff")
    expect(merged.length).toBe(1)
    expect(merged[0].packets).toBe(3)
    expect(merged[0].addresses).toContain("fd00::5")
    expect(analysis.devices.some((d) => d.ip === "239.255.255.250")).toBe(false)
  })

  it("does not double-count retransmissions as out-of-order (pure-loss flow)", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, protocol: "TCP", srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 5000, dstPort: 443, timestamp: 1000000, tcpFlags: "ACK", tcpSeq: 100, tcpPayloadLen: 100, tcpWin: 65535 }),
      makePacket({ num: 2, protocol: "TCP", srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 5000, dstPort: 443, timestamp: 1000001, tcpFlags: "ACK", tcpSeq: 100, tcpPayloadLen: 100, tcpWin: 65535 }),
      makePacket({ num: 3, protocol: "TCP", srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 5000, dstPort: 443, timestamp: 1000002, tcpFlags: "ACK", tcpSeq: 200, tcpPayloadLen: 100, tcpWin: 65535 }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 2, startTime: 1000000, endTime: 1000002, protocols: { TCP: packets.length } },
    }
    const flow = analyzePcap(result).flows.find((f) => f.protocol === "TCP")
    expect(flow!.retrans).toBe(1)
    expect(flow!.ooo).toBe(0)
  })

  it("does not count RSTs (window 0) as zero-window advertisements", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, protocol: "TCP", srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 5000, dstPort: 443, timestamp: 1000000, tcpFlags: "RST", tcpWin: 0 }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 0, startTime: 1000000, endTime: 1000000, protocols: { TCP: packets.length } },
    }
    const flow = analyzePcap(result).flows.find((f) => f.protocol === "TCP")
    expect(flow!.rstCount).toBe(1)
    expect(flow!.zeroWindow).toBe(0)
  })

  it("counts a self-addressed packet once per device (gratuitous ARP / DAD)", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, protocol: "ARP", srcIp: "192.168.1.5", dstIp: "192.168.1.5", timestamp: 1000000, length: 60 }),
      makePacket({ num: 2, protocol: "ARP", srcIp: "192.168.1.5", dstIp: "192.168.1.5", timestamp: 1000001, length: 60 }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 1, startTime: 1000000, endTime: 1000001, protocols: { ARP: packets.length } },
    }
    const dev = analyzePcap(result).devices.find((d) => d.ip === "192.168.1.5")
    expect(dev).toBeDefined()
    expect(dev!.packets).toBe(2)
    expect(dev!.bytes).toBe(120)
  })

  it("computes v3.2 TCP health: retrans, out-of-order, zero-window, RST, RTT, loss", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, protocol: "TCP", srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 5000, dstPort: 443, timestamp: 1000000, tcpFlags: "SYN", tcpSeq: 0, tcpPayloadLen: 0, tcpWin: 65535 }),
      makePacket({ num: 2, protocol: "TCP", srcIp: "8.8.8.8", dstIp: "192.168.1.5", srcPort: 443, dstPort: 5000, timestamp: 1000002, tcpFlags: "SYNACK", tcpSeq: 0, tcpPayloadLen: 0, tcpWin: 65535 }),
      makePacket({ num: 3, protocol: "TCP", srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 5000, dstPort: 443, timestamp: 1000003, tcpFlags: "ACK", tcpSeq: 100, tcpPayloadLen: 100, tcpWin: 65535 }),
      makePacket({ num: 4, protocol: "TCP", srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 5000, dstPort: 443, timestamp: 1000004, tcpFlags: "ACK", tcpSeq: 100, tcpPayloadLen: 100, tcpWin: 65535 }),
      makePacket({ num: 5, protocol: "TCP", srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 5000, dstPort: 443, timestamp: 1000005, tcpFlags: "ACK", tcpSeq: 300, tcpPayloadLen: 100, tcpWin: 65535 }),
      makePacket({ num: 6, protocol: "TCP", srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 5000, dstPort: 443, timestamp: 1000006, tcpFlags: "ACK", tcpSeq: 200, tcpPayloadLen: 50, tcpWin: 0 }),
      makePacket({ num: 7, protocol: "TCP", srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 5000, dstPort: 443, timestamp: 1000007, tcpFlags: "RST", tcpWin: 65535 }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 7, startTime: 1000000, endTime: 1000007, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    const flow = analysis.flows.find((f) => f.protocol === "TCP")
    expect(flow).toBeDefined()
    expect(flow!.retrans).toBe(1)
    expect(flow!.ooo).toBe(1)
    expect(flow!.zeroWindow).toBe(1)
    expect(flow!.rstCount).toBe(1)
    expect(flow!.rttMs).toBe(2000)
    expect(flow!.lossPct).toBe(25) // 1 retrans / 4 data segments
  })

  it("calibration: SSDP/mDNS/STUN-only capture stays SAFE", () => {
    const packets: ParsedPacket[] = []
    let n = 0
    for (let i = 0; i < 6; i++) packets.push(makePacket({ num: ++n, protocol: "UDP", srcPort: 40000 + i, dstIp: "203.0.113.9", dstPort: 3478, timestamp: 1000000 + i * 5, length: 120 }))
    for (let i = 0; i < 6; i++) packets.push(makePacket({ num: ++n, protocol: "UDP", srcPort: 30000 + i, dstIp: "239.255.255.250", dstPort: 1900, timestamp: 1000000 + i * 5, length: 300 }))
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 30, startTime: 1000000, endTime: 1000030, protocols: { UDP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.advancedMetrics.beaconDetected).toBe(false)
    expect(analysis.job.riskScore).toBeLessThan(20)
  })

  it("records the real IP TTL instead of a hardcoded 64", () => {
    const result: PCAPResult = {
      packets: [makePacket({ num: 1, ttl: 128 })],
      stats: { totalPackets: 1, totalBytes: 64, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 1 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.packets[0].ttl).toBe(128)
  })

  it("relative Seq rebases EACH direction on its own first segment (server side too)", () => {
    // Client SYN (seq 1000) -> server SYN-ACK (seq 8000) -> server data (8010).
    // The server side must read Seq=0/Seq=10 against ITS SYN-ACK, never raw
    // 8000/8010 or values subtracted from the client's SYN (QA: Seq=834237805).
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcIp: "192.168.1.5", dstIp: "8.8.8.8", srcPort: 50000, dstPort: 443, tcpFlags: "SYN", tcpSeq: 1000, tcpPayloadLen: 0 }),
      makePacket({ num: 2, srcIp: "8.8.8.8", dstIp: "192.168.1.5", srcPort: 443, dstPort: 50000, tcpFlags: "SYN,ACK", tcpSeq: 8000, tcpPayloadLen: 0 }),
      makePacket({ num: 3, srcIp: "8.8.8.8", dstIp: "192.168.1.5", srcPort: 443, dstPort: 50000, tcpFlags: "ACK,PSH", tcpSeq: 8010, tcpPayloadLen: 500 }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 3, totalBytes: 192, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 3 } },
    }
    const analysis = analyzePcap(result)
    const infos = analysis.packets.map((p) => p.info)
    expect(infos[0]).toContain("Seq=0")
    expect(infos[1]).toContain("Seq=0")
    expect(infos[2]).toContain("Seq=10")
  })

  it("DNS rows carry the question type and the answer TTL (D3)", () => {
    const result: PCAPResult = {
      packets: [
        makePacket({ num: 1, protocol: "UDP", dstPort: 53, dnsQuery: "example.com", dnsQtype: 1 }),
        makePacket({ num: 2, protocol: "UDP", dstPort: 53, dnsQuery: "example.com", dnsQtype: 1, dnsQr: true, dnsRcode: 3, dnsTtl: 3600 }),
      ],
      stats: { totalPackets: 2, totalBytes: 128, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { UDP: 2 } },
    }
    const analysis = analyzePcap(result)
    const [q, r] = analysis.dns
    expect(q.type).toBe("A")
    // Queries carry no answer record, so no TTL exists — null, not a
    // fabricated 0 (the DNS page renders "—" instead of "0s").
    expect(q.ttl).toBeNull()
    expect(r.type).toBe("A")
    expect(r.ttl).toBe(3600)
    expect(r.responseCode).toBe("NXDOMAIN")
  })

  it("session states come from the observed TCP handshake (A5)", () => {
    const base = makePacket({ num: 1, dstPort: 443 })
    const result: PCAPResult = {
      packets: [
        { ...base, tcpFlags: "SYN", dstPort: 443 },
        { ...base, tcpFlags: "SYN,ACK", dstPort: 443 },
        { ...base, tcpFlags: "ACK", dstPort: 443 },
        { ...base, tcpFlags: "SYN,ACK", dstPort: 444 },
        { ...base, tcpFlags: "SYN", dstPort: 445 },
        { ...base, tcpFlags: "SYN", dstPort: 445 },
        { ...base, tcpFlags: "SYN", dstPort: 446 },
        { ...base, tcpFlags: "RST", dstPort: 446 },
        { ...base, protocol: "UDP", dstPort: 53, tcpFlags: undefined },
      ],
      stats: { totalPackets: 9, totalBytes: 576, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 8, UDP: 1 } },
    }
    const analysis = analyzePcap(result)
    // Flow direction follows IP sort order, not the client's — key by the
    // non-ephemeral endpoint port (the port that is not the client's 12345).
    const stateByPort = new Map<number, string>()
    for (const s of analysis.sessions) {
      const p = s.srcPort === 12345 ? s.dstPort : s.srcPort
      stateByPort.set(p, s.state)
    }
    expect(stateByPort.get(443)).toBe("ESTABLISHED")
    expect(stateByPort.get(444)).toBe("HALF_OPEN")
    expect(stateByPort.get(445)).toBe("INITIATED")
    expect(stateByPort.get(446)).toBe("RESET")
    expect(stateByPort.get(53)).toBe("STATELESS")
  })

  it("a host keeps its own MAC even when frames TO it carry the router's (E4)", () => {
    const result: PCAPResult = {
      packets: [
        makePacket({ num: 1, srcMac: "aa:bb:cc:dd:ee:01", srcIp: "192.168.1.20", dstIp: "192.168.1.1", dstMac: "aa:bb:cc:dd:ee:02" }),
        makePacket({ num: 2, srcMac: "aa:bb:cc:dd:ee:02", srcIp: "192.168.1.1", dstIp: "192.168.1.20", dstMac: "aa:bb:cc:dd:ee:01" }),
      ],
      stats: { totalPackets: 2, totalBytes: 128, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 2 } },
    }
    const analysis = analyzePcap(result)
    const host = analysis.devices.find((d) => d.ip === "192.168.1.20")
    const gw = analysis.devices.find((d) => d.ip === "192.168.1.1")
    expect(host?.mac).toBe("aa:bb:cc:dd:ee:01")
    expect(gw?.mac).toBe("aa:bb:cc:dd:ee:02")
    expect(analysis.devices.length).toBe(2)
  })

  it("a public IPv6 never shows the LAN/gateway MAC even when frames carry it (reviewer Meta)", () => {
    const v6 = "2a03:2880:f312:120::167"
    const packets: ParsedPacket[] = [
      // Two different LAN interfaces source the same public /64 — by the old
      // homePrefix rule that made 2a03:2880:f312:120 "local" and attached the
      // LAN MAC to Meta's device row. It is still a remote endpoint.
      makePacket({ num: 1, srcMac: "aa:bb:cc:dd:ee:01", srcIp: "192.168.1.20", dstIp: "8.8.8.8" }),
      makePacket({ num: 2, srcMac: "aa:bb:cc:dd:ee:02", srcIp: v6, dstIp: "192.168.1.20" }),
      makePacket({ num: 3, srcMac: "aa:bb:cc:dd:ee:01", srcIp: v6, dstIp: "192.168.1.14" }),
      makePacket({ num: 4, srcMac: "aa:bb:cc:dd:ee:01", srcIp: "192.168.1.20", dstIp: v6 }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    const remote = analysis.devices.find((d) => d.ip === v6)
    expect(remote?.mac).toBe("\u2014")
    // Sanity: the local v4 host still keeps its own MAC.
    expect(analysis.devices.find((d) => d.ip === "192.168.1.20")?.mac).toBe("aa:bb:cc:dd:ee:01")
  })

  it("subnet broadcast and zero-IPv6 destinations are not devices or external IPs (E3/E5)", () => {
    const result: PCAPResult = {
      packets: [
        makePacket({ num: 1, srcIp: "192.168.1.5", dstIp: "192.168.1.255", protocol: "UDP", dstPort: 68, tcpFlags: undefined }),
        makePacket({ num: 2, srcIp: "192.168.1.5", dstIp: "::", protocol: "IPv6", dstPort: 0, tcpFlags: undefined }),
        makePacket({ num: 3, srcIp: "192.168.1.5", dstIp: "8.8.8.8", dstPort: 53, protocol: "UDP", tcpFlags: undefined }),
      ],
      stats: { totalPackets: 3, totalBytes: 192, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { UDP: 2, IPv6: 1 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.devices.some((d) => d.ip === "192.168.1.255")).toBe(false)
    expect(analysis.devices.some((d) => d.ip === "::")).toBe(false)
    expect(analysis.job.externalIps).toBe(1)
  })

  it("folds a delegated home-prefix IPv6 into the private host and keeps it out of External (QA calls.pcap)", () => {
    const v6 = "2401:4900:1:2::308f"
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcMac: "aa:bb:cc:dd:ee:01", srcIp: "192.168.1.20", dstIp: "8.8.8.8" }),
      makePacket({ num: 2, srcMac: "aa:bb:cc:dd:ee:01", srcIp: v6, dstIp: "8.8.8.8" }),
      // Router's own v6 in the same /64 — a SECOND LAN interface sources it,
      // so the /64 is the LAN's delegated prefix, not a remote server.
      makePacket({ num: 3, srcMac: "aa:bb:cc:dd:ee:02", srcIp: "2401:4900:1:2::1", dstIp: "8.8.8.8" }),
      // Router forwards INTO the client's own v6 — that v6 is an alias of
      // 192.168.1.20, so it must not count as an external peer either.
      makePacket({ num: 4, srcMac: "aa:bb:cc:dd:ee:02", srcIp: "192.168.1.1", dstIp: v6 }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.devices.some((d) => d.ip === v6)).toBe(false)
    const host = analysis.devices.find((d) => d.ip === "192.168.1.20")
    expect(host?.addresses).toContain(v6)
    // Only 8.8.8.8 is a real external destination; the client's own v6 and
    // the router's v6 are LAN aliases.
    expect(analysis.job.externalIps).toBe(1)
  })

  it("merges the router's v4, link-local and delegated v6 into ONE device on the ARP sender MAC (QA: Devices 5 vs 4)", () => {
    const fe80 = "fe80::bad1:cafe:1"
    const routerV6 = "2401:4900:1:2::1"
    const clientV6 = "2401:4900:1:2::308f"
    const routerMac = "aa:bb:cc:dd:ee:02"
    const clientMac = "aa:bb:cc:dd:ee:01"
    const result: PCAPResult = {
      packets: [
        // Router's own ARP: the ETHERNET header carries no MAC (capture
        // quirk), but the ARP payload's sender-MAC is the hard identity.
        makePacket({ num: 1, srcIp: "192.168.1.1", dstIp: "192.168.1.20", protocol: "ARP", appProtocol: "ARP-Request", tcpFlags: undefined, arpSenderMac: routerMac }),
        makePacket({ num: 2, srcMac: clientMac, srcIp: "192.168.1.20", dstIp: "8.8.8.8" }),
        // Same interface speaks link-local IPv6 (NDP) and the delegated
        // global v6 — all three addresses are the same NIC.
        makePacket({ num: 3, srcMac: routerMac, srcIp: fe80, dstIp: "ff02::1:2" }),
        makePacket({ num: 4, srcMac: routerMac, srcIp: routerV6, dstIp: "8.8.8.8" }),
        // The client's own v6 in the same /64: two LAN interfaces source the
        // prefix, so it is the LAN's delegated /64 (home-prefix folding).
        makePacket({ num: 5, srcMac: clientMac, srcIp: clientV6, dstIp: "8.8.8.8" }),
      ],
      stats: { totalPackets: 5, totalBytes: 320, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { ARP: 1, TCP: 4 } },
    }
    const analysis = analyzePcap(result)
    const router = analysis.devices.find((d) => d.ip === "192.168.1.1")
    const client = analysis.devices.find((d) => d.ip === "192.168.1.20")
    const remote = analysis.devices.find((d) => d.ip === "8.8.8.8")
    expect(analysis.devices.length).toBe(3) // router + client + remote peer
    expect(router).toBeTruthy()
    expect(router?.mac).toBe(routerMac) // identity came from the ARP payload
    expect(router?.addresses).toEqual(expect.arrayContaining([fe80, routerV6]))
    // Invariant: a device never mixes another endpoint's addresses in.
    expect(router?.addresses).toEqual(expect.not.arrayContaining(["192.168.1.20", clientV6, "8.8.8.8"]))
    expect(client?.addresses).toContain(clientV6)
    expect(client?.addresses).toEqual(expect.not.arrayContaining([fe80, routerV6, "8.8.8.8"]))
    expect(remote?.mac).toBe("\u2014")
  })

  it("ARP sender MAC never folds a private host into a remote's row (no private+public mix)", () => {
    const result: PCAPResult = {
      packets: [
        // A rogue/relayed ARP claims 192.168.1.99 with the ROUTER's MAC — the
        // sender MAC alone must not merge the private host into the router,
        // and the remote peer must stay MAC-less.
        makePacket({ num: 1, srcIp: "192.168.1.99", dstIp: "192.168.1.1", protocol: "ARP", appProtocol: "ARP-Request", tcpFlags: undefined, arpSenderMac: "aa:bb:cc:dd:ee:02" }),
        makePacket({ num: 2, srcIp: "192.168.1.99", dstIp: "8.8.8.8" }),
        makePacket({ num: 3, srcIp: "203.0.113.9", dstIp: "192.168.1.99" }),
      ],
      stats: { totalPackets: 3, totalBytes: 192, duration: 1, startTime: 1000000, endTime: 1000001, protocols: { ARP: 1, TCP: 2 } },
    }
    const analysis = analyzePcap(result)
    const host = analysis.devices.find((d) => d.ip === "192.168.1.99")
    const remote = analysis.devices.find((d) => d.ip === "203.0.113.9")
    expect(host?.mac).toBe("aa:bb:cc:dd:ee:02")
    expect(remote).toBeTruthy()
    // The remote peer never inherits the LAN MAC, and the private host never
    // gains the remote's address.
    expect(remote?.mac).toBe("\u2014")
    expect(host?.addresses ?? []).toEqual(expect.not.arrayContaining(["203.0.113.9"]))
  })

  it("undecodable packets form one direction-unknown flow with no fabricated bytes (QA large/verylarge)", () => {
    const undecodable = (n: number, length: number): ParsedPacket => ({
      num: n, timestamp: 1000000 + n, length, origLength: length,
      srcIp: undefined, dstIp: undefined, srcPort: 0, dstPort: 0,
      protocol: "OTHER", tcpFlags: undefined, payload: "",
    })
    const result: PCAPResult = {
      packets: [undecodable(1, 100), undecodable(2, 200), undecodable(3, 300)],
      stats: { totalPackets: 3, totalBytes: 600, duration: 1, startTime: 1000001, endTime: 1000003, protocols: { OTHER: 3 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.flows).toHaveLength(1)
    const f = analysis.flows[0]
    expect(f.srcIp).toBe("\u2014")
    expect(f.protocol).toBe("OTHER")
    expect(f.directionUnknown).toBe(true)
    expect(f.bytesSent).toBe(0)
    expect(f.bytesRecv).toBe(0)
    expect(f.bytesTotal).toBe(600)
  })

  it("decoded flows stay directional in a mixed capture; undecodable ones stay unknown", () => {
    const result: PCAPResult = {
      packets: [
        makePacket({ num: 1, tcpFlags: "SYN" }),
        makePacket({ num: 2, srcIp: undefined, dstIp: undefined, srcPort: 0, dstPort: 0, protocol: "OTHER", tcpFlags: undefined }),
      ],
      stats: { totalPackets: 2, totalBytes: 128, duration: 1, startTime: 1000000, endTime: 1000002, protocols: { TCP: 1, OTHER: 1 } },
    }
    const analysis = analyzePcap(result)
    const tcp = analysis.flows.find((f) => f.protocol === "TCP")
    expect(tcp).toBeDefined()
    expect(tcp!.directionUnknown).toBeFalsy()
    // deriveFlows normalizes direction by IP order: 10.0.0.1 < 192.168.1.1,
    // so the 192.168.1.1→10.0.0.1 packet is the received leg.
    expect(tcp!.bytesSent).toBe(0)
    expect(tcp!.bytesRecv).toBe(64)
    const other = analysis.flows.find((f) => f.protocol === "OTHER")
    expect(other).toBeDefined()
    expect(other!.directionUnknown).toBe(true)
    expect(other!.bytesSent).toBe(0)
    expect(other!.bytesRecv).toBe(0)
  })

  // ── v3.2 QA regressions (F-04 fixes) ───────────────────────────────────

  it("self-IP flows (ARP srcIp == dstIp) count each packet once; sub-second durations survive", () => {
    // 84-byte ARP self-flow: the old sent/recv filters matched both legs and
    // emitted 84 sent + 84 recv for a 84-byte total (QA: ARP byte-total
    // audit). Direction is meaningless for a self-flow — Rust attributes all
    // bytes to the "orig" side; the web must match (sent=total, recv=0).
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcIp: "192.168.1.17", dstIp: "192.168.1.17", srcPort: 0, dstPort: 0, protocol: "ARP", tcpFlags: undefined, timestamp: 1000000 }),
      makePacket({ num: 2, srcIp: "192.168.1.17", dstIp: "192.168.1.17", srcPort: 0, dstPort: 0, protocol: "ARP", tcpFlags: undefined, timestamp: 1000000.116 }),
    ]
    const result: PCAPResult = { packets, stats: { totalPackets: 2, totalBytes: 128, duration: 1, startTime: 1000000, endTime: 1000116, protocols: { ARP: 2 } } }
    const flow = analyzePcap(result).flows.find((f) => f.protocol === "ARP")
    expect(flow).toBeDefined()
    expect(flow!.bytesTotal).toBe(flow!.bytesSent + flow!.bytesRecv)
    expect(flow!.bytesSent).toBe(flow!.bytesTotal)
    expect(flow!.bytesRecv).toBe(0)
    // 116 ms must export as 0.116 s — Math.round had zeroed sub-second
    // flows, losing packet-analysis precision (QA: durationSec=0 audit).
    expect(flow!.duration).toBe(0.116)
  })

  it("attaches an OS only to the device whose own packets carry it, never to remote endpoints", () => {
    // Client sends its own HTTP with an Android UA; the router forwards
    // one packet (single TTL sample) and the public server only appears as a
    // destination. None of those may inherit the client's OS.
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcIp: "192.168.1.5", dstIp: "93.184.216.34", srcPort: 52000, dstPort: 80, protocol: "TCP", tcpFlags: "PSH ACK", ttl: 64, httpMethod: "GET", httpUri: "/", httpUa: "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/122.0 Mobile" }),
      makePacket({ num: 2, srcIp: "192.168.137.1", dstIp: "93.184.216.34", srcPort: 1, dstPort: 1, protocol: "TCP", tcpFlags: "ACK", ttl: 64 }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 2, startTime: 1000000, endTime: 1000002, protocols: { TCP: packets.length } },
    }
    const analysis = analyzePcap(result)
    const client = analysis.devices.find((d) => d.ip === "192.168.1.5")
    expect(client?.os).toMatch(/Android/i)
    const server = analysis.devices.find((d) => d.ip === "93.184.216.34")
    // Public endpoint: no own UA, TTL fallback is private-only → honest "—".
    expect(server?.os).toBe("")
    const router = analysis.devices.find((d) => d.ip === "192.168.137.1")
    // One forwarded sample is below the ≥2 TTL confidence floor → no claim.
    expect(router?.os).toBe("")
  })

  it("Microsoft-CryptoAPI user agents are Windows (parity with the report's osFromUserAgent)", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcIp: "192.168.1.5", dstIp: "93.184.216.34", srcPort: 52000, dstPort: 443, protocol: "TCP", tcpFlags: "PSH ACK", ttl: 64, httpUa: "Microsoft-CryptoAPI/10.0" }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 1, startTime: 1000000, endTime: 1000001, protocols: { TCP: 1 } },
    }
    const analysis = analyzePcap(result)
    const device = analysis.devices.find((d) => d.ip === "192.168.1.5")
    expect(device?.os).toBe("Windows")
  })

  it("timeline buckets are mutually exclusive: a DNS/TLS packet lands in one slice, never two (QA stacked bars)", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, protocol: "UDP", dstPort: 53, tcpFlags: undefined, dnsQuery: "example.com", dnsQtype: 1, timestamp: 1000000 }),
      makePacket({ num: 2, protocol: "UDP", dstPort: 53, tcpFlags: undefined, dnsQuery: "example.com", dnsQtype: 1, timestamp: 1000100 }),
      makePacket({ num: 3, protocol: "TCP", dstPort: 443, tcpFlags: "SYN", tlsSni: "example.com", timestamp: 1000300 }),
      makePacket({ num: 4, protocol: "TCP", dstPort: 80, tcpFlags: "ACK", timestamp: 1000300 }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: packets.length, totalBytes: packets.reduce((s, p) => s + p.length, 0), duration: 300, startTime: 1000000, endTime: 1000300, protocols: { TCP: 2, UDP: 2 } },
    }
    const timeline = analyzePcap(result).timeline
    const tl = timeline.find((t) => t.dns > 0)
    expect(tl).toMatchObject({ dns: 2, udp: 0, tls: 0, tcp: 0, packets: 2 })
    const tlsBucket = timeline.find((t) => t.tls > 0)
    expect(tlsBucket).toMatchObject({ tls: 1, tcp: 1, dns: 0, udp: 0, packets: 2 })
    // Stacked bars can never overflow a bucket.
    for (const t of timeline) expect(t.tcp + t.udp + t.dns + t.tls).toBeLessThanOrEqual(t.packets)
  })

  it("merges same-MAC addresses only within one L2 surface (same /24, same /64, v4↔v6)", () => {
    const same = (ip1: string, ip2: string) => {
      const packets: ParsedPacket[] = [
        makePacket({ num: 1, srcIp: ip1, dstIp: "10.0.0.1", srcMac: "aa:bb:cc:dd:ee:01" }),
        makePacket({ num: 2, srcIp: ip2, dstIp: "10.0.0.1", srcMac: "aa:bb:cc:dd:ee:01" }),
      ]
      const result: PCAPResult = {
        packets,
        stats: { totalPackets: 2, totalBytes: 128, duration: 1, startTime: 1000000, endTime: 1000002, protocols: { TCP: 2 } },
      }
      return analyzePcap(result).devices
    }
    // Same /24 → one merged row whose aliases include both addresses.
    const merged = same("192.168.1.5", "192.168.1.9").filter((d) => d.mac === "aa:bb:cc:dd:ee:01")
    expect(merged.length).toBe(1)
    expect(merged[0].addresses).toContain("192.168.1.9")
    // Cross-subnet (router bridged 192.168.137.1 and forwarded 192.168.1.10)
    // → two rows: the QA-accepted fix is honesty, not merging across subnets.
    const split = same("192.168.137.1", "192.168.1.10").filter((d) => d.mac === "aa:bb:cc:dd:ee:01")
    expect(split.length).toBe(2)
    // v4 ↔ v6 on the same NIC is one surface (dual-stack).
    const dual = same("192.168.1.5", "fe80::cafe:1234").filter((d) => d.mac === "aa:bb:cc:dd:ee:01")
    expect(dual.length).toBe(1)
  })

  it("pairs RTT against the LAST SYN, so SYN retransmits do not inflate it", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcIp: "10.0.0.5", dstIp: "10.0.0.1", srcPort: 40000, dstPort: 443, timestamp: 1, tcpFlags: "SYN" }),
      // Lost first SYN, retransmitted after the retransmit backoff; a naive
      // first-SYN pairing would claim a ~3 s RTT.
      makePacket({ num: 2, srcIp: "10.0.0.5", dstIp: "10.0.0.1", srcPort: 40000, dstPort: 443, timestamp: 4, tcpFlags: "SYN" }),
      makePacket({ num: 3, srcIp: "10.0.0.1", dstIp: "10.0.0.5", srcPort: 443, dstPort: 40000, timestamp: 4.05, tcpFlags: "SYN ACK" }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 3, totalBytes: 192, duration: 4, startTime: 1, endTime: 4.05, protocols: { TCP: 3 } },
    }
    const analysis = analyzePcap(result)
    const flow = analysis.flows.find((f) => f.srcIp === "10.0.0.5" || f.dstIp === "10.0.0.5")
    expect(flow?.rttMs).toBeDefined()
    expect(flow!.rttMs!).toBeGreaterThanOrEqual(1)
    expect(flow!.rttMs!).toBeLessThanOrEqual(1000)
  })

  it("drops handshakes spanning more than 5 s from the RTT aggregate", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcIp: "10.0.0.5", dstIp: "10.0.0.1", srcPort: 40000, dstPort: 443, timestamp: 1000, tcpFlags: "SYN" }),
      // 6 s gap: capture artifact (backoff), not path RTT.
      makePacket({ num: 2, srcIp: "10.0.0.1", dstIp: "10.0.0.5", srcPort: 443, dstPort: 40000, timestamp: 7000, tcpFlags: "SYN ACK" }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 2, totalBytes: 128, duration: 6, startTime: 1000, endTime: 7000, protocols: { TCP: 2 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.flows.find((f) => f.srcIp === "10.0.0.5" || f.dstIp === "10.0.0.5")?.rttMs).toBeUndefined()
  })

  it("pairs HTTP responses with their requests so status and Content-Type are real", () => {
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcIp: "10.0.0.5", dstIp: "93.184.216.34", srcPort: 52000, dstPort: 80, timestamp: 1000, protocol: "TCP", tcpFlags: "PSH ACK", httpMethod: "GET", httpUri: "/", httpHost: "example.com", httpUa: "curl/8.0" }),
      // Response on the reversed flow.
      makePacket({ num: 2, srcIp: "93.184.216.34", dstIp: "10.0.0.5", srcPort: 80, dstPort: 52000, timestamp: 1010, protocol: "TCP", tcpFlags: "PSH ACK", httpStatus: 200, httpContentType: "text/html; charset=utf-8" }),
      // Second request never answered (missing response half).
      makePacket({ num: 3, srcIp: "10.0.0.5", dstIp: "93.184.216.34", srcPort: 52001, dstPort: 80, timestamp: 1020, protocol: "TCP", tcpFlags: "PSH ACK", httpMethod: "GET", httpUri: "/missing", httpHost: "example.com" }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 3, totalBytes: 192, duration: 2, startTime: 1000, endTime: 1020, protocols: { TCP: 3 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.http.length).toBe(2)
    const answered = analysis.http.find((h) => h.uri === "/")
    expect(answered?.status).toBe(200)
    expect(answered?.contentType).toBe("text/html; charset=utf-8")
    expect(answered?.userAgent).toBe("curl/8.0")
    const unanswered = analysis.http.find((h) => h.uri === "/missing")
    // No response captured → 0 renders as "—", never a faked 200.
    expect(unanswered?.status).toBe(0)
    expect(unanswered?.contentType).toBe("")
  })

  it("derives the certificates list from parsed TLS Certificate handshakes (deduped)", () => {
    const cert = {
      subject: "example.com", issuer: "Test Issuer CA", serial: "01020304",
      notBefore: 1767225600000, notAfter: 1834848000000,
      san: ["example.com", "93.184.216.34"], signatureAlgorithm: "sha256WithRSA", keySize: 2048,
    }
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcIp: "93.184.216.34", dstIp: "10.0.0.5", srcPort: 443, dstPort: 40000, tlsCert: cert }),
      // Same subject+serial in a second handshake → still one row.
      makePacket({ num: 2, srcIp: "93.184.216.34", dstIp: "10.0.0.5", srcPort: 443, dstPort: 40001, tlsCert: cert }),
    ]
    const result: PCAPResult = {
      packets,
      stats: { totalPackets: 2, totalBytes: 128, duration: 1, startTime: 1000000, endTime: 1000002, protocols: { TCP: 2 } },
    }
    const analysis = analyzePcap(result)
    expect(analysis.certificates.length).toBe(1)
    expect(analysis.certificates[0].subject).toBe("example.com")
    expect(analysis.certificates[0].issuer).toBe("Test Issuer CA")
    expect(analysis.certificates[0].serial).toBe("01020304")
    expect(analysis.certificates[0].keySize).toBe(2048)
    expect(analysis.certificates[0].san).toContain("93.184.216.34")
  })
})

describe("Credential extraction (deriveCredentials)", () => {
  const mkResult = (packets: ParsedPacket[]): PCAPResult => ({
    packets,
    stats: {
      totalPackets: packets.length,
      totalBytes: packets.reduce((s, p) => s + p.length, 0),
      duration: 10,
      startTime: 1000000,
      endTime: 1000010,
      protocols: { TCP: packets.length },
    },
  })

  const hex = (s: string): string => Buffer.from(s, "utf8").toString("hex")

  const httpPacket = (payload: string, overrides: Partial<ParsedPacket> = {}): ParsedPacket =>
    makePacket({
      num: 1,
      srcIp: "192.168.1.5",
      dstIp: "100.101.45.41",
      srcPort: 52000,
      dstPort: 80,
      protocol: "TCP",
      tcpFlags: "PSH ACK",
      httpMethod: "GET",
      payload: hex(payload),
      ...overrides,
    })

  it("form-encoded credentials are split on & and percent-decoded", () => {
    const analysis = analyzePcap(mkResult([
      httpPacket('GET /login?username=qudufero&txtPassword=Pa%24%24w0rd%21 HTTP/1.1\r\nHost: example.com\r\n'),
    ]))
    expect(analysis.credentials).toHaveLength(1)
    expect(analysis.credentials[0].username).toBe("qudufero")
    expect(analysis.credentials[0].password).toBe("Pa$$w0rd!")
    expect(analysis.credentials[0].service).toBe("HTTP Form")
  })

  it("real HTTP Basic auth is decoded from the Authorization header", () => {
    const analysis = analyzePcap(mkResult([
      httpPacket('GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcjpzM2NyZXQ=\r\n'),
    ]))
    expect(analysis.credentials).toHaveLength(1)
    expect(analysis.credentials[0].username).toBe("user")
    expect(analysis.credentials[0].password).toBe("s3cret")
    expect(analysis.credentials[0].service).toBe("HTTP Basic")
  })

  it("malformed percent-encoding falls back to the raw value without crashing", () => {
    const analysis = analyzePcap(mkResult([
      httpPacket('GET /login?username=x%zz HTTP/1.1\r\nHost: example.com\r\n'),
    ]))
    expect(analysis.credentials).toHaveLength(1)
    expect(analysis.credentials[0].username).toBe("x%zz")
  })

  it("file MIME types stop at the header boundary (no next-header gluing)", () => {
    // Regression: CR/LF-stripped decoding merged "Content-Type: ...\r\nUser-Agent:"
    // into one token, yielding mime "application/x-www-form-urlencodedUser-Agent:".
    const analysis = analyzePcap(mkResult([
      httpPacket('POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: Mozilla/5.0\r\n\r\na=1'),
      httpPacket('POST /up2 HTTP/1.1\r\nHost: example.com\r\nContent-Disposition: form-data; name="f"; filename=doc.txt\r\nContent-Type: text/plain\r\n\r\nx'),
    ]))
    expect(analysis.files).toHaveLength(2)
    expect(analysis.files[0].mimeType).toBe("application/x-www-form-urlencoded")
    expect(analysis.files[1].mimeType).toBe("text/plain")
    expect(analysis.files[1].filename).toBe("doc.txt")
  })

  it("a plus sign in form data decodes to a space", () => {
    const analysis = analyzePcap(mkResult([
      httpPacket('GET /login?password=a+b HTTP/1.1\r\nHost: example.com\r\n'),
    ]))
    expect(analysis.credentials).toHaveLength(1)
    expect(analysis.credentials[0].password).toBe("a b")
  })

  it("does not treat bypass/compass/surpass keys as passwords", () => {
    const analysis = analyzePcap(mkResult([
      httpPacket('GET /login?bypass=1&username=admin&password=letmein HTTP/1.1\r\nHost: example.com\r\n'),
    ]))
    expect(analysis.credentials).toHaveLength(1)
    expect(analysis.credentials[0].username).toBe("admin")
    expect(analysis.credentials[0].password).toBe("letmein")
  })

  it("keeps one row per request carrying credentials (duplicates are real events)", () => {
    const payload = 'POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=jane&password=secret1'
    const analysis = analyzePcap(mkResult([
      httpPacket(payload, { num: 1, timestamp: 1000 }),
      httpPacket(payload, { num: 2, timestamp: 4000 }),
    ]))
    expect(analysis.credentials).toHaveLength(2)
    expect(analysis.credentials[0].password).toBe("secret1")
    expect(analysis.credentials[1].password).toBe("secret1")
  })

  it("does NOT read credentials from headers (Accept q=0.1 false positive, real capture)", () => {
    // login.pcapng regression: "Accept: text/css,*/*;q=0.1" after User-Agent
    // used to produce a bogus "0.1Sec-GPC:" username row.
    const analysis = analyzePcap(mkResult([
      httpPacket('GET /style.css HTTP/1.1\r\nHost: http-login.badssl.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/css,*/*;q=0.1\r\nDNT: 1\r\n'),
    ]))
    expect(analysis.credentials).toHaveLength(0)
  })

  it("reads txtUsername from the body past a header containing '=' (real capture)", () => {
    // login.pcapng regression: "Cache-Control: max-age=0" used to swallow the
    // first '=' and the username was lost.
    const analysis = analyzePcap(mkResult([
      httpPacket('POST /login/login_results.asp HTTP/1.1\r\nHost: vbsca.ca\r\nCache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: Mozilla/5.0\r\n\r\ntxtUsername=qudufero&txtPassword=Pa%24%24w0rd%21'),
    ]))
    expect(analysis.credentials).toHaveLength(1)
    expect(analysis.credentials[0].username).toBe("qudufero")
    expect(analysis.credentials[0].password).toBe("Pa$$w0rd!")
    expect(analysis.credentials[0].service).toBe("HTTP Form")
  })

  it("parses a body-only segment (headers arrived in a previous packet)", () => {
    const analysis = analyzePcap(mkResult([
      httpPacket('txtUsername=qudufero&txtPassword=secret1'),
    ]))
    expect(analysis.credentials).toHaveLength(1)
    expect(analysis.credentials[0].username).toBe("qudufero")
    expect(analysis.credentials[0].password).toBe("secret1")
  })

  it("ignores multipart/form-data bodies (boundary markers, not & pairs)", () => {
    const analysis = analyzePcap(mkResult([
      httpPacket('POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: multipart/form-data; boundary=xyz\r\n\r\n--xyz\r\nContent-Disposition: form-data; name="username"\r\n\r\nqudufero\r\n--xyz--'),
    ]))
    expect(analysis.credentials).toHaveLength(0)
  })
})

describe("v3.2 QA regression fixes", () => {
  const mkResult = (packets: ParsedPacket[]): PCAPResult => ({
    packets,
    stats: {
      totalPackets: packets.length,
      totalBytes: packets.reduce((s, p) => s + p.length, 0),
      duration: 10,
      startTime: 1000000,
      endTime: 1000010,
      protocols: { TCP: packets.length },
    },
  })

  it("exfil detector: a download (big receive, small send) does NOT fire DATA-EXFIL-001", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = []
    // Client uploads ~1.5 KB (requests/acks) …
    for (let i = 0; i < 5; i++) packets.push(makePacket({ num: i + 1, timestamp: t0 + i, srcIp: "192.168.1.10", dstIp: "198.51.100.7", srcPort: 50000, dstPort: 443, tcpFlags: "ACK", length: 300 }))
    // … and the server pushes ~420 KB back (WhatsApp media style).
    for (let i = 0; i < 300; i++) packets.push(makePacket({ num: 100 + i, timestamp: t0 + 10 + i, srcIp: "198.51.100.7", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000, tcpFlags: "ACK", length: 1400 }))
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.advancedMetrics.dataExfiltrationSuspected).toBe(false)
    expect(analysis.threats.find((t) => t.ruleId === "DATA-EXFIL-001")).toBeUndefined()
  })

  it("exfil detector: a private host SENDING >100 KB outward fires DATA-EXFIL-001 with category Exfiltration", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 150; i++) packets.push(makePacket({ num: i + 1, timestamp: t0 + i, srcIp: "192.168.1.10", dstIp: "198.51.100.7", srcPort: 50000, dstPort: 443, tcpFlags: "ACK", length: 1400 }))
    for (let i = 0; i < 3; i++) packets.push(makePacket({ num: 200 + i, timestamp: t0 + 200 + i, srcIp: "198.51.100.7", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000, tcpFlags: "ACK", length: 300 }))
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.advancedMetrics.dataExfiltrationSuspected).toBe(true)
    const t = analysis.threats.find((t) => t.ruleId === "DATA-EXFIL-001")
    expect(t).toBeDefined()
    expect(t?.category).toBe("Exfiltration")
    expect(t?.evidence).toMatch(/KB sent/)
  })

  it("exfil detector: fires even when the PUBLIC IP sorts first in the flow key (QA: flowKeyOf is lexicographic — 104.x < 192.168.x)", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = []
    // 104.20.1.154 sorts BEFORE 192.168.1.10, so the flow key srcIp is the
    // PUBLIC server — the old isPrivateIp(f.srcIp) gate missed the whole
    // class of captures whose remote IP sorts first (Cloudflare, AWS, Apple).
    for (let i = 0; i < 150; i++) packets.push(makePacket({ num: i + 1, timestamp: t0 + i, srcIp: "192.168.1.10", dstIp: "104.20.1.154", srcPort: 50000, dstPort: 443, tcpFlags: "ACK", length: 1400 }))
    for (let i = 0; i < 3; i++) packets.push(makePacket({ num: 200 + i, timestamp: t0 + 200 + i, srcIp: "104.20.1.154", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000, tcpFlags: "ACK", length: 300 }))
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.advancedMetrics.dataExfiltrationSuspected).toBe(true)
    const t = analysis.threats.find((t) => t.ruleId === "DATA-EXFIL-001")
    expect(t).toBeDefined()
    // Evidence reads private → public regardless of key order
    expect(t?.evidence).toMatch(/192\.168\.1\.10 → 104\.20\.1\.154/)
  })

  it("exfil detector: a LAN-only transfer between private hosts is NEVER exfiltration", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 200; i++) packets.push(makePacket({ num: i + 1, timestamp: t0 + i, srcIp: "192.168.1.10", dstIp: "192.168.1.20", srcPort: 50000, dstPort: 445, tcpFlags: "ACK", length: 1400 }))
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.advancedMetrics.dataExfiltrationSuspected).toBe(false)
    expect(analysis.threats.find((t) => t.ruleId === "DATA-EXFIL-001")).toBeUndefined()
  })

  it("topTalkers includes EXTERNAL IPs (packet-direction attribution, not the private-IP proxy)", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 200; i++) packets.push(makePacket({ num: i + 1, timestamp: t0 + i, srcIp: "172.64.190.1", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000, tcpFlags: "ACK", length: 1400 }))
    for (let i = 0; i < 20; i++) packets.push(makePacket({ num: 300 + i, timestamp: t0 + 300 + i, srcIp: "192.168.1.10", dstIp: "172.64.190.1", srcPort: 50000, dstPort: 443, tcpFlags: "ACK", length: 60 }))
    const analysis = analyzePcap(mkResult(packets))
    const server = analysis.advancedMetrics.topTalkers.find((t) => t.ip === "172.64.190.1")
    const phone = analysis.advancedMetrics.topTalkers.find((t) => t.ip === "192.168.1.10")
    expect(server).toBeDefined()
    expect(server!.packetsOut).toBe(200)
    expect(server!.bytesOut).toBe(200 * 1400)
    expect(server!.packetsIn).toBe(20)
    expect(phone!.packetsIn).toBe(200)
    expect(phone!.packetsOut).toBe(20)
  })

  it("burst direction: LAN chatter must NOT tilt outboundDominant on a download-heavy capture", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = []
    let n = 1
    // Steady small baseline (phone ↔ internet)
    for (let i = 0; i < 60; i++) packets.push(makePacket({ num: n++, timestamp: t0 + i, srcIp: "192.168.1.10", dstIp: "172.64.190.1", srcPort: 50000, dstPort: 443, tcpFlags: "ACK", length: 200 }))
    // Download burst: 3 s of 800 KB/s from the CDN
    for (let s = 0; s < 3; s++) for (let b = 0; b < 80; b++) packets.push(makePacket({ num: n++, timestamp: t0 + 100 + s, srcIp: "172.64.190.1", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000, tcpFlags: "ACK", length: 10000 }))
    // LAN chatter inside the burst window: router DNS replies + ARP (private→private)
    for (let s = 0; s < 3; s++) for (let b = 0; b < 20; b++) packets.push(makePacket({ num: n++, timestamp: t0 + 100 + s, srcIp: "192.168.1.1", dstIp: "192.168.1.10", srcPort: 53, dstPort: 50001, protocol: "UDP", tcpFlags: "", length: 1200 }))
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.advancedMetrics.burst?.detected).toBe(true)
    // The router's LAN replies are not an upload: direction stays download
    expect(analysis.advancedMetrics.burst?.outboundDominant).toBe(false)
  })

  it("packets page: relative TCP Seq is rebased per flow, not a global counter", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, timestamp: t0, srcIp: "192.168.1.10", dstIp: "8.8.8.8", srcPort: 40000, dstPort: 443, tcpFlags: "SYN", tcpSeq: 1000000 }),
      makePacket({ num: 2, timestamp: t0 + 1, srcIp: "8.8.8.8", dstIp: "192.168.1.10", srcPort: 443, dstPort: 40000, tcpFlags: "SYN-ACK", tcpSeq: 5000000 }),
      makePacket({ num: 3, timestamp: t0 + 2, srcIp: "192.168.1.10", dstIp: "8.8.8.8", srcPort: 40000, dstPort: 443, tcpFlags: "ACK", tcpSeq: 1000001 }),
      makePacket({ num: 4, timestamp: t0 + 3, srcIp: "192.168.1.20", dstIp: "9.9.9.9", srcPort: 50000, dstPort: 80, tcpFlags: "SYN", tcpSeq: 9000000 }),
    ]
    const analysis = analyzePcap(mkResult(packets))
    const info = new Map(analysis.packets.map((p) => [p.num, p.info]))
    // Global ordinal would read Seq=3 on the SYN of the second flow.
    expect(info.get(1)).toBe("SYN Seq=0")
    expect(info.get(3)).toBe("ACK Seq=1")
    expect(info.get(4)).toBe("SYN Seq=0")
    // EACH direction rebases on its own first segment: the server's SYN-ACK
    // starts the server seq-space at 0, never raw 5000000 or 4000000 (old QA).
    expect(info.get(2)).toBe("SYN-ACK Seq=0")
  })

  it("cipher suite joins the ServerHello to its SNI handshake row", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, timestamp: t0, srcIp: "192.168.1.10", dstIp: "93.184.216.34", srcPort: 50000, dstPort: 443, tlsSni: "example.com" }),
      makePacket({ num: 2, timestamp: t0 + 1, srcIp: "93.184.216.34", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000, tcpFlags: "ACK", tlsCipherSuite: 0x1301 }),
    ]
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.tls.length).toBe(1)
    expect(analysis.tls[0].cipherSuite).toBe("TLS_AES_128_GCM_SHA256")
  })

  it("negotiated 0x13xx suite forces TLSv1.3 despite a 0x0303 legacy ClientHello (QA: TLS_AES_256_GCM_SHA384 read as TLSv1.2)", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, timestamp: t0, srcIp: "192.168.1.10", dstIp: "93.184.216.34", srcPort: 50000, dstPort: 443, tlsSni: "www.wireshark.org", tlsVersion: 0x0303 }),
      makePacket({ num: 2, timestamp: t0 + 1, srcIp: "93.184.216.34", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000, tcpFlags: "ACK", tlsCipherSuite: 0x1302 }),
    ]
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.tls.length).toBe(1)
    expect(analysis.tls[0].version).toBe("TLSv1.3")
    expect(analysis.tls[0].cipherSuite).toBe("TLS_AES_256_GCM_SHA384")
    expect(analysis.devices.find((d) => d.ip === "93.184.216.34")?.hostname).toBe("www.wireshark.org")
  })

  it("negotiated legacy suite forces TLSv1.2 despite a 1.3-capable ClientHello (QA: qwen handshake offered TLS_AES_128_GCM_SHA256, ServerHello answered ECDHE-RSA-AES128-GCM-SHA256)", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, timestamp: t0, srcIp: "192.168.1.10", dstIp: "8.208.41.88", srcPort: 50000, dstPort: 443, tlsSni: "qwen-webui-prod.oss-accelerate.aliyuncs.com", tlsVersion: 0x0304 }),
      makePacket({ num: 2, timestamp: t0 + 1, srcIp: "8.208.41.88", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000, tcpFlags: "ACK", tlsCipherSuite: 0xc02f }),
    ]
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.tls.length).toBe(1)
    expect(analysis.tls[0].version).toBe("TLSv1.2")
    expect(analysis.tls[0].cipherSuite).toBe("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
  })

  it("beaconing: regular talk to a WNS/Skype push endpoint is not C2 (QA: keepalive FP)", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 4; i++) {
      packets.push(makePacket({ num: i * 2 + 1, timestamp: t0 + i * 2, srcIp: "192.168.1.10", dstIp: "104.20.1.154", srcPort: 50000 + i, dstPort: 443, tcpFlags: "SYN", tcpSeq: 1000 + i, dnsAnswers: [{ name: "client.wns.windows.com", ip: "104.20.1.154" }] }))
      packets.push(makePacket({ num: i * 2 + 2, timestamp: t0 + i * 2 + 1, srcIp: "104.20.1.154", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000 + i, tcpFlags: "SYN-ACK", tcpSeq: 5000 + i }))
    }
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.threats.find((t) => t.ruleId === "C2-BEACON-001")).toBeUndefined()
  })

  it("beaconing: the same cadence to an IP with no benign DNS name DOES fire C2-BEACON-001", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = []
    // 6 connections over 10s: ≥ beacon_min_packets (5) and ≥ beacon_min_duration (10s)
    for (let i = 0; i < 6; i++) {
      packets.push(makePacket({ num: i * 2 + 1, timestamp: t0 + i * 2, srcIp: "192.168.1.10", dstIp: "104.20.1.154", srcPort: 50000 + i, dstPort: 443, tcpFlags: "SYN", tcpSeq: 1000 + i }))
      packets.push(makePacket({ num: i * 2 + 2, timestamp: t0 + i * 2 + 1, srcIp: "104.20.1.154", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000 + i, tcpFlags: "SYN-ACK", tcpSeq: 5000 + i }))
    }
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.threats.find((t) => t.ruleId === "C2-BEACON-001")).toBeDefined()
  })

  it("SYN-FLOOD-001 fires only past the 100-SYN threshold (QA: rule was dead code locally)", () => {
    const t0 = 1_700_000_000
    const mk = (n: number) => {
      const packets: ParsedPacket[] = []
      for (let i = 0; i < n; i++) {
        packets.push(makePacket({ num: i + 1, timestamp: t0 + i, srcIp: "10.0.0.50", dstIp: "8.8.8.8", srcPort: 40000 + (i % 100), dstPort: 80, tcpFlags: "SYN", tcpSeq: 1000 + i }))
      }
      return analyzePcap(mkResult(packets))
    }
    const under = mk(99)
    expect(under.threats.find((t) => t.ruleId === "SYN-FLOOD-001")).toBeUndefined()
    const over = mk(100)
    const t = over.threats.find((x) => x.ruleId === "SYN-FLOOD-001")
    expect(t).toBeDefined()
    expect(t!.severity).toBe(4)
    expect(t!.evidence).toContain("100 SYN packets")
    expect(over.job.riskScore).toBeGreaterThan(0)
  })

  it("beaconing: a 4-connection keepalive cadence to an IP with no benign name is NOT C2 (QA: verylarge.pcapng Cloudflare keepalive FP)", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 4; i++) {
      packets.push(makePacket({ num: i * 2 + 1, timestamp: t0 + i * 2, srcIp: "192.168.1.10", dstIp: "104.20.1.154", srcPort: 50000 + i, dstPort: 443, tcpFlags: "SYN", tcpSeq: 1000 + i }))
      packets.push(makePacket({ num: i * 2 + 2, timestamp: t0 + i * 2 + 1, srcIp: "104.20.1.154", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000 + i, tcpFlags: "SYN-ACK", tcpSeq: 5000 + i }))
    }
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.advancedMetrics.beaconDetected).toBe(false)
    expect(analysis.threats.find((t) => t.ruleId === "C2-BEACON-001")).toBeUndefined()
  })

  it("beaconing: a VPN API poll loop identified ONLY by TLS SNI is not C2 (QA: large.pcapng api.windscribe.com at ~60 s)", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = []
    // 9 connections at a 60 s cadence — no DNS answer in the capture, only SNI.
    for (let i = 0; i < 9; i++) {
      packets.push(makePacket({ num: i * 2 + 1, timestamp: t0 + i * 60, srcIp: "192.168.1.10", dstIp: "104.20.1.154", srcPort: 50000 + i, dstPort: 443, tcpFlags: "SYN", tcpSeq: 1000 + i, tlsSni: "api.windscribe.com" }))
      packets.push(makePacket({ num: i * 2 + 2, timestamp: t0 + i * 60 + 1, srcIp: "104.20.1.154", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000 + i, tcpFlags: "SYN-ACK", tcpSeq: 5000 + i }))
    }
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.advancedMetrics.beaconDetected).toBe(false)
    expect(analysis.threats.find((t) => t.ruleId === "C2-BEACON-001")).toBeUndefined()
  })

  it("beaconing: the same cadence with an UNKNOWN SNI still fires C2-BEACON-001 (SNI suppression is name-scoped)", () => {
    const t0 = 1_700_000_000
    const packets: ParsedPacket[] = []
    for (let i = 0; i < 6; i++) {
      packets.push(makePacket({ num: i * 2 + 1, timestamp: t0 + i * 2, srcIp: "192.168.1.10", dstIp: "104.20.1.154", srcPort: 50000 + i, dstPort: 443, tcpFlags: "SYN", tcpSeq: 1000 + i, tlsSni: "c2.evil.example" }))
      packets.push(makePacket({ num: i * 2 + 2, timestamp: t0 + i * 2 + 1, srcIp: "104.20.1.154", dstIp: "192.168.1.10", srcPort: 443, dstPort: 50000 + i, tcpFlags: "SYN-ACK", tcpSeq: 5000 + i }))
    }
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.threats.find((t) => t.ruleId === "C2-BEACON-001")).toBeDefined()
  })

  it("remote public devices NEVER absorb local addresses via the router MAC (QA: Cloudflare row claimed 192.168.1.1)", () => {
    // Router MAC forwarded every frame; public sources are processed first, so a
    // later 192.168.1.1 (the router) or its home-v6 would fold into them through
    // same L2 + "v4/v6 is one surface" unless the merge requires a LOCAL primary.
    const routerMac = "aa:bb:cc:dd:ee:ff"
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcMac: routerMac, srcIp: "2606:4700:90d1::ccf5:ac50", dstIp: "192.168.1.20", dstPort: 443 }),
      makePacket({ num: 2, srcMac: routerMac, srcIp: "192.168.1.1", dstIp: "192.168.1.20", protocol: "ARP" }),
      makePacket({ num: 3, srcMac: routerMac, srcIp: "101.2.27.162", dstIp: "192.168.1.20", dstPort: 3478, protocol: "UDP" }),
      makePacket({ num: 4, srcMac: routerMac, srcIp: "2401:4900:8910:960f::1", dstIp: "192.168.1.20" }),
      makePacket({ num: 5, srcMac: "11:22:33:44:55:66", srcIp: "2401:4900:8910:960f::80", dstIp: "192.168.1.20" }),
    ]
    const analysis = analyzePcap(mkResult(packets))
    // The two remote rows must stay clean: no alias may ever fold into them.
    for (const ip of ["2606:4700:90d1::ccf5:ac50", "101.2.27.162"]) {
      const remote = analysis.devices.find((d) => d.ip === ip)
      expect(remote, `${ip} row must exist`).toBeDefined()
      expect(remote!.addresses, `${ip} must not claim aliases`).toEqual([])
    }
    // Bodyguard invariant: no device row may mix a public primary with a
    // private (RFC1918/link-local) alias.
    for (const d of analysis.devices) {
      if (isPrivateIP(d.ip)) continue
      for (const a of d.addresses ?? []) {
        expect(isPrivateIP(a), `${d.ip} (public) must not alias private ${a}`).toBe(false)
      }
    }
    // The router's own private address keeps its own row — not swallowed into a
    // remote device. (Old bug made it an "Other address" of 2606:/101.2.27.162.)
    const routerRow = analysis.devices.find((d) => d.ip === "192.168.1.1")
    expect(routerRow).toBeDefined()
  })

  it("proxy claim fires only for the Tor exit subnet, never TEST-NET or CDN ranges (audit)", () => {
    const t0 = 1_700_000_000
    const make = (dstIp: string) => {
      const packets: ParsedPacket[] = [makePacket({ num: 1, timestamp: t0, srcIp: "192.168.1.10", dstIp, srcPort: 50000, dstPort: 443, tcpFlags: "ACK", length: 300 })]
      return analyzePcap(mkResult(packets))
    }
    // TEST-NET-2 (198.51.100.x) and Cloudflare (198.41.x) are not proxies.
    expect(make("198.51.100.7").advancedMetrics.torVpnProxyDetected).toBe(false)
    expect(make("198.41.212.35").advancedMetrics.torVpnProxyDetected).toBe(false)
    // Actual Tor exit-node subnet (ASN-TOR) still fires T1090.
    expect(make("185.220.101.5").advancedMetrics.torVpnProxyDetected).toBe(true)
    expect(make("185.220.101.5").advancedMetrics.mitreMappings.some((m) => m.id === "T1090")).toBe(true)
  })

  it("5-minute timeline labels survive single-digit months/days (QA)", () => {
    // 2025-09-05 08:05 local — an unpadded bucket key used to shift the
    // label into the clock digits, rendering "8:05" or ":05" ~280 days a year.
    const t = new Date(2025, 8, 5, 8, 5, 0).getTime() / 1000
    const p1 = makePacket({ num: 1, timestamp: t })
    const p2 = makePacket({ num: 2, timestamp: t + 150 })
    const analysis = analyzePcap(mkResult([p1, p2]))
    expect(analysis.timeline).toHaveLength(1)
    expect(analysis.timeline[0].time).toBe("08:05")
    expect(analysis.bandwidth[0].time).toBe("08:05")
  })

  it("multi-day captures label buckets with the date to keep keys unique (QA)", () => {
    const day1 = makePacket({ num: 1, timestamp: new Date(2025, 8, 15, 8, 5, 0).getTime() / 1000 })
    const day2 = makePacket({ num: 2, timestamp: new Date(2025, 8, 16, 8, 5, 0).getTime() / 1000 })
    const analysis = analyzePcap(mkResult([day1, day2]))
    const times = analysis.timeline.map((t) => t.time)
    // Two buckets with the same HH:MM across days would collide as React keys.
    expect(times).toEqual(["09-15 08:05", "09-16 08:05"])
  })

  it("certificates without a validity time report null, not a 1969 date (QA)", () => {
    const p = makePacket({
      num: 1,
      tlsCert: {
        subject: "CN=example.com", issuer: "CN=R3", serial: "01",
        notBefore: -1, notAfter: -1, san: ["example.com"],
        signatureAlgorithm: "SHA256-RSA", keySize: 2048,
      },
    })
    const analysis = analyzePcap(mkResult([p]))
    const cert = analysis.certificates[0]
    expect(cert.notBefore).toBeNull()
    expect(cert.notAfter).toBeNull()
    expect(cert.subject).toBe("CN=example.com")
  })

  it("a host's delegated public IPv6 folds into its device via the link-local pairing; forwarded servers stay remote (QA: test.pcapng)", () => {
    const hostMac = "8c:90:2d:ca:b4:d5"
    const routerMac = "6c:22:f7:e5:0f:d3"
    const wanMac = "6e:22:f7:e5:0f:dd"
    const hostV6 = "2401:4900:8911:7943:754b:ad97:bd76:275b"
    const hostFe80 = "fe80::16b0:3a5e:da5a:39b6"
    const routerV6 = "2401:4900:8911:7943:0:0:0:1"
    const serverV6 = "2600:9000:245b:6000:15:913f:6800:93a1"
    const packets: ParsedPacket[] = [
      // Host's own link-local (NDP) — first, as in the real capture; its MAC
      // is what the delegated v6 later folds into.
      makePacket({ num: 1, srcMac: hostMac, srcIp: hostFe80, dstIp: "ff02::1:2", dstPort: 0, protocol: "UDP", tcpFlags: "" }),
      makePacket({ num: 2, srcMac: routerMac, srcIp: "fe80::1", dstIp: "ff02::1:2", dstPort: 0, protocol: "UDP", tcpFlags: "" }),
      // Host uploads over its SLAAC v6 (server sorts LAST — irrelevant here).
      makePacket({ num: 3, srcMac: hostMac, srcIp: hostV6, dstIp: serverV6, dstPort: 443, length: 1000 }),
      // The server's /64 is forwarded through the router LAN MAC AND its
      // WAN/capture NIC — without the shadow-MAC collapse this /64 would
      // look like a two-interface "delegated prefix" and fold the server in.
      makePacket({ num: 4, srcMac: routerMac, srcIp: serverV6, dstIp: hostV6, srcPort: 443, tcpFlags: "ACK", length: 1200 }),
      makePacket({ num: 5, srcMac: wanMac, srcIp: serverV6, dstIp: hostV6, srcPort: 443, tcpFlags: "ACK", length: 1200 }),
      // Router's own delegated v6: a SECOND real LAN interface sources the /64.
      makePacket({ num: 6, srcMac: routerMac, srcIp: routerV6, dstIp: "8.8.8.8", length: 500 }),
      // ARP declarations mark both MACs as real LAN interfaces.
      makePacket({ num: 7, srcMac: hostMac, srcIp: "192.168.1.10", dstIp: "8.8.8.8", srcPort: 50000, length: 300 }),
      makePacket({ num: 8, srcMac: routerMac, srcIp: "192.168.1.1", dstIp: "192.168.1.10", protocol: "ARP", tcpFlags: "", arpSenderMac: routerMac }),
      makePacket({ num: 9, srcMac: hostMac, srcIp: "192.168.1.10", dstIp: "192.168.1.1", protocol: "ARP", tcpFlags: "", arpSenderMac: hostMac }),
    ]
    const analysis = analyzePcap(mkResult(packets))
    // Host: ONE device holding v4 + link-local + delegated v6 (the fe80 is
    // the row's PRIMARY — it was seen first — so check ip + aliases); the v6
    // is never its own "external" row (pre-fix it stranded on its own MAC).
    const host = analysis.devices.find((d) => d.ip === hostFe80 || d.addresses?.includes(hostFe80))
    expect(host).toBeDefined()
    const hostAddrs = [host!.ip, ...(host!.addresses ?? [])]
    expect(hostAddrs).toEqual(expect.arrayContaining([hostV6, hostFe80, "192.168.1.10"]))
    expect(analysis.devices.some((d) => d.ip === hostV6)).toBe(false)
    // Router: holds its own delegated v6, never the forwarded server.
    const router = analysis.devices.find((d) => d.addresses?.includes(routerV6))
    expect(router).toBeDefined()
    expect(router?.addresses).not.toContain(serverV6)
    // The server stays a clean remote row.
    const server = analysis.devices.find((d) => d.ip === serverV6)
    expect(server).toBeDefined()
    expect(server?.mac).toBe("\u2014")
    expect(server?.addresses ?? []).toEqual([])
    // External = 8.8.8.8 + the server only (host v6, router v6, fe80s all local).
    expect(analysis.job.externalIps).toBe(2)
  })

  it("exfil detector: a host uploading over its own delegated public IPv6 fires DATA-EXFIL-001 (QA: test.pcapng SLAAC uploads)", () => {
    const t0 = 1_700_000_000
    const hostMac = "8c:90:2d:ca:b4:d5"
    const routerMac = "6c:22:f7:e5:0f:d3"
    const hostV6 = "2401:4900:8911:7943:754b:ad97:bd76:275b"
    const serverV6 = "2001:db8::1" // sorts BEFORE 2401:… → server owns the flow key srcIp
    const packets: ParsedPacket[] = [
      // Host's link-local anchors its MAC as a LAN interface (NDP).
      makePacket({ num: 1, srcMac: hostMac, srcIp: "fe80::16b0:3a5e:da5a:39b6", dstIp: "ff02::1:2", dstPort: 0, protocol: "UDP", tcpFlags: "" }),
      // Router's own v6 on the same /64: second LAN interface sources it.
      makePacket({ num: 2, srcMac: routerMac, srcIp: "2401:4900:8911:7943:0:0:0:1", dstIp: "8.8.8.8", length: 100 }),
    ]
    // Host uploads 210 KB over its SLAAC address.
    for (let i = 0; i < 150; i++) packets.push(makePacket({ num: 100 + i, timestamp: t0 + i, srcMac: hostMac, srcIp: hostV6, dstIp: serverV6, srcPort: 50000, dstPort: 443, tcpFlags: "ACK", length: 1400 }))
    // Server replies are tiny.
    for (let i = 0; i < 3; i++) packets.push(makePacket({ num: 300 + i, timestamp: t0 + 200 + i, srcMac: routerMac, srcIp: serverV6, dstIp: hostV6, srcPort: 443, dstPort: 50000, tcpFlags: "ACK", length: 300 }))
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.advancedMetrics.dataExfiltrationSuspected).toBe(true)
    const t = analysis.threats.find((t) => t.ruleId === "DATA-EXFIL-001")
    expect(t).toBeDefined()
    expect(t?.category).toBe("Exfiltration")
    // Evidence reads local-v6 → public, never the reverse.
    expect(t?.evidence).toMatch(/2401:4900:8911:7943:754b:ad97:bd76:275b → 2001:db8::1/)
  })

  it("beacon detector: remoteOf names the SERVER when the local side is a delegated public IPv6 that sorts first (QA: test.pcapng)", () => {
    const t0 = 1_700_000_000
    const hostMac = "8c:90:2d:ca:b4:d5"
    const routerMac = "6c:22:f7:e5:0f:d3"
    const hostV6 = "2401:4900:8911:7943:754b:ad97:bd76:275b"
    const serverV6 = "2600:9000:245b:6000:15:913f:6800:93a1" // sorts AFTER the host v6
    const packets: ParsedPacket[] = [
      makePacket({ num: 1, srcMac: hostMac, srcIp: "fe80::16b0:3a5e:da5a:39b6", dstIp: "ff02::1:2", dstPort: 0, protocol: "UDP", tcpFlags: "" }),
      makePacket({ num: 2, srcMac: routerMac, srcIp: "2401:4900:8911:7943:0:0:0:1", dstIp: "8.8.8.8", length: 100 }),
    ]
    // 6 regular connections from the host's SLAAC v6: the flow key srcIp is
    // the HOST v6, so the old isPrivateIp(srcIp) remoteOf grouped by the
    // local host's own address and the cadence was invisible.
    for (let i = 0; i < 6; i++) {
      packets.push(makePacket({ num: 100 + i * 2, timestamp: t0 + i * 2, srcMac: hostMac, srcIp: hostV6, dstIp: serverV6, srcPort: 50000 + i, dstPort: 443, tcpFlags: "SYN", tcpSeq: 1000 + i }))
      packets.push(makePacket({ num: 101 + i * 2, timestamp: t0 + i * 2 + 1, srcMac: routerMac, srcIp: serverV6, dstIp: hostV6, srcPort: 443, dstPort: 50000 + i, tcpFlags: "SYN-ACK", tcpSeq: 5000 + i }))
    }
    const analysis = analyzePcap(mkResult(packets))
    expect(analysis.advancedMetrics.beaconDetected).toBe(true)
    const t = analysis.threats.find((t) => t.ruleId === "C2-BEACON-001")
    expect(t).toBeDefined()
    // The remote is the SERVER (stable :443), never the local host's rotating ports.
    expect(t?.evidence).toMatch(/2600:9000:245b:6000:15:913f:6800:93a1:443/)
    expect(t?.evidence).not.toMatch(/2401:4900/)
  })
})