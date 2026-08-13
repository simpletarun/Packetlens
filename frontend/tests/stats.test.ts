import { describe, it, expect } from "vitest"
import { computeStats, formatDuration } from "@/lib/stats"
import { deriveMapData, isPrivateIP } from "@/lib/map-data"

const job = {
  id: "j1", filename: "a.pcap", fileSize: 100, status: "done" as const, progress: 100, stage: "complete",
  totalPackets: 1000, totalFlows: 50, conversations: 46, devices: 12, externalIps: 8,
  countries: 0, domains: 9, protocols: ["TCP", "UDP"], alerts: 3, riskScore: 25,
  captureDuration: 28, createdAt: "2024-01-01T00:00:00.000Z",
}

describe("computeStats — canonical statistics", () => {
  it("prefers job aggregates over truncated array counts", () => {
    const stats = computeStats({ job, packets: [], flows: [], sessions: [], dns: [], devices: [], alerts: [], geo: new Map() })
    expect(stats.totalPackets).toBe(1000)
    expect(stats.totalFlows).toBe(50)
    expect(stats.sessions).toBe(46)
    expect(stats.devices).toBe(12)
    expect(stats.alerts).toBe(3)
    expect(stats.riskScore).toBe(25)
  })

  it("falls back to array counts when job is null", () => {
    const p = { num: 1, timestamp: "2024-01-01T00:00:00Z", srcIp: "10.0.0.1", dstIp: "8.8.8.8", srcPort: 1, dstPort: 53, protocol: "DNS", length: 64, flags: "", ttl: 64, info: "" }
    const stats = computeStats({ job: null, packets: [p], flows: [], sessions: [], dns: [{ id: "d", timestamp: "", srcIp: "10.0.0.1", dstIp: "8.8.8.8", query: "example.com", type: "A", responseCode: "NOERROR", answer: "", ttl: 1 }], devices: [], alerts: [], geo: new Map() })
    expect(stats.totalPackets).toBe(1)
    expect(stats.domains).toBe(1)
  })

  it("counts countries from resolved geo, excluding local/unknown", () => {
    const geo = new Map([
      ["8.8.8.8", { ip: "8.8.8.8", country: "United States", countryCode: "US", city: "x", lat: 0, lon: 0, isPrivate: false }],
      ["1.1.1.1", { ip: "1.1.1.1", country: "United States", countryCode: "US", city: "x", lat: 0, lon: 0, isPrivate: false }],
      ["10.0.0.1", { ip: "10.0.0.1", country: "Local Network", countryCode: "LOC", city: "LAN", lat: 0, lon: 0, isPrivate: true }],
      ["9.9.9.9", { ip: "9.9.9.9", country: "Unknown", countryCode: "??", city: "", lat: 0, lon: 0, isPrivate: false }],
    ])
    const stats = computeStats({ job: null, packets: [], flows: [], sessions: [], dns: [], devices: [], alerts: [], geo })
    expect(stats.countries).toBe(1)
  })

  it("counts external IPs from packets", () => {
    const mk = (n: number, src: string, dst: string) => ({ num: n, timestamp: "", srcIp: src, dstIp: dst, srcPort: 1, dstPort: 2, protocol: "TCP", length: 64, flags: "", ttl: 64, info: "" })
    const stats = computeStats({
      job: null,
      packets: [mk(1, "192.168.1.5", "8.8.8.8"), mk(2, "192.168.1.5", "8.8.8.8"), mk(3, "10.0.0.1", "1.1.1.1")],
      flows: [], sessions: [], dns: [], devices: [], alerts: [], geo: new Map(),
    })
    expect(stats.externalIps).toBe(2)
  })

  it("excludes a private device's own delegated IPv6 alias from External (QA calls.pcap)", () => {
    const v6 = "2401:4900:1:2::308f"
    const mk = (n: number, src: string, dst: string) => ({ num: n, timestamp: "", srcIp: src, dstIp: dst, srcPort: 1, dstPort: 2, protocol: "TCP", length: 64, flags: "", ttl: 64, info: "" })
    const dev = (ip: string, addresses: string[]) => ({ id: "d", ip, mac: "aa:bb:cc:dd:ee:ff", hostname: "", vendor: "", os: "", firstSeen: "", lastSeen: "", packets: 1, bytes: 1, addresses })
    const stats = computeStats({
      job: null,
      packets: [mk(1, "192.168.1.20", v6), mk(2, "192.168.1.20", "8.8.8.8")],
      flows: [], sessions: [], dns: [], devices: [dev("192.168.1.20", [v6])], alerts: [], geo: new Map(),
    })
    expect(stats.externalIps).toBe(1)
  })

  it("devices counts LOCAL endpoints only — remote services never inflate it", () => {
    const dev = (id: string, ip: string) => ({ id, ip, mac: "—", hostname: "", vendor: "", os: "", firstSeen: "", lastSeen: "", packets: 1, bytes: 1 })
    const devices = [
      dev("d1", "192.168.1.5"),
      dev("d2", "192.168.1.1"),
      dev("d3", "8.8.8.8"),      // Cloudflare
      dev("d4", "172.64.190.1"), // Akamai
      dev("d5", "142.250.122.94"), // Google
    ]
    const stats = computeStats({ job, packets: [], flows: [], sessions: [], dns: [], devices, alerts: [], geo: new Map() })
    expect(stats.devices).toBe(2)
  })
})

describe("formatDuration", () => {
  it("shows seconds under a minute", () => expect(formatDuration(28)).toBe("28 s"))
  it("shows minutes and seconds", () => expect(formatDuration(125)).toBe("2 m 5 s"))
  it("shows hours", () => expect(formatDuration(3725)).toBe("1 h 2 m 5 s"))
  it("handles invalid input", () => expect(formatDuration(NaN)).toBe("0 s"))
})

describe("deriveMapData — shared map derivation", () => {
  it("aggregates public nodes and arcs from packets", () => {
    const mk = (n: number, src: string, dst: string, proto: string, len: number) => ({ num: n, timestamp: "2024-01-01T00:00:00Z", srcIp: src, dstIp: dst, srcPort: 1, dstPort: 2, protocol: proto, length: len, flags: "", ttl: 64, info: "" })
    const geo = new Map([
      ["8.8.8.8", { ip: "8.8.8.8", country: "United States", countryCode: "US", city: "Mountain View", lat: 37.386, lon: -122.084, isPrivate: false }],
      ["1.1.1.1", { ip: "1.1.1.1", country: "Australia", countryCode: "AU", city: "Sydney", lat: -33.8688, lon: 151.2093, isPrivate: false }],
    ])
    const packets = [mk(1, "192.168.1.5", "8.8.8.8", "TCP", 100), mk(2, "192.168.1.5", "8.8.8.8", "TCP", 50), mk(3, "192.168.1.5", "1.1.1.1", "DNS", 60)]
    const data = deriveMapData(packets, geo)
    expect(data.nodes).toHaveLength(2)
    const pub = data.nodeMap.get("8.8.8.8")!
    expect(pub.packets).toBe(2)
    expect(pub.isPrivate).toBe(false)
    expect(pub.isDest).toBe(true)
    expect(pub.isSource).toBe(false)
    expect(data.nodeMap.get("192.168.1.5")).toBeUndefined()
    expect(data.arcs).toHaveLength(0) // every flow involves the private peer — nothing drawable
    expect(data.protocols).toContain("TCP")
    expect(data.localSummary.hosts).toBe(1)
  })

  it("keeps private IPs out of nodes and arcs entirely — LAN traffic lands in localSummary", () => {
    const mk = (n: number, src: string, dst: string) => ({ num: n, timestamp: "", srcIp: src, dstIp: dst, srcPort: 1, dstPort: 2, protocol: "TCP", length: 64, flags: "", ttl: 64, info: "" })
    const geo = new Map([["8.8.8.8", { ip: "8.8.8.8", country: "United States", countryCode: "US", city: "Mountain View", lat: 37.386, lon: -122.084, isPrivate: false }]])
    const data = deriveMapData([mk(1, "192.168.1.5", "10.0.0.2")], geo)
    expect(data.nodes).toHaveLength(0)
    expect(data.arcs).toHaveLength(0)
    expect(data.nodeMap.size).toBe(0)
    expect(data.localSummary.hosts).toBe(2)
    expect(data.localSummary.bytes).toBe(64)
    expect(data.localSummary.topHost).toBe("192.168.1.5")
  })

  it("places public IPs via geo; private peers never become nodes", () => {
    const mk = (n: number, src: string, dst: string) => ({ num: n, timestamp: "", srcIp: src, dstIp: dst, srcPort: 1, dstPort: 2, protocol: "TCP", length: 64, flags: "", ttl: 64, info: "" })
    const geo = new Map([["8.8.8.8", { ip: "8.8.8.8", country: "United States", countryCode: "US", city: "Mountain View", lat: 37.386, lon: -122.084, isPrivate: false }]])
    const data = deriveMapData([mk(1, "192.168.1.5", "8.8.8.8")], geo)
    const pub = data.nodeMap.get("8.8.8.8")!
    expect(pub.lat).toBe(37.386)
    expect(pub.countryCode).toBe("US")
    expect(pub.isPrivate).toBe(false)
    expect(data.nodeMap.get("192.168.1.5")).toBeUndefined()
    expect(data.localSummary.hosts).toBe(1)
  })

  it("never draws ungeocoded public IPs — counts them as undrawn with bytes", () => {
    const mk = (n: number, src: string, dst: string) => ({ num: n, timestamp: "", srcIp: src, dstIp: dst, srcPort: 1, dstPort: 2, protocol: "TCP", length: 64, flags: "", ttl: 64, info: "" })
    const data = deriveMapData([mk(1, "192.168.1.5", "203.0.113.9")])
    expect(data.nodeMap.get("203.0.113.9")).toBeUndefined()
    expect(data.nodes).toHaveLength(0)
    expect(data.arcs).toHaveLength(0)
    expect(data.undrawnPublic).toHaveLength(1)
    expect(data.undrawnPublic[0].ip).toBe("203.0.113.9")
    expect(data.undrawnPublic[0].bytes).toBe(64)
    expect(data.localSummary.hosts).toBe(1)
  })

  it("draws only public-to-public arcs; private-involved flows never produce arcs", () => {
    const mk = (n: number, src: string, dst: string) => ({ num: n, timestamp: "", srcIp: src, dstIp: dst, srcPort: 1, dstPort: 2, protocol: "TCP", length: 64, flags: "", ttl: 64, info: "" })
    const geo = new Map([
      ["8.8.8.8", { ip: "8.8.8.8", country: "United States", countryCode: "US", city: "x", lat: 37.386, lon: -122.084, isPrivate: false }],
      ["1.1.1.1", { ip: "1.1.1.1", country: "Australia", countryCode: "AU", city: "y", lat: -33.8688, lon: 151.2093, isPrivate: false }],
    ])
    const data = deriveMapData([
      mk(1, "8.8.8.8", "1.1.1.1"),           // public↔public → drawn
      mk(2, "192.168.1.5", "8.8.8.8"),       // private↔public → not drawn
      mk(3, "192.168.1.5", "10.0.0.2"),      // private↔private → not drawn
    ], geo)
    expect(data.arcs).toHaveLength(1)
    expect(data.arcs[0].srcIp).toBe("8.8.8.8")
    expect(data.arcs[0].dstIp).toBe("1.1.1.1")
    expect(data.arcs[0].coordinates.length).toBeGreaterThan(2)
    expect(data.localSummary.hosts).toBe(2)
    expect(data.localSummary.bytes).toBe(64) // LAN-only bytes, not the private→public flow
  })
})

describe("isPrivateIP", () => {
  it("detects RFC1918 ranges", () => {
    expect(isPrivateIP("192.168.1.1")).toBe(true)
    expect(isPrivateIP("10.0.0.1")).toBe(true)
    expect(isPrivateIP("172.16.0.1")).toBe(true)
    expect(isPrivateIP("172.31.255.1")).toBe(true)
    expect(isPrivateIP("172.32.0.1")).toBe(false)
    expect(isPrivateIP("8.8.8.8")).toBe(false)
    expect(isPrivateIP("fe80::1")).toBe(true)
  })

  it("never treats non-routable LAN artifacts as public", () => {
    expect(isPrivateIP("224.0.0.251")).toBe(true)  // mDNS
    expect(isPrivateIP("239.255.255.250")).toBe(true) // SSDP
    expect(isPrivateIP("169.254.1.5")).toBe(true)  // link-local
    expect(isPrivateIP("255.255.255.255")).toBe(true) // broadcast
    expect(isPrivateIP("100.64.0.1")).toBe(true)  // CGNAT
    expect(isPrivateIP("100.127.255.1")).toBe(true)
    expect(isPrivateIP("100.63.0.1")).toBe(false)
    expect(isPrivateIP("198.18.0.1")).toBe(true)
    expect(isPrivateIP("240.0.0.1")).toBe(true)
    expect(isPrivateIP("0.0.0.1")).toBe(true)
    expect(isPrivateIP("ff02::fb")).toBe(true)    // mDNSv6
  })
})
