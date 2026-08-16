import { describe, it, expect } from "vitest"
import { buildGraphElements } from "@/lib/graph-data"

function geo(ip: string, country: string, countryCode: string, asn?: string, org?: string) {
  return { ip, country, countryCode, city: "", lat: 0, lon: 0, isPrivate: false, asn, org }
}

const base = {
  packets: [] as { srcIp?: string; dstIp?: string; protocol?: string }[],
  dns: [] as { query: string; srcIp: string; dstIp: string; type: string; responseCode?: string; isResponse?: boolean }[],
  http: [] as { method: string; uri: string; host: string; srcIp: string; dstIp: string }[],
  tls: [] as { sni: string; srcIp: string; dstIp: string; version: string }[],
  files: [] as { filename: string; srcIp: string; dstIp: string; size: number }[],
  credentials: [] as { username: string; protocol: string; srcIp: string; dstIp: string; service?: string }[],
  certificates: [] as { subject: string; issuer: string; san: string[] }[],
  alerts: [] as { signature: string; srcIp: string; dstIp: string; severity: number }[],
}

describe("buildGraphElements", () => {
  it("B-49: builds Country + ASN nodes/edges for geocoded external IPs, never for private/LOC", () => {
    const geoMap = new Map([
      ["8.8.8.8", geo("8.8.8.8", "United States", "US", "AS15169", "Google LLC")],
      ["1.1.1.1", geo("1.1.1.1", "Australia", "AU", "AS13335", "Cloudflare")],
      ["192.168.1.20", { ...geo("192.168.1.20", "Local Network", "LOC"), isPrivate: true }],
    ])
    const flows = [
      { srcIp: "192.168.1.20", dstIp: "8.8.8.8", protocol: "UDP", packets: 2, bytesTotal: 160 },
      { srcIp: "192.168.1.20", dstIp: "1.1.1.1", protocol: "UDP", packets: 1, bytesTotal: 80 },
    ]
    const { nodes, edges } = buildGraphElements({ ...base, devices: [], flows, geoMap, beginnerMode: false })

    expect(nodes.filter(n => n.data.type === "country").map(n => n.data.id).sort()).toEqual(["country:AU", "country:US"])
    expect(nodes.some(n => n.data.id === "asn:AS15169" && String(n.data.label).includes("Google LLC"))).toBe(true)
    expect(nodes.some(n => n.data.id === "country:LOC")).toBe(false)
    expect(edges.some(e => e.data.id === "ip:8.8.8.8->country:US")).toBe(true)
    expect(edges.some(e => e.data.id === "ip:8.8.8.8->asn:AS15169")).toBe(true)
    // the private LAN host gets no country edge of its own
    expect(edges.some(e => e.data.source === "ip:192.168.1.20" && e.data.type === "edge" && e.data.target !== "dev:192.168.1.20" && String(e.data.label) === "in")).toBe(false)
  })

  it("B-50: pairs each device IP node with its Device node via an identity edge and differentiates labels", () => {
    const flows = [{ srcIp: "192.168.1.20", dstIp: "8.8.8.8", protocol: "TCP", packets: 4, bytesTotal: 300 }]
    const devices = [{ ip: "192.168.1.20", hostname: "DESKTOP-X", mac: "00:11:22:33:44:55", vendor: "Intel", os: "Windows" }]
    const { nodes, edges } = buildGraphElements({ ...base, devices, flows, geoMap: new Map(), beginnerMode: false })

    expect(edges.some(e => e.data.id === "ip:192.168.1.20->dev:192.168.1.20" && e.data.type === "identity" && e.data.label === "same host")).toBe(true)
    const ipNode = nodes.find(n => n.data.id === "ip:192.168.1.20")
    const devNode = nodes.find(n => n.data.id === "dev:192.168.1.20")
    expect(ipNode).toBeTruthy()
    expect(devNode).toBeTruthy()
    expect(String(devNode!.data.label)).toContain("DESKTOP-X")
    expect(String(devNode!.data.label)).not.toEqual(String(ipNode!.data.label))
  })

  it("B-50: device with no hostname falls back to vendor, then to 'Device' (never the raw IP)", () => {
    const flows = [{ srcIp: "10.0.0.5", dstIp: "8.8.4.4", protocol: "UDP", packets: 1, bytesTotal: 64 }]
    const devices = [
      { ip: "10.0.0.5", hostname: "", mac: "6e:22:f7:aa:bb:cc", vendor: "Nokia", os: "" },
      { ip: "10.0.0.9", hostname: "", mac: "—", vendor: "", os: "" },
    ]
    const { nodes } = buildGraphElements({ ...base, devices, flows, geoMap: new Map(), beginnerMode: false })
    expect(nodes.find(n => n.data.id === "dev:10.0.0.5")?.data.label).toContain("Nokia")
    expect(nodes.find(n => n.data.id === "dev:10.0.0.9")?.data.label).toContain("Device")
  })

  it("beginner mode masks IPs in both the node label AND the info panel (no full-IP leak on tap)", () => {
    const flows = [{ srcIp: "192.168.1.20", dstIp: "8.8.8.8", protocol: "TCP", packets: 4, bytesTotal: 300 }]
    const { nodes } = buildGraphElements({ ...base, devices: [], flows, geoMap: new Map(), beginnerMode: true })
    const ipNode = nodes.find(n => n.data.id === "ip:8.8.8.8")
    expect(String(ipNode!.data.label)).toContain("8.8.x.x")
    expect(String(ipNode!.data.label)).not.toContain("8.8.8.8")
    expect(String(ipNode!.data.info)).toContain("8.8.x.x")
    expect(String(ipNode!.data.info)).not.toContain("8.8.8.8")
  })

  it("expert mode keeps the full IP in label and info", () => {
    const flows = [{ srcIp: "192.168.1.20", dstIp: "8.8.8.8", protocol: "TCP", packets: 4, bytesTotal: 300 }]
    const { nodes } = buildGraphElements({ ...base, devices: [], flows, geoMap: new Map(), beginnerMode: false })
    const ipNode = nodes.find(n => n.data.id === "ip:8.8.8.8")
    expect(String(ipNode!.data.label)).toContain("8.8.8.8")
    expect(String(ipNode!.data.info)).toContain("8.8.8.8")
  })

  it("beginner mode masks IPv6 to its /64 — no full-address leak on v6 (IPv4-only mask was the bug)", () => {
    const flows = [{ srcIp: "2401:4900:8910:960f:e908:c660:a32f:308f", dstIp: "8.8.8.8", protocol: "TCP", packets: 4, bytesTotal: 300 }]
    const { nodes } = buildGraphElements({ ...base, devices: [], flows, geoMap: new Map(), beginnerMode: true })
    const v6 = nodes.find(n => n.data.id === "ip:2401:4900:8910:960f:e908:c660:a32f:308f")
    expect(String(v6!.data.label)).toContain("2401:4900:8910:960f::")
    expect(String(v6!.data.label)).not.toContain("e908:c660:a32f:308f")
    expect(String(v6!.data.info)).not.toContain("e908:c660:a32f:308f")
  })

  it("remote/public devices never become device nodes (Devices card counts LOCAL endpoints only)", () => {
    const flows = [{ srcIp: "192.168.1.20", dstIp: "8.8.8.8", protocol: "TCP", packets: 4, bytesTotal: 300 }]
    const devices = [
      { ip: "8.8.8.8", hostname: "", mac: "—", vendor: "Google", os: "" },
      { ip: "203.0.113.9", hostname: "", mac: "—", vendor: "", os: "" },
    ]
    const { nodes } = buildGraphElements({ ...base, devices, flows, geoMap: new Map(), beginnerMode: false })
    // Remote service IPs keep their IP/pcap edges but get NO teal device node.
    expect(nodes.some(n => n.data.id === "dev:8.8.8.8")).toBe(false)
    expect(nodes.some(n => n.data.id === "dev:203.0.113.9")).toBe(false)
    expect(nodes.some(n => n.data.id === "ip:8.8.8.8")).toBe(true)
  })

  it("DNS node counts QUERIES only — responses echo the question and must never double the count (page/report convention)", () => {
    const dns = [
      { query: "example.com", srcIp: "192.168.1.20", dstIp: "8.8.8.8", type: "A", responseCode: "NOERROR" },
      { query: "example.com", srcIp: "192.168.1.20", dstIp: "8.8.8.8", type: "AAAA", responseCode: "NOERROR" },
      { query: "example.com", srcIp: "8.8.8.8", dstIp: "192.168.1.20", type: "A", responseCode: "NOERROR", isResponse: true },
      { query: "example.com", srcIp: "8.8.8.8", dstIp: "192.168.1.20", type: "A", responseCode: "NOERROR", isResponse: true },
      { query: "example.com", srcIp: "8.8.8.8", dstIp: "192.168.1.20", type: "A", responseCode: "NXDOMAIN", isResponse: true },
    ]
    const { nodes } = buildGraphElements({ ...base, devices: [], flows: [], dns, geoMap: new Map(), beginnerMode: false })
    const dnsNode = nodes.find(n => n.data.id === "dns:example.com")
    expect(dnsNode).toBeTruthy()
    const info = String(dnsNode!.data.info)
    expect(info).toContain("Queries: 2")
    expect(info).toContain("A ×1, AAAA ×1")
    expect(info).toContain("Responses: NOERROR ×2, NXDOMAIN ×1")
    expect(info).not.toContain("Queries: 5")
  })

  it("DNS 'resolved' edges attach to the RESOLVER, never to the client on response rows", () => {
    const dns = [
      { query: "example.com", srcIp: "192.168.1.20", dstIp: "8.8.8.8", type: "A", responseCode: "NOERROR" },
      { query: "example.com", srcIp: "8.8.8.8", dstIp: "192.168.1.20", type: "A", responseCode: "NOERROR", isResponse: true },
    ]
    const flows = [{ srcIp: "192.168.1.20", dstIp: "8.8.8.8", protocol: "UDP", packets: 2, bytesTotal: 160 }]
    const { edges } = buildGraphElements({ ...base, devices: [], flows, dns, geoMap: new Map(), beginnerMode: false })
    expect(edges.some(e => e.data.id === "ip:8.8.8.8->dns:example.com" && e.data.label === "resolved")).toBe(true)
    expect(edges.some(e => e.data.source === "ip:192.168.1.20" && String(e.data.label) === "resolved")).toBe(false)
  })

  it("flow edges aggregate per IP PAIR: one edge, summed packets/bytes, both protocols", () => {
    const flows = [
      { srcIp: "192.168.1.20", dstIp: "8.8.8.8", protocol: "UDP", packets: 2, bytesTotal: 160, duration: 3 },
      { srcIp: "192.168.1.20", dstIp: "8.8.8.8", protocol: "TCP", packets: 40, bytesTotal: 40960, duration: 12 },
    ]
    const { edges } = buildGraphElements({ ...base, devices: [], flows, geoMap: new Map(), beginnerMode: false })
    const pairEdges = edges.filter(e => e.data.source === "ip:192.168.1.20" && e.data.target === "ip:8.8.8.8" && e.data.kind === "flow")
    expect(pairEdges).toHaveLength(1)
    const label = String(pairEdges[0].data.label)
    expect(label).toContain("UDP, TCP")
    expect(label).toContain("42pkts")
    expect(label).toContain("40.2 KiB")
    expect(label).toContain("12s")
    expect(pairEdges[0].data.weight).toBeGreaterThan(1)
  })

  it("the undecodable '—|—|0|0|OTHER' flow draws NO flow edge (no self-loop on the unknown endpoint node)", () => {
    const flows = [
      { srcIp: "192.168.1.20", dstIp: "8.8.8.8", protocol: "TCP", packets: 4, bytesTotal: 300 },
      { srcIp: "\u2014", dstIp: "\u2014", protocol: "OTHER", packets: 7, bytesTotal: 420 },
    ]
    const { edges } = buildGraphElements({ ...base, devices: [], flows, geoMap: new Map(), beginnerMode: false })
    expect(edges.some(e => e.data.source === "ip:\u2014" && e.data.target === "ip:\u2014")).toBe(false)
    expect(edges.some(e => e.data.source === "ip:192.168.1.20" && e.data.target === "ip:8.8.8.8")).toBe(true)
  })
})