import { describe, it, expect } from "vitest"
import { deriveMapData, mapPanels, isPrivateIP, clusterByCity, isLanFlow, slaacPrefixesOf } from "@/lib/map-data"
import { isNonUnicast, packetProtocolCounts } from "@/lib/analysis"
import { ownerOfDevices, endpointRowsOf, tcpHealthRttCaption, countryCountsByDst, localOwnedAddresses } from "@/lib/report"
import { computeStats } from "@/lib/stats"

const mk = (n: number, src: string, dst: string, len = 64) => ({
  num: n, timestamp: "2024-01-01T00:00:00Z", srcIp: src, dstIp: dst,
  srcPort: 1, dstPort: 2, protocol: "TCP", length: len, flags: "", ttl: 64, info: "",
})

// WS1 merges: the analyzer's addresses[] field (MAC-joined aliases).
describe("ownerOfDevices", () => {
  it("maps a MAC-merged v6 alias to its private primary", () => {
    const devices = [
      { id: "1", ip: "192.168.1.20", addresses: ["192.168.1.20", "2401:4900:1111:2222::308f"], mac: "aa", vendor: "X" },
      { id: "2", ip: "8.8.8.8", addresses: ["8.8.8.8"], mac: "bb", vendor: "Y" },
    ]
    const owner = ownerOfDevices(devices)
    expect(owner.get("2401:4900:1111:2222::308f")).toBe("192.168.1.20")
    expect(owner.has("192.168.1.20")).toBe(false) // primary key, not an alias
    expect(owner.has("8.8.8.8")).toBe(false) // public primary never owns aliases
  })

  it("folded top-talker count = owner absorbs the alias packets", () => {
    const owner = ownerOfDevices([{ ip: "192.168.1.20", addresses: ["192.168.1.20", "2401::308f"] }])
    const packets = [mk(1, "2401::308f", "8.8.8.8"), mk(2, "192.168.1.20", "8.8.8.8")]
    const seen = new Set<string>()
    for (const p of packets) seen.add(owner.get(p.srcIp) ?? p.srcIp)
    expect([...seen]).toEqual(["192.168.1.20"]) // one host, not two rows
  })
})

// §13 Endpoints: unspecified/multicast placeholders are never rows.
describe("endpointRowsOf", () => {
  it("drops ::, ::1, multicast ff00::/8; keeps local v4/v6 and remotes", () => {
    const rows = endpointRowsOf([
      { ip: "::" }, { ip: "::1" }, { ip: "ff00::1" },
      { ip: "192.168.1.20" }, { ip: "fd00::5" }, { ip: "8.8.8.8" }, { ip: "172.217.26.3" },
    ])
    expect(rows.map((r) => r.ip)).toEqual(["192.168.1.20", "fd00::5", "8.8.8.8", "172.217.26.3"])
    expect(rows.some((r) => r.ip === "::" || r.ip === "::1" || r.ip.startsWith("ff"))).toBe(false)
  })
})

describe("tcpHealthRttCaption", () => {
  it("measured RTTs → average; none → mid-session flows, not 'unavailable'", () => {
    expect(tcpHealthRttCaption([250, 150])).toBe("avg handshake RTT 200 ms")
    expect(tcpHealthRttCaption([])).toBe("no handshakes captured (mid-session flows)")
  })
})

// B-58: the fixture emits the unspecified/loopback IPv6 placeholders in FULL
// form (0:0:0:0:0:0:0:0), which the compressed :: checks used to miss — the
// unspecified address then went to GeoIP and surfaced as a fake "no GeoIP"
// unresolved external on the map and an inflated external_ips count.
describe("full-form IPv6 placeholders", () => {
  it("isPrivateIP treats 0:0:0:0:0:0:0:0 / 0:0:0:0:0:0:0:1 like :: / ::1", () => {
    for (const ip of ["0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "::", "::1", "::ffff:10.0.0.1"]) {
      expect(isPrivateIP(ip), ip).toBe(true)
    }
  })

  it("isNonUnicast rejects the full-form placeholders (external_ips parity)", () => {
    expect(isNonUnicast("0:0:0:0:0:0:0:0")).toBe(true)
    expect(isNonUnicast("0:0:0:0:0:0:0:1")).toBe(true)
    expect(isNonUnicast("::")).toBe(true)
    expect(isNonUnicast("8.8.8.8")).toBe(false)
  })

  it("deriveMapData never draws or lists the full-form unspecified address", () => {
    const packets = [
      mk(1, "0:0:0:0:0:0:0:0", "101.2.27.162", 64), // unspecified → private, never a GeoIP lookup
      mk(2, "192.168.1.20", "101.2.27.162", 64),
      mk(3, "192.168.1.20", "203.0.113.9", 64), // genuinely unresolved public → undrawn
    ]
    const data = deriveMapData(packets, new Map([
      ["101.2.27.162", { country: "India", countryCode: "IN", city: "Bengaluru", lat: 12.9716, lon: 77.5946, isPrivate: false }],
    ]))
    expect(data.undrawnPublic.map((u) => u.ip)).toEqual(["203.0.113.9"]) // only the real miss
    expect(data.nodes.some((n) => n.ip.includes("0:0:0:0"))).toBe(false)
    expect(data.localSummary.hosts).toBe(1) // unspecified is not a machine
  })
})

// B-54 map data-layer: geo-wired publics become dots, private never drawn.
describe("clusterByCity (B-60 dot pile-up)", () => {
  const node = (ip: string, countryCode: string, city: string, lat: number, lon: number) => ({ ip, countryCode, city, lat, lon })

  it("merges same-cell dots per country and keeps distant cities separate", () => {
    const clusters = clusterByCity([
      node("101.2.27.162", "IN", "Bengaluru", 12.97, 77.59),
      node("1.2.3.4", "IN", "Bengaluru", 12.97, 77.6),
      // Same country, same 1° cell → one cluster; Seattle is far → separate.
      node("1.2.3.5", "IN", "Mumbai", 19.07, 72.87),
      node("9.9.9.9", "US", "Seattle", 47.6, -122.33),
    ])
    expect(clusters).toHaveLength(3)
    const blr = clusters.find((c) => c.ips.includes("101.2.27.162"))
    expect(blr!.ips).toEqual(["101.2.27.162", "1.2.3.4"])
    expect(blr!.lat).toBeCloseTo(12.97, 2) // centroid of the two Bengaluru dots
  })

  it("merges metro-area rows even when city labels differ (Dadri vs Noida)", () => {
    const clusters = clusterByCity([
      node("1.1.1.1", "IN", "Delhi", 28.66, 77.2),
      node("2.2.2.2", "IN", "Dadri", 28.55, 77.6),
      node("3.3.3.3", "IN", "Greater Noida", 28.54, 77.33),
      node("4.4.4.4", "IN", "Chennai", 13.08, 80.27),
    ])
    expect(clusters).toHaveLength(2) // Delhi metro pile merges; Chennai is a separate cell
    expect(clusters.find((c) => c.ips.length === 3)!.ips).toEqual(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
  })
})

// B-61 census classification: "local host / LAN traffic" means private
// UNICAST. The DHCPv6 client (0:0:0:0:0:0:0:0), the DHCPv4 pair (0.0.0.0,
// 255.255.255.255) and multicast peers pass isPrivateIP but are never LAN
// peers — the private-unicast predicate used by stats.devices, the LAN card,
// and external_ips must reject every one of them (QA: 5→6 census drift when
// the full-form :: became "private").
describe("private-unicast census predicate (B-61)", () => {
  const isLocalPeer = (ip: string) => isPrivateIP(ip) && !isNonUnicast(ip)

  it("rejects every non-unicast LAN artifact", () => {
    for (const ip of ["0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "::", "::1", "ff02::1:2", "ff02::fb", "0.0.0.0", "255.255.255.255", "224.0.0.251"]) {
      expect(isLocalPeer(ip), ip).toBe(false)
    }
  })

  it("keeps real hosts", () => {
    for (const ip of ["192.168.1.1", "192.168.1.20", "10.0.0.5", "fe80::1", "fd00::1"]) {
      expect(isLocalPeer(ip), ip).toBe(true)
    }
  })

  it("a device row on a full-form unspecified address never counts (stats.devices)", () => {
    const dev = (id: string, ip: string) => ({ id, ip, mac: "aa:bb:cc:dd:ee:ff", hostname: "", vendor: "", os: "", firstSeen: "", lastSeen: "", packets: 1, bytes: 1 })
    const stats = computeStats({
      job: null,
      packets: [],
      flows: [], sessions: [], dns: [], alerts: [],
      devices: [dev("d1", "192.168.1.20"), dev("d2", "192.168.1.1"), dev("d3", "0:0:0:0:0:0:0:0")],
      geo: new Map(),
    })
    expect(stats.devices).toBe(2)
  })
})

// B-59: Top Protocols chips on the map must count packets by protocol label —
// the exact classifier the Protocol Distribution panel uses — so the flat
// map, the globe, and the panel can never show different numbers.
describe("map chips match the panel classifier", () => {
  it("packetProtocolCounts over the same packets equals the panel totals", () => {
    const packets = [
      { ...mk(1, "192.168.1.20", "101.2.27.162"), protocol: "TCP" },
      { ...mk(2, "192.168.1.20", "101.2.27.162"), protocol: "TCP" },
      { ...mk(3, "192.168.1.20", "8.8.8.8"), protocol: "UDP" },
      { ...mk(4, "192.168.1.20", "8.8.8.8"), protocol: "HOPOPT" },
      { ...mk(5, "192.168.1.20", "8.8.8.8"), protocol: "ARP" },
    ]
    const counts = packetProtocolCounts(packets)
    expect(counts).toEqual({ TCP: 2, UDP: 1, HOPOPT: 1, ARP: 1 })
    // sorted chips the map renders
    expect([...Object.entries(counts)].sort((a, b) => b[1] - a[1]).slice(0, 6)[0]).toEqual(["TCP", 2])
  })

  it("chips include LAN-only protocols (ARP) that node aggregates drop", () => {
    const packets = [
      { ...mk(1, "192.168.1.20", "192.168.1.255"), protocol: "ARP" }, // LAN-only: never a node
      { ...mk(2, "192.168.1.20", "101.2.27.162"), protocol: "UDP" },
    ]
    const data = deriveMapData(packets, new Map([
      ["101.2.27.162", { country: "India", countryCode: "IN", city: "Bengaluru", lat: 12.9716, lon: 77.5946, isPrivate: false }],
    ]))
    const nodeAggregated = new Map<string, number>()
    for (const n of data.nodes) for (const [p, c] of Object.entries(n.protocols)) nodeAggregated.set(p, (nodeAggregated.get(p) || 0) + c)
    const panel = packetProtocolCounts(packets)
    expect(nodeAggregated.has("ARP")).toBe(false) // old chips would drop it…
    expect(panel.ARP).toBe(1) // …the panel counts it
  })
})
describe("map data layer (flat map parity)", () => {
  const geo = new Map<string, { country: string; countryCode: string; city: string; lat: number; lon: number; isPrivate: boolean }>([
    // Bengaluru for 101.2.27.162 (IN) — B-54 acceptance coordinates.
    ["101.2.27.162", { country: "India", countryCode: "IN", city: "Bengaluru", lat: 12.9716, lon: 77.5946, isPrivate: false }],
    ["44.225.104.163", { country: "Australia", countryCode: "AU", city: "Sydney", lat: -33.8688, lon: 151.2093, isPrivate: false }],
    ["52.84.122.53", { country: "United States", countryCode: "US", city: "Seattle", lat: 47.6062, lon: -122.3321, isPrivate: false }],
  ])

  it("a public IP with a location becomes a drawn node at its coords; privates never drawn", () => {
    const packets = [
      mk(1, "192.168.1.20", "101.2.27.162", 512),
      mk(2, "192.168.1.20", "44.225.104.163", 128),
      mk(3, "192.168.1.20", "203.0.113.9", 64), // unresolved → undrawnPublic
      mk(4, "101.2.27.162", "44.225.104.163", 256), // public→public → an arc
    ]
    const data = deriveMapData(packets, geo)
    expect(data.nodes.length).toBe(2) // resolved public IPs only
    const inode = data.nodes.find((n) => n.ip === "101.2.27.162")
    expect(inode).toBeDefined()
    expect(inode!.countryCode).toBe("IN")
    expect(inode!.lat).toBeCloseTo(12.9716, 2)
    expect(inode!.lon).toBeCloseTo(77.5946, 2)
    expect(data.nodes.some((n) => isPrivateIP(n.ip))).toBe(false) // private never drawn
    expect(data.localSummary.hosts).toBe(1)
    expect(data.undrawnPublic.map((u) => u.ip)).toEqual(["203.0.113.9"])
    expect(data.arcs.length).toBeGreaterThanOrEqual(1)
  })

  it("mapPanels ranks Top Countries by bytes and counts the drawn/undrawn split", () => {
    const packets = [
      mk(1, "192.168.1.20", "101.2.27.162", 5120), // IN heavy
      mk(2, "192.168.1.20", "44.225.104.163", 1280),
      mk(3, "192.168.1.20", "52.84.122.53", 64),
      mk(4, "192.168.1.20", "203.0.113.9", 64), // not drawn
    ]
    const data = deriveMapData(packets, geo)
    const panels = mapPanels(data)
    expect(panels.topCountries[0].name).toBe("India")
    expect(panels.topCountries[0].bytes).toBe(5120)
    expect(panels.drawnNodes).toBe(3)
    expect(panels.undrawnCount).toBe(1)
    expect(panels.localHosts).toBe(1)
    expect(panels.drawnBytes).toBe(data.arcs.reduce((s, a) => s + a.bytes, 0) + data.localPublicFlows.reduce((s, f) => s + f.bytes, 0))
  })

  it("all-unresolved public traffic → zero nodes, every peer in undrawnPublic", () => {
    const packets = [mk(1, "192.168.1.20", "203.0.113.9"), mk(2, "192.168.1.20", "198.51.100.7")]
    const data = deriveMapData(packets, new Map())
    expect(data.nodes).toHaveLength(0)
    expect(data.undrawnPublic).toHaveLength(2)
  })
})

// B-68: the LAN card predicate. Source must be a private UNICAST host;
// destination must NOT be a public-unicast IP. Multicast/broadcast/private
// destinations are LAN peers — the old "both ends private unicast" rule
// dropped 97 packets of local→multicast/broadcast traffic (QA: LAN card read
// 2.4 KB/31 pkts vs the true 13.9 KB/128).
describe("isLanFlow (B-68)", () => {
  it("rejects non-unicast sources (interface chatter, never LAN peers)", () => {
    for (const src of ["0:0:0:0:0:0:0:0", "0.0.0.0", "::", "ff02::1:2", "224.0.0.251"]) {
      expect(isLanFlow(src, "192.168.1.3"), src).toBe(false)
    }
  })

  it("rejects egress: private source → public-unicast destination", () => {
    expect(isLanFlow("192.168.1.20", "8.8.8.8")).toBe(false)
    expect(isLanFlow("192.168.1.20", "2401:4900:9999::1")).toBe(false)
  })

  it("accepts private→multicast/broadcast and private→private (mDNS, SSDP, HOPOPT→ff02::)", () => {
    expect(isLanFlow("192.168.1.20", "224.0.0.251")).toBe(true) // mDNS
    expect(isLanFlow("192.168.1.20", "239.255.255.250")).toBe(true) // SSDP
    expect(isLanFlow("192.168.1.20", "ff02::fb")).toBe(true)
    expect(isLanFlow("192.168.1.20", "ff02::1:2")).toBe(true) // HOPOPT
    expect(isLanFlow("192.168.1.20", "192.168.1.255")).toBe(true) // broadcast
    expect(isLanFlow("192.168.1.20", "192.168.1.3")).toBe(true)
    expect(isLanFlow("fe80::1", "ff02::1:2")).toBe(true)
  })

  it("calls.pcap contract: 131 packets − 3 unspecified-sourced = 128 LAN pkts", () => {
    const packets: ReturnType<typeof mk>[] = []
    let n = 0
    for (let i = 0; i < 3; i++) packets.push(mk(++n, "0:0:0:0:0:0:0:0", "ff02::1:2", 64)) // DHCPv6 chatter — not LAN
    for (let i = 0; i < 97; i++) packets.push(mk(++n, "192.168.1.20", "224.0.0.251", 96)) // mDNS/SSDP — LAN
    for (let i = 0; i < 31; i++) packets.push(mk(++n, "192.168.1.20", "192.168.1.3", 128)) // private↔private — LAN
    const lanPkts = packets.filter((p) => isLanFlow(p.srcIp!, p.dstIp!)).length
    expect(packets.length).toBe(131)
    expect(lanPkts).toBe(128)
  })
})

// B-69: MAC-merged aliases of LOCAL devices (ownerOfDevices keys) are the
// same machine as their private primary — the map must never plot them as
// external dots, and the report must never credit their traffic to an
// external country (QA: India read 4 IPs / 173.3 KB for the client's own
// 2401:…:308f/f027/234c aliases + its 2401::1 router).
describe("local-device aliases stay off the map and out of country stats (B-69)", () => {
  const ALIAS = "2401:4900:1:2::308f"
  const geo = new Map<string, { country: string; countryCode: string; city: string; lat: number; lon: number; isPrivate: boolean }>([
    ["101.2.27.162", { country: "India", countryCode: "IN", city: "Bengaluru", lat: 12.9716, lon: 77.5946, isPrivate: false }],
    ["44.225.104.163", { country: "Australia", countryCode: "AU", city: "Sydney", lat: -33.8688, lon: 151.2093, isPrivate: false }],
  ])
  const aliases = new Set<string>([ALIAS])

  it("deriveMapData drops the alias node/arcs but keeps the peer's bytes (plotted 21 → 17)", () => {
    const packets = [
      mk(1, ALIAS, "101.2.27.162", 512), // alias→peer: peer keeps the bytes, no alias node
      mk(2, "192.168.1.20", "101.2.27.162", 1024),
      mk(3, "192.168.1.20", "44.225.104.163", 128),
    ]
    const data = deriveMapData(packets, geo, aliases)
    expect(data.nodes.some((n) => n.ip === ALIAS)).toBe(false)
    expect(data.nodes).toHaveLength(2) // peer + AU only
    const peer = data.nodes.find((n) => n.ip === "101.2.27.162")
    expect(peer!.bytes).toBe(1536) // alias-side traffic still counts on the peer
    expect(data.arcs).toHaveLength(0) // alias→peer arc must not draw
    const panels = mapPanels(data)
    expect(panels.drawnNodes).toBe(2)
    expect(panels.topCountries[0]).toEqual({ name: "India", code: "IN", bytes: 1536 })
  })

  it("aliases with no GeoIP never land in undrawnPublic", () => {
    const packets = [mk(1, ALIAS, "203.0.113.9", 64)]
    const data = deriveMapData(packets, new Map(), aliases)
    expect(data.nodes).toHaveLength(0)
    expect(data.undrawnPublic.map((u) => u.ip)).toEqual(["203.0.113.9"]) // the real peer stays; the alias is local, not an unresolved external
  })

  it("countryCountsByDst skips local-owned destinations (§8 Top Countries)", () => {
    const packets = [
      mk(1, "192.168.1.20", "101.2.27.162"),
      mk(2, "101.2.27.162", ALIAS), // traffic TO the local alias used to credit India
      mk(3, "192.168.1.20", "44.225.104.163"),
    ]
    const counts = countryCountsByDst(packets, geo, aliases)
    expect(counts.get("IN")).toBe(1) // the peer's own row only — alias traffic skipped
    expect(counts.get("AU")).toBe(1)
  })
})

// B-72: the merge closure — MAC groups plus /64 SLAAC ownership. The plain
// addresses[] rule caught only …:308f; the router's global (same MAC as
// fe80::1) and the no-MAC /64 siblings …:f027/…:234c still plotted as
// external India IPs (20 plotted vs the true 17).
describe("extended local ownership (B-72)", () => {
  it("slaacPrefixesOf extracts clean /64s, skips private and short forms", () => {
    const p = slaacPrefixesOf(["2401:4900:1:2::308f", "2401:4900:8910:960f::1", "::1", "fe80::1", "2001:db8::1", "8.8.8.8"])
    expect(p).toEqual(new Set(["2401:4900:1:2:", "2401:4900:8910:960f:"]))
  })

  it("localOwnedAddresses folds MAC groups and /64 siblings, not just addresses[]", () => {
    const devices = [
      { id: "1", ip: "192.168.1.20", addresses: ["192.168.1.20", "2401:4900:1:2::308f"], mac: "aa:bb:01" },
      { id: "2", ip: "2401:4900:8910:960f::1", addresses: ["2401:4900:8910:960f::1"], mac: "aa:bb:01" }, // router: same MAC, public primary
      { id: "3", ip: "2401:4900:1:2::f027", addresses: [], mac: "—" }, // /64 sibling, no MAC evidence
      { id: "4", ip: "8.8.8.8", addresses: ["8.8.8.8"], mac: "cc:dd:02" }, // genuine remote
    ]
    const owned = localOwnedAddresses(devices)
    expect(owned.has("2401:4900:1:2::308f")).toBe(true) // rule 1: addresses[]
    expect(owned.has("2401:4900:8910:960f::1")).toBe(true) // rule 2: MAC group
    expect(owned.has("2401:4900:1:2::f027")).toBe(true) // rule 3: /64 sibling
    expect(owned.has("8.8.8.8")).toBe(false)
  })

  it("localOwnedAddresses treats a home-prefix PUBLIC primary as local when a private alias exists — the map can never draw more nodes than the report's external IPs (QA)", () => {
    // The byte-tie merge can leave a delegated home-prefix v6 as a device
    // row's PRIMARY. stats.ts/analysis.ts exclude it via its private alias;
    // the map's alias set must do the same or the LAN's own v6 draws as a
    // phantom external dot (screenshot: 7 markers for 5 external IPs).
    const devices = [
      { id: "1", ip: "2401:4900:1:2::100", addresses: ["192.168.1.20", "2401:4900:1:2::100"], mac: "aa:bb:01" },
      { id: "2", ip: "8.8.8.8", addresses: ["8.8.8.8"], mac: "cc:dd:02" },
    ]
    const owned = localOwnedAddresses(devices)
    expect(owned.has("2401:4900:1:2::100")).toBe(true)
    expect(owned.has("192.168.1.20")).toBe(true)
    expect(owned.has("8.8.8.8")).toBe(false)
    // End-to-end: the phantom v6 never reaches the globe as a node.
    const geo = new Map<string, { country: string; countryCode: string; city: string; lat: number; lon: number; isPrivate: boolean }>([
      ["2401:4900:1:2::100", { country: "India", countryCode: "IN", city: "Mumbai", lat: 19.07, lon: 72.87, isPrivate: false }],
      ["8.8.8.8", { country: "United States", countryCode: "US", city: "Mountain View", lat: 37.386, lon: -122.084, isPrivate: false }],
    ])
    const data = deriveMapData([
      mk(1, "2401:4900:1:2::100", "8.8.8.8", 256),
      mk(2, "192.168.1.20", "8.8.8.8", 128),
    ], geo, owned)
    expect(data.nodes.map((n) => n.ip)).toEqual(["8.8.8.8"])
    expect(data.undrawnPublic).toHaveLength(0)
  })

  it("deriveMapData hides /64 siblings of aliases even without MAC data", () => {
    const geo = new Map<string, { country: string; countryCode: string; city: string; lat: number; lon: number; isPrivate: boolean }>([
      ["101.2.27.162", { country: "India", countryCode: "IN", city: "Bengaluru", lat: 12.9716, lon: 77.5946, isPrivate: false }],
    ])
    const packets = [
      mk(1, "2401:4900:1:2::308f", "101.2.27.162", 512), // owned alias
      mk(2, "2401:4900:1:2::f027", "101.2.27.162", 256), // same /64, not in the alias set
      mk(3, "192.168.1.20", "101.2.27.162", 1024),
    ]
    const data = deriveMapData(packets, geo, new Set(["2401:4900:1:2::308f"]))
    expect(data.nodes).toHaveLength(1) // peer only — both alias forms hidden
    expect(data.nodes[0].ip).toBe("101.2.27.162")
  })
})

// B-71: local↔public traffic — the map's connection layer after aliases became
// local. Flows are aggregated per peer (with directional pair counts), the
// peer's dot keeps the bytes, "drawn bytes" includes them, and the peer gets
// the "↔ your local network" tooltip flag.
describe("local↔public flows (B-71)", () => {
  const geo = new Map<string, { country: string; countryCode: string; city: string; lat: number; lon: number; isPrivate: boolean }>([
    ["101.2.27.162", { country: "India", countryCode: "IN", city: "Bengaluru", lat: 12.9716, lon: 77.5946, isPrivate: false }],
  ])

  it("aggregates per peer, counts directional pairs, stamps localConns, keeps bytes on the dot", () => {
    const packets = [
      { ...mk(1, "192.168.1.20", "101.2.27.162", 512), protocol: "UDP" },
      mk(2, "101.2.27.162", "192.168.1.20", 128),
      mk(3, "2401:4900:1:2::308f", "101.2.27.162", 256), // alias side — same peer
      mk(4, "192.168.1.20", "192.168.1.3", 64), // LAN-only: never a local↔public flow
    ]
    const data = deriveMapData(packets, geo, new Set(["2401:4900:1:2::308f"]))
    expect(data.localPublicFlows).toHaveLength(1)
    const f = data.localPublicFlows[0]
    expect(f.peerIp).toBe("101.2.27.162")
    expect(f.bytes).toBe(896)
    expect(f.packets).toBe(3)
    expect(f.flows).toBe(3) // three directional pairs: .20→peer, peer→.20, alias→peer
    // Dominant protocol by bytes rides along so home arcs can be colored
    // per protocol instead of legend-gray (QA: all local↔public arcs gray).
    expect(f.protocol).toBe("UDP") // 512+256 UDP beats the 128 TCP return
    // Directional bytes: .20→peer (512) + alias→peer (256) are outbound;
    // the peer→.20 return (128) is inbound — home arcs color blue/green by it.
    expect(f.outBytes).toBe(768)
    expect(f.inBytes).toBe(128)
    // Per-direction packets so the DRAWN strip can sum packets over the same
    // arcs as bytes (QA: drawn PKTS used to be capture-wide, 152 vs 148).
    expect(f.outPackets).toBe(2)
    expect(f.inPackets).toBe(1)
    const peer = data.nodeMap.get("101.2.27.162")!
    expect(peer.bytes).toBe(896) // alias-side traffic still sized on the dot
    expect(peer.localConns).toBe(3)
    const panels = mapPanels(data)
    expect(panels.drawnBytes).toBe(896) // local↔public counts as drawn
    expect(panels.drawnNodes).toBe(1)
  })

  it("LAN-only captures produce zero local↔public flows", () => {
    const packets = [mk(1, "192.168.1.20", "192.168.1.3", 64), mk(2, "192.168.1.20", "224.0.0.251", 96)]
    const data = deriveMapData(packets, geo)
    expect(data.localPublicFlows).toHaveLength(0)
    expect(data.arcs).toHaveLength(0)
    expect(mapPanels(data).drawnBytes).toBe(0)
  })

  it("a peer without GeoIP still counts bytes/flows but never becomes an arc", () => {
    const packets = [mk(1, "192.168.1.20", "203.0.113.9", 64)]
    const data = deriveMapData(packets, new Map())
    expect(data.localPublicFlows[0].peerIp).toBe("203.0.113.9")
    expect(data.localPublicFlows[0].bytes).toBe(64)
    expect(data.arcs).toHaveLength(0)
    expect(mapPanels(data).drawnBytes).toBe(64) // counted as drawn, not an arc
  })
})
