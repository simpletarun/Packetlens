import { describe, it, expect } from "vitest"
import { deriveMapData, isPrivateIP, homeAnchorFromOwnedPublic, topCountriesOf, mapPanels } from "@/lib/map-data"

const mk = (n: number, src: string, dst: string, len = 64) => ({
  num: n, timestamp: "2024-01-01T00:00:00Z", srcIp: src, dstIp: dst,
  srcPort: 1, dstPort: 2, protocol: "TCP", length: len, flags: "", ttl: 64, info: "",
})

const PRIVATES = ["192.168.1.5", "10.0.0.2", "100.64.0.9"]
const PUBLICS = ["8.8.8.8", "1.1.1.1"]

const publicGeo = () => new Map(
  PUBLICS.map((ip, i) => [ip, {
    ip, country: "Country", countryCode: ["US", "AU"][i], city: "City",
    lat: [37.386, -33.8688][i], lon: [-122.084, 151.2093][i], isPrivate: false,
  }]),
)

describe("deriveMapData — globe draws public IPs only", () => {
  it("3 private + 2 geo publics → nodes are only the 2 publics, none at the old Local Network zone", () => {
    const packets = [
      mk(1, PRIVATES[0], PUBLICS[0]),
      mk(2, PRIVATES[1], PUBLICS[1]),
      mk(3, PRIVATES[0], PRIVATES[2]),
      mk(4, PRIVATES[1], PRIVATES[2]),
      mk(5, PUBLICS[0], PUBLICS[1]),
    ]
    const data = deriveMapData(packets, publicGeo())
    expect(data.nodes).toHaveLength(2)
    expect(data.nodes.map(n => n.ip).sort()).toEqual([...PUBLICS].sort())
    for (const n of data.nodes) {
      expect(n.isPrivate).toBe(false)
      expect(n.lat).toBeGreaterThan(-90)
      expect(n.lat).not.toBeLessThan(-45)  // never the -40 "Local Network" line
    }
    expect(data.localSummary.hosts).toBe(3)
    expect(data.arcs).toHaveLength(1)
  })

  it("no GeoIP → 0 nodes/arcs, undrawnPublic counts public peers by bytes, localSummary intact", () => {
    const packets = [mk(1, PRIVATES[0], PUBLICS[0], 128), mk(2, PRIVATES[0], PRIVATES[2], 64)]
    const data = deriveMapData(packets)
    expect(data.nodes).toHaveLength(0)
    expect(data.arcs).toHaveLength(0)
    expect(data.undrawnPublic).toHaveLength(1)
    expect(data.undrawnPublic[0].ip).toBe(PUBLICS[0])
    expect(data.undrawnPublic[0].bytes).toBe(128)
    expect(data.undrawnPublic[0].packets).toBe(1)
    expect(data.localSummary.hosts).toBe(2)
    expect(data.localSummary.bytes).toBe(64) // LAN-only packet, not the private→public one
  })

  it("public↔public arc drawn; private-involved flows never become arcs", () => {
    const data = deriveMapData([
      mk(1, PUBLICS[0], PUBLICS[1]),
      mk(2, PRIVATES[0], PUBLICS[0]),
      mk(3, PRIVATES[0], PRIVATES[1]),
    ], publicGeo())
    expect(data.arcs).toHaveLength(1)
    expect(`${data.arcs[0].srcIp}>${data.arcs[0].dstIp}`).toBe(`${PUBLICS[0]}>${PUBLICS[1]}`)
    expect(data.arcs[0].coordinates.length).toBeGreaterThan(2)
  })

  it("localSummary bytes count only LAN traffic (both endpoints private), top host by LAN bytes", () => {
    const data = deriveMapData([
      mk(1, PRIVATES[0], PRIVATES[2], 100),
      mk(2, PRIVATES[0], PUBLICS[0], 900),
      mk(3, PRIVATES[1], PRIVATES[2], 50),
    ], publicGeo())
    expect(data.localSummary.bytes).toBe(150)
    expect(data.localSummary.packets).toBe(2)
    expect(data.localSummary.topHost).toBe(PRIVATES[2])
  })

  it("localSummary uses the SAME definition as the page LAN card (isLanFlow) — placeholder-sourced chatter excluded (QA: 14.1 vs 13.4 KB)", () => {
    const data = deriveMapData([
      mk(1, "0.0.0.0", "192.168.1.5", 64), // placeholder source — not a LAN peer
      mk(2, "192.168.1.5", "ff02::fb", 32), // private→multicast — LAN
      mk(3, "192.168.1.5", "10.0.0.2", 48), // private↔private — LAN
    ])
    expect(data.localSummary.packets).toBe(2)
    expect(data.localSummary.bytes).toBe(80)
    expect(data.localSummary.topHost).toBe("192.168.1.5")
  })
})

describe("deriveMapData — globe draws only IPs with a resolved country", () => {
  it("no GeoIP DB: nodes 0, every public peer counted undrawn, nothing placed at (0,0) or elsewhere", () => {
    const publics = ["8.8.8.8", "1.1.1.1", "203.0.113.9", "93.184.216.34"]
    const packets = publics.map((ip, i) => mk(i + 1, PRIVATES[0], ip, 100 + i))
    const data = deriveMapData(packets)
    expect(data.nodes).toHaveLength(0)
    expect(data.arcs).toHaveLength(0)
    expect(data.undrawnPublic).toHaveLength(publics.length)
    expect(data.undrawnPublic[0].ip).toBe("93.184.216.34") // 103 B — most bytes
    expect(data.undrawnPublic.every(u => u.bytes > 0)).toBe(true)
  })

  it("an 'Unknown'/?? geo row (fabricated fallback) is never drawable — same as a miss", () => {
    const junkGeo = new Map([[PUBLICS[0], { ip: PUBLICS[0], country: "Unknown", countryCode: "??", city: "", lat: -39.6, lon: 83.1, isPrivate: false }]])
    const data = deriveMapData([mk(1, PRIVATES[0], PUBLICS[0])], junkGeo)
    expect(data.nodes).toHaveLength(0)
    expect(data.nodeMap.has(PUBLICS[0])).toBe(false)
    expect(data.undrawnPublic).toHaveLength(1)
    expect(data.undrawnPublic[0].ip).toBe(PUBLICS[0])
  })

  it("mocked DB: nodes at country centroids, undrawn empty, arcs drawn", () => {
    const data = deriveMapData([mk(1, PRIVATES[0], PUBLICS[0]), mk(2, PUBLICS[0], PUBLICS[1])], publicGeo())
    expect(data.nodes).toHaveLength(2)
    expect(data.undrawnPublic).toHaveLength(0)
    expect(data.nodeMap.get(PUBLICS[0])!.lat).toBe(37.386)
    expect(data.nodeMap.get(PUBLICS[1])!.lat).toBe(-33.8688)
    expect(data.arcs).toHaveLength(1)
  })

  it("parity: drawn + undrawn === unique public IPs in the capture", () => {
    const packets = [
      mk(1, PRIVATES[0], PUBLICS[0]),
      mk(2, PRIVATES[0], "203.0.113.9"),
      mk(3, PUBLICS[1], "9.9.9.9"),
      mk(4, PUBLICS[0], PUBLICS[1]),
    ]
    const data = deriveMapData(packets, publicGeo())
    const uniquePublics = new Set<string>()
    for (const p of packets) {
      if (!isPrivateIP(p.srcIp)) uniquePublics.add(p.srcIp)
      if (!isPrivateIP(p.dstIp)) uniquePublics.add(p.dstIp)
    }
    const drawn = new Set(data.nodes.map(n => n.ip))
    const undrawn = new Set(data.undrawnPublic.map(u => u.ip))
    expect(drawn.size + undrawn.size).toBe(uniquePublics.size)
    expect([...drawn].filter(ip => undrawn.has(ip))).toHaveLength(0)
  })

  it("tracks bytesSent/bytesRecv per node for the metadata panel", () => {
    const data = deriveMapData([
      mk(1, PUBLICS[0], PUBLICS[1], 100), // 8.8.8.8 sends
      mk(2, PUBLICS[1], PUBLICS[0], 50),  // 8.8.8.8 receives
    ], publicGeo())
    const n = data.nodeMap.get(PUBLICS[0])!
    expect(n.bytesSent).toBe(100)
    expect(n.bytesRecv).toBe(50)
    expect(n.bytes).toBe(150)
    expect(n.isSource).toBe(true)
    expect(n.isDest).toBe(true)
  })
})

describe("isPrivateIP", () => {
  it("treats private/LAN/non-routable artifacts as non-public", () => {
    for (const ip of ["192.168.1.1", "10.0.0.1", "100.64.0.1", "169.254.1.5", "224.0.0.251"]) {
      expect(isPrivateIP(ip)).toBe(true)
    }
    expect(isPrivateIP("::")).toBe(true)
    expect(isPrivateIP("::ffff:0.0.0.0")).toBe(true)
    expect(isPrivateIP("8.8.8.8")).toBe(false)
    expect(isPrivateIP("1.1.1.1")).toBe(false)
  })
})

describe("deriveMapData — local host counting matches the MAC-merged devices", () => {
  it("unspecified ::, multicast ff02 and link-local fe80 are not local hosts or external IPs", () => {
    const noise = [
      mk(1, "192.168.1.5", "::"),
      mk(2, "192.168.1.5", "ff02::2"),
      mk(3, "fe80::123", "ff02::1"),
      mk(4, "192.168.1.5", "10.0.0.2"),
    ]
    const data = deriveMapData(noise)
    // Only the two real unicast LAN hosts count; :: / multicast / link-local
    // are interface chatter, not machines.
    expect(data.localSummary.hosts).toBe(2)
    expect(data.undrawnPublic).toHaveLength(0)
    expect(data.nodes).toHaveLength(0)
  })

  it("pure IPv6 link-local capture reports 0 hosts (no MAC merge possible from raw IPs)", () => {
    const data = deriveMapData([mk(1, "fe80::1", "fe80::2")])
    expect(data.localSummary.hosts).toBe(0)
  })
})

describe("deriveMapData — undecodable/placeholder artifacts (B-45/B-48)", () => {
  it("\"—\" packets surface as undecodable/other — never a fake external IP or LAN traffic", () => {
    const data = deriveMapData([
      mk(1, "\u2014", "\u2014", 200),
      mk(2, "\u2014", "8.8.8.8", 300),
      mk(3, "192.168.1.5", "10.0.0.2", 64),
    ], publicGeo())
    expect(data.nodes.map(n => n.ip)).toEqual(["8.8.8.8"])
    expect(data.undrawnPublic).toHaveLength(0)
    expect(data.undecodable).toEqual({ packets: 2, bytes: 500 }) // one per "—" side
    expect(data.localSummary.hosts).toBe(2)
    expect(data.localSummary.bytes).toBe(64) // placeholders never pollute LAN bytes
  })

  it("\":: \" (unspecified with trailing space) is private like \"::\" — not an unresolved external", () => {
    const data = deriveMapData([
      mk(1, ":: ", "192.168.1.5", 40),
      mk(2, "192.168.1.5", "8.8.8.8", 100),
    ], publicGeo())
    expect(data.undrawnPublic).toHaveLength(0)
    expect(data.undecodable.packets).toBe(0)
    expect(data.localSummary.hosts).toBe(1) // only the real unicast LAN host
  })

  it("\":: \" is no local host either — trailing-space unspecified never inflates hosts", () => {
    const data = deriveMapData([
      mk(1, ":: ", "ff02::2", 30),
      mk(2, "192.168.1.5", ":: ", 50),
    ])
    expect(data.localSummary.hosts).toBe(1)
  })
})

describe("homeAnchorFromOwnedPublic (B-75) — local↔public arcs anchor offline", () => {
  const geo = new Map([
    ["2401:4900:8910:960f::1", { ip: "2401:4900:8910:960f::1", country: "India", countryCode: "IN", city: "Mumbai", lat: 19.07, lon: 72.87, isPrivate: false }],
    ["8.8.8.8", { ip: "8.8.8.8", country: "United States", countryCode: "US", city: "Mountain View", lat: 37.386, lon: -122.084, isPrivate: false }],
  ])

  it("returns the first geocoded OWNED public address (router /64 → ISP PoP)", () => {
    const aliases = new Set(["192.168.1.20", "2401:4900:8910:960f:e908:c660:a32f:308f", "2401:4900:8910:960f::1"])
    const anchor = homeAnchorFromOwnedPublic(aliases, geo as never)
    expect(anchor).toEqual({ lat: 19.07, lon: 72.87 })
  })

  it("private primaries are never an anchor", () => {
    const aliases = new Set(["192.168.1.20", "fe80::1"])
    expect(homeAnchorFromOwnedPublic(aliases, geo as never)).toBeNull()
  })

  it("an owned public with no geo (or only '??') yields nothing — no fabrication", () => {
    const aliases = new Set(["2401:4900:8910:960f::1"])
    expect(homeAnchorFromOwnedPublic(aliases, new Map())).toBeNull()
    const junk = new Map([["2401:4900:8910:960f::1", { ip: "x", country: "Unknown", countryCode: "??", city: "", lat: 0, lon: 0, isPrivate: false }]])
    expect(homeAnchorFromOwnedPublic(aliases, junk as never)).toBeNull()
  })
})

describe("MapArc shape (memory)", () => {
  it("arcs never retain per-packet timestamp arrays — nothing consumed them and they held O(packets) memory (QA)", () => {
    const data = deriveMapData([
      mk(1, PUBLICS[0], PUBLICS[1], 64),
      mk(2, PUBLICS[0], PUBLICS[1], 64),
    ], publicGeo())
    expect(data.arcs).toHaveLength(1)
    expect("timestamps" in data.arcs[0]).toBe(false)
    expect(data.arcs[0].packets).toBe(2)
    expect(data.arcs[0].bytes).toBe(128)
  })
})

describe("topCountriesOf (search-filtered Top Countries)", () => {
  const geo = new Map([
    ["8.8.8.8", { ip: "8.8.8.8", country: "United States", countryCode: "US", city: "", lat: 37, lon: -122, isPrivate: false }],
    ["1.1.1.1", { ip: "1.1.1.1", country: "United States", countryCode: "US", city: "", lat: 34, lon: -118, isPrivate: false }],
    ["93.184.216.34", { ip: "93.184.216.34", country: "Ireland", countryCode: "IE", city: "", lat: 53, lon: -6, isPrivate: false }],
  ])

  it("aggregates an explicit node set by country bytes, ranked desc", () => {
    const data = deriveMapData([
      mk(1, "192.168.1.5", "8.8.8.8", 100),
      mk(2, "192.168.1.5", "93.184.216.34", 50),
      mk(3, "192.168.1.5", "1.1.1.1", 200),
    ], geo as never)
    expect(topCountriesOf(data.nodes)).toEqual([
      { name: "United States", code: "US", bytes: 300 },
      { name: "Ireland", code: "IE", bytes: 50 },
    ])
    // A search-filtered subset re-ranks from just those nodes.
    const filtered = topCountriesOf(data.nodes.filter((n) => n.ip === "93.184.216.34"))
    expect(filtered).toEqual([{ name: "Ireland", code: "IE", bytes: 50 }])
  })

  it("matches mapPanels.topCountries when given the full node set", () => {
    const data = deriveMapData([
      mk(1, PRIVATES[0], PUBLICS[0], 100),
      mk(2, PRIVATES[1], PUBLICS[1], 50),
    ], publicGeo())
    expect(topCountriesOf(data.nodes)).toEqual(mapPanels(data).topCountries)
  })
})