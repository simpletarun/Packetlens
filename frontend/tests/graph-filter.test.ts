import { describe, it, expect } from "vitest"
import { computeVisibleIds } from "@/lib/graph-filter"

const NODES = [
  { data: { id: "pcap", label: "📦 PCAP", type: "pcap", info: "PCAP file" } },
  { data: { id: "ip:192.168.1.5", label: "🖥️ 192.168.1.x", type: "ip", info: "IP: 192.168.1.5" } },
  { data: { id: "ip:8.8.8.8", label: "🖥️ 8.8.x.x", type: "ip", info: "IP: 8.8.8.8" } },
  { data: { id: "proto:TCP", label: "📡 TCP", type: "protocol", info: "Protocol: TCP" } },
  { data: { id: "dns:router.lan", label: "🔍 router.lan", type: "dns", info: "DNS Query: router.lan" } },
  { data: { id: "alert:SYN Flood Attempt", label: "🚨 SYN Flood Attempt", type: "alert", info: "Alert: SYN Flood Attempt" } },
]

const EDGES = [
  { data: { id: "e1", source: "pcap", target: "ip:192.168.1.5", type: "edge" } },
  { data: { id: "e2", source: "ip:192.168.1.5", target: "ip:8.8.8.8", type: "edge" } },
  { data: { id: "e3", source: "ip:8.8.8.8", target: "dns:router.lan", type: "edge" } },
  { data: { id: "e4", source: "pcap", target: "proto:TCP", type: "edge" } },
  { data: { id: "e5", source: "pcap", target: "alert:SYN Flood Attempt", type: "edge" } },
]

const ALL = [...NODES, ...EDGES]
const ALL_TYPES = new Set(["all", "pcap", "ip", "protocol", "dns", "alert"])

describe("computeVisibleIds", () => {
  it("shows everything with the all-types filter and no query", () => {
    const v = computeVisibleIds(ALL, ALL_TYPES, "")
    expect(v.size).toBe(ALL.length)
  })

  it("searches IPs by full address via id/info, not the short label", () => {
    const v = computeVisibleIds(ALL, ALL_TYPES, "192.168.1.5")
    expect(v.has("ip:192.168.1.5")).toBe(true)
    expect(v.has("ip:8.8.8.8")).toBe(true) // 1-hop context
    expect(v.has("dns:router.lan")).toBe(false) // 2 hops — not revealed
  })

  it("search keeps the match's edges and context endpoints", () => {
    const v = computeVisibleIds(ALL, ALL_TYPES, "192.168.1.5")
    expect(v.has("e1")).toBe(true) // pcap -> match (pcap is context)
    expect(v.has("e2")).toBe(true) // match -> context
    expect(v.has("e3")).toBe(false) // context -> unrelated node
  })

  it("type filter hides non-selected types and their edges", () => {
    const v = computeVisibleIds(ALL, new Set(["ip"]), "")
    expect(v.has("ip:192.168.1.5")).toBe(true)
    expect(v.has("proto:TCP")).toBe(false)
    expect(v.has("e1")).toBe(false) // pcap node not in the visible set
    expect(v.has("e2")).toBe(true)
  })

  it("context nodes still respect the type filter", () => {
    const v = computeVisibleIds(ALL, new Set(["ip"]), "192.168.1.5")
    expect(v.has("ip:8.8.8.8")).toBe(true)
    expect(v.has("pcap")).toBe(false) // pcap type is filtered out
    expect(v.has("e1")).toBe(false)
    expect(v.has("e2")).toBe(true)
  })

  it("empty filter set means 'All' — the UI lights the All chip for size 0, so nothing may be hidden", () => {
    const v = computeVisibleIds(ALL, new Set(), "")
    expect(v.size).toBe(ALL.length)
  })

  it("trims whitespace around the query", () => {
    const v = computeVisibleIds(ALL, ALL_TYPES, "  8.8.8.8  ")
    expect(v.has("ip:8.8.8.8")).toBe(true)
  })

  it("identity edges (type 'identity', B-50) count as edges, never pseudo-nodes", () => {
    const idEdge = { data: { id: "ip:192.168.1.5->dev:192.168.1.5", source: "ip:192.168.1.5", target: "dev:192.168.1.5", type: "identity", label: "same host" } }
    const devNode = { data: { id: "dev:192.168.1.5", label: "🖥️ DESKTOP-X", type: "device", info: "Device: DESKTOP-X" } }
    const all = [...ALL, devNode, idEdge]
    // Edge label text must not make the pair "visible" — edges are never search targets.
    expect(computeVisibleIds(all, ALL_TYPES, "same host").has("ip:192.168.1.5->dev:192.168.1.5")).toBe(false)
    // Both endpoints visible → the identity edge is in the visible set (counter == rendered).
    expect(computeVisibleIds(all, ALL_TYPES, "").has("ip:192.168.1.5->dev:192.168.1.5")).toBe(true)
  })

  it("search spotlight spreads 1-hop context through identity edges (IP search reveals its same-host device)", () => {
    const idEdge = { data: { id: "ip:192.168.1.5->dev:192.168.1.5", source: "ip:192.168.1.5", target: "dev:192.168.1.5", type: "identity", label: "same host" } }
    const devNode = { data: { id: "dev:192.168.1.5", label: "🖥️ DESKTOP-X", type: "device", info: "Device: DESKTOP-X" } }
    const all = [...ALL, devNode, idEdge]
    const v = computeVisibleIds(all, ALL_TYPES, "192.168.1.5")
    expect(v.has("dev:192.168.1.5")).toBe(true)
    expect(v.has("ip:192.168.1.5->dev:192.168.1.5")).toBe(true)
  })

  it("identity-edge context still respects the type filter", () => {
    const idEdge = { data: { id: "ip:192.168.1.5->dev:192.168.1.5", source: "ip:192.168.1.5", target: "dev:192.168.1.5", type: "identity", label: "same host" } }
    const devNode = { data: { id: "dev:192.168.1.5", label: "🖥️ DESKTOP-X", type: "device", info: "Device: DESKTOP-X" } }
    const all = [...ALL, devNode, idEdge]
    const v = computeVisibleIds(all, new Set(["ip"]), "192.168.1.5")
    expect(v.has("dev:192.168.1.5")).toBe(false)
    expect(v.has("ip:192.168.1.5->dev:192.168.1.5")).toBe(false)
  })
})
