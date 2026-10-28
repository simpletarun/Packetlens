import { describe, it, expect, beforeEach } from "vitest"
import { useAnalysisStore } from "@/stores/analysis"

describe("Analysis store", () => {
  beforeEach(() => {
    useAnalysisStore.getState().resetAnalysis()
  })

  it("initializes with empty state", () => {
    const state = useAnalysisStore.getState()
    expect(state.packets).toEqual([])
    expect(state.flows).toEqual([])
    expect(state.currentJob).toBeNull()
  })

  it("sets and gets packets", () => {
    const packet = { num: 1, timestamp: "2024-01-01T00:00:00.000Z", srcIp: "1.2.3.4", dstIp: "5.6.7.8", srcPort: 1234, dstPort: 80, protocol: "TCP", length: 64, flags: "ACK", ttl: 64, info: "test" }
    useAnalysisStore.getState().setPackets([packet])
    expect(useAnalysisStore.getState().packets).toHaveLength(1)
    expect(useAnalysisStore.getState().packets[0].srcIp).toBe("1.2.3.4")
  })

  it("sets all data at once", () => {
    const job = { id: "test-1", filename: "test.pcap", fileSize: 1000, status: "done" as const, progress: 100, stage: "complete", totalPackets: 10, totalFlows: 5, conversations: 3, devices: 2, externalIps: 1, countries: 0, domains: 1, protocols: ["TCP"], alerts: 0, riskScore: 0, captureDuration: 60, createdAt: "2024-01-01T00:00:00.000Z" }
    useAnalysisStore.getState().setAllData({
       job, packets: [], flows: [], sessions: [], dns: [], http: [], tls: [], files: [], credentials: [], certificates: [], devices: [], alerts: [], timeline: [], bandwidth: [], advancedMetrics: null, burst: null,
    })
    expect(useAnalysisStore.getState().currentJob).toEqual(job)
  })

  it("toggles beginner mode", () => {
    const initial = useAnalysisStore.getState().beginnerMode
    useAnalysisStore.getState().toggleBeginnerMode()
    expect(useAnalysisStore.getState().beginnerMode).toBe(!initial)
  })

  it("toggles sidebar", () => {
    const initial = useAnalysisStore.getState().sidebarOpen
    useAnalysisStore.getState().toggleSidebar()
    expect(useAnalysisStore.getState().sidebarOpen).toBe(!initial)
  })

  it("resets to initial state", () => {
    const packet = { num: 1, timestamp: "2024-01-01T00:00:00.000Z", srcIp: "1.2.3.4", dstIp: "5.6.7.8", srcPort: 1234, dstPort: 80, protocol: "TCP", length: 64, flags: "ACK", ttl: 64, info: "test" }
    useAnalysisStore.getState().setPackets([packet])
    useAnalysisStore.getState().resetAnalysis()
    expect(useAnalysisStore.getState().packets).toEqual([])
  })
})