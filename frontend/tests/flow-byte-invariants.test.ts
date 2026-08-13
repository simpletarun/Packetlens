import { describe, it, expect, beforeAll } from "vitest"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { parsePcap } from "@/lib/pcap"
import { analyzePcap, type AnalysisResult } from "@/lib/analysis"
import { formatBytes } from "@/lib/map-data"

// QA regression: a flow's displayed size must never contradict its own
// direction split or the capture's file size. The bug report showed the
// "Top Flows by Volume" card printing 921 KB for a flow whose Flows page
// showed Sent 33.3 KB + Recv 58.8 KB = 92.1 KB — a 10x stored bytes_total.
// The pipeline (and the gateway, which now shapes bytes_total as
// sent + recv) must keep this invariant so every surface agrees.
const fixture = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "testing.pcapng")

let analysis: AnalysisResult

beforeAll(async () => {
  analysis = analyzePcap(await parsePcap(readFileSync(fixture)))
}, 60000)

describe("flow byte invariants (sessions = flows = capture)", () => {
  it("bytesTotal is the exact sum of bytesSent + bytesRecv; sessions agree; no flow exceeds the capture", () => {
    expect(analysis.flows.length).toBeGreaterThan(0)
    const captureBytes = analysis.packets.reduce((s, p) => s + p.length, 0)
    const byFlow = new Map(analysis.flows.map((f) => [`${f.srcIp}|${f.dstIp}|${f.srcPort}|${f.dstPort}|${f.protocol}`, f]))

    for (const f of analysis.flows) {
      expect(f.bytesTotal, `flow ${f.srcIp}->${f.dstIp} (${formatBytes(f.bytesTotal)})`).toBe(f.bytesSent + f.bytesRecv)
      expect(f.bytesTotal, `flow ${f.srcIp}->${f.dstIp} larger than the whole capture`).toBeLessThanOrEqual(captureBytes)
    }
    for (const s of analysis.sessions) {
      const f = byFlow.get(`${s.srcIp}|${s.dstIp}|${s.srcPort}|${s.dstPort}|${s.protocol}`)
      expect(f, `session ${s.srcIp}->${s.dstIp} must match a flow`).toBeDefined()
      expect(s.bytes, `session ${s.srcIp}->${s.dstIp} bytes must equal its flow's bytesTotal`).toBe(f!.bytesTotal)
    }
  }, 60000)

  it("formatBytes keeps the decimal in the KB range (92.1, never 921)", () => {
    expect(formatBytes(94_310)).toBe("92.1 KB")
    expect(formatBytes(943_104)).toBe("921.0 KB")
    expect(formatBytes(943_104)).not.toBe("921 KB")
  })
})