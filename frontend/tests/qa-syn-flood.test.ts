import { describe, it, expect } from "vitest"
import { existsSync, readFileSync } from "fs"
import { join } from "path"
import { parsePcap } from "../src/lib/pcap"
import { analyzePcap } from "../src/lib/analysis"

// QA verification for the canonical metrics engine: the 1-SYN flood capture
// that previously reported 66 B/s average throughput over a fake 1 s interval.
describe("QA: SYN_Flood.pcap canonical rates", () => {
  const dir = process.env.EXTERNAL_PCAP_DIR ?? "C:\\Users\\hp\\Downloads\\all pcap"
  const file = join(dir, "SYN_Flood.pcap")
  const present = existsSync(file)

  it("a single-packet capture has NO rates, N/A everywhere, no burst, no bandwidth", async () => {
    if (!present) return // external corpus not present on this machine
    const parsed = await parsePcap(readFileSync(file))
    const a = analyzePcap(parsed)
    const r = a.advancedMetrics.rates
    expect(r.quality).toBe("SINGLE_PACKET")
    expect(r.durationSec).toBeNull()
    expect(a.advancedMetrics.throughputAvg).toBeNull()
    expect(a.advancedMetrics.throughputPeak).toBeNull()
    expect(a.advancedMetrics.burst).toBeNull()
    expect(a.job.captureQuality).toBe("SINGLE_PACKET")
    expect(a.job.captureDuration).toBe(0)
  })
})