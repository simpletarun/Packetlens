import { describe, it, expect } from "vitest"
import { captureRates, CaptureRates } from "../src/lib/metrics"

// Canonical metrics engine — the single source of truth for duration and
// rate numbers. These tests pin the edge-case contract that the old engine
// violated (QA: a 1-SYN capture reported 66 B/s average throughput because
// duration was clamped to >= 1 s; identical timestamps divided by 0.001 s).

function rates(packets: Array<[number, number]>): CaptureRates {
  return captureRates(packets.map(([timestamp, length]) => ({ timestamp, length })))
}

describe("captureRates edge cases", () => {
  it("empty capture -> EMPTY with no rates", () => {
    const r = rates([])
    expect(r.quality).toBe("EMPTY")
    expect(r.durationSec).toBeNull()
    expect(r.avgPacketsSec).toBeNull()
    expect(r.avgBps).toBeNull()
    expect(r.peakBps).toBeNull()
    expect(r.peakBps100ms).toBeNull()
    expect(r.bucketCount).toBe(0)
  })

  it("single packet -> SINGLE_PACKET with no rates (no interval)", () => {
    const r = rates([[1000, 66]])
    expect(r.quality).toBe("SINGLE_PACKET")
    expect(r.durationSec).toBeNull()
    expect(r.avgPacketsSec).toBeNull()
    expect(r.avgBps).toBeNull()
    expect(r.peakBps).toBeNull()
    expect(r.peakBps100ms).toBeNull()
    expect(r.bucketCount).toBe(1)
  })

  it("identical timestamps -> ZERO_DURATION with no rates (no interval)", () => {
    const r = rates([[1000, 60], [1000, 80]])
    expect(r.quality).toBe("ZERO_DURATION")
    expect(r.durationSec).toBeNull()
    expect(r.avgBps).toBeNull()
    expect(r.peakBps).toBeNull()
    expect(r.peakBps100ms).toBeNull()
  })

  it("zero-duration must never fabricate a 1s fallback denominator", () => {
    const r = rates([[1000, 66], [1000, 66]])
    expect(r.avgBps).toBeNull()
    expect(r.avgPacketsSec).toBeNull()
  })
})

describe("captureRates valid captures", () => {
  it("avg is total/span — sub-second bursts honestly exceed the peak rate", () => {
    const r = rates([[0, 100], [0.42, 100]])
    expect(r.quality).toBe("VALID")
    expect(r.durationSec).toBeCloseTo(0.42, 5)
    // 200 bytes over a 0.42s span is 476.19 B/s. There is only ONE 1s bucket
    // (peak 200 B/s), so the average of the whole capture may legitimately
    // sit above the largest single-second bucket — the flag says so.
    expect(r.avgBps).toBeCloseTo(200 / 0.42, 5)
    expect(r.avgPacketsSec).toBeCloseTo(2 / 0.42, 5)
    expect(r.peakBps).toBe(200)
    expect(r.avgExceedsPeak).toBe(true)
  })

  it("sparse captures divide by the real span (Wireshark-style)", () => {
    const r = rates([[0, 100], [0.5, 100], [3, 100]])
    expect(r.durationSec).toBe(3)
    expect(r.bucketCount).toBe(2)
    // 300 bytes / 3s = 100 B/s regardless of bucket count.
    expect(r.avgBps).toBe(100)
    expect(r.avgPacketsSec).toBe(1)
    expect(r.avgExceedsPeak).toBe(false)
  })

  it("peak is the largest per-second bucket", () => {
    const r = rates([[0, 100], [1, 900], [1.5, 200], [3, 50]])
    // seconds 0, 1, 3 -> buckets 100, 1100, 50
    expect(r.peakBps).toBe(1100)
    expect(r.bucketCount).toBe(3)
  })

  it("a short capture inside one big second can out-average its own peak (flag on)", () => {
    const r = rates([[0, 100], [0.5, 200], [2, 50]])
    // 350 bytes / 2s span = 175 B/s; peak bucket (second 0) = 300 B/s.
    expect(r.avgBps).toBe(175)
    expect(r.peakBps).toBe(300)
    expect(r.avgExceedsPeak).toBe(false)
    // A gap mid-capture shrinks the divisor and can push the average above
    // the peak bucket — the flag is the single source of truth.
    const r2 = rates([[0, 900], [8, 100]])
    expect(r2.avgBps).toBe(125)
    expect(r2.peakBps).toBe(900)
    expect(r2.avgExceedsPeak).toBe(false)
  })

  it("dense integer-second captures: avg is total/span, never re-windowed (QA: Teardrop)", () => {
    const r = rates([[0, 1], [1, 1], [2, 1]])
    // span = 2, total 3 bytes -> avg 1.5 B/s. The old max(span, buckets)=3
    // denominator faked 1 B/s; Teardrop honestly reads 914 avg vs 764 peak.
    expect(r.durationSec).toBe(2)
    expect(r.avgBps).toBe(1.5)
    expect(r.peakBps).toBe(1)
    expect(r.avgExceedsPeak).toBe(true)
  })

  it("a single spike to a tall bucket is the peak", () => {
    const r = rates([[0, 500], [1, 500], [2, 500], [3, 5000]])
    expect(r.peakBps).toBe(5000)
    // 6500 bytes over the 3s span = 2166.67 B/s (honest total/span).
    expect(r.avgBps).toBeCloseTo(6500 / 3, 5)
    expect(r.avgExceedsPeak).toBe(false)
  })
})

describe("peakBps100ms — the honest instantaneous peak", () => {
  it("is the largest 100 ms bucket scaled to bytes/sec", () => {
    // Second 0 holds 900 B spread 200ms apart: the whole second (peakBps) is
    // 900 B/s, but the tightest 100 ms window holds 500 B -> 5000 B/s.
    const r = rates([[0, 200], [0.2, 300], [0.2, 200], [0.6, 200], [1, 100], [2, 100]])
    expect(r.quality).toBe("VALID")
    expect(r.peakBps).toBe(900)
    expect(r.peakBps100ms).toBe(5000)
  })

  it("is always >= the 1-second peak (same zero base, ten windows per second)", () => {
    const r = rates([[0, 100], [0.5, 100], [0.9, 100], [1.2, 700], [1.8, 100], [2.4, 100], [3.3, 50]])
    expect(r.peakBps100ms!).toBeGreaterThanOrEqual(r.peakBps!)
  })

  it("dense flat traffic: 100 ms peak equals the 1 s peak (all windows full)", () => {
    // 10 equally-spaced 150 B packets per second -> every window sees 1500 B.
    const pkts: Array<[number, number]> = []
    for (let s = 0; s < 3; s++) for (let i = 0; i < 10; i++) pkts.push([s + i * 0.1, 150])
    const r = rates(pkts)
    expect(r.peakBps).toBe(1500)
    expect(r.peakBps100ms).toBe(1500)
  })
})
