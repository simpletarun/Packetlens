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
    expect(r.bucketCount).toBe(0)
  })

  it("single packet -> SINGLE_PACKET with no rates (no interval)", () => {
    const r = rates([[1000, 66]])
    expect(r.quality).toBe("SINGLE_PACKET")
    expect(r.durationSec).toBeNull()
    expect(r.avgPacketsSec).toBeNull()
    expect(r.avgBps).toBeNull()
    expect(r.peakBps).toBeNull()
    expect(r.bucketCount).toBe(1)
  })

  it("identical timestamps -> ZERO_DURATION with no rates (no interval)", () => {
    const r = rates([[1000, 60], [1000, 80]])
    expect(r.quality).toBe("ZERO_DURATION")
    expect(r.durationSec).toBeNull()
    expect(r.avgBps).toBeNull()
    expect(r.peakBps).toBeNull()
  })

  it("zero-duration must never fabricate a 1s fallback denominator", () => {
    const r = rates([[1000, 66], [1000, 66]])
    expect(r.avgBps).toBeNull()
    expect(r.avgPacketsSec).toBeNull()
  })
})

describe("captureRates valid captures", () => {
  it("duration is the real span; avg divides the rate window (never above peak)", () => {
    const r = rates([[0, 100], [0.42, 100]])
    expect(r.quality).toBe("VALID")
    expect(r.durationSec).toBeCloseTo(0.42, 5)
    // Both packets land in the same 1s bucket: the rate window is 1s, so the
    // average (200 B/s) equals the peak and never overstates the 0.42s span.
    expect(r.avgBps).toBe(200)
    expect(r.avgPacketsSec).toBe(2)
    expect(r.peakBps).toBe(200)
    expect(r.avgBps!).toBeLessThanOrEqual(r.peakBps!)
  })

  it("sparse captures divide by the real span (Wireshark-style)", () => {
    const r = rates([[0, 100], [0.5, 100], [3, 100]])
    expect(r.durationSec).toBe(3)
    expect(r.bucketCount).toBe(2)
    // max(span=3, buckets=2) = 3
    expect(r.avgBps).toBe(100)
    expect(r.avgPacketsSec).toBe(1)
  })

  it("peak is the largest per-second bucket", () => {
    const r = rates([[0, 100], [1, 900], [1.5, 200], [3, 50]])
    // seconds 0, 1, 3 -> buckets 100, 1100, 50
    expect(r.peakBps).toBe(1100)
    expect(r.bucketCount).toBe(3)
  })

  it("average <= peak holds BY CONSTRUCTION", () => {
    const r = rates([[0, 100], [0.5, 200], [2, 50], [9, 9000]])
    expect(r.avgBps!).toBeLessThanOrEqual(r.peakBps!)
  })

  it("dense integer-second captures cannot average above the peak (QA: Teardrop)", () => {
    const r = rates([[0, 1], [1, 1], [2, 1]])
    // span = 2 but all 3 seconds are covered -> window 3, avg = 1 <= peak 1
    expect(r.durationSec).toBe(2)
    expect(r.avgBps).toBe(1)
    expect(r.avgBps!).toBeLessThanOrEqual(r.peakBps!)
  })

  it("a single spike to a tall bucket is the peak", () => {
    const r = rates([[0, 500], [1, 500], [2, 500], [3, 5000]])
    expect(r.peakBps).toBe(5000)
    // window = max(3, 4) = 4
    expect(r.avgBps).toBeCloseTo(6500 / 4, 5)
  })
})
