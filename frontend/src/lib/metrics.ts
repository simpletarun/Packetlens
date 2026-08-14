// Canonical capture metrics — the SINGLE source of truth for duration and
// rate numbers (packets/sec, average/peak throughput) used by the engine,
// the report, and every export. Nothing else may divide bytes by time.
//
// Edge-case contract (QA: SYN_Flood.pcap showed 66 B/s "average throughput"
// for a single 66-byte SYN because the old code clamped duration to >= 1 s):
//   - 0 packets                          -> EMPTY, no rates
//   - 1 packet                           -> SINGLE_PACKET, no rates (no interval)
//   - >= 2 packets, identical timestamps -> ZERO_DURATION, no rates (no interval)
//   - otherwise                          -> VALID, rates over the real span
// Rates are never fabricated with a fallback denominator. When no time
// interval exists the values are null and the report must show N/A.
//
// The AVERAGE is the true capture average: totalBytes / captureSpan (and
// packetCount / captureSpan). The PEAK is the largest 1-second bucket. These
// are independent measures, so avg <= peak is NOT enforced by construction —
// a dense sub-second capture (100 B at t=0, 100 B at t=0.5 -> span 0.5 s,
// both bytes in the same second) honestly has avg 400 B/s above its 200 B/s
// peak bucket. The earlier code divided by max(span, bucketCount) to force
// avg <= peak, which silently REPLACED the average with a different number
// (QA: Teardrop_Attack.pcap read 914 B/s avg vs 764 B/s peak). Instead the
// engine reports both honest numbers and sets avgExceedsPeak so the UI can
// annotate the capture rather than misstate its average.

export type CaptureQuality = "EMPTY" | "SINGLE_PACKET" | "ZERO_DURATION" | "VALID"

export interface CaptureRates {
  quality: CaptureQuality
  /** Real capture span in seconds, null when no interval exists. */
  durationSec: number | null
  avgPacketsSec: number | null
  avgBps: number | null
  peakBps: number | null
  /** Number of non-empty 1-second buckets (burst detection needs >= 2). */
  bucketCount: number
  /** True when the honest average exceeds the largest 1-second bucket —
   *  dense sub-second traffic. Reported, never "fixed" by resizing the
   *  average's denominator. */
  avgExceedsPeak: boolean
}

export function captureRates(
  packets: Array<{ timestamp: number; length: number }>
): CaptureRates {
  if (packets.length === 0) {
    return { quality: "EMPTY", durationSec: null, avgPacketsSec: null, avgBps: null, peakBps: null, bucketCount: 0, avgExceedsPeak: false }
  }
  if (packets.length === 1) {
    return { quality: "SINGLE_PACKET", durationSec: null, avgPacketsSec: null, avgBps: null, peakBps: null, bucketCount: 1, avgExceedsPeak: false }
  }
  let first = Number.POSITIVE_INFINITY
  let last = Number.NEGATIVE_INFINITY
  let bytes = 0
  for (const p of packets) {
    if (p.timestamp < first) first = p.timestamp
    if (p.timestamp > last) last = p.timestamp
    bytes += p.length
  }
  const span = last - first
  if (!(span > 0)) {
    // Identical timestamps (or NaN timestamps): no measurable interval.
    return { quality: "ZERO_DURATION", durationSec: null, avgPacketsSec: null, avgBps: null, peakBps: null, bucketCount: 1, avgExceedsPeak: false }
  }
  const buckets = new Map<number, number>()
  for (const p of packets) {
    const sec = Math.floor(p.timestamp - first)
    buckets.set(sec, (buckets.get(sec) ?? 0) + p.length)
  }
  let peakBps = 0
  for (const b of buckets.values()) if (b > peakBps) peakBps = b
  const avgBps = bytes / span
  return {
    quality: "VALID",
    durationSec: span,
    avgPacketsSec: packets.length / span,
    avgBps,
    peakBps,
    bucketCount: buckets.size,
    avgExceedsPeak: avgBps > peakBps,
  }
}
