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
// average <= peak holds BY CONSTRUCTION: the average divides the total by the
// rate window = max(span, bucketCount). When packets cover every second of
// the span (dense captures, e.g. 3 packets at t=0,1,2 -> span 2, 3 buckets)
// dividing by the raw span would produce an average ABOVE the largest
// 1-second bucket — a real, honest number that violates avg <= peak and reads
// as an overstatement (QA: Teardrop_Attack.pcap 914 B/s avg vs 764 B/s peak).
// The rate window is >= span and >= the number of covered seconds, so the
// average can never exceed the peak bucket. Duration display still uses the
// real span; for sparse captures (gaps between buckets) max(span, bucketCount)
// = span, giving the Wireshark-style total/span average.

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
}

export function captureRates(
  packets: Array<{ timestamp: number; length: number }>
): CaptureRates {
  if (packets.length === 0) {
    return { quality: "EMPTY", durationSec: null, avgPacketsSec: null, avgBps: null, peakBps: null, bucketCount: 0 }
  }
  if (packets.length === 1) {
    return { quality: "SINGLE_PACKET", durationSec: null, avgPacketsSec: null, avgBps: null, peakBps: null, bucketCount: 1 }
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
    return { quality: "ZERO_DURATION", durationSec: null, avgPacketsSec: null, avgBps: null, peakBps: null, bucketCount: 1 }
  }
  const buckets = new Map<number, number>()
  for (const p of packets) {
    const sec = Math.floor(p.timestamp - first)
    buckets.set(sec, (buckets.get(sec) ?? 0) + p.length)
  }
  let peakBps = 0
  for (const b of buckets.values()) if (b > peakBps) peakBps = b
  // Rate window (see header): >= span and >= covered seconds, so
  // avg <= peak by construction while staying total/span for sparse captures.
  const window = Math.max(span, buckets.size)
  return {
    quality: "VALID",
    durationSec: span,
    avgPacketsSec: packets.length / window,
    avgBps: bytes / window,
    peakBps,
    bucketCount: buckets.size,
  }
}
