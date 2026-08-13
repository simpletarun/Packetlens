// Deterministic in-memory capture builders for feature tests — no binary
// fixtures needed for most acceptance criteria. Feature tests extend these
// with their own canned helpers (raw-IP/SLL for F-01, retransmission flows
// for F-05, …).

import type { PCAPResult, ParsedPacket } from "@/lib/pcap"

const ZERO: ParsedPacket = { num: 0, timestamp: 0, length: 0, origLength: 0, payload: "" }

export function makePacket(p: Partial<ParsedPacket>): ParsedPacket {
  return { ...ZERO, ...p }
}

export function buildPCAP(
  packets: ParsedPacket[],
  opts: { linkTypes?: number[]; decodedPackets?: number } = {}
): PCAPResult {
  let startTime = 0
  let endTime = 0
  let totalBytes = 0
  const protocols: Record<string, number> = {}
  for (const p of packets) {
    if (startTime === 0 || p.timestamp < startTime) startTime = p.timestamp
    if (p.timestamp > endTime) endTime = p.timestamp
    totalBytes += p.length
    const proto = p.protocol || "OTHER"
    protocols[proto] = (protocols[proto] || 0) + 1
  }
  return {
    packets,
    stats: {
      totalPackets: packets.length,
      totalBytes,
      duration: endTime - startTime,
      startTime,
      endTime,
      protocols,
      linkTypes: opts.linkTypes,
      decodedPackets: opts.decodedPackets ?? packets.length,
    },
  }
}
