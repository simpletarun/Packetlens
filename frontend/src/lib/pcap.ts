import { Buffer } from 'buffer'

export interface PCAPResult {
  packets: ParsedPacket[]
  stats: {
    totalPackets: number
    totalBytes: number
    duration: number
    startTime: number
    endTime: number
    protocols: Record<string, number>
    // Decode diagnostics for undecodable-input handling: the pcapng
    // interface (or pcap global header) link types and how many packets the
    // encapsulation was actually parsed for. A capture whose link type is not
    // Ethernet (DLT 1) yields lengths + timestamps but no headers — the
    // analyst must be told WHY every column is empty (QA: large/verylarge).
    // Optional: legacy callers/tests may omit them, meaning "everything
    // decoded" (pre-decode-tracking behavior).
    linkTypes?: number[]
    decodedPackets?: number
    // Capture integrity signals for the canonical validator: frames whose
    // captured length is shorter than their original length (snaplen or file
    // truncation), frames too short for their own link-layer header
    // (malformed), and whether the file ended mid-record (leftover bytes).
    truncatedPackets?: number
    malformedPackets?: number
    fileTruncated?: boolean
  }
}

export interface ParsedPacket {
  num: number
  timestamp: number
  length: number
  origLength: number
  srcMac?: string
  dstMac?: string
  // ARP sender hardware address (RFC 826 sha field). The Ethernet header's
  // srcMac is usually the same value, but the ARP payload is the authoritative
  // binding of a sender IPv4 → interface MAC — used to coalesce the router's
  // v4/link-local/delegated-v6 addresses into ONE device (device regression).
  arpSenderMac?: string
  ethType?: number
  srcIp?: string
  dstIp?: string
  protocol?: string
  // IP TTL (v4) / hop limit (v6) from the header — the only offline OS hint
  // besides User-Agent. Header-only, never faked.
  ttl?: number
  srcPort?: number
  dstPort?: number
  tcpFlags?: string
  // v3.2 TCP health inputs: sequence/ack/window + payload bytes (retrans/OoO
  // detection and RTT need these; the UI otherwise only had flags).
  tcpSeq?: number
  tcpAck?: number
  tcpWin?: number
  tcpPayloadLen?: number
  appProtocol?: string
  // True only when the app protocol label above was CONFIRMED BY PAYLOAD
  // (HTTP request/response line, TLS/QUIC handshake record, DNS, SIP, ARP
  // opcode). Absent = the label came from the well-known-port table
  // (port-inferred): TCP/80 with no HTTP payload is HTTP *by port*, never a
  // definitive claim (protocol-honesty audit).
  appPayloadConfirmed?: boolean
  // Transport layer (TCP/UDP/ICMP…) separate from `protocol` (app layer:
  // HTTPS/STUN/mDNS…). Transport is what the timeline's TCP/UDP split and the
  // session state machine key on — app labels must not erase the transport.
  transport?: string
  dnsQuery?: string
  dnsQr?: boolean
  dnsRcode?: number
  dnsQtype?: number
  dnsTtl?: number
  dnsAnswers?: { name: string; ip?: string }[]
  tlsSni?: string
  // Negotiated cipher suite from the ServerHello (TLS 1.3 includes it in
  // plaintext, so it is readable without keys).
  tlsCipherSuite?: number
  // client_version field of the ClientHello — the real TLS version offered
  // by the client (deriveTls used to hardcode TLSv1.3).
  tlsVersion?: number
  httpHost?: string
  httpMethod?: string
  httpUri?: string
  httpUa?: string
  httpStatus?: number
  httpContentType?: string
  tlsCert?: { subject: string; issuer: string; serial: string; notBefore: number; notAfter: number; san: string[]; signatureAlgorithm: string; keySize: number }
  // SIP signalling (UDP/TCP 5060/5061 or a SIP start line) and RTP media
  // (version-2 header, non-zero SSRC), mirroring analyzer/src/modules/voip.rs.
  sip?: { method: string; statusCode: number; callId: string; fromUser: string; toUser: string; viaIp: string; userAgent: string; rtpPort: number }
  rtp?: { payloadType: number; ssrc: number; sequence: number }
  payload: string
}

function hex(dv: DataView, off: number, len: number): string {
  const n = Math.min(len, 4096)
  const b: string[] = new Array(n)
  for (let i = 0; i < n; i++) b[i] = dv.getUint8(off + i).toString(16).padStart(2, '0')
  return b.join('')
}

function macStr(dv: DataView, off: number): string {
  const b: string[] = new Array(6)
  for (let i = 0; i < 6; i++) b[i] = dv.getUint8(off + i).toString(16).padStart(2, '0')
  return b.join(':')
}

function ip4Str(dv: DataView, off: number): string {
  return `${dv.getUint8(off)}.${dv.getUint8(off + 1)}.${dv.getUint8(off + 2)}.${dv.getUint8(off + 3)}`
}

function ip6Str(dv: DataView, off: number): string {
  const p: string[] = new Array(8)
  for (let i = 0; i < 8; i++) p[i] = dv.getUint16(off + i * 2).toString(16)
  return p.join(':')
}

function flagStr(f: number): string {
  const s: string[] = []
  if (f & 0x02) s.push('SYN')
  if (f & 0x20) s.push('URG')
  if (f & 0x10) s.push('ACK')
  if (f & 0x08) s.push('PSH')
  if (f & 0x04) s.push('RST')
  if (f & 0x01) s.push('FIN')
  return s.join('-')
}

function newResult(): PCAPResult {
  return { packets: [], stats: { totalPackets: 0, totalBytes: 0, duration: 0, startTime: 0, endTime: 0, protocols: {}, linkTypes: [], decodedPackets: 0, truncatedPackets: 0, malformedPackets: 0, fileTruncated: false } }
} 

function finalize(r: PCAPResult): void {
  if (r.packets.length > 0) {
    // Capture window = min/max over ALL packets, not the first/last in file
    // order: pcapng writers can record out-of-order timestamps (multi-interface
    // captures, live merges) and first/last would understate the true duration.
    let tMin = r.packets[0].timestamp
    let tMax = r.packets[0].timestamp
    for (const p of r.packets) {
      if (p.timestamp < tMin) tMin = p.timestamp
      if (p.timestamp > tMax) tMax = p.timestamp
    }
    r.stats.startTime = tMin
    r.stats.endTime = tMax
    r.stats.duration = tMax - tMin
  }
}

function addPkt(r: PCAPResult, p: ParsedPacket): void {
  r.packets.push(p)
  r.stats.totalPackets++
  r.stats.totalBytes += p.length
  const proto = p.protocol || 'OTHER'
  r.stats.protocols[proto] = (r.stats.protocols[proto] || 0) + 1
}

// Link layers the analyzer can decode (F-01): Ethernet (1), raw IP (12/101),
// NULL/loopback (0/108), Linux cooked v1/v2 (113/276). Anything else yields
// lengths + timestamps only — the decode-rate gate and banner depend on that
// split staying honest.
export const KNOWN_DLTS = new Set([0, 1, 12, 101, 108, 113, 276])

// Returns whether the frame was decoded AND whether it was malformed (shorter
// than its own link-layer header — corrupt or cut data, distinct from
// "unsupported link type", which is a clean frame the parser has no decoder
// for). The canonical validator uses both signals.
function parseLinkLayer(linkType: number, dv: DataView, maxLen: number, p: ParsedPacket): { decoded: boolean; malformed: boolean } {
  switch (linkType) {
    case 1:
      if (maxLen < 14) return { decoded: false, malformed: true }
      parseEthernet(dv, maxLen, p)
      return { decoded: true, malformed: false }
    case 12:
    case 101:
      if (maxLen < 1) return { decoded: false, malformed: true }
      parseRawIp(dv, 0, maxLen, p)
      return { decoded: true, malformed: false }
    case 0:
    case 108:
      if (maxLen < 4) return { decoded: false, malformed: true }
      parseLoopback(dv, maxLen, p)
      return { decoded: true, malformed: false }
    case 113:
      if (maxLen < 16) return { decoded: false, malformed: true }
      parseSll(dv, maxLen, p)
      return { decoded: true, malformed: false }
    case 276:
      if (maxLen < 20) return { decoded: false, malformed: true }
      parseSll2(dv, maxLen, p)
      return { decoded: true, malformed: false }
    default:
      return { decoded: false, malformed: false }
  }
}

// Raw IP (DLT 12/101): the capture starts directly at the IP header.
function parseRawIp(dv: DataView, off: number, maxLen: number, p: ParsedPacket): void {
  if (maxLen < 1) return
  const ver = dv.getUint8(off) >> 4
  if (ver === 4) parseIPv4(dv, off, maxLen, p)
  else if (ver === 6) parseIPv6(dv, off, maxLen, p)
}

// NULL/loopback (DLT 0/108): 4-byte address family in host order; on real
// little-endian captures the family is byte 0 (2 = AF_INET, 24/28/30 =
// AF_INET6 depending on BSD/Linux).
function parseLoopback(dv: DataView, maxLen: number, p: ParsedPacket): void {
  if (maxLen < 4) return
  const family = dv.getUint8(0)
  if (family === 2) parseIPv4(dv, 4, maxLen - 4, p)
  else if (family === 10 || family === 24 || family === 28 || family === 30) parseIPv6(dv, 4, maxLen - 4, p)
}

// Linux cooked v1 (DLT 113): pkttype(2) arphrd(2) halen(2) addr(8) proto(2).
function parseSll(dv: DataView, maxLen: number, p: ParsedPacket): void {
  if (maxLen < 16) return
  if (dv.getUint16(4) === 6) p.srcMac = macStr(dv, 6)
  let ethType = dv.getUint16(14)
  let off = 16
  if (ethType === 0x8100 && maxLen >= 20) {
    ethType = dv.getUint16(18)
    off = 20
  }
  parseEthPayload(ethType, dv, off, maxLen - off, p)
}

// Linux cooked v2 (DLT 276): proto(2) reserved(2) ifindex(4) arphrd(2)
// pkttype(1) halen(1) addr(8).
function parseSll2(dv: DataView, maxLen: number, p: ParsedPacket): void {
  if (maxLen < 20) return
  if (dv.getUint8(11) === 6) p.srcMac = macStr(dv, 12)
  let ethType = dv.getUint16(0)
  let off = 20
  if (ethType === 0x8100 && maxLen >= 24) {
    ethType = dv.getUint16(4)
    off = 24
  }
  parseEthPayload(ethType, dv, off, maxLen - off, p)
}

function parseEthPayload(ethType: number, dv: DataView, off: number, len: number, p: ParsedPacket): void {
  if (ethType === 0x0800) parseIPv4(dv, off, len, p)
  else if (ethType === 0x86dd) parseIPv6(dv, off, len, p)
  else if (ethType === 0x0806) parseARP(dv, off, len, p)
}

export async function parsePcap(buffer: Buffer, linkTypeOverride?: number): Promise<PCAPResult> {
  if (buffer.length < 4) return newResult()
  const magic = buffer.readUInt32LE(0)
  if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1) return parsePCAP(buffer, linkTypeOverride)
  if (buffer[0] === 0x0a && buffer[1] === 0x0d && buffer[2] === 0x0d && buffer[3] === 0x0a) return parsePCAPNG(buffer, linkTypeOverride)
  return newResult()
}

function parsePCAP(buf: Buffer, linkTypeOverride?: number): PCAPResult {
  if (buf.length < 24) return newResult()
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  const magic = dv.getUint32(0, true)
  const le = magic === 0xa1b2c3d4
  const u32 = (o: number) => dv.getUint32(o, le)

  const linkType = linkTypeOverride ?? u32(20)
  const r = newResult()
  r.stats.linkTypes = [linkType]
  let off = 24
  let num = 0

  while (off + 16 <= buf.length) {
    const tsSec = u32(off)
    const tsUsec = u32(off + 4)
    const inclLen = u32(off + 8)
    const origLen = u32(off + 12)
    off += 16

    const avail = buf.length - off
    if (inclLen === 0 || avail === 0) break
    const dataLen = Math.min(inclLen, avail)

    const pdv = new DataView(buf.buffer, buf.byteOffset + off, dataLen)
    const pkt: ParsedPacket = { num: ++num, timestamp: tsSec + tsUsec / 1_000_000, length: dataLen, origLength: origLen, payload: '' }

    if (dataLen < origLen) r.stats.truncatedPackets = (r.stats.truncatedPackets ?? 0) + 1
    const ll = parseLinkLayer(linkType, pdv, dataLen, pkt)
    if (ll.decoded) r.stats.decodedPackets = (r.stats.decodedPackets ?? 0) + 1
    if (ll.malformed) r.stats.malformedPackets = (r.stats.malformedPackets ?? 0) + 1

    pkt.payload = hex(pdv, 0, dataLen)
    addPkt(r, pkt)
    off += inclLen
  }

  // EOF mid-record: the loop exited with either leftover bytes too short for
  // another 16-byte record header, or a declared packet length that extended
  // past the end of the file (off overflowed the buffer).
  if (off !== buf.length && off + 16 > buf.length) r.stats.fileTruncated = true

  reassembleTlsSni(r.packets)
  finalize(r)
  return r
}

function parsePCAPNG(buf: Buffer, linkTypeOverride?: number): PCAPResult {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  if (buf.length < 12) return newResult()

  const bomRaw = dv.getUint32(8, true)
  const le = bomRaw === 0x1a2b3c4d

  const r = newResult()
  let off = 0
  let num = 0
  const ifaceRes: number[] = []
  const ifaceLink: number[] = []

  while (off + 8 <= buf.length) {
    const blockType = dv.getUint32(off, le)
    const blockLen = dv.getUint32(off + 4, le)
    if (blockLen < 12) { if (off + 8 <= buf.length) r.stats.fileTruncated = true; break }
    if (off + blockLen > buf.length) { r.stats.fileTruncated = true; break }

    if (blockType === 0x0a0d0d0a) {
    } else if (blockType === 0x00000001 && off + 20 <= buf.length) {
      const rawLinkType = dv.getUint16(off + 8, le)
      const linkType = linkTypeOverride ?? rawLinkType
      let optOff = off + 16
      const optEnd = off + blockLen - 4
      let resol = 1_000_000
      while (optOff + 4 <= optEnd) {
        const code = dv.getUint16(optOff, le)
        const len = dv.getUint16(optOff + 2, le)
        if (code === 0) break
        if (code === 9 && len >= 1) {
          const v = dv.getUint8(optOff + 4)
          resol = v & 0x80 ? Math.pow(2, v & 0x7f) : Math.pow(10, v)
        }
        optOff += 4 + ((len + 3) & ~3)
      }
      ifaceRes.push(resol)
      ifaceLink.push(linkType)
      if (!(r.stats.linkTypes ??= []).includes(linkType)) r.stats.linkTypes.push(linkType)
    } else if (blockType === 0x00000006 && off + 32 <= buf.length) {
      const ifaceId = dv.getUint32(off + 8, le)
      const tsHi = dv.getUint32(off + 12, le)
      const tsLo = dv.getUint32(off + 16, le)
      const capLen = dv.getUint32(off + 20, le)
      const origLen = dv.getUint32(off + 24, le)
      const pktOff = off + 28
      const avail = buf.length - pktOff
      if (capLen === 0 || avail === 0) { off += blockLen; continue }
      const dataLen = Math.min(capLen, avail)

      const tsRaw = tsHi * 4294967296 + tsLo
      const resol = ifaceRes[ifaceId] || 1_000_000
      const timestamp = tsRaw / resol
      const lt = ifaceLink[ifaceId] || 1

      const pdv = new DataView(buf.buffer, buf.byteOffset + pktOff, dataLen)
      const pkt: ParsedPacket = { num: ++num, timestamp, length: dataLen, origLength: origLen, payload: '' }

      if (dataLen < origLen) r.stats.truncatedPackets = (r.stats.truncatedPackets ?? 0) + 1
      const ll = parseLinkLayer(lt, pdv, dataLen, pkt)
      if (ll.decoded) r.stats.decodedPackets = (r.stats.decodedPackets ?? 0) + 1
      if (ll.malformed) r.stats.malformedPackets = (r.stats.malformedPackets ?? 0) + 1
      pkt.payload = hex(pdv, 0, dataLen)
      addPkt(r, pkt)
    }

    off += blockLen
  }

  // EOF mid-record: leftover bytes too short for another block header, or a
  // block whose declared length extends past the end of the file.
  if (off !== buf.length && off + 8 > buf.length) r.stats.fileTruncated = true

  reassembleTlsSni(r.packets)
  finalize(r)
  return r
}

function parseEthernet(dv: DataView, maxLen: number, p: ParsedPacket): void {
  if (maxLen < 14) return
  p.dstMac = macStr(dv, 0)
  p.srcMac = macStr(dv, 6)
  let ethType = dv.getUint16(12)
  let ipOff = 14
  if (ethType === 0x8100 && maxLen >= 18) {
    ethType = dv.getUint16(16)
    ipOff = 18
  }
  p.ethType = ethType
  if (ethType === 0x0800) parseIPv4(dv, ipOff, maxLen - ipOff, p)
  else if (ethType === 0x86dd) parseIPv6(dv, ipOff, maxLen - ipOff, p)
  else if (ethType === 0x0806) parseARP(dv, ipOff, maxLen - ipOff, p)
}

// ARP (RFC 826): htype(2) ptype(2) hlen(1) plen(1) oper(2) sha(6) spa(4)
// tha(6) tpa(4). Decodes sender/target IPv4 so ARP shows as its own protocol
// instead of leaking through as "Other"/"unknown", and links MACs to IPs
// (the Ethernet header already captured srcMac/dstMac).
function parseARP(dv: DataView, off: number, maxLen: number, p: ParsedPacket): void {
  if (maxLen < 28) return
  if (dv.getUint16(off) !== 1 || dv.getUint8(off + 4) !== 6 || dv.getUint8(off + 5) !== 4) return
  const oper = dv.getUint16(off + 6)
  p.protocol = 'ARP'
  p.appProtocol = oper === 2 ? 'ARP-Reply' : oper === 1 ? 'ARP-Request' : 'ARP'
  p.appPayloadConfirmed = true
  p.srcIp = ipv4At(dv, off + 14)
  p.dstIp = ipv4At(dv, off + 24)
  if (maxLen >= 14) p.arpSenderMac = macStr(dv, off + 8)
}

function ipv4At(dv: DataView, off: number): string {
  return `${dv.getUint8(off)}.${dv.getUint8(off + 1)}.${dv.getUint8(off + 2)}.${dv.getUint8(off + 3)}`
}

// IP protocol number → analyst-readable name (IPv4 protocol field / IPv6
// next-header). Unknown numbers fall back to "Other (n)" — the previous
// "IP{n}" form leaked parser internals into reports as "IP0"/"IP47".
function ipProtocolName(n: number): string {
  switch (n) {
    case 0: return "HOPOPT"
    case 1: return "ICMP"
    case 2: return "IGMP"
    case 4: return "IPIP"
    case 6: return "TCP"
    case 17: return "UDP"
    case 41: return "IPv6"
    case 43: return "IPv6-Route"
    case 44: return "IPv6-Frag"
    case 47: return "GRE"
    case 50: return "ESP"
    case 51: return "AH"
    case 58: return "ICMPv6"
    case 59: return "IPv6-NoNxt"
    case 89: return "OSPF"
    case 112: return "VRRP"
    case 132: return "SCTP"
    case 136: return "UDPLite"
    default: return `Other (${n})`
  }
}

function parseIPv4(dv: DataView, off: number, maxLen: number, p: ParsedPacket): void {
  if (process.env.DEBUG_QUIC) console.error("DBG ipv4", { off, maxLen, vhl: dv.getUint8(off), totalLen: dv.getUint16(off + 2) })
  if (maxLen < 20) return
  const vhl = dv.getUint8(off)
  if ((vhl >> 4) !== 4) return
  const ihl = (vhl & 0x0f) * 4
  if (ihl < 20 || maxLen < ihl) return
  const totalLen = dv.getUint16(off + 2)
  const ttl = dv.getUint8(off + 8)
  const proto = dv.getUint8(off + 9)
  p.protocol = ipProtocolName(proto)
  p.ttl = ttl
  p.srcIp = ip4Str(dv, off + 12)
  p.dstIp = ip4Str(dv, off + 16)

  const dataOff = off + ihl
  const dataLen = Math.min(totalLen - ihl, maxLen - ihl)
  if (dataLen <= 0) return

  if (proto === 6) parseTCP(dv, dataOff, dataLen, p)
  else if (proto === 17) parseUDP(dv, dataOff, dataLen, p)
}

function parseIPv6(dv: DataView, off: number, maxLen: number, p: ParsedPacket): void {
  if (maxLen < 40) return
  let nextHdr = dv.getUint8(off + 6)
  p.ttl = dv.getUint8(off + 7) // hop limit
  p.srcIp = ip6Str(dv, off + 8)
  p.dstIp = ip6Str(dv, off + 24)
  // Walk the extension-header chain (HOPOPT/Route/Frag/AH/Dest) so TCP/UDP
  // behind extension headers is not mislabeled as e.g. "HOPOPT" (audit: 0x13xx
  // analysis saw TCP/443 flagged HOPOPT). HdrExtLen counts 8-octet units past
  // the first 8 for HOPOPT/Route/Dest; AH counts 32-bit words minus 2; Frag is
  // a fixed 8 bytes (RFC 8200). All offsets stay relative to `off`, matching
  // the caller's maxLen convention (parseIPv4).
  let rel = 40
  let fragNonFirst = false
  let guard = 0
  while (guard++ < 8 && (nextHdr === 0 || nextHdr === 43 || nextHdr === 44 || nextHdr === 51 || nextHdr === 60)) {
    if (rel + 2 > maxLen) return
    const hdrLen = nextHdr === 44 ? 8 : nextHdr === 51 ? (dv.getUint8(off + rel + 1) + 2) * 4 : (dv.getUint8(off + rel + 1) + 1) * 8
    if (hdrLen < 4 || rel + hdrLen > maxLen) return
    if (nextHdr === 44 && ((dv.getUint16(off + rel + 2) >> 3) & 0x1fff) !== 0) fragNonFirst = true
    nextHdr = dv.getUint8(off + rel)
    rel += hdrLen
  }
  p.protocol = ipProtocolName(nextHdr)
  // A non-first fragment carries no transport header — parsing one would
  // fabricate ports from fragment payload bytes.
  if (fragNonFirst) return
  const dataLen = maxLen - rel
  if (dataLen <= 0) return
  if (nextHdr === 6) parseTCP(dv, off + rel, dataLen, p)
  else if (nextHdr === 17) parseUDP(dv, off + rel, dataLen, p)
}

function parseTCP(dv: DataView, off: number, maxLen: number, p: ParsedPacket): void {
  if (process.env.DEBUG_QUIC) console.error("DBG tcp", { off, maxLen, ports: [dv.getUint16(off), dv.getUint16(off + 2)], doff: ((dv.getUint8(off + 12) >> 4) & 0x0f) * 4 })
  if (maxLen < 20) return
  const srcPort = dv.getUint16(off)
  const dstPort = dv.getUint16(off + 2)
  p.srcPort = srcPort
  p.dstPort = dstPort
  p.transport = 'TCP'
  p.tcpSeq = dv.getUint32(off + 4)
  p.tcpAck = dv.getUint32(off + 8)
  const dataOff = ((dv.getUint8(off + 12) >> 4) & 0x0f) * 4
  // dataOff < 20 means a corrupt header (or a header whose options field is
  // shorter than advertised): bailing keeps the header bytes from being
  // misparsed as app data (QA: fake "GET" payloads on pure-SYN packets).
  if (dataOff < 20 || dataOff > maxLen) {
    p.tcpPayloadLen = 0
    p.appProtocol = appProtocol(srcPort, dstPort, 'TCP')
    return
  }
  const flags = dv.getUint8(off + 13)
  p.tcpFlags = flagStr(flags)
  p.tcpWin = dv.getUint16(off + 14)

  const appOff = off + dataOff
  const appLen = maxLen - dataOff
  p.tcpPayloadLen = appLen > 0 ? appLen : 0
  if (appLen > 0) detectAppProtocol(dv, appOff, appLen, srcPort, dstPort, 'TCP', p)
  else p.appProtocol = appProtocol(srcPort, dstPort, 'TCP')
}

function parseUDP(dv: DataView, off: number, maxLen: number, p: ParsedPacket): void {
  if (maxLen < 8) return
  const srcPort = dv.getUint16(off)
  const dstPort = dv.getUint16(off + 2)
  p.srcPort = srcPort
  p.dstPort = dstPort
  p.transport = 'UDP'
  const appOff = off + 8
  const appLen = Math.min(dv.getUint16(off + 4) - 8, maxLen - 8)
  if (appLen > 0) detectAppProtocol(dv, appOff, appLen, srcPort, dstPort, 'UDP', p)
  else p.appProtocol = appProtocol(srcPort, dstPort, 'UDP')
  // A port-only "STUN" label needs the RFC 5389 magic cookie to be real —
  // every STUN message carries 0x2112A442 at offset 4. Without it the
  // datagram is just UDP on a service port (audit: observation honesty).
  if (p.appProtocol === 'STUN' && (appLen < 20 || dv.getUint32(appOff + 4) !== 0x2112a442)) {
    p.appProtocol = 'UDP'
  }
}

function detectAppProtocol(dv: DataView, off: number, len: number, srcPort: number, dstPort: number, transport: string, p: ParsedPacket): void {
  // SIP: any datagram on the signalling ports or with a SIP start line. RTP:
  // any UDP payload matching the RTP header heuristic (version 2, non-zero
  // SSRC) — mirrors analyzer/src/pipeline.rs.
  if (isSipStart(dv, off, len) || srcPort === 5060 || dstPort === 5060 || srcPort === 5061 || dstPort === 5061) {
    const sip = parseSip(dv, off, len)
    if (sip) { p.sip = sip; p.appProtocol = 'SIP'; p.appPayloadConfirmed = true }
  }
  if (transport === 'UDP') {
    const rtp = parseRtp(dv, off, len)
    if (rtp) p.rtp = rtp
  }
  if (srcPort === 53 || dstPort === 53) parseDNS(dv, off, len, p)
  else if (srcPort === 443 || dstPort === 443) {
    // QUIC (UDP 443) shares the port with TLS-over-TCP: its first byte is a
    // long-header flag (0xC0), never the TLS record type 0x16.
    if (transport === 'UDP' && !parseQUIC(dv, off, len, p)) parseTLS(dv, off, len, p)
    else if (transport === 'TCP') parseTLS(dv, off, len, p)
  }
  else if (srcPort === 80 || dstPort === 80 || srcPort === 8080 || dstPort === 8080) parseHTTP(dv, off, len, p)
  else parseHTTP(dv, off, len, p)
  // Port-table fallback: response packets from :443/:80/:3478 decode as
  // HTTPS/HTTP/STUN, not bare transport (mirrors analyzer/src/decode/mod.rs).
  if (!p.appProtocol) p.appProtocol = appProtocol(srcPort, dstPort, transport)
}

// First visible line of a SIP message: a method followed by "SIP/2.0", or a
// "SIP/2.0 <code>" response. Mirrors voip.rs's request/response split.
function isSipStart(dv: DataView, off: number, len: number): boolean {
  const head = ascii(dv, off, Math.min(len, 32))
  return /^(INVITE|REGISTER|BYE|ACK|OPTIONS|CANCEL|SUBSCRIBE|NOTIFY|MESSAGE)\s+SIP\/2\.0\s*(\r?\n|$)/.test(head)
    || /^SIP\/2\.0\s+\d{3}/.test(head)
}

function parseSip(dv: DataView, off: number, len: number): ParsedPacket['sip'] | null {
  const txt = ascii(dv, off, Math.min(len, 4096))
  const firstLineEnd = txt.indexOf('\n')
  const first = firstLineEnd >= 0 ? txt.slice(0, firstLineEnd) : txt
  const parts: string[] = []
  for (const s of first.split(/\s+/)) if (s) parts.push(s)
  if (!parts.length) return null
  let method: string, statusCode = 0
  if (parts[0].startsWith('SIP/2.0')) {
    method = 'SIP/2.0'
    statusCode = parseInt(parts[1] ?? '', 10) || 0
  } else if (parts.length >= 3 && parts[2].startsWith('SIP/2.0')) {
    method = parts[0]
  } else {
    return null
  }

  let callId = '', fromUser = '', toUser = '', viaIp = '', userAgent = '', rtpPort = 0
  let inSdp = false
  for (const raw of txt.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line) { inSdp = true; continue }
    if (!inSdp) {
      const ci = line.indexOf(':')
      if (ci < 0) continue
      const key = line.slice(0, ci).trim().toLowerCase()
      const value = line.slice(ci + 1).trim()
      if (key === 'call-id') callId = value
      else if (key === 'from') fromUser = sipUser(value)
      else if (key === 'to') toUser = sipUser(value)
      else if (key === 'via') viaIp = viaHost(value)
      else if (key === 'user-agent') userAgent = value
    } else if (line.startsWith('m=audio')) {
      const port = parseInt(line.split(/\s+/)[1] ?? '', 10) || 0
      if (port) rtpPort = port
    }
  }
  return { method, statusCode, callId, fromUser, toUser, viaIp, userAgent, rtpPort }
}

function viaHost(value: string): string {
  const tokens = value.split(/\s+/)
  for (let i = 0; i + 1 < tokens.length; i++) {
    if (tokens[i].startsWith('SIP/2.0/')) return tokens[i + 1].split(':')[0] ?? ''
  }
  return ''
}

function sipUser(value: string): string {
  const after = value.includes('<') ? value.slice(value.lastIndexOf('<') + 1) : value
  const uri = after.startsWith('sip:') ? after.slice(4) : after.startsWith('sips:') ? after.slice(5) : after
  const user = uri.split(/[@>:]/)[0] ?? ''
  return user.replace(/^"|"$/g, '')
}

// RTP header check: version bits == 2, sensible payload length, non-zero SSRC
// (kills most false positives on plain DNS/STUN UDP).
function parseRtp(dv: DataView, off: number, len: number): ParsedPacket['rtp'] | null {
  if (len < 12 || len > 1500) return null
  if (dv.getUint8(off) >> 6 !== 2) return null
  const ssrc = dv.getUint32(off + 8)
  if (ssrc === 0) return null
  return { payloadType: dv.getUint8(off + 1) & 0x7f, ssrc, sequence: dv.getUint16(off + 2) }
}

function ascii(dv: DataView, off: number, len: number): string {
  let out = ''
  for (let i = 0; i < len; i++) {
    const c = dv.getUint8(off + i)
    if (c >= 32 && c < 127) out += String.fromCharCode(c)
    else if (c === 9 || c === 13 || c === 10) out += String.fromCharCode(c)
    else out += '\n'
  }
  return out
}

// Known service ports, matched on either side of the conversation.
function appProtocol(srcPort: number, dstPort: number, transport: string): string {
  return knownProtocol(dstPort, transport) ?? knownProtocol(srcPort, transport) ?? transport
}

function knownProtocol(port: number, transport: string): string | undefined {
  if (transport === 'TCP') {
    switch (port) {
      case 20: return 'FTP-DATA'
      case 21: return 'FTP'
      case 22: return 'SSH'
      case 23: return 'Telnet'
      case 25: return 'SMTP'
      case 53: return 'DNS'
      case 80: return 'HTTP'
      case 110: return 'POP3'
      case 143: return 'IMAP'
      case 443: return 'HTTPS'
      case 445: return 'SMB'
      case 853: return 'DoT'
      case 993: return 'IMAPS'
      case 995: return 'POP3S'
      case 3389: return 'RDP'
      case 8080: return 'HTTP-Proxy'
      case 8443: return 'HTTPS-Alt'
    }
  } else if (transport === 'UDP') {
    switch (port) {
      case 53: return 'DNS'
      case 67: case 68: return 'DHCP'
      case 69: return 'TFTP'
      case 123: return 'NTP'
      case 137: return 'NetBIOS-NS'
      case 138: return 'NetBIOS-DGM'
      case 161: case 162: return 'SNMP'
      case 443: return 'QUIC'
      case 514: return 'Syslog'
      case 520: return 'RIP'
      case 546: case 547: return 'DHCPv6'
      case 1900: return 'SSDP'
      case 3478: case 3479: case 5349: case 19302: return 'STUN'
      case 3702: return 'WS-Discovery'
      case 5353: return 'mDNS'
      case 5355: return 'LLMNR'
      case 8001: return 'HTTP-Alt'
      case 51820: return 'WireGuard'
    }
  }
  return undefined
}

// Reads a DNS name at pos, following compression pointers (0xC0 0xXX) to their
// target (relative to the message start at `base`) and collecting labels.
// `next` is the message offset after the name.
function readDnsName(dv: DataView, pos: number, end: number, base: number): { name: string; next: number } | null {
  const labels: string[] = []
  let p = pos
  let next = -1
  let guard = 0
  while (p < end && guard++ < 64) {
    const b = dv.getUint8(p)
    if (b === 0) {
      if (next < 0) next = p + 1
      break
    }
    if (b & 0xc0) {
      if (p + 1 >= end) return null
      if (next < 0) next = p + 2
      p = base + (((b & 0x3f) << 8) | dv.getUint8(p + 1))
      continue
    }
    if (p + 1 + b > end) return null
    let label = ''
    for (let i = 0; i < b; i++) label += String.fromCharCode(dv.getUint8(p + 1 + i))
    labels.push(label)
    p += 1 + b
  }
  if (labels.length === 0 && next < 0) return null
  return { name: labels.join('.'), next: next < 0 ? p : next }
}

// Reverses "4.3.2.1.in-addr.arpa" -> "1.2.3.4" for PTR records.
function arpaToIp(name: string): string | undefined {
  const m = /^([0-9.]+)\.in-addr\.arpa$/.exec(name.replace(/\.$/, ''))
  if (!m) return undefined
  return m[1].split('.').reverse().join('.')
}

function parseDNS(dv: DataView, off: number, len: number, p: ParsedPacket): void {
  if (len < 12) return
  p.appProtocol = 'DNS'
  p.appPayloadConfirmed = true
  // QR bit (0x80 of the FLAGS word): queries echo no question of their own for
  // counting, but responses often DO echo the question — so distinguishing the
  // two matters for any "queries" metric (a response must never count as one).
  p.dnsQr = (dv.getUint8(off + 2) & 0x80) !== 0
  const end = off + len
  const qdcount = dv.getUint16(off + 4)
  const ancount = dv.getUint16(off + 6)
  p.dnsRcode = dv.getUint8(off + 3) & 0x0f
  if (qdcount === 0) return
  let pos = off + 12

  let query = ''
  for (let q = 0; q < qdcount; q++) {
    const r = readDnsName(dv, pos, end, off)
    if (!r) return
    if (q === 0) {
      query = r.name
      // Question type (2 bytes before qclass): the record type the client
      // ASKED for. A query carries no answers, so its type must come from the
      // question section, never from the (absent) answer. readDnsName consumed
      // the name and returned the offset AFTER it (r.next) — the TYPE field
      // lives there, not at the name start.
      if (r.next + 4 <= end) p.dnsQtype = dv.getUint16(r.next)
    }
    pos = r.next
    if (pos + 4 > end) return
    pos += 4
  }
  if (query) p.dnsQuery = query

  const answers: { name: string; ip?: string }[] = []
  for (let a = 0; a < ancount; a++) {
    if (pos + 10 > end) break
    const r = readDnsName(dv, pos, end, off)
    if (!r) break
    const owner = r.name || query
    pos = r.next
    if (pos + 10 > end) break
    const type = dv.getUint16(pos)
    const ttl = dv.getUint32(pos + 4)
    const rdlength = dv.getUint16(pos + 8)
    const rdOff = pos + 10
    if (rdOff + rdlength > end) break
    // TTL lives only in answer records — the first answer's TTL is the one
    // the resolver returned for the queried record. Queries carry none.
    if (a === 0) p.dnsTtl = ttl
    const entry: { name: string; ip?: string } = { name: owner }
    if (type === 1 && rdlength >= 4) {
      entry.ip = ip4Str(dv, rdOff)
    } else if (type === 28 && rdlength >= 16) {
      entry.ip = ip6Str(dv, rdOff)
    } else if (type === 12 && rdlength > 0) {
      const rr = readDnsName(dv, rdOff, end, off)
      if (rr) entry.name = rr.name
      const arpa = arpaToIp(owner)
      if (arpa) entry.ip = arpa
    }
    if (entry.ip || type === 12) answers.push(entry)
    pos = rdOff + rdlength
  }
  if (answers.length > 0) p.dnsAnswers = answers
}

function parseHTTP(dv: DataView, off: number, len: number, p: ParsedPacket): void {
  const end = off + Math.min(len, 2048)
  let data = ''
  for (let i = off; i < end; i++) data += String.fromCharCode(dv.getUint8(i))

  if (data.startsWith('GET ') || data.startsWith('POST ') || data.startsWith('PUT ') || data.startsWith('DELETE ') || data.startsWith('HEAD ') || data.startsWith('PATCH ')) {
    p.appProtocol = 'HTTP'
    p.appPayloadConfirmed = true
    const firstSpace = data.indexOf(' ')
    const secondSpace = data.indexOf(' ', firstSpace + 1)
    if (firstSpace > 0 && secondSpace > firstSpace) {
      p.httpMethod = data.substring(0, firstSpace)
      p.httpUri = data.substring(firstSpace + 1, secondSpace)
    }
    const hostMatch = data.match(/Host:\s*(\S+)/i)
    if (hostMatch) p.httpHost = hostMatch[1]
    // User-Agent: the only client-side OS fingerprint the capture exposes
    // (device OS column + "OS fingerprinting" observations).
    const uaMatch = data.match(/User-Agent:\s*([^\r\n]+)/i)
    if (uaMatch) p.httpUa = uaMatch[1].trim()
  } else if (data.startsWith('HTTP/1.')) {
    p.appProtocol = 'HTTP'
    p.appPayloadConfirmed = true
    // Response line: HTTP/1.1 200 OK → status code for the request row on
    // the same flow (v3.2 F-04 QA: the old UI faked 200 on every row).
    const statusMatch = data.match(/^HTTP\/1\.[01]\s+(\d{3})/)
    if (statusMatch) p.httpStatus = Number(statusMatch[1])
    const ctMatch = data.match(/Content-Type:\s*([^\r\n]+)/i)
    if (ctMatch) p.httpContentType = ctMatch[1].trim()
  }
}

function parseTLS(dv: DataView, off: number, len: number, p: ParsedPacket): void {
  if (len < 5) return
  const contentType = dv.getUint8(off)
  if (contentType !== 0x16) return
  const recordLen = dv.getUint16(off + 3)
  if (process.env.DEBUG_QUIC) console.error("DBG tls", { contentType, recordLen, len })
  // The record may span several TCP segments; only the record+handshake
  // header (9 bytes) must be present here. hsEnd is clamped to the segment
  // below, so each branch's own bounds checks keep reads in-bounds.
  if (recordLen < 4 || len < 9) return
  const handshakeType = dv.getUint8(off + 5)
  const hsLen = (dv.getUint8(off + 6) << 16) | (dv.getUint8(off + 7) << 8) | dv.getUint8(off + 8)
  if (process.env.DEBUG_QUIC) console.error("DBG tls hs", handshakeType.toString(16), hsLen, "payload", [0, 1, 2, 3, 4, 5, 6, 7, 8].map((k) => dv.getUint8(off + k).toString(16)).join(","))
  const hsEnd = off + 9 + Math.min(hsLen, recordLen - 4, len - 9)

  if (handshakeType === 0x01 && hsLen >= 39) {
    // ClientHello: SNI + version (shared with QUIC's CRYPTO frame body).
    p.appProtocol = 'TLS'
    p.appPayloadConfirmed = true
    scanClientHelloSni(dv, off + 9, hsEnd, p)
  } else if (handshakeType === 0x02 && hsLen >= 37) {
    // ServerHello: the negotiated cipher suite. TLS 1.3 changed the legacy
    // version/random/session-ID echo, but the cipher_suite still follows
    // version[2] random[32] sid_len[1] sid[..] — readable without keys (QA:
    // Cipher Suite column was empty on TLSv1.3 rows).
    if (off + 43 >= hsEnd) return
    const sidLen = dv.getUint8(off + 9 + 2 + 32)
    const suiteOff = off + 9 + 2 + 32 + 1 + sidLen
    if (suiteOff + 2 <= hsEnd) {
      p.tlsCipherSuite = dv.getUint16(suiteOff)
      // Negotiating a 0x13xx suite means TLS 1.3 regardless of the legacy
      // record/hello version field (RFC 8446 keeps 0x0303 in the header).
      if (p.tlsCipherSuite >= 0x1301 && p.tlsCipherSuite <= 0x1303) p.tlsVersion = 0x0304
    }
  } else if (handshakeType === 0x0b) {
    // Certificate: cert_list (3-byte len) → leaf cert = first DER entry.
    let pos = off + 9 + 3
    if (pos + 3 > hsEnd) return
    const certLen = (dv.getUint8(pos) << 16) | (dv.getUint8(pos + 1) << 8) | dv.getUint8(pos + 2)
    pos += 3
    if (certLen < 16 || pos + certLen > hsEnd) return
    if (process.env.DEBUG_QUIC) console.error("DBG cert hsType 0x0b certLen", certLen)
    const cert = parseX509Der(dv, pos, certLen)
    if (process.env.DEBUG_QUIC) console.error("DBG parsed cert", cert)
    if (cert) { p.tlsCert = cert; p.appProtocol = 'TLS'; p.appPayloadConfirmed = true }
  }
}

// TCP reassembly-lite: a ClientHello record larger than the MSS spans several
// segments and its SNI extension (after the key_share ext) lands in a later
// segment, so the per-packet pass above can't see it. Per 4-tuple, walk
// seq-ordered app payloads, buffer any handshake record that doesn't fit one
// segment, then re-run parseTLS on the assembled record so SNI/version/cipher
// are attributed to its first segment. Retransmits (repeated seqs) are skipped;
// a seq gap discards the partial buffer (a corrupted reassembly would be worse
// than a missed SNI).
// ponytail: reassembles only 0x16 handshake records; encrypted record bodies
// yield nothing for the report anyway, and per-connection state beyond a single
// partial record is never needed.
function reassembleTlsSni(packets: ParsedPacket[]): void {
  const flows = new Map<string, ParsedPacket[]>()
  for (const p of packets) {
    if (p.protocol !== 'TCP' || typeof p.tcpPayloadLen !== 'number' || p.tcpSeq === undefined) continue
    const k = `${p.srcIp}|${p.srcPort}|${p.dstIp}|${p.dstPort}`
    let list = flows.get(k)
    if (!list) { list = []; flows.set(k, list) }
    list.push(p)
  }
  for (const list of flows.values()) {
    if (list.length < 2) continue
    list.sort((a, b) => (a.tcpSeq ?? 0) - (b.tcpSeq ?? 0))
    let buf = ''
    let recLen = 0
    let recStart: ParsedPacket | null = null
    let lastSeq = 0
    let lastAppLen = 0
    for (const p of list) {
      const seq = p.tcpSeq ?? 0
      if (seq < lastSeq + lastAppLen) continue
      if (recStart && seq > lastSeq + lastAppLen) { buf = ''; recStart = null }
      lastSeq = seq
      const appLen = p.tcpPayloadLen ?? 0
      lastAppLen = appLen
      const app = p.payload.slice((p.length - appLen) * 2)
      let i = 0
      while (i < app.length) {
        if (recStart) {
          // The record header's length excludes its own 5 bytes, so a full
          // record is 5 + recLen bytes — buffering only recLen would drop the
          // final 5 bytes (the SNI name ends exactly at the record boundary).
          const need = (5 + recLen) * 2 - buf.length
          const take = Math.min(need, app.length - i)
          buf += app.slice(i, i + take)
          i += take
          if (buf.length >= (5 + recLen) * 2) {
            const rec = Buffer.from(buf.slice(0, (5 + recLen) * 2), 'hex')
            parseTLS(new DataView(rec.buffer, rec.byteOffset, rec.length), 0, rec.length, recStart)
            buf = ''
            recStart = null
          } else break
        } else if (app.length - i >= 10 && app.slice(i, i + 2) === '16') {
          const len = parseInt(app.slice(i + 6, i + 10), 16)
          if (len < 4) break
          if (i + (5 + len) * 2 <= app.length) { i += (5 + len) * 2; continue }
          buf = app.slice(i)
          recLen = len
          recStart = p
          break
        } else break
      }
    }
  }
}

// IANA cipher suite names — common TLS 1.3 (0x13xx) + legacy 1.2 suites.
// Unknown suites render as their hex id, never a wrong name.
export function tlsCipherSuiteName(suite: number): string {
  const NAMES: Record<number, string> = {
    0x1301: 'TLS_AES_128_GCM_SHA256',
    0x1302: 'TLS_AES_256_GCM_SHA384',
    0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
    0x1304: 'TLS_AES_128_CCM_SHA256',
    0x1305: 'TLS_AES_128_CCM_8_SHA256',
    0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  }
  return NAMES[suite] || `0x${suite.toString(16).toUpperCase().padStart(4, '0')}`
}

// Extracts the SNI extension from a TLS ClientHello body (starts at the
// client-version field). Used by both TLS records and QUIC CRYPTO frames.
function scanClientHelloSni(dv: DataView, start: number, end: number, p: ParsedPacket): void {
  if (start + 1 < end) p.tlsVersion = dv.getUint16(start)
  let pos = start
  pos += 2 // client version
  pos += 32 // random
  if (process.env.DEBUG_QUIC) console.error("DBG scan start/end/pos", start, end, pos)
  if (pos + 1 > end) return
  const sidLen = dv.getUint8(pos); pos += 1 + sidLen
  if (pos + 2 > end) return
  const csLen = dv.getUint16(pos)
  // Offering a TLS 1.3-only suite (0x13xx) marks a 1.3-capable client — the
  // legacy_version field stays 0x0303 in 1.3 ClientHellos by spec, so the
  // suite list is the honest signal (mirrors the Rust analyzer's rule).
  if (p.tlsVersion !== 0x0304) {
    const csStart = pos + 2
    for (let i = 0; i + 1 < csLen && csStart + i + 2 <= end; i += 2) {
      const suite = dv.getUint16(csStart + i)
      if (suite >= 0x1301 && suite <= 0x1303) { p.tlsVersion = 0x0304; break }
    }
  }
  pos += 2 + csLen
  if (pos + 1 > end) return
  const cmLen = dv.getUint8(pos); pos += 1 + cmLen
  if (process.env.DEBUG_QUIC) console.error("DBG scan extLenPos", pos, "byte", dv.getUint8(pos), dv.getUint8(pos + 1))
  if (pos + 2 > end) return
  const extLen = dv.getUint16(pos); pos += 2
  const extEnd = Math.min(pos + extLen, end)

  if (process.env.DEBUG_QUIC) console.error("DBG scan ext start", pos, "ttlExt", extLen, "end", extEnd)
  while (pos + 4 <= extEnd) {
    const extType = dv.getUint16(pos)
    const extDataLen = dv.getUint16(pos + 2)
    if (process.env.DEBUG_QUIC) console.error("DBG ext", extType.toString(16), extDataLen)
    if (extType === 0x0000 && extDataLen >= 5) {
      // extData = [listLen(2)][type(1)][nameLen(2)][name]; the whole SNI
      // extension fits iff listLen covers type+name — the old guard
      // `6 + listLen <= extDataLen` ALWAYS rejected well-formed extensions.
      // Reads are bound to extEnd (≤ end ≤ byteLength): extDataLen is
      // attacker-controlled and must not be trusted for bounds.
      if (pos + 6 <= extEnd) {
        const sniListLen = dv.getUint16(pos + 4)
        if (sniListLen >= 3 && sniListLen <= extDataLen - 2) {
          const nameType = dv.getUint8(pos + 6)
          if (nameType === 0x00 && pos + 9 <= extEnd) {
            const nameLen = dv.getUint16(pos + 7)
            if (nameLen > 0 && nameLen <= sniListLen - 3 && pos + 9 + nameLen <= extEnd) {
              let name = ''
              for (let i = 0; i < nameLen; i++) name += String.fromCharCode(dv.getUint8(pos + 9 + i))
              p.tlsSni = name
            }
          }
        }
      }
      break
    }
    pos += 4 + extDataLen
  }
}

// ── QUIC: long-header Initial packets carry the TLS ClientHello in the first
// CRYPTO frame, so the SNI is reachable without any QUIC connection state. ──

function quicVarint(dv: DataView, pos: number, end: number): { value: number; bytes: number } {
  // A 0-byte result means "out of range": the caller bails instead of
  // advancing, so a truncated trailing packet can never RangeError the
  // whole parse (QA: last-packet truncation killed the entire upload).
  if (pos >= end) return { value: 0, bytes: 0 }
  const b = dv.getUint8(pos)
  const mode = b >> 6
  if (mode === 0) return { value: b & 0x3f, bytes: 1 }
  if (mode === 1) {
    if (pos + 2 > end) return { value: 0, bytes: 0 }
    return { value: ((b & 0x3f) << 8) | dv.getUint8(pos + 1), bytes: 2 }
  }
  if (mode === 2) {
    if (pos + 4 > end) return { value: 0, bytes: 0 }
    return { value: ((b & 0x3f) << 24) | (dv.getUint8(pos + 1) << 16) | (dv.getUint8(pos + 2) << 8) | dv.getUint8(pos + 3), bytes: 4 }
  }
  if (pos + 8 > end) return { value: 0, bytes: 0 }
  const hi = ((b & 0x3f) << 24) | (dv.getUint8(pos + 1) << 16) | (dv.getUint8(pos + 2) << 8) | dv.getUint8(pos + 3)
  let lo = 0
  for (let i = 4; i < 8; i++) lo = lo * 256 + dv.getUint8(pos + i)
  return { value: hi * 0x100000000 + lo, bytes: 8 }
}

// Returns true when the payload is a parseable QUIC Initial packet.
function parseQUIC(dv: DataView, off: number, len: number, p: ParsedPacket): boolean {
  if (len < 20) return false
  const first = dv.getUint8(off)
  if ((first & 0x40) === 0) return false // short header (1-RTT): no SNI there
  const type = (first >> 4) & 0x03
  if (type !== 0) return false // only Initial packets carry a full CH
  const version = dv.getUint32(off + 1)
  if (version === 0) return false // version negotiation
  // Absolute end of the payload: pos is absolute (DataView-wide), len relative.
  const end = off + len
  let pos = off + 5
  const dcid = quicVarint(dv, pos, end); pos += dcid.bytes
  if (dcid.bytes === 0 || pos + dcid.value > end) return false
  pos += dcid.value
  const scid = quicVarint(dv, pos, end); pos += scid.bytes
  if (scid.bytes === 0 || pos + scid.value > end) return false
  pos += scid.value
  const token = quicVarint(dv, pos, end); pos += token.bytes
  if (token.bytes === 0 || pos + token.value > end) return false
  pos += token.value
  // Packet number field length: 1-4 bytes (leading two bits of the byte).
  if (pos + 1 > end) return false
  const pnLen = (dv.getUint8(pos) & 0x03) + 1
  pos += 1 + pnLen

  // Frames: the first CRYPTO frame carries the CH handshake message.
  while (pos < end) {
    const frameType = dv.getUint8(pos)
    if (frameType !== 0x06) { pos += 1; continue } // non-CRYPTO frame, skip tag
    let f = pos + 1
    const offV = quicVarint(dv, f, end); f += offV.bytes
    const dataLen = quicVarint(dv, f, end); f += dataLen.bytes
    if (offV.bytes === 0 || dataLen.bytes === 0 || offV.value !== 0 || dataLen.value < 6 || f + dataLen.value > end) return false
    // TLS handshake message header (type + 3-byte length), then CH body.
    const hsType = dv.getUint8(f)
    if (hsType !== 0x01) return false
    const hsBodyLen = (dv.getUint8(f + 1) << 16) | (dv.getUint8(f + 2) << 8) | dv.getUint8(f + 3)
    if (hsBodyLen < 39 || f + 4 + hsBodyLen > f + dataLen.value) return false
    p.appProtocol = 'QUIC'
    p.appPayloadConfirmed = true
    scanClientHelloSni(dv, f + 4, f + 4 + hsBodyLen, p)
    return true
  }
  return false
}

// ── X.509 (DER) minimal extractor: subject/issuer CN, serial, validity, SAN,
// signature algorithm and public key size via targeted pattern scans. Enough
// for display; a full ASN.1 walker would be over-engineering for a browser. ──

interface DerTlv { tag: number; ctor: boolean; off: number; len: number }

function derTlv(dv: DataView, i: number, end: number): DerTlv | null {
  if (i + 1 > end) return null
  const id = dv.getUint8(i)
  const tag = id & 0x1f
  const ctor = (id & 0x20) !== 0
  let pos = i + 1
  if ((id & 0x1f) === 0x1f) { // long-form tag
    while (pos < end && (dv.getUint8(pos) & 0x80) !== 0) pos++
    pos++
  }
  if (pos >= end) return null
  let len = dv.getUint8(pos); pos++
  if (len === 0x80) return null // indefinite length: not valid in X.509
  if ((len & 0x80) !== 0) {
    const n = len & 0x7f
    if (n === 0 || n > 4 || pos + n > end) return null
    len = 0
    for (let k = 0; k < n; k++) len = len * 256 + dv.getUint8(pos + k)
    pos += n
  }
  if (pos + len > end) return null
  return { tag, ctor, off: pos, len }
}

// Byte-scan for a pattern (OIDs live inside TLV content, so matches can't be
// restricted to TLV starts). Only the FOLLOWING value is read as a TLV, so a
// rare mid-content match mislabels at worst — never crashes.
function derFind(dv: DataView, i: number, end: number, pattern: number[]): number {
  for (; i + pattern.length <= end; i++) {
    let match = true
    for (let k = 0; k < pattern.length; k++) {
      if (dv.getUint8(i + k) !== pattern[k]) { match = false; break }
    }
    if (match) return i
  }
  return -1
}

function derString(dv: DataView, t: DerTlv): string | null {
  if (t.len > 128) return null
  let s = ''
  for (let k = 0; k < t.len; k++) {
    const b = dv.getUint8(t.off + k)
    if (b === 0 || b > 0x7f) return null // printable/UTF-8 ASCII subset only
    s += String.fromCharCode(b)
  }
  return s
}

function derTime(dv: DataView, t: DerTlv): number | null {
  // UTCTime YYMMDDHHMMSSZ (2-digit year), GeneralizedTime YYYYMMDDHHMMSSZ.
  const s = derString(dv, t)
  if (!s) return null
  if (t.tag === 0x17 && s.length === 13 && s.endsWith('Z')) {
    const yy = Number(s.slice(0, 2))
    const y = (yy >= 50 ? 1900 : 2000) + yy
    return Date.parse(`${y}-${s.slice(2, 4)}-${s.slice(4, 6)}T${s.slice(6, 8)}:${s.slice(8, 10)}:${s.slice(10, 12)}Z`)
  }
  if (t.tag === 0x18 && s.length === 15 && s.endsWith('Z')) {
    return Date.parse(`${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 14)}Z`)
  }
  return null
}

function parseX509Der(dv: DataView, off: number, len: number): ParsedPacket['tlsCert'] | null {
  const end = off + len
  const outer = derTlv(dv, off, end)
  if (!outer || outer.tag !== 0x10 || !outer.ctor) return null

  // Certificate → tbs (SEQUENCE) → optional version [0] (tag 0, 0x00 or
  // 0xa0) → serial INTEGER.
  let i = outer.off
  const tbs = derTlv(dv, i, end)
  if (!tbs || tbs.tag !== 0x10 || !tbs.ctor) return null
  i = tbs.off
  let first = derTlv(dv, i, end)
  if (first && first.tag === 0) i = first.off + first.len
  first = derTlv(dv, i, end)
  if (!first || first.tag !== 0x02) return null
  let serial = ''
  for (let k = 0; k < first.len; k++) serial += dv.getUint8(first.off + k).toString(16).padStart(2, '0')

  // CNs in layout order: issuer comes before subject in a certificate.
  const cnTag = [0x06, 0x03, 0x55, 0x04, 0x03]
  let subject = '', issuer = ''
  const cnIdx1 = derFind(dv, outer.off, end, cnTag)
  if (cnIdx1 >= 0) {
    const after = cnIdx1 + cnTag.length
    const s1 = derTlv(dv, after, end)
    const firstCn = s1 ? derString(dv, s1) : null
    if (firstCn && s1) {
      issuer = firstCn
      const cnIdx2 = derFind(dv, s1.off + s1.len, end, cnTag)
      if (cnIdx2 >= 0) {
        const s2 = derTlv(dv, cnIdx2 + cnTag.length, end)
        const secondCn = s2 ? derString(dv, s2) : null
        if (secondCn) subject = secondCn
      }
    }
  }

  // Validity: every time value; min = notBefore, max = notAfter. Times are
  // nested inside the tbs validity SEQUENCE, so byte-scan the tag and
  // validate the following TLV (derTime rejects any false-positive match).
  let notBefore = -1, notAfter = -1
  const timeEnd = tbs.off + tbs.len
  for (const tag of [0x17, 0x18]) {
    for (let j = tbs.off; j < timeEnd; j++) {
      if (dv.getUint8(j) !== tag) continue
      const t = derTlv(dv, j, timeEnd)
      if (t && t.tag === tag && !t.ctor) {
        const tm = derTime(dv, t)
        if (tm !== null) { if (notBefore < 0 || tm < notBefore) notBefore = tm; if (tm > notAfter) notAfter = tm }
      }
    }
  }

  // SAN: extension OID 2.5.29.17 → OCTET STRING → SEQUENCE of GeneralNames.
  const san: string[] = []
  const sanIdx = derFind(dv, outer.off, end, [0x06, 0x03, 0x55, 0x1d, 0x11])
  if (sanIdx >= 0) {
    const oct = derTlv(dv, sanIdx + 5, end)
    if (oct && oct.tag === 0x04) {
      const inner = derTlv(dv, oct.off, oct.off + oct.len)
      if (inner && inner.tag === 0x10) {
        for (let j = inner.off; j < inner.off + inner.len; ) {
          const g = derTlv(dv, j, inner.off + inner.len)
          if (!g) break
          if (g.tag === 0x02) { const d = derString(dv, g); if (d) san.push(d) } // dNSName
          else if (g.tag === 0x07 && (g.len === 4 || g.len === 16)) {
            let ip = ''
            for (let k = 0; k < g.len; k++) { if (k) ip += '.'; ip += dv.getUint8(g.off + k) }
            san.push(ip) // iPAddress
          }
          j = g.off + g.len
        }
      }
    }
  }

  // Signature algorithm: scan the well-known OID encodings.
  const sigOids: [number[], string][] = [
    [[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b], 'sha256WithRSA'],
    [[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c], 'sha384WithRSA'],
    [[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d], 'sha512WithRSA'],
    [[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05], 'sha1WithRSA'],
    [[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02], 'ecdsaWithSHA256'],
    [[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03], 'ecdsaWithSHA384'],
  ]
  let signatureAlgorithm = ''
  for (const [oid, name] of sigOids) {
    if (derFind(dv, outer.off, end, oid) >= 0) { signatureAlgorithm = name; break }
  }

  // Key size: RSA → modulus INTEGER inside the SPKI BIT STRING; EC / Ed25519
  // → curve OID length. The BIT STRING marker depends on its length encoding
  // (0x81 one-byte / 0x82 two-byte long form, or plain `0x03`), and a stray
  // single-byte match inside an OID is rejected by the content guard (content
  // must be 0x00 0x30 = unused-bits 0 then a SEQUENCE).
  let keySize = 0
  const spkiSigs = [[0x03, 0x81], [0x03, 0x82], [0x03]]
  for (const marker of spkiSigs) {
    const bitStr = derFind(dv, outer.off, end, marker)
    if (bitStr < 0) continue
    const b = derTlv(dv, bitStr, end)
    if (b && b.tag === 0x03 && b.len >= 3 && dv.getUint8(b.off) === 0 && dv.getUint8(b.off + 1) === 0x30) {
      const seq = derTlv(dv, b.off + 1, b.off + b.len)
      if (seq && seq.tag === 0x10) {
        const mod = derTlv(dv, seq.off, seq.off + seq.len)
        if (mod && mod.tag === 0x02) keySize = mod.len * 8
      }
    }
    if (keySize > 0) break
  }
  if (keySize === 0) {
    const curveOids: [number[], number][] = [
      [[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22], 256],
      [[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23], 384],
      [[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x24], 521],
      [[0x2b, 0x65, 0x70], 256], // Ed25519
    ]
    for (const [oid, bits] of curveOids) {
      if (derFind(dv, outer.off, end, oid) >= 0) { keySize = bits; break }
    }
  }

  return { subject, issuer, serial, notBefore, notAfter, san, signatureAlgorithm, keySize }
}
