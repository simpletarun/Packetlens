import { PCAPResult, ParsedPacket, tlsCipherSuiteName } from './pcap'
import { computeRisk, buildRiskInputs, burstDetected, RISK_PARAMS } from './risk'

export const ANALYZER_VERSION = "3.2.0"

export interface AnalysisPacket {
  num: number; timestamp: string; srcIp: string; dstIp: string
  srcPort: number; dstPort: number; protocol: string
  length: number; flags: string; ttl: number; info: string
  // On-wire frame size (captured length when snaplen truncated the frame).
  origLength?: number
  // App-layer label when the parser identified one (HTTPS/STUN/mDNS…).
  // Optional: older demo packets don't carry it.
  appProtocol?: string
  // Transport layer (TCP/UDP/ICMP…) — the timeline's TCP/UDP split keys on
  // this, never on the app-layer `protocol` (HTTPS is still a TCP packet).
  transport?: string
}

export interface AnalysisFlow {
  id: string; srcIp: string; dstIp: string
  srcPort: number; dstPort: number; protocol: string
  packets: number; bytesTotal: number; bytesSent: number; bytesRecv: number
  duration: number; startTime: string; endTime: string
  // True when either endpoint is undecodable ("—" placeholder): direction is
  // unknowable, so bytesSent/bytesRecv are 0 and UI must show "—" / "unknown"
  // instead of implying a zero-byte or symmetric conversation (QA: large/verylarge).
  directionUnknown?: boolean
  // v3.2 TCP health (TCP flows only): retransmitted segments, out-of-order
  // segments, zero-window advertisements, RST count, handshake RTT (ms) and
  // loss % (retrans/data segments). Absent on UDP traffic.
  retrans?: number
  ooo?: number
  zeroWindow?: number
  rstCount?: number
  rttMs?: number
  lossPct?: number
}

export interface AnalysisSession {
  id: string; srcIp: string; dstIp: string
  srcPort: number; dstPort: number; protocol: string
  packets: number; bytes: number; state: string
  duration: number; startTime: string
}

export interface AnalysisDnsEntry {
  id: string; timestamp: string; srcIp: string; dstIp: string
  query: string; type: string; responseCode: string; answer: string
  // null = no answer record in this response (QA: 0 rendered as a fake
  // "0s" TTL — a real DNS TTL was never seen).
  ttl: number | null
  isResponse?: boolean
}

export interface AnalysisHttpEntry {
  id: string; timestamp: string; srcIp: string; dstIp: string
  method: string; uri: string; host: string
  status: number; contentType: string; userAgent: string; length: number
}

export interface AnalysisTlsEntry {
  id: string; timestamp: string; srcIp: string; dstIp: string
  version: string; sni: string; cipherSuite: string
  ja3: string; issuer: string; validityDays: number
}

export interface AnalysisFile {
  id: string; timestamp: string; srcIp: string; dstIp: string
  filename: string; mimeType: string; size: number
  protocol: string; md5: string
}

// A VoIP/SIP call: one INVITE dialog unified with its RTP media stream. RTP
// packets are matched back to the call by the SDP `m=audio` port plus the
// caller/callee peer pair; a call with no matching RTP shows null media.
export interface AnalysisCall {
  id: string
  callId: string
  from: string
  to: string
  viaIp: string
  startTime: string
  endTime: string | null
  durationSec: number | null
  userAgent: string
  status: string
  rtpPayloadType: number | null
  rtpSsrc: number | null
  rtpPackets: number
  rtpBytes: number
}

export interface AnalysisCredential {
  id: string; timestamp: string; srcIp: string; dstIp: string
  protocol: string; username: string; password: string; service: string
}

export interface AnalysisCertificate {
  id: string; serial: string; subject: string; issuer: string
  // null = the capture had no valid time for this certificate (a validity of
  // -1 used to render as "1969-12-31" — a fabricated date).
  notBefore: string | null; notAfter: string | null; san: string[]
  signatureAlgorithm: string; keySize: number
}

export interface AnalysisDevice {
  id: string; ip: string; mac: string; hostname: string
  vendor: string; os: string; firstSeen: string; lastSeen: string
  packets: number; bytes: number
  // v3.2: every other address this device was seen on (IPv6, extra IPv4).
  addresses?: string[]
  // Where the OS column's value came from: a User-Agent in this device's own
  // requests, or the TTL heuristic (≥2 samples, private IPs only).
  osSource?: 'ua' | 'ttl'
}

export interface AnalysisThreat {
  id: string; timestamp: string; signature: string; category: string
  severity: number; confidence: number; ruleId: string; srcIp: string; dstIp: string
  srcPort: number; dstPort: number; protocol: string; evidence: string
}

export interface AnalysisTimelineEntry {
  time: string; packets: number; bytes: number
  tcp: number; udp: number; dns: number; tls: number
}

export interface AnalysisBandwidthPoint {
  time: string; in: number; out: number
}

export interface AnalysisJob {
  id: string; filename: string; fileSize: number
  status: string; progress: number; stage: string
  totalPackets: number; totalFlows: number; conversations: number
  devices: number; externalIps: number; countries: number
  domains: number; protocols: string[]
  alerts: number; riskScore: number; captureDuration: number; createdAt: string
  analyzerVersion?: string
  sha256?: string
  sha1?: string
  md5?: string
}

export interface FileInfo {
  sha256: string
  sha1: string
  md5: string
}

export interface BurstInfo {
  detected: boolean
  peakThroughput: number
  averageThroughput: number
  ratio: number
  start: number
  end: number
  duration: number
}

export interface AnalysisAdvancedMetrics {
  throughputAvg: number
  throughputPeak: number
  burst: BurstInfo | null
  beaconDetected: boolean
  dnsTunnelingSuspected: boolean
  dataExfiltrationSuspected: boolean
  torVpnProxyDetected: boolean
  portScanEnhanced: boolean
  ja3Suspicious: boolean
  dnsTunnelEvidence?: string
  beaconEvidence?: string
  topTalkers: { ip: string; bytesOut: number; bytesIn: number; packetsOut: number; packetsIn: number }[]
  iocs: { type: string; value: string; description: string; severity: number }[]
  mitreMappings: { technique: string; id: string; description: string; severity: number }[]
}

export interface AnalysisResult {
  job: AnalysisJob
  packets: AnalysisPacket[]
  flows: AnalysisFlow[]
  sessions: AnalysisSession[]
  dns: AnalysisDnsEntry[]
  http: AnalysisHttpEntry[]
  tls: AnalysisTlsEntry[]
  files: AnalysisFile[]
  calls: AnalysisCall[]
  credentials: AnalysisCredential[]
  certificates: AnalysisCertificate[]
  devices: AnalysisDevice[]
  threats: AnalysisThreat[]
  timeline: AnalysisTimelineEntry[]
  bandwidth: AnalysisBandwidthPoint[]
  advancedMetrics: AnalysisAdvancedMetrics
  fileInfo: FileInfo
  // Decode diagnostics (undecodable-input handling): link types from the
  // capture header and how many packets had their encapsulation parsed.
  // decodeRate = decoded / total — a rate near 0 means the verdict must be
  // UNKNOWN, never SAFE.
  decode: { decoded: number; total: number; linkTypes: number[] }
}

function hexToAscii(hex: string, max = 2048): string {
  const len = Math.min(hex.length, max * 2)
  let out = ''
  for (let i = 0; i < len; i += 2) {
    const c = parseInt(hex.substring(i, i + 2), 16)
    if (c >= 32 && c < 127) out += String.fromCharCode(c)
  }
  return out
}

function pktToAnalysis(p: ParsedPacket, seqBase: number | undefined): AnalysisPacket {
  const flags = p.tcpFlags || '\u2014'
  let info: string
  // Responses echo the question name, so the Info column must say "response",
  // not "query", or every reply looks like a second client query (D2).
  if (p.dnsQuery) info = p.dnsQr ? `DNS response for ${p.dnsQuery}` : `DNS query for ${p.dnsQuery}`
  else if (p.httpMethod) info = `${p.httpMethod} ${p.httpUri || '/'}`
  else if (p.tlsSni) info = `TLS Client Hello - ${p.tlsSni}`
  else if (p.tcpFlags) {
    // Relative TCP sequence per flow, rebased on the flow's first packet
    // (capture order = the SYN). The previous Seq=p.num was a GLOBAL packet
    // counter that jumped between flows and read as TCP behavior (QA).
    const seq = typeof p.tcpSeq === 'number' && seqBase !== undefined ? p.tcpSeq - seqBase : undefined
    info = seq !== undefined ? `${p.tcpFlags} Seq=${seq}` : `${p.tcpFlags} pkt #${p.num}`
  }
  else info = `${p.protocol || 'IP'} packet #${p.num}`
  return {
    num: p.num,
    timestamp: new Date(p.timestamp * 1000).toISOString(),
    srcIp: p.srcIp || '\u2014',
    dstIp: p.dstIp || '\u2014',
    srcPort: p.srcPort || 0,
    dstPort: p.dstPort || 0,
    protocol: p.protocol || 'OTHER',
length: p.length,
    origLength: p.origLength,
    flags,
    // Real IP TTL from the header — the previous hardcoded 64 made the TTL
    // column useless and OS fingerprinting impossible.
    ttl: p.ttl ?? 0,
    info,
    appProtocol: p.appProtocol || undefined,
    transport: p.transport,
  }
}

// Direction-normalized key for a conversation (smaller IP sorts first): the
// same 5-tuple both flow grouping and the TCP state machine key on.
function flowKeyOf(p: ParsedPacket): string {
  const a = p.srcIp || '\u2014'
  const b = p.dstIp || '\u2014'
  const ap = p.srcPort || 0
  const bp = p.dstPort || 0
  const proto = p.protocol || 'OTHER'
  return a < b || (a === b && ap < bp)
    ? `${a}|${b}|${ap}|${bp}|${proto}`
    : `${b}|${a}|${bp}|${ap}|${proto}`
}

// Direction-SENSITIVE 4-tuple: the sequence-space base for relative Seq
// display. TCP sequences are per-direction (each side numbers independently),
// so rebasing must be too — flowKeyOf's normalized key would subtract the
// client's SYN from the server's segments (QA: server Seq=834237805).
function dirKeyOf(p: ParsedPacket): string {
  return `${p.srcIp || '\u2014'}|${p.dstIp || '\u2014'}|${p.srcPort || 0}|${p.dstPort || 0}`
}

function deriveFlows(packets: ParsedPacket[]): AnalysisFlow[] {
  const groups = new Map<string, ParsedPacket[]>()
  for (const p of packets) {
    const key = flowKeyOf(p)
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key)!.push(p)
  }
  return Array.from(groups.entries()).map(([key, pkts], idx) => {
    const [srcIp, dstIp, srcPort, dstPort, protocol] = key.split('|')
    // min/max over packet timestamps; a single large flow (or big capture)
    // can exceed the argument limit of Math.max/min spreads (RangeError).
    let tMin = Infinity, tMax = -Infinity
    for (const p of pkts) {
      const t = p.timestamp * 1000
      if (t < tMin) tMin = t
      if (t > tMax) tMax = t
    }
    // Direction attribution requires DECODED addresses. Undecodable packets
    // (unsupported encapsulation) all key as "—|—|0|0|OTHER"; counting them
    // in both legs would make bytesSent = bytesRecv = total — a perfectly
    // symmetric conversation that never happened (QA: large/verylarge).
    // The recv leg is exclusive (srcIp !== srcIp of the flow) so self-flows
    // (ARP srcIp == dstIp, e.g. 192.168.1.17 → 192.168.1.17) count each
    // packet ONCE — the old filters matched both legs and produced
    // 84 sent + 84 recv for a 84-byte flow (QA: ARP byte-total audit).
    const sent = pkts.filter(p => p.srcIp === srcIp)
    const recv = pkts.filter(p => p.dstIp === srcIp && p.srcIp !== srcIp)
    return {
      id: `flow-${idx + 1}`, srcIp, dstIp, srcPort: Number(srcPort), dstPort: Number(dstPort),
      protocol, packets: pkts.length,
      bytesTotal: pkts.reduce((s, p) => s + p.length, 0),
      bytesSent: sent.reduce((s, p) => s + p.length, 0),
      bytesRecv: recv.reduce((s, p) => s + p.length, 0),
      directionUnknown: srcIp === '\u2014' || dstIp === '\u2014',
      // Sub-second flows keep ms precision (116 ms → 0.116 s); the desktop
      // engine exports raw f64 seconds, rounding here broke parity (QA audit).
      duration: Math.round(((tMax - tMin) / 1000) * 1000) / 1000,
      startTime: new Date(tMin).toISOString(),
      endTime: new Date(tMax).toISOString(),
      ...(protocol === 'TCP' ? tcpHealth(pkts, srcIp) : {}),
    }
  }).sort((a, b) => b.packets - a.packets)
}

// TCP health per flow. Retransmission = a data segment whose (seq, len) was
// already seen in the same direction; OoO = a data seq below the direction's
// last observed seq; RTT from the LAST SYN before the first SYN-ACK (a SYN
// retransmission would otherwise pair with a stale SYN and inflate RTT);
// loss% = retrans/data segments. Seq spaces are tracked per direction (each
// side numbers independently).
// ponytail: whole-flow map with 32-bit seq wraparound near 4 GB of transfer is
// not handled — split the seq space per matched segment if such captures matter.
interface TcpHealth {
  retrans: number
  ooo: number
  zeroWindow: number
  rstCount: number
  rttMs?: number
  lossPct?: number
}
function tcpHealth(pkts: ParsedPacket[], srcIp: string): TcpHealth {
  const sorted = [...pkts].sort((a, b) => a.timestamp - b.timestamp)
  const dir = (p: ParsedPacket) => (p.srcIp || '\u2014') === srcIp ? 0 : 1
  const seen: [Map<number, number>, Map<number, number>] = [new Map(), new Map()]
  const lastSeq: [number, number] = [-1, -1]
  let retrans = 0, ooo = 0, zeroWindow = 0, rstCount = 0, dataSegments = 0
  let lastSynT: number | null = null
  let rttMs: number | null = null
  for (const p of sorted) {
    if (!p.tcpFlags) continue
    if (p.tcpFlags.includes('RST')) rstCount++
    // RSTs conventionally carry window 0 (RFC 793 reset semantics) — a reset
    // is not a flow-control advertisement, so it must not inflate the
    // zero-window counter (QA: 4 RSTs read as "4 zero-window").
    if (p.tcpWin === 0 && !p.tcpFlags.includes('RST')) zeroWindow++
    if (p.tcpFlags.includes('SYN') && !p.tcpFlags.includes('ACK')) lastSynT = p.timestamp
    if (p.tcpFlags.includes('SYN') && p.tcpFlags.includes('ACK') && lastSynT !== null && rttMs === null) {
      const rtt = Math.round((p.timestamp - lastSynT) * 1000)
      // A handshake > 5 s is a capture artifact (SYN retransmit backoff, gap
      // between packets), not a path RTT — don't pollute the aggregate.
      if (rtt >= 1 && rtt <= 5000) rttMs = rtt
    }
    const plen = p.tcpPayloadLen ?? 0
    if (plen <= 0 || typeof p.tcpSeq !== 'number') continue
    const d = dir(p)
    dataSegments++
    // Retransmission and out-of-order are mutually exclusive: a retransmitted
    // segment is below lastSeq by construction, so counting it again as ooo
    // double-reports pure-loss flows (QA: 1 retrans read as 1 retrans + 1 ooo).
    if (seen[d].get(p.tcpSeq) === plen) retrans++
    else {
      seen[d].set(p.tcpSeq, plen)
      if (lastSeq[d] >= 0 && p.tcpSeq < lastSeq[d]) ooo++
    }
    lastSeq[d] = p.tcpSeq
  }
  const lossPct = dataSegments === 0 ? null : Math.round((retrans / dataSegments) * 1000) / 10
  return {
    retrans, ooo, zeroWindow, rstCount,
    ...(rttMs !== null ? { rttMs } : {}),
    ...(lossPct !== null ? { lossPct } : {}),
  }
}

// Observed TCP flags per conversation — the session state machine's input.
interface TcpConversationState {
  syn: boolean
  synAck: boolean
  ack: boolean
  rst: boolean
  fin: boolean
}

function tcpConversationStates(packets: ParsedPacket[]): Map<string, TcpConversationState> {
  const states = new Map<string, TcpConversationState>()
  for (const p of packets) {
    if (!p.tcpFlags) continue
    const key = flowKeyOf(p)
    let s = states.get(key)
    if (!s) {
      s = { syn: false, synAck: false, ack: false, rst: false, fin: false }
      states.set(key, s)
    }
    if (p.tcpFlags.includes('SYN')) s.syn = true
    if (p.tcpFlags.includes('ACK')) s.ack = true
    if (p.tcpFlags.includes('RST')) s.rst = true
    if (p.tcpFlags.includes('FIN')) s.fin = true
    if (p.tcpFlags.includes('SYN') && p.tcpFlags.includes('ACK')) s.synAck = true
  }
  return states
}

function deriveSessions(flows: AnalysisFlow[], tcpStates: Map<string, TcpConversationState>): AnalysisSession[] {
  // State from the OBSERVED handshake, not a blanket "ESTABLISHED": a flow
  // with 2-3 SYN packets and no ACK is a failed/partial handshake, and a
  // flow that only saw RST never established. Mid-stream captures without a
  // SYN fall back to ESTABLISHED (the honest guess).
  // Flow srcIp/dstIp carry the direction-normalized order from deriveFlows,
  // so the state key rebuilds identically to flowKeyOf(p) on raw packets.
  const keyOf = (f: AnalysisFlow): string =>
    `${f.srcIp}|${f.dstIp}|${f.srcPort}|${f.dstPort}|${f.protocol}`
  const stateFor = (f: AnalysisFlow): string => {
    if (f.protocol !== 'TCP') return 'STATELESS'
    const s = tcpStates.get(keyOf(f))
    if (s?.rst) return 'RESET'
    if (s?.fin) return 'CLOSED'
    if (s?.synAck) return 'ESTABLISHED'
    if (s?.syn) return 'INITIATED'
    return 'ESTABLISHED'
  }
  return flows.map((f, i) => ({
    id: `sess-${i + 1}`, srcIp: f.srcIp, dstIp: f.dstIp,
    srcPort: f.srcPort, dstPort: f.dstPort, protocol: f.protocol,
    packets: f.packets, bytes: f.bytesTotal,
    state: stateFor(f),
    duration: f.duration, startTime: f.startTime,
  }))
}

// DNS record-type names for the question-type code captured per message.
// The type column shows what was ASKED (the question section) — a response's
// own answers could be CNAME chains, so the question type is the honest label.
const DNS_TYPE_NAMES: Record<number, string> = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
  28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 43: 'DS', 46: 'RRSIG', 47: 'NSEC',
  48: 'DNSKEY', 255: 'ANY',
}

// DNS response-code names — the page's NXDOMAIN counter keys on the literal.
const DNS_RCODE_NAMES: Record<number, string> = {
  0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
  4: 'NOTIMP', 5: 'REFUSED',
}

function deriveDns(packets: ParsedPacket[]): AnalysisDnsEntry[] {
  // All DNS messages are kept (queries AND responses): responses carry the
  // rcode and answer data the pages display. The QR flag labels each row so
  // query counts and distinct-lookup counts never treat a response echo or a
  // relayed copy as a second query from the client.
  return packets.filter(p => p.dnsQuery).map((p, i) => {
    const first = p.dnsAnswers?.[0]
    return {
      id: `dns-${i + 1}`,
      timestamp: new Date(p.timestamp * 1000).toISOString(),
      srcIp: p.srcIp || '\u2014', dstIp: p.dstIp || '\u2014',
      query: p.dnsQuery!,
      // Record type from the question section; the old answer-based
      // heuristic mislabeled response rows (D3).
      type: DNS_TYPE_NAMES[p.dnsQtype ?? -1] || (first?.ip?.includes(':') ? 'AAAA' : 'A'),
      responseCode: p.dnsRcode === undefined ? 'NOERROR' : (DNS_RCODE_NAMES[p.dnsRcode] || `RCODE ${p.dnsRcode}`),
      answer: first?.ip || first?.name || '\u2014',
      // Real TTL from the answer record; null when there is no answer
      // (queries and answer-less responses carry no TTL — 0 would fabricate
      // one on the DNS page).
      ttl: p.dnsQr ? (p.dnsTtl ?? null) : null,
      isResponse: p.dnsQr === true,
    }
  })
}

function deriveHttp(packets: ParsedPacket[]): AnalysisHttpEntry[] {
  // Response side first: index by reversed flow so each request row shows the
  // real status + Content-Type the server sent back (QA: was faked 200 / "").
  const responseByFlow = new Map<string, ParsedPacket>()
  for (const p of packets) {
    if (p.httpStatus === undefined || !p.srcIp || !p.dstIp) continue
    responseByFlow.set(`${p.srcIp}:${p.srcPort}:${p.dstIp}:${p.dstPort}`, p)
  }
  return packets.filter(p => p.httpMethod).map((p, i) => {
    const res = p.srcIp && p.dstIp
      ? responseByFlow.get(`${p.dstIp}:${p.dstPort}:${p.srcIp}:${p.srcPort}`)
      : undefined
    return {
      id: `http-${i + 1}`,
      timestamp: new Date(p.timestamp * 1000).toISOString(),
      srcIp: p.srcIp || '\u2014', dstIp: p.dstIp || '\u2014',
      method: p.httpMethod!, uri: p.httpUri || '/', host: p.httpHost || '',
      // Real status when the server answered; 0 renders as "—" (no response).
      status: res?.httpStatus ?? 0,
      contentType: res?.httpContentType || '',
      // Real User-Agent from the request — feeds the device OS fingerprint.
      userAgent: p.httpUa || '',
      // Payload only — p.length counts Ethernet/IP/TCP headers (~54 B/frame)
      // and inflates "Total Data" by that per request (QA: body-less GETs
      // showed ~400 B of "data"). Same rule deriveFiles already uses.
      length: p.tcpPayloadLen ?? p.length,
    }
  })
}

// The legacy_version / supported_versions field of a ClientHello: the
// real TLS version the client offered. Unknown values render as a hex
// label, never a wrong name (QA: the TLSv1.2 report card read 0 forever
// because deriveTls hardcoded TLSv1.3).
function tlsVersionName(v?: number): string {
  switch (v) {
    case 0x0304: return 'TLSv1.3'
    case 0x0303: return 'TLSv1.2'
    case 0x0302: return 'TLSv1.1'
    case 0x0301: return 'TLSv1.0'
    case 0x0300: return 'SSLv3'
    default: return v ? `TLS 0x${v.toString(16)}` : 'TLS'
  }
}

function deriveTls(packets: ParsedPacket[]): AnalysisTlsEntry[] {
  // The cipher suite is negotiated in the ServerHello — a different packet
  // from the SNI ClientHello. Key by the ServerHello's SRC (the server; its
  // dst is the client) and join onto the handshake row by the SNI packet's
  // dst, so every row shows the suite the two sides actually agreed on.
  const serverSuite = new Map<string, number>()
  for (const p of packets) {
    if (typeof p.tlsCipherSuite === 'number' && p.srcIp && !serverSuite.has(p.srcIp)) serverSuite.set(p.srcIp, p.tlsCipherSuite)
  }
  return packets.filter(p => p.tlsSni).map((p, i) => {
    const negotiated = p.dstIp && serverSuite.has(p.dstIp) ? serverSuite.get(p.dstIp)! : undefined
    // A 0x13xx suite can only be NEGOTIATED by TLS 1.3 (RFC 8446) — when the
    // server agreed one, the handshake is 1.3 even if this ClientHello's
    // legacy_version field reads 0x0303 (RFC 8446 §4.1.2 keeps it there by
    // spec, and the suite-scan can miss on truncated CH payloads) (QA: row
    // showed TLSv1.2 with TLS_AES_256_GCM_SHA384).
    const version = negotiated !== undefined && negotiated >= 0x1301 && negotiated <= 0x1305
      ? 'TLSv1.3'
      : tlsVersionName(p.tlsVersion)
    return {
      id: `tls-${i + 1}`,
      timestamp: new Date(p.timestamp * 1000).toISOString(),
      srcIp: p.srcIp || '\u2014', dstIp: p.dstIp || '\u2014',
      version, sni: p.tlsSni!,
      cipherSuite: negotiated !== undefined ? tlsCipherSuiteName(negotiated) : '',
      ja3: '', issuer: '', validityDays: 0,
    }
  })
}

function deriveFiles(packets: ParsedPacket[]): AnalysisFile[] {
  const files: AnalysisFile[] = []
  let idx = 0
  for (const p of packets) {
    if (!p.httpMethod) continue
    const ascii = hexToAscii(p.payload)
    const ct = ascii.match(/Content-Type:\s*(\S+)/i)
    if (!ct) continue
    const mime = ct[1].replace(/;.*/, '')
    const fn = ascii.match(/filename="?([^"\r\n]+)"?/i)
    files.push({
      id: `file-${++idx}`,
      timestamp: new Date(p.timestamp * 1000).toISOString(),
      srcIp: p.srcIp || '\u2014', dstIp: p.dstIp || '\u2014',
      filename: fn ? fn[1] : `file-${idx}`,
      // Honest size: the HTTP payload bytes of THIS packet (no reassembly —
      // a multi-packet transfer yields one row per observed chunk). The wire
      // length previously counted IP/TCP headers and looked like file size.
      mimeType: mime, size: p.tcpPayloadLen ?? p.length,
      protocol: p.protocol || 'HTTP', md5: '',
    })
  }
  return files
}

// SIP dialogs unified with their RTP media: INVITE starts a call, BYE (or the
// last observed RTP packet) ends it, and the SDP `m=audio` port links the
// dialog to its stream. Mirrors analyzer/src/pipeline.rs (sip + rtp_agg).
function deriveVoip(packets: ParsedPacket[]): AnalysisCall[] {
  const rtpKey = (p: ParsedPacket) =>
    p.rtp ? `${p.srcIp || ''}|${p.dstIp || ''}|${p.srcPort ?? 0}|${p.dstPort ?? 0}|${p.rtp.ssrc}` : ''
  const rtpStreams = new Map<string, { packets: number; bytes: number; last: number; payloadType: number | null }>()
  for (const p of packets) {
    const k = rtpKey(p)
    if (!k) continue
    const s = rtpStreams.get(k)
    if (s) {
      s.packets += 1
      s.bytes += p.length
      if (p.timestamp > s.last) s.last = p.timestamp
    } else {
      rtpStreams.set(k, { packets: 1, bytes: p.length, last: p.timestamp, payloadType: p.rtp!.payloadType })
    }
  }

  // Dialog state per Call-ID. INVITE defines the endpoints/SDP; the final
  // status (200 OK / 486 Busy) comes from the last SIP/2.0 response seen.
  type Dialog = {
    from: string; to: string; viaIp: string; userAgent: string
    start: number; end: number | null
    status: string
    srcIp: string | undefined; dstIp: string | undefined; rtpPort: number
  }
  const dialogs = new Map<string, Dialog>()
  for (const p of packets) {
    const sip = p.sip
    if (!sip || !sip.callId) continue
    let d = dialogs.get(sip.callId)
    if (!d) {
      d = { from: '', to: '', viaIp: '', userAgent: '', start: p.timestamp, end: null, status: '', srcIp: undefined, dstIp: undefined, rtpPort: 0 }
      dialogs.set(sip.callId, d)
    }
    if (sip.method === 'INVITE') {
      d.from = sip.fromUser
      d.to = sip.toUser
      d.userAgent = sip.userAgent || d.userAgent
      d.srcIp = p.srcIp
      d.dstIp = p.dstIp
      if (sip.rtpPort) d.rtpPort = sip.rtpPort
      if (p.timestamp < d.start) d.start = p.timestamp
    }
    if (sip.method === 'BYE') d.end = p.timestamp
    if (sip.method === 'SIP/2.0' && sip.statusCode > 0) d.status = String(sip.statusCode)
    d.viaIp = sip.viaIp || d.viaIp
  }

  const calls: AnalysisCall[] = []
  let idx = 0
  for (const [callId, d] of dialogs) {
    // Match the RTP stream(s) to this dialog: SDP port on either side of the
    // conversation. rtpStreams are direction-sensitive (one stream per ssrc),
    // so a call spans two streams — caller→callee and callee→caller — and
    // both must be aggregated, or RTP packets/bytes read ~half the real call
    // (QA: 240 RTP packets reported as 120). Without any match the call is
    // signalling-only.
    let matched: { packets: number; bytes: number; last: number; payloadType: number | null } | null = null
    for (const [key, s] of rtpStreams) {
      const [a, b, pa, pb] = key.split('|')
      const pairOk = (d.srcIp === a && d.dstIp === b) || (d.dstIp === a && d.srcIp === b)
      const portOk = Number(pa) === d.rtpPort || Number(pb) === d.rtpPort
      if (pairOk && portOk) {
        if (!matched) matched = { ...s }
        else {
          matched.packets += s.packets
          matched.bytes += s.bytes
          if (s.last > matched.last) matched.last = s.last
        }
      }
    }
    const end = d.end !== null ? d.end : matched ? matched.last : null
    calls.push({
      id: `call-${++idx}`,
      callId,
      from: d.from || '\u2014',
      to: d.to || '\u2014',
      viaIp: d.viaIp || '\u2014',
      startTime: new Date(d.start * 1000).toISOString(),
      endTime: end !== null ? new Date(end * 1000).toISOString() : null,
      durationSec: end !== null ? Math.max(0, end - d.start) : null,
      userAgent: d.userAgent || '\u2014',
      status: d.status ? `SIP ${d.status}` : 'SIP',
      rtpPayloadType: matched?.payloadType ?? null,
      rtpSsrc: null,
      rtpPackets: matched?.packets ?? 0,
      rtpBytes: matched?.bytes ?? 0,
    })
  }
  return calls
}

function percentDecode(value: string): string {
  // application/x-www-form-urlencoded: '+' means space, '%XX' is a byte.
  // Malformed sequences (e.g. "%zz") return the raw value — never throw.
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '))
  } catch {
    return value
  }
}

function decodeBasicAuth(token: string): string {
  // atob + TextDecoder stay browser-safe: analysis.ts is imported by client
  // pages, so node-only Buffer is not available here.
  const bytes = Uint8Array.from(atob(token), (c) => c.charCodeAt(0))
  return new TextDecoder().decode(bytes)
}

function hexToAsciiKeep(hex: string, max = 2048): string {
  // Like hexToAscii but keeps \r and \n so the HTTP message structure
  // (header/body split on \r\n\r\n, request line) survives the printable
  // filter; everything else non-printable is dropped.
  const len = Math.min(hex.length, max * 2)
  let out = ''
  for (let i = 0; i < len; i += 2) {
    const c = parseInt(hex.substring(i, i + 2), 16)
    if (c === 13 || c === 10 || (c >= 32 && c < 127)) out += String.fromCharCode(c)
  }
  return out
}

function parseFormPairs(text: string): [string, string][] {
  // key=value pairs split on '&' BEFORE decoding, so an encoded '%26' inside
  // a value stays intact; values end at whitespace.
  const out: [string, string][] = []
  for (const pair of text.split('&')) {
    const eq = pair.indexOf('=')
    if (eq < 0) continue
    const key = pair.slice(0, eq).trim()
    if (!key) continue
    out.push([key, percentDecode(pair.slice(eq + 1).split(/\s/)[0])])
  }
  return out
}

function deriveCredentials(packets: ParsedPacket[]): AnalysisCredential[] {
  const creds: AnalysisCredential[] = []
  let idx = 0
  for (const p of packets) {
    if (!p.httpMethod) continue
    const raw = hexToAsciiKeep(p.payload)

    // Real HTTP Basic auth: Authorization: Basic base64(user:pass)
    const basic = raw.match(/Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i)
    if (basic) {
      const decoded = decodeBasicAuth(basic[1])
      const colon = decoded.indexOf(':')
      if (colon < 0) continue
      creds.push({
        id: `cred-${++idx}`,
        timestamp: new Date(p.timestamp * 1000).toISOString(),
        srcIp: p.srcIp || '\u2014', dstIp: p.dstIp || '\u2014',
        protocol: p.protocol || 'HTTP',
        username: decoded.slice(0, colon),
        password: decoded.slice(colon + 1),
        service: 'HTTP Basic',
      })
      continue
    }

    // Form-encoded login — parsed on the HTTP message structure, NEVER on the
    // raw payload blob. Header lines merge into one string once CR/LF are
    // filtered, so a header like "Accept: ...;q=0.1" or "Cache-Control:
    // max-age=0" would swallow the first '=' and yield garbage keys (a real
    // capture produced a "0.1Sec-GPC:" username this way).
    const sep = raw.indexOf('\r\n\r\n')
    const head = sep >= 0 ? raw.slice(0, sep) : raw
    // Body-only segment (headers were in a previous packet): treat the whole
    // payload as the body when it is not itself an HTTP request line.
    const isRequest = /^[A-Z]+\s+\S+\s+HTTP\//i.test(raw)
    const body = sep >= 0 ? raw.slice(sep + 4) : isRequest ? '' : raw
    // Query string comes from the request line only: "METHOD /path?query HTTP/x"
    const requestLine = head.split(/\r?\n/)[0] ?? ''
    const target = requestLine.split(' ')[1] ?? ''
    const qmark = target.indexOf('?')
    const query = qmark >= 0 ? target.slice(qmark + 1) : ''

    const pairs: [string, string][] = []
    if (query) pairs.push(...parseFormPairs(query))
    // multipart bodies use boundary markers, not '&' pairs.
    if (body && !/multipart\/form-data/i.test(head)) pairs.push(...parseFormPairs(body))

    // 'bypass'/'compass'/'surpass' keys contain "pass" but are not passwords.
    let user: string | undefined
    let pass: string | undefined
    for (const [key, value] of pairs) {
      if (/user|login|email/i.test(key)) user = value
      else if (/pass/i.test(key) && !/bypass|compass|surpass/i.test(key)) pass = value
    }
    if (!user && !pass) continue
    creds.push({
      id: `cred-${++idx}`,
      timestamp: new Date(p.timestamp * 1000).toISOString(),
      srcIp: p.srcIp || '\u2014', dstIp: p.dstIp || '\u2014',
      protocol: p.protocol || 'HTTP',
      username: user ?? '\u2014',
      password: pass ?? '\u2014',
      service: 'HTTP Form',
    })
  }
  return creds
}

// Offline OS fingerprint from what the capture actually exposes:
// 1) User-Agent strings sent by the device's own HTTP requests;
// 2) the IP TTL the device's own packets carry (Windows=128±, Unix=64±,
//    network gear=255±). UA wins; TTL is the fallback when the host never
//    speaks HTTP. Unknown stays "" — the devices page shows "—".
// Attribution rules (F-04 QA): a UA belongs ONLY to the device that SENT it,
// and only for its OWN source packets — a remote server never inherits the
// client's UA. The TTL heuristic is likewise keyed to the device's own
// packets, requires >= 2 samples (a lone RST would guess the wrong OS), and
// is suppressed entirely for public endpoints: a CDN edge TTL says nothing
// about the client behind NAT, and guessing "Windows" for Google erodes
// trust in the column.
function osFingerprint(ips: string[], packets: ParsedPacket[], isPrivate: boolean): { os: string; source: AnalysisDevice['osSource'] } {
  const ipSet = new Set(ips)
  const uaOf = (ua: string): string | null => {
    if (/Android/i.test(ua)) return 'Android'
    if (/iPhone|iPad|iPod/i.test(ua)) return 'iOS'
    if (/Microsoft-CryptoAPI|MSIE|Trident|Windows|Win32/i.test(ua)) return 'Windows'
    if (/Macintosh|Mac OS/i.test(ua)) return 'macOS'
    if (/CrOS/i.test(ua)) return 'ChromeOS'
    if (/Linux|Ubuntu|Debian|Fedora/i.test(ua)) return 'Linux'
    return null
  }
  const uas = new Set<string>()
  const ttlCounts = new Map<number, number>()
  for (const p of packets) {
    if (p.srcIp && ipSet.has(p.srcIp)) {
      if (p.httpUa) uas.add(p.httpUa)
      if (typeof p.ttl === 'number') ttlCounts.set(p.ttl, (ttlCounts.get(p.ttl) ?? 0) + 1)
    }
  }
  for (const ua of uas) {
    const os = uaOf(ua)
    if (os) return { os, source: 'ua' }
  }
  if (!isPrivate) return { os: '', source: undefined }
  // Mode of the device's own TTLs; a single outlier shouldn't win — and a
  // single sample is too thin to claim an OS (F-04 QA: router = "Windows").
  let best: { ttl: number; n: number } | null = null
  for (const [ttl, n] of ttlCounts) if (!best || n > best.n) best = { ttl, n }
  if (!best || best.n < 2) return { os: '', source: undefined }
  if (best.ttl >= 110 && best.ttl <= 140) return { os: 'Windows', source: 'ttl' }
  if (best.ttl >= 40 && best.ttl <= 80) return { os: 'Linux/Unix', source: 'ttl' }
  if (best.ttl >= 230 && best.ttl <= 255) return { os: 'Network Device', source: 'ttl' }
  return { os: 'Unknown', source: 'ttl' }
}

function deriveDevices(packets: ParsedPacket[]): AnalysisDevice[] {
  // IP -> hostname from DNS answers observed in the capture: A/AAAA answers
  // map the queried name to its IP, PTR answers map the reverse-arpa IP back
  // to a hostname. First-seen wins; no network calls involved.
  const ipToName = new Map<string, string>()
  for (const p of packets) {
    for (const a of p.dnsAnswers || []) {
      if (a.ip && a.name) {
        const name = a.name.replace(/\.$/, '').toLowerCase()
        if (name && !ipToName.has(a.ip)) ipToName.set(a.ip, name)
      }
    }
  }
  // TLS SNI names the SERVER the client is contacting (the ClientHello's
  // dst); it is client-observed, so DNS answers stay authoritative and SNI
  // only backfills hosts with no DNS resolution (QA: www.wireshark.org never
  // surfaced in Devices).
  const sniByIp = new Map<string, string>()
  for (const p of packets) {
    if (p.tlsSni && p.dstIp && !sniByIp.has(p.dstIp)) sniByIp.set(p.dstIp, p.tlsSni.toLowerCase())
  }
  const map = new Map<string, { mac: string; l2: string; first: number; last: number; count: number; bytes: number }>()
  // The /64 of every global-scope IPv6 this capture saw as SOURCE, and which
  // MACs sourced it. A global v6 on a LAN is the delegated /64 — unless the
  // /64 shows up from two or more LAN interfaces it is a server reachable
  // through the router, and folding it into the LAN would mislabel the
  // router's forwarded hosts as local (QA: calls.pcap client kept showing its
  // own delegated IPv6 as a phantom Remote device).
  const prefixSourcers = new Map<string, Set<string>>()
  for (const p of packets) {
    const ip = p.srcIp
    if (!ip || !p.srcMac) continue
    if (ip.includes(':') && !isPrivateIp(ip) && !isNonUnicast(ip)) {
      const prefix = ip.split(':').slice(0, 4).join(':')
      let s = prefixSourcers.get(prefix)
      if (!s) { s = new Set<string>(); prefixSourcers.set(prefix, s) }
      s.add(p.srcMac)
    }
  }
  const homePrefix = (ip: string): boolean => {
    if (!ip.includes(':') || isPrivateIp(ip) || isNonUnicast(ip)) return false
    const n = (prefixSourcers.get(ip.split(':').slice(0, 4).join(':')) ?? new Set()).size
    return n >= 2
  }
  // ARP sender MAC → the IP the sender claims to own (RFC 826 sha/spa). This
  // is hard identity evidence the Ethernet header alone can miss: the router's
  // own ARP (192.168.1.1 → 192.168.1.20) declares its interface MAC, which is
  // the same MAC its link-local fe80:: and delegated public v6 speak on — so
  // all three fold into ONE device instead of a phantom router split (QA:
  // Devices card read 5 where the report said 4).
  const arpMacByIp = new Map<string, string>()
  for (const p of packets) {
    if (p.protocol !== 'ARP' || !p.srcIp || !p.arpSenderMac) continue
    if (!arpMacByIp.has(p.srcIp)) arpMacByIp.set(p.srcIp, p.arpSenderMac.toLowerCase())
  }
  for (const p of packets) {
    // Dedupe self-addressed packets (gratuitous ARP, DAD): srcIp === dstIp
    // would otherwise count the packet twice for one device (QA).
    const ips = [...new Set([p.srcIp, p.dstIp].filter(Boolean) as string[])]
    for (const ip of ips) {
      if (isNonUnicast(ip)) continue // multicast/broadcast/unspecified: never devices
      const e = map.get(ip)
      // A MAC belongs to the LAN interface that OWNS the IP — prefer the
      // sender MAC of the IP's own packets (ARP: the request's srcMac is the
      // requester's MAC, dstMac the target; both are this LAN). A MAC seen
      // only on remote/forwarded traffic is the router's, not the host's, so
      // remote public IPs never carry a MAC here. A public-scope IPv6 inside
      // the /64 the LAN itself sources (SLAAC/DHCPv6 on the same NIC) carries
      // its own interface's MAC and folds into that device as an alias.
      const onSource = p.srcIp === ip ? p.srcMac : ''
      const onOwn = p.srcIp === ip ? p.srcMac : (isPrivateIp(ip) ? p.dstMac : '')
      // The ARP-declared sender MAC wins when present: it is the IP's own
      // interface binding, independent of whether the capture stamped the
      // Ethernet header (the router's identity is what merges its addresses).
      const ownMac = arpMacByIp.get(ip) || onSource || onOwn || ''
      if (e) {
        e.first = Math.min(e.first, p.timestamp)
        e.last = Math.max(e.last, p.timestamp)
        e.count++
        e.bytes += p.length
        // Backfill a MAC when the first frame for this IP lacked one (e.g. the
        // target of a stripped-header ARP) but a later frame carries it. Only
        // when still empty: first MAC observed wins (QA: Devices card 5 vs 4).
        if (!e.l2 && ownMac) {
          e.l2 = ownMac
          if (isPrivateIp(ip)) e.mac = ownMac
        }
      } else {
        map.set(ip, {
          // Only private-scope hosts carry a public MAC: a MAC observed on
          // public traffic is the router's or the capture NIC's, never the
          // remote host's (reviewer: Meta 2a03:/64 inherited 6e:22 from
          // forwarded frames). The internal l2 keeps home-prefix folding
          // working without exposing a bogus MAC on the alias row.
          mac: isPrivateIp(ip) ? ownMac || '\u2014' : '\u2014',
          l2: ownMac,
          first: p.timestamp, last: p.timestamp, count: 1, bytes: p.length,
        })
      }
    }
  }
  // Coalesce private hosts sharing a MAC (IPv4+IPv6 of one NIC, DHCP lease
  // renewals): the MAC is the stable identity. Public IPs never merge — the
  // MAC recorded against them is the router's. (Mirrors analyzer stats.rs.)
  // F-04 QA: a MAC crossing LAN subnets is the router forwarding (one NIC per
  // subnet, e.g. 192.168.137.1 vs 192.168.1.10) — same-MAC different-subnet
  // IPs stay separate rows instead of silently folding into one device.
  const merged: { ip: string; e: { mac: string; l2: string; first: number; last: number; count: number; bytes: number }; addresses: string[] }[] = []
  // A home-prefix public IPv6 (its /64 is sourced by ≥2 LAN MACs) is the LAN's
  // own delegated address, so it shares the MAC-merge pass with private hosts
  // and folds into the substrate device instead of surfacing as Remote.
  const mergeable = (ip: string): boolean => isPrivateLanIp(ip) || homePrefix(ip)
  for (const [ip, e] of map) {
    if (!e.l2 || !mergeable(ip)) {
      merged.push({ ip, e, addresses: [] })
      continue
    }
    // Match only against a LOCAL row: a public primary carries the router's
    // MAC (forwarded frames), and folding the router's own private IPs into a
    // remote device would pollute it (QA: Cloudflare row claiming 192.168.1.1,
    // STUN row claiming the home v6 router address). mergeable(x.ip) is the
    // existing row's own local-domain check — never merge INTO a remote row.
    const m = merged.find(x => x.e.l2 === e.l2 && mergeable(x.ip) && sameL2Surface(x.ip, ip))
    if (!m) {
      merged.push({ ip, e, addresses: [] })
      continue
    }
    // When merging private + home-v6, keep the PRIVATE address as the row's
    // primary IP (the useful label; the v6 becomes an alias), regardless of
    // byte totals. Between two equally-private hosts, bytes still decide.
    const privateBeatsV6 = isPrivateLanIp(ip) !== isPrivateLanIp(m.ip) && (isPrivateLanIp(ip) || isPrivateLanIp(m.ip))
    if (e.bytes > m.e.bytes && !privateBeatsV6) {
      const old = { ip: m.ip, e: m.e, addresses: m.addresses }
      m.ip = ip
      m.e = e
      m.addresses = [...old.addresses, old.ip]
      m.e.first = Math.min(m.e.first, old.e.first)
      m.e.last = Math.max(m.e.last, old.e.last)
      m.e.count += old.e.count
      m.e.bytes += old.e.bytes
    } else {
      m.e.first = Math.min(m.e.first, e.first)
      m.e.last = Math.max(m.e.last, e.last)
      m.e.count += e.count
      m.e.bytes += e.bytes
      m.addresses = [...m.addresses, ip]
    }
  }
  return merged.map((m, i) => {
    const fp = osFingerprint([m.ip, ...m.addresses], packets, isPrivateIp(m.ip))
    return {
      id: `dev-${i + 1}`, ip: m.ip, mac: m.e.mac, hostname: ipToName.get(m.ip) ?? sniByIp.get(m.ip) ?? m.ip,
      vendor: '', os: fp.os, osSource: fp.source,
      firstSeen: new Date(m.e.first * 1000).toISOString(),
      lastSeen: new Date(m.e.last * 1000).toISOString(),
      packets: m.e.count, bytes: m.e.bytes,
      addresses: m.addresses.sort(),
    }
  })
}

// Two IPs share one L2 surface (one NIC) when they are on the same subnet:
// same /24 for IPv4, same /64 for IPv6, or any v4+v6 pair (dual-stack NIC —
// link-local fe80:: and ULA fc/fd:: sit on the same interface as the v4).
function sameL2Surface(a: string, b: string): boolean {
  const va = a.includes(':'), vb = b.includes(':')
  if (va !== vb) return true
  if (va) return a.split(':').slice(0, 4).join(':') === b.split(':').slice(0, 4).join(':')
  return a.split('.').slice(0, 3).join('.') === b.split('.').slice(0, 3).join('.')
}

// RFC 1918 + link-local + loopback + CGNAT + benchmark. Prefix checks like
// startsWith('172.') misclassify public 172.64.x/172.217.x as private — only
// 172.16.0.0/12 is. (Mirrors map-data's isPrivateIP.)
function isPrivateIp(ip?: string): boolean {
  if (!ip) return false
  const ip0 = ip.trim()
  if (ip0.includes(':')) {
    const v = ip0.toLowerCase()
    return v.startsWith('::1') || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80') || v.startsWith('ff')
  }
  const m = ip0.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return false
  const a = Number(m[1])
  const b = Number(m[2])
  if (a === 0 || a >= 224 || ip0 === '127.0.0.1') return true
  if (a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254)) return true
  if (a === 100 && b >= 64 && b <= 127) return true // CGNAT
  return a === 198 && (b === 18 || b === 19) // benchmark 198.18/15
}

// Multicast, broadcast, unspecified or loopback addresses: discovery chatter
// and placeholder addresses, never LAN devices or beacon destinations.
// (Mirrors analyzer stats.rs::is_non_unicast.)
export function isNonUnicast(ip: string): boolean {
  const ip0 = ip.trim() // some writers emit ":: " with trailing space
  if (ip0.includes(':')) {
    const v = ip0.toLowerCase()
    // Full-form placeholders 0:0:0:0:0:0:0:0 / 0:0:0:0:0:0:0:1 are :: / ::1
    // emitted uncompressed — the unspecified address is not an external peer
    // and never a device (QA B-58).
    return v.startsWith('ff') || v === '::' || v === '::1' || v === '::ffff:0.0.0.0' ||
      v === '0:0:0:0:0:0:0:0' || v === '0:0:0:0:0:0:0:1'
  }
  const m = ip0.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return true
  const a = Number(m[1])
  const b = Number(m[2])
  const c = Number(m[4]) // last octet — m[3] is the third, not the last
  if (a === 0 || a >= 224 || ip0 === '255.255.255.255' || ip0 === '127.0.0.1') return true
  // Subnet broadcast addresses (x.y.z.255 on /24 LANs): routers and hosts
  // address them constantly (DHCP offers, mDNS, ARP probing) but they are
  // not hosts — counting them as external destinations inflates the map.
  if (c === 255) {
    if (a === 192 && b === 168) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 10) return true
  }
  return false
}

// Strict RFC1918 + IPv6 loopback/ULA/link-local — the merge key in device
// coalescing. More permissive than isPrivateIp (no CGNAT/benchmark) so public
// IPs never merge through the router MAC. (Mirrors analyzer stats.rs::is_private.)
function isPrivateLanIp(ip: string): boolean {
  if (ip.includes(':')) {
    const v = ip.toLowerCase()
    return v === '::1' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe8') || v.startsWith('fe9') || v.startsWith('fea') || v.startsWith('feb')
  }
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return false
  const a = Number(m[1])
  const b = Number(m[2])
  return a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)
}

// Destinations that legitimately keep regular cadences — discovery chatter
// (SSDP, mDNS, LLMNR, WS-Discovery, NetBIOS), LAN housekeeping (DHCP, NTP,
// SNMP, RIP, ARP) and STUN keepalives. Regular traffic to these is protocol
// behavior, not C2 beaconing. (Mirrors analyzer threat/mod.rs.)
function isBenignBeaconEndpoint(protocol: string, port: number, dstIp: string, names?: Set<string>): boolean {
  if (isNonUnicast(dstIp)) return true
  const names2 = ['ARP', 'DHCP', 'NTP', 'SSDP', 'mDNS', 'LLMNR', 'STUN', 'NetBIOS-NS', 'NetBIOS-DGM', 'WS-Discovery', 'SNMP', 'Syslog', 'TFTP', 'RIP']
  if (names2.includes(protocol)) return true
  const benignPorts = new Set([53, 67, 68, 69, 123, 137, 138, 161, 162, 520, 1900, 3702, 3478, 3479, 5349, 5353, 5355, 19302])
  if ((protocol === 'UDP' && benignPorts.has(port)) || (protocol === 'TCP' && port === 53)) return true
  // Push/keepalive poller families resolve from DNS answers — the IP alone
  // cannot tell a benign push edge (WhatsApp, Skype config, WNS, Apple,
  // Google) from a C2 server; both beacon over plain 443 (QA: beacon FP on
  // pps.whatsapp.net / config.edge.skype.com / client.wns.windows.com).
  if (names) {
    for (const n of names) {
      const host = n.toLowerCase()
      for (const dom of BENIGN_POLLER_DOMAINS) {
        if (host === dom || host.endsWith('.' + dom)) return true
      }
    }
  }
  return false
}

// Second-level families whose pollers keep regular cadences by design.
const BENIGN_POLLER_DOMAINS = [
  'whatsapp.net', 'whatsapp.com', 'skype.com', 'wns.windows.com',
  'windowsupdate.com', 'msftconnecttest.com', 'apple.com', 'mzstatic.com',
  'icloud.com', 'mtalk.google.com', 'google.com', 'googleapis.com', 'gstatic.com',
]

function deriveThreats(packets: ParsedPacket[]): AnalysisThreat[] {
  const threats: AnalysisThreat[] = []
  const scans = new Map<string, { ports: Set<number>; dsts: Set<string>; syn: number; rst: number; fin: number; first: number; last: number }>()
  for (const p of packets) {
    if (!p.srcIp) continue
    if (p.dstPort && p.tcpFlags?.includes('SYN')) {
      // Parity with the Rust engine (PortScanRule over syn_probes): only TCP
      // SYN probes constitute a port scan. Counting any unique destination
      // port fired on plain UDP traffic (WebRTC/STUN/NAT traversal).
      let e = scans.get(p.srcIp)
      if (!e) {
        e = { ports: new Set(), dsts: new Set(), syn: 0, rst: 0, fin: 0, first: p.timestamp, last: p.timestamp }
        scans.set(p.srcIp, e)
      }
      e.ports.add(p.dstPort)
      if (p.dstIp) e.dsts.add(p.dstIp)
      e.syn++
      e.first = Math.min(e.first, p.timestamp)
      e.last = Math.max(e.last, p.timestamp)
    } else if (p.tcpFlags?.includes('RST') || p.tcpFlags?.includes('FIN')) {
      // RST/FIN from a scanner count toward the scan evidence even when the
      // probe handshake was already covered (or the capture missed the SYN).
      const e = scans.get(p.srcIp)
      if (!e) continue
      if (p.tcpFlags.includes('RST')) e.rst++
      if (p.tcpFlags.includes('FIN')) e.fin++
      e.first = Math.min(e.first, p.timestamp)
      e.last = Math.max(e.last, p.timestamp)
    }
  }
  for (const [ip, e] of scans) {
    if (e.ports.size <= RISK_PARAMS.port_scan_min_unique_ports) continue
    const samples = [...e.ports].sort((a, b) => a - b).slice(0, 6).join(', ')
    const dur = (e.last - e.first).toFixed(1)
    threats.push({
      id: `alert-${threats.length + 1}`,
      timestamp: new Date(e.last * 1000).toISOString(),
      signature: 'Port Scan Detected', category: 'Reconnaissance', severity: 3,
      confidence: 70, ruleId: 'PORT-SCAN-001',
      srcIp: ip, dstIp: 'multiple', srcPort: 0, dstPort: 0,
      protocol: 'TCP',
      evidence: `${ip} scanned ${e.ports.size} ports on ${e.dsts.size} host(s) over ${dur}s (${e.syn} SYN, ${e.rst} RST, ${e.fin} FIN; e.g. ${samples})`,
    })
  }
  return threats
}

// Mirror of the Rust threat engine's anomaly rules: when a behavioral flag is
// set, the engine would have emitted the corresponding signature alert, so the
// local path (no Rust analyzer) emits it here. Keeps risk input a pure function
// of alerts on every path. Signatures/severity/confidence/category mirror
// analyzer/src/threat/mod.rs.
export function deriveFlagThreats(advancedMetrics: AnalysisAdvancedMetrics, existing: number, captureEndSec?: number): AnalysisThreat[] {
  const out: AnalysisThreat[] = []
  const push = (ruleId: string, signature: string, category: string, severity: number, confidence: number, evidence: string) => {
    out.push({
      id: `alert-${existing + out.length + 1}`,
      // The Rust engine stamps alerts with the last triggering packet's time
      // (stats.flow_end) — mirror that with the capture end, never "now".
      timestamp: new Date((captureEndSec ?? Date.now() / 1000) * 1000).toISOString(),
      signature, category, severity, confidence, ruleId,
      srcIp: 'multiple', dstIp: 'external', srcPort: 0, dstPort: 0,
      protocol: 'TCP', evidence,
    })
  }
  if (advancedMetrics.dnsTunnelingSuspected) push('DNS-TUNNEL-001', 'Possible DNS Tunneling', 'Exfiltration', 4, 80, advancedMetrics.dnsTunnelEvidence ?? 'DNS tunneling behavior detected')
  if (advancedMetrics.dataExfiltrationSuspected) push('DATA-EXFIL-001', 'Data Exfiltration Suspected', 'Exfiltration', 5, 70, advancedMetrics.iocs.find((i) => i.type === "data-exfiltration")?.description ?? 'Significant data transfer to external IPs')
  if (advancedMetrics.beaconDetected) push('C2-BEACON-001', 'Regular Beaconing Detected', 'Command and Control', 5, 65, advancedMetrics.beaconEvidence ?? 'C2 beaconing behavior detected')
  if (advancedMetrics.ja3Suspicious) push('TLS-SUSPICIOUS-001', 'Suspicious TLS Certificate', 'Command and Control', 2, 75, 'Suspicious TLS fingerprint or oversized SNI')
  return out
}

// Bucket key includes the date: a capture spanning midnight would otherwise
// merge the 00:00 buckets of both days (and duplicate React keys). The
// displayed label stays HH:MM — the date only separates the keys.
function m5Bucket(d: Date): string {
  const mm = String(Math.floor(d.getMinutes() / 5) * 5).padStart(2, '0')
  const display = `${String(d.getHours()).padStart(2, '0')}:${mm}`
  // Padded day/month (QA): an unpadded key like "2025-8-15 08:05" shifts the
  // date part, so m5Label's key.slice(11) lands inside the clock digits —
  // labels came out as "8:05" or ":05" for ~280 days of the year, and
  // lexicographic sort ordered "2025-10-*" before "2025-9-*".
  const day = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
  return `${day} ${display}`
}

function m5Label(key: string, multiDay: boolean): string {
  // Multi-day captures have two buckets with the same HH:MM — include the
  // date in the label so it stays a unique React key and reads correctly.
  return multiDay ? key.slice(5, 16) : key.slice(11)
}

function deriveTimeline(packets: ParsedPacket[]): AnalysisTimelineEntry[] {
  const buckets = new Map<string, AnalysisTimelineEntry>()
  for (const p of packets) {
    const key = m5Bucket(new Date(p.timestamp * 1000))
    if (!buckets.has(key)) {
      buckets.set(key, { time: key, packets: 0, bytes: 0, tcp: 0, udp: 0, dns: 0, tls: 0 })
    }
    const b = buckets.get(key)!
    b.packets++
    b.bytes += p.length
    // One bucket per packet: TLS/DNS are app-layer slices of TCP/UDP, so a
    // packet must land in exactly one slice or the stacked bars double-count
    // it (QA: DNS over UDP counted as both udp and dns).
    if (p.tlsSni) b.tls++
    else if (p.dnsQuery) b.dns++
    else if (p.protocol === 'TCP') b.tcp++
    else if (p.protocol === 'UDP') b.udp++
  }
  // Labels depend on whether the capture spans multiple days (m5Label shows
  // the date then, to keep every label a unique React key).
  const entries = Array.from(buckets.entries()).sort((a, b) => a[0].localeCompare(b[0]))
  const multiDay = entries.length > 1 && new Set(entries.map(([k]) => k.slice(0, 10))).size > 1
  return entries.map(([k, v]) => ({ ...v, time: m5Label(k, multiDay) }))
}

function deriveBandwidth(packets: ParsedPacket[]): AnalysisBandwidthPoint[] {
  const buckets = new Map<string, AnalysisBandwidthPoint>()
  for (const p of packets) {
    const key = m5Bucket(new Date(p.timestamp * 1000))
    if (!buckets.has(key)) {
      buckets.set(key, { time: key, in: 0, out: 0 })
    }
    const b = buckets.get(key)!
    if (p.srcIp && isPrivateIp(p.srcIp)) {
      b.out += p.length
    } else {
      b.in += p.length
    }
  }
  const entries = Array.from(buckets.entries()).sort((a, b) => a[0].localeCompare(b[0]))
  const multiDay = entries.length > 1 && new Set(entries.map(([k]) => k.slice(0, 10))).size > 1
  return entries.map(([k, v]) => ({ ...v, time: m5Label(k, multiDay) }))
}

function deriveAdvancedMetrics(raw: ParsedPacket[], flows: AnalysisFlow[], threats: AnalysisThreat[]): AnalysisAdvancedMetrics {
  // Scan for min/max timestamps: Math.max(...raw.map()) spreads overflow the
  // call stack on captures with hundreds of thousands of packets.
  let firstTs = 0, lastTs = 0
  for (const p of raw) {
    if (firstTs === 0 || p.timestamp < firstTs) firstTs = p.timestamp
    if (p.timestamp > lastTs) lastTs = p.timestamp
  }
  const duration = Math.max(raw.length > 0 ? lastTs - firstTs : 1, 1)

  let totalBytesOut = 0
  let totalBytesIn = 0
  const talkerMap = new Map<string, { bytesOut: number; bytesIn: number; packetsOut: number; packetsIn: number }>()

  for (const p of raw) {
    const isInternal = isPrivateIp(p.srcIp)
    const bytes = p.length
    if (isInternal && p.srcIp) {
      totalBytesOut += bytes
      const t = talkerMap.get(p.srcIp) || { bytesOut: 0, bytesIn: 0, packetsOut: 0, packetsIn: 0 }
      t.bytesOut += bytes
      t.packetsOut++
      talkerMap.set(p.srcIp, t)
    } else {
      totalBytesIn += bytes
      if (p.dstIp) {
        const t = talkerMap.get(p.dstIp) || { bytesOut: 0, bytesIn: 0, packetsOut: 0, packetsIn: 0 }
        t.bytesIn += bytes
        t.packetsIn++
        talkerMap.set(p.dstIp, t)
      }
    }
  }

  const throughputAvg = duration > 0 ? (totalBytesOut + totalBytesIn) / duration : 0

  // Per-second throughput buckets — real peak, not the fabricated avg*3
  const buckets = new Map<number, number>()
  for (const p of raw) {
    const sec = Math.floor(p.timestamp - firstTs)
    buckets.set(sec, (buckets.get(sec) || 0) + p.length)
  }
  let throughputPeak = 0
  for (const b of buckets.values()) if (b > throughputPeak) throughputPeak = b

  const burst = (() => {
    if (totalBytesOut + totalBytesIn <= 10000 || buckets.size < 2) {
      return { detected: false, peakThroughput: throughputPeak, averageThroughput: throughputAvg, ratio: 0, start: 0, end: 0, duration: 0 } satisfies BurstInfo
    }
    const threshold = throughputAvg * 2
    const detected = throughputPeak > threshold
    if (!detected) {
      return { detected: false, peakThroughput: throughputPeak, averageThroughput: throughputAvg, ratio: throughputPeak / Math.max(throughputAvg, 1), start: 0, end: 0, duration: 0 } satisfies BurstInfo
    }
    // Window = the contiguous run containing the PEAK second. The banner's
    // ratio is peak/average, so a window elsewhere would label the spike
    // with unrelated seconds (QA: 42.3× banner over the flat 00:00:00–00:00:01
    // while the burst was at 00:05).
    let peakSec = -1
    let peakBytes = 0
    for (const [sec, bytes] of buckets) {
      if (bytes > peakBytes) { peakBytes = bytes; peakSec = sec }
    }
    let start = peakSec
    let end = peakSec
    while (start - 1 >= 0 && (buckets.get(start - 1) ?? 0) > threshold) start--
    while ((buckets.get(end + 1) ?? 0) > threshold) end++
    const bestLen = end - start + 1
    return { detected: true, peakThroughput: throughputPeak, averageThroughput: throughputAvg, ratio: throughputPeak / Math.max(throughputAvg, 1), start, end, duration: bestLen } satisfies BurstInfo
  })()

  // Beaconing: repeated connections to the same host at a regular cadence.
  // One sustained connection is normal traffic, not a beacon pattern.
  const dstNames = new Map<string, Set<string>>()
  for (const p of raw) {
    for (const a of p.dnsAnswers ?? []) {
      if (!a.ip) continue
      const set = dstNames.get(a.ip) || new Set<string>()
      set.add(a.name)
      dstNames.set(a.ip, set)
    }
  }
  const beaconEvidence = (() => {
    // Flows key lexicographically, so "dstIp" is NOT always the server: for a
    // client 192.168.x talking to 8.8.8.8 the flow srcIp IS 8.8.8.8. Group by
    // the REMOTE endpoint instead — the side that is not the private host —
    // or the cadence detector silently misses half of all conversations
    // (QA-adjacent: beacon FPs keyed on dstIp that was sometimes the client).
    const remoteOf = (f: AnalysisFlow): { ip: string; port: number } =>
      isPrivateIp(f.srcIp) && !isPrivateIp(f.dstIp)
        ? { ip: f.dstIp, port: f.dstPort }
        : { ip: f.srcIp, port: f.srcPort }
    const byRemote = new Map<string, AnalysisFlow[]>()
    for (const f of flows) {
      const r = remoteOf(f)
      if (isBenignBeaconEndpoint(f.protocol, r.port, r.ip, dstNames.get(r.ip))) continue
      const key = `${r.ip}:${r.port}`
      if (!byRemote.has(key)) byRemote.set(key, [])
      byRemote.get(key)!.push(f)
    }
    for (const [key, list] of byRemote) {
      if (list.length < 3) continue
      const starts = list.map(f => new Date(f.startTime).getTime()).sort((a, b) => a - b)
      const intervals: number[] = []
      for (let i = 1; i < starts.length; i++) {
        const iv = (starts[i] - starts[i - 1]) / 1000
        if (iv > 0) intervals.push(iv)
      }
      if (intervals.length < 2) continue
      const mean = intervals.reduce((s, x) => s + x, 0) / intervals.length
      if (mean < 1) continue // rapid chatter, not a beacon cadence
      const variance = intervals.reduce((s, x) => s + (x - mean) ** 2, 0) / intervals.length
      if (Math.sqrt(variance) / mean < 0.35) {
        const cv = Math.sqrt(variance) / mean
        return `${list.length} connections to ${key} at ~${mean.toFixed(1)}s intervals (σ ${Math.sqrt(variance).toFixed(2)}s, CV ${cv.toFixed(3)})`
      }
    }
    return ''
  })()
  const beaconDetected = beaconEvidence !== ''

  // DNS tunneling: queries with very long or high-entropy labels (encoded
  // data), or a sustained abnormal query rate. Ordinary dotted names — any
  // normal lookup — never trip this. Queries only; response echoes of the
  // same name would otherwise double the apparent rate.
  const dnsQueries = raw.filter(p => p.dnsQuery && p.dnsQr !== true).map(p => p.dnsQuery as string)
  const label = (q: string) => q.split('.').reduce((m, l) => (l.length > m.length ? l : m), '')
  const entropy = (s: string) => {
    if (!s) return 0
    const counts = new Map<string, number>()
    for (const c of s) counts.set(c, (counts.get(c) || 0) + 1)
    let h = 0
    for (const n of counts.values()) {
      const p = n / s.length
      h -= p * Math.log2(p)
    }
    return h
  }
  const suspiciousDns = dnsQueries.filter(q => label(q).length > 40 || entropy(label(q)) > 4.5)
  const dnsRate = dnsQueries.length / duration
  let maxLabelLen = 0
  let maxEntropy = 0
  for (const q of dnsQueries) {
    const ll = label(q).length
    const e = entropy(label(q))
    if (ll > maxLabelLen) maxLabelLen = ll
    if (e > maxEntropy) maxEntropy = e
  }
  const dnsTunnelEvidence =
    suspiciousDns.length >= 5
      ? `${suspiciousDns.length} tunneling-like queries (max label ${maxLabelLen} chars, max entropy ${maxEntropy.toFixed(1)}) among ${dnsQueries.length} total`
      : dnsQueries.length > 20 && dnsRate > 2.5
        ? `${dnsQueries.length} queries at ${dnsRate.toFixed(1)}/s sustained (${new Set(dnsQueries).size} domains)`
        : ''
  const dnsTunnelingSuspected = dnsTunnelEvidence !== ''

  // Upload-style exfiltration: a private host SENDING >100 KB outward, at
  // least 5× what it receives. Triggering on bytesTotal flags CDN/media
  // DOWNLOADS as exfiltration — a WhatsApp media fetch (≈10 MB total, 123 KB
  // sent) must not fire (QA: exfil detector counted downloads).
  const externalFlows = flows.filter(f =>
    isPrivateIp(f.srcIp) && !isPrivateIp(f.dstIp) &&
    f.bytesSent > 100000 && f.bytesSent > 5 * f.bytesRecv
  )
  const dataExfiltrationSuspected = externalFlows.length > 0
  const dataExfilDetail = externalFlows.length > 0
    ? `${externalFlows.length} flow(s) sending >100 KB to external IPs (outbound ≥5× received; top: ${externalFlows[0].srcIp} → ${externalFlows[0].dstIp}, ${(externalFlows[0].bytesSent / 1024).toFixed(0)} KB sent)`
    : ''

  // Tor exit-node subnet (ASN-TOR, 185.220.101.0/24) in either direction. A
  // blanket "185."/"198." prefix also matched Cloudflare (198.41.x) and
  // TEST-NET-2 (198.51.100.x), fabricating a proxy claim for CDN/lab traffic;
  // checking only srcIp missed every flow toward such an address (audit).
  const torVpnProxyDetected = raw.some(p =>
    (p.srcIp ?? '').startsWith('185.220.101.') || (p.dstIp ?? '').startsWith('185.220.101.')
  )

  const ja3Suspicious = raw.some(p => p.tlsSni && p.tlsSni.length > 100)

  const portScanEnhanced = threats.some(t => t.signature === 'Port Scan Detected')

  const topTalkers = Array.from(talkerMap.entries())
    .sort((a, b) => b[1].bytesOut + b[1].bytesIn - (a[1].bytesOut + a[1].bytesIn))
    .slice(0, 10)
    .map(([ip, t]) => ({ ip, ...t }))

  const iocs: AnalysisAdvancedMetrics['iocs'] = []
  for (const t of threats) {
    iocs.push({ type: "threat", value: t.signature, description: t.evidence, severity: t.severity })
  }
  if (dnsTunnelingSuspected) {
    iocs.push({ type: "dns-tunneling", value: "Suspicious DNS patterns", description: dnsTunnelEvidence, severity: 3 })
  }
  if (dataExfiltrationSuspected) {
    iocs.push({ type: "data-exfiltration", value: "Large outbound transfers", description: dataExfilDetail || "Significant data transfer to external IPs", severity: 4 })
  }
  if (beaconDetected) {
    iocs.push({ type: "beaconing", value: "Periodic communication detected", description: beaconEvidence, severity: 3 })
  }

  const mitreMappings: AnalysisAdvancedMetrics['mitreMappings'] = []
  if (portScanEnhanced) {
    mitreMappings.push({ technique: "Port Scan", id: "T1046", description: "Network scanning for open ports", severity: 3 })
  }
  if (dnsTunnelingSuspected) {
    mitreMappings.push({ technique: "DNS Tunneling", id: "T1071.004", description: "Data encoded in DNS queries/responses", severity: 4 })
  }
  if (dataExfiltrationSuspected) {
    mitreMappings.push({ technique: "Exfiltration Over C2 Channel", id: "T1041", description: "Data sent to external server", severity: 4 })
  }
  if (beaconDetected) {
    mitreMappings.push({ technique: "Application Layer Protocol", id: "T1071", description: "Periodic C2 beaconing detected", severity: 3 })
  }
  if (torVpnProxyDetected) {
    mitreMappings.push({ technique: "Proxy", id: "T1090", description: "Traffic routed through proxy/VPN/TOR", severity: 2 })
  }
  for (const c of threats) {
    if (c.category === "Credential Access") {
      mitreMappings.push({ technique: "Credential Dumping", id: "T1003", description: "Credentials may have been extracted", severity: 4 })
    }
    if (c.category === "Collection") {
      mitreMappings.push({ technique: "Data from Information Repositories", id: "T1213", description: "Sensitive data collection detected", severity: 3 })
    }
  }

  return {
    throughputAvg: Math.round(throughputAvg),
    throughputPeak: Math.round(throughputPeak),
    burst,
    beaconDetected,
    dnsTunnelingSuspected,
    dataExfiltrationSuspected,
    torVpnProxyDetected,
    portScanEnhanced,
    ja3Suspicious,
    dnsTunnelEvidence,
    beaconEvidence,
    topTalkers,
    iocs,
    mitreMappings,
  }
}

// Protocol counters derived straight from the parsed packets — the ONE
// classification source for dashboard + viz tabs + timeline, so the
// "Protocols" pie and the tab chips can never disagree (C2). Transport-level
// names (TCP/UDP/ICMP/ARP) match the job summary's protocol list; app-layer
// labels (HTTPS/STUN) must not leak in or the pie and the dashboard diverge.
// Job summary counts from the backend stay authoritative for totals.
export function packetProtocolCounts(
  packets: Array<{ protocol?: string }>
): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const p of packets) {
    const name = p.protocol || 'OTHER'
    counts[name] = (counts[name] ?? 0) + 1
  }
  return counts
}

export function analyzePcap(result: PCAPResult): AnalysisResult {
  const { packets: raw, stats } = result
  // Per-direction initial TCP sequence so each side's relative Seq starts at 0
  // from ITS OWN first segment in capture order (the client SYN on the client
  // leg, the SYN-ACK on the server leg for a handshake in the capture). The
  // previous flowKeyOf base rebased BOTH directions against whichever side
  // appeared first, so mid-session server replies showed raw 32-bit values
  // (QA: client Seq=0/519, server Seq=834237805).
  const seqBases = new Map<string, number>()
  for (const p of raw) {
    if (p.protocol === 'TCP' && typeof p.tcpSeq === 'number') {
      const key = dirKeyOf(p)
      if (!seqBases.has(key)) seqBases.set(key, p.tcpSeq)
    }
  }
  const packets = raw.map((p) => pktToAnalysis(p, seqBases.get(dirKeyOf(p))))
  const flows = deriveFlows(raw)
  const sessions = deriveSessions(flows, tcpConversationStates(raw))
  const dns = deriveDns(raw)
  const http = deriveHttp(raw)
  const tls = deriveTls(raw)
  const files = deriveFiles(raw)
  const calls = deriveVoip(raw)
  const credentials = deriveCredentials(raw)
  // Leaf certificates parsed from TLS Certificate handshakes (X.509 DER
  // extractor in pcap.ts); deduped by subject+serial across the capture.
  const certificates: AnalysisCertificate[] = []
  {
    const seen = new Set<string>()
    for (const p of raw) {
      const c = p.tlsCert
      if (!c) continue
      const key = `${c.subject}|${c.serial}`
      if (seen.has(key)) continue
      seen.add(key)
      certificates.push({
        id: `cert-${certificates.length + 1}`,
        serial: c.serial, subject: c.subject || '\u2014', issuer: c.issuer || '\u2014',
        notBefore: c.notBefore > 0 ? new Date(c.notBefore).toISOString() : null,
        notAfter: c.notAfter > 0 ? new Date(c.notAfter).toISOString() : null,
        san: c.san, signatureAlgorithm: c.signatureAlgorithm || 'unknown',
        keySize: c.keySize,
      })
    }
  }
  const devices = deriveDevices(raw)
  const threats = deriveThreats(raw)
  const timeline = deriveTimeline(raw)
  const bandwidth = deriveBandwidth(raw)
  const advancedMetrics = deriveAdvancedMetrics(raw, flows, threats)
  let captureEndSec = Date.now() / 1000
  if (raw.length) {
    let cMax = 0
    for (const p of raw) if (p.timestamp > cMax) cMax = p.timestamp
    captureEndSec = cMax
  }
  threats.push(...deriveFlagThreats(advancedMetrics, threats.length, captureEndSec))

  // External = non-LAN destinations; multicast/broadcast/unspecified/loopback
  // are transport chatter, not peers (they used to inflate the count). VPN and
  // the client's own delegated-prefix IPv6 are local, so their aliases never
  // count (QA: calls.pcap External 22 behaved as 21 after the v6 merged).
  const localAliases = new Set<string>()
  for (const d of devices) {
    if (!isPrivateIp(d.ip)) continue
    localAliases.add(d.ip)
    for (const a of d.addresses ?? []) localAliases.add(a)
  }
  const externalIps = new Set(
    raw.map(p => p.dstIp).filter(Boolean).filter((ip): ip is string => !isNonUnicast(ip!) && !localAliases.has(ip!))
  )
  const domains = new Set(dns.map(d => d.query))

const job: AnalysisJob = {
    id: 'analysis-1', filename: 'capture.pcapng',
    fileSize: stats.totalBytes, status: 'done', progress: 100, stage: 'complete',
    totalPackets: stats.totalPackets, totalFlows: flows.length,
    conversations: sessions.length, devices: devices.length,
    externalIps: externalIps.size, countries: 0, domains: domains.size,
    protocols: [...new Set(raw.map(p => p.protocol).filter(Boolean) as string[])],
    alerts: threats.length, analyzerVersion: ANALYZER_VERSION,
    riskScore: computeRisk(
      buildRiskInputs(threats),
      burstDetected(advancedMetrics)
    ),
    captureDuration: stats.duration,
    createdAt: new Date((stats.startTime || raw[0]?.timestamp || 0) * 1000).toISOString(),
  }

  // File info is provided by the backend Rust analyzer
  const fileInfo: FileInfo = { sha256: '', sha1: '', md5: '' }

  return {
    job, packets, flows, sessions, dns, http, tls, files,
    calls,
    credentials, certificates, devices, threats, timeline, bandwidth, advancedMetrics,
    fileInfo,
    decode: {
      decoded: stats.decodedPackets ?? packets.length,
      total: stats.totalPackets,
      linkTypes: stats.linkTypes || [],
    },
  }
}
