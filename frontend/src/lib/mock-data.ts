import type {
  AnalysisPacket, AnalysisFlow, AnalysisSession, AnalysisDnsEntry, AnalysisHttpEntry,
  AnalysisTlsEntry, AnalysisFile, AnalysisCredential, AnalysisCertificate,
  AnalysisDevice, AnalysisThreat, AnalysisTimelineEntry, AnalysisBandwidthPoint,
  AnalysisAdvancedMetrics,
} from './analysis'
import { deriveFlagThreats, ANALYZER_VERSION } from './analysis'
import { computeRisk, buildRiskInputs, burstConfidenceBoost } from './risk'

const NUM_PACKETS = 1200

export type MockPacket = AnalysisPacket
export type MockFlow = AnalysisFlow
export type MockSession = AnalysisSession
export type MockDnsEntry = AnalysisDnsEntry
export type MockHttpEntry = AnalysisHttpEntry
export type MockTlsEntry = AnalysisTlsEntry
export type MockFile = AnalysisFile
export type MockCredential = AnalysisCredential
export type MockCertificate = AnalysisCertificate
export type MockDevice = AnalysisDevice
export type MockThreat = AnalysisThreat
export type MockTimelineEntry = AnalysisTimelineEntry
export type MockBandwidthPoint = AnalysisBandwidthPoint

const SRC_IPS = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
const DST_IPS = ["203.0.113.5", "198.51.100.2"]
const PROTOCOLS = ["TCP", "UDP", "DNS", "TLS"]
// Protocol and port must be consistent: DNS lives on 53, TLS on 443 — the top
// ports table derives protocol/port pairs from packets, so mismatched pairs
// ("DNS/22 SSH") are physically impossible in real captures.
const PROTO_PORTS: Record<string, number[]> = {
  TCP: [80, 443, 22, 8080],
  UDP: [53, 123, 67],
  DNS: [53],
  TLS: [443],
}
const FLAGS = ["SYN", "ACK", "PSH", "FIN"]

function seededRandom(seed: number): () => number {
  let s = seed
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff
    return s / 0x7fffffff
  }
}

function pick<T>(arr: T[], rand: () => number): T {
  return arr[Math.floor(rand() * arr.length)]
}

function randInt(min: number, max: number, rand: () => number): number {
  return min + Math.floor(rand() * (max - min + 1))
}

export const REFERENCE_TIME = 1704067200000 // 2025-01-01T00:00:00.000Z fixed epoch for deterministic data

function generateMockPackets(): MockPacket[] {
  const rand = seededRandom(42)
  const startTime = REFERENCE_TIME
  return Array.from({ length: NUM_PACKETS }, (_, i) => {
    const proto = pick(PROTOCOLS, rand)
    const srcIp = pick(SRC_IPS, rand)
    const dstPort = pick(PROTO_PORTS[proto], rand)
    return {
      num: i + 1,
      timestamp: new Date(startTime + i * 3000 + randInt(0, 500, rand)).toISOString(),
      srcIp,
      dstIp: pick(DST_IPS, rand),
      srcPort: 10000 + randInt(0, 50000, rand),
      dstPort,
      protocol: proto,
      length: randInt(40, 1500, rand),
      flags: proto === "TCP" ? pick(FLAGS, rand) : "—",
      ttl: randInt(32, 128, rand),
      info: proto === "DNS"
        ? "DNS query for " + pick(["example.com", "google.com", "github.com", "stackoverflow.com", "cdn.cloudflare.com"], rand)
        : proto === "TLS"
          ? "TLS " + pick(["Client Hello", "Server Hello", "Certificate", "Finished"], rand)
          : pick(["ACK", "SYN", "FIN", "PSH"], rand) + " [Packet " + (i + 1) + "]",
    }
  })
}

function deriveFlows(packets: MockPacket[]): MockFlow[] {
  const groups = new Map<string, MockPacket[]>()
  for (const p of packets) {
    const key = `${p.srcIp}|${p.dstIp}|${p.srcPort}|${p.dstPort}|${p.protocol}`
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key)!.push(p)
  }
  return Array.from(groups.entries()).map(([key, pkts], idx) => {
    const [srcIp, dstIp, srcPort, dstPort, protocol] = key.split("|")
    const sent = pkts.filter((p) => p.srcIp === srcIp)
    const recv = pkts.filter((p) => p.dstIp === srcIp)
    const times = pkts.map((p) => new Date(p.timestamp).getTime())
    return {
      id: `flow-${idx + 1}`,
      srcIp,
      dstIp,
      srcPort: Number(srcPort),
      dstPort: Number(dstPort),
      protocol,
      packets: pkts.length,
      bytesTotal: pkts.reduce((s, p) => s + p.length, 0),
      bytesSent: sent.reduce((s, p) => s + p.length, 0),
      bytesRecv: recv.reduce((s, p) => s + p.length, 0),
      duration: Math.round((Math.max(...times) - Math.min(...times)) / 1000),
      startTime: new Date(Math.min(...times)).toISOString(),
      endTime: new Date(Math.max(...times)).toISOString(),
    }
  }).sort((a, b) => b.packets - a.packets)
}

function deriveSessions(packets: MockPacket[]): MockSession[] {
  const flows = deriveFlows(packets)
  const states = ["ESTABLISHED", "CLOSED", "TIME_WAIT", "SYN_SENT"]
  const rand = seededRandom(99)
  return flows.slice(0, 200).map((f, i) => ({
    id: `sess-${i + 1}`,
    srcIp: f.srcIp,
    dstIp: f.dstIp,
    srcPort: f.srcPort,
    dstPort: f.dstPort,
    protocol: f.protocol,
    packets: f.packets,
    bytes: f.bytesTotal,
    state: f.protocol === "TCP" ? pick(states, rand) : "STATELESS",
    duration: f.duration,
    startTime: f.startTime,
  }))
}

function deriveDns(packets: MockPacket[]): MockDnsEntry[] {
  const dnsPackets = packets.filter((p) => p.protocol === "DNS")
  const queries = ["example.com", "google.com", "github.com", "stackoverflow.com", "cdn.cloudflare.com", "api.example.org", "mail.google.com", "docs.google.com"]
  const types = ["A", "AAAA", "MX", "CNAME", "TXT"]
  const answers = ["93.184.216.34", "142.250.80.46", "140.82.121.3", "151.101.129.69", "104.16.132.229"]
  const rand = seededRandom(7)
  return dnsPackets.map((p, i) => {
    const q = pick(queries, rand)
    const t = pick(types, rand)
    // Real pipeline marks query/response per packet (dnsQr); the mock used
    // to skip isResponse entirely, so the demo DNS page showed every row as
    // a query with a fabricated TTL (QA).
    const isResponse = rand() > 0.9
    return {
      id: `dns-${i + 1}`,
      timestamp: p.timestamp,
      srcIp: p.srcIp,
      dstIp: p.dstIp,
      query: q,
      type: t,
      responseCode: isResponse && rand() > 0.95 ? "NXDOMAIN" : "NOERROR",
      answer: isResponse && (t === "A" || t === "AAAA") ? pick(answers, rand) : "—",
      ttl: isResponse ? randInt(60, 86400, rand) : null,
      isResponse,
    }
  })
}

function deriveHttp(packets: MockPacket[]): MockHttpEntry[] {
  const httpPackets = packets.filter((p) => p.dstPort === 80 || p.info.includes("GET") || p.info.includes("POST"))
  const methods = ["GET", "POST", "PUT", "DELETE"]
  const uris = ["/index.html", "/api/data", "/login", "/assets/main.js", "/style.css", "/images/logo.png", "/api/users", "/search"]
  const hosts = ["example.com", "api.example.com", "cdn.example.com", "app.example.com"]
  const agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "curl/8.0", "Python/3.12", "PostmanRuntime/7.36"]
  const contentTypes = ["text/html", "application/json", "application/javascript", "text/css", "image/png"]
  const rand = seededRandom(13)
  return httpPackets.slice(0, 180).map((p, i) => ({
    id: `http-${i + 1}`,
    timestamp: p.timestamp,
    srcIp: p.srcIp,
    dstIp: p.dstIp,
    method: pick(methods, rand),
    uri: pick(uris, rand),
    host: pick(hosts, rand),
    status: pick([200, 201, 301, 302, 400, 401, 403, 404, 500], rand),
    contentType: pick(contentTypes, rand),
    userAgent: pick(agents, rand),
    length: randInt(100, 50000, rand),
  }))
}

function deriveTls(packets: MockPacket[]): MockTlsEntry[] {
  const tlsPackets = packets.filter((p) => p.protocol === "TLS" || p.dstPort === 443)
  const versions = ["TLSv1.2", "TLSv1.3"]
  const snis = ["example.com", "google.com", "github.com", "cdn.cloudflare.com", "api.example.org", "*.googleapis.com"]
  const ciphers = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"]
  const issuers = ["C=US, O=Let's Encrypt, CN=R3", "C=US, O=Google Trust Services, CN=GTS CA 1P5", "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1"]
  const ja3s = ["51c64c77e60f3980eea90869b68c58a8", "b8b1e8e5b8b1e8e5b8b1e8e5b8b1e8e5", "c4a0e5b8b1e8e5b8b1e8e5b8b1e8e5b8"]
  const rand = seededRandom(21)
  return tlsPackets.filter(() => rand() > 0.5).map((p, i) => ({
    id: `tls-${i + 1}`,
    timestamp: p.timestamp,
    srcIp: p.srcIp,
    dstIp: p.dstIp,
    version: pick(versions, rand),
    sni: pick(snis, rand),
    cipherSuite: pick(ciphers, rand),
    ja3: pick(ja3s, rand),
    issuer: pick(issuers, rand),
    validityDays: randInt(30, 398, rand),
  }))
}

function deriveFiles(packets: MockPacket[]): MockFile[] {
  const rand = seededRandom(31)
  const fileEntries: { filename: string; mimeType: string }[] = [
    { filename: "document.pdf", mimeType: "application/pdf" },
    { filename: "image.png", mimeType: "image/png" },
    { filename: "script.js", mimeType: "application/javascript" },
    { filename: "data.json", mimeType: "application/json" },
    { filename: "archive.zip", mimeType: "application/zip" },
    { filename: "report.docx", mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
    { filename: "config.xml", mimeType: "application/xml" },
    { filename: "logo.svg", mimeType: "image/svg+xml" },
    { filename: "backup.sql", mimeType: "application/sql" },
    { filename: "notes.txt", mimeType: "text/plain" },
  ]
  const md5s = Array.from({ length: 10 }, () => Array.from({ length: 32 }, () => "0123456789abcdef"[Math.floor(rand() * 16)]).join(""))
  return packets.filter(() => rand() > 0.97).slice(0, 30).map((p, i) => {
    const entry = pick(fileEntries, rand)
    return {
      id: `file-${i + 1}`,
      timestamp: p.timestamp,
      srcIp: p.srcIp,
      dstIp: p.dstIp,
      filename: entry.filename,
      mimeType: entry.mimeType,
      size: randInt(1024, 10 * 1024 * 1024, rand),
      protocol: p.protocol,
      md5: pick(md5s, rand),
    }
  })
}

function deriveCredentials(packets: MockPacket[]): MockCredential[] {
  const rand = seededRandom(47)
  const usernames = ["admin", "user", "test", "john", "jane", "root", "guest", "developer"]
  const passwords = ["password123", "admin123", "letmein", "qwerty123", "P@ssw0rd", "secret!", "12345678", "welcome1"]
  const services = ["HTTP Basic", "FTP", "SMTP", "IMAP", "SSH"]
  return packets.filter(() => rand() > 0.98).slice(0, 15).map((p, i) => ({
    id: `cred-${i + 1}`,
    timestamp: p.timestamp,
    srcIp: p.srcIp,
    dstIp: p.dstIp,
    protocol: p.protocol,
    username: pick(usernames, rand),
    password: pick(passwords, rand),
    service: pick(services, rand),
  }))
}

function deriveCertificates(packets: MockPacket[]): MockCertificate[] {
  const rand = seededRandom(59)
  const subjects = ["CN=example.com", "CN=google.com", "CN=github.com", "CN=cloudflare.com", "CN=*.googleapis.com", "CN=stackoverflow.com"]
  const issuers = ["CN=R3, O=Let's Encrypt, C=US", "CN=GTS CA 1P5, O=Google Trust Services, C=US", "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US"]
  const sans = [["example.com", "www.example.com"], ["google.com", "*.google.com"], ["github.com", "www.github.com"], ["cloudflare.com", "*.cloudflare.com"], ["*.googleapis.com"], ["stackoverflow.com", "meta.stackoverflow.com"]]
  const sigAlgs = ["SHA256-RSA", "SHA384-RSA", "SHA256-ECDSA", "SHA384-ECDSA"]
  return packets.filter(() => rand() > 0.97).slice(0, 12).map((_, i) => {
    const sub = pick(subjects, rand)
    const notBefore = new Date(REFERENCE_TIME + randInt(-365, -30, rand) * 86400000)
    const notAfter = new Date(notBefore.getTime() + randInt(30, 398, rand) * 86400000)
    return {
      id: `cert-${i + 1}`,
      serial: Array.from({ length: 32 }, () => "0123456789abcdef"[Math.floor(rand() * 16)]).join(""),
      subject: sub,
      issuer: pick(issuers, rand),
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      san: pick(sans, rand),
      signatureAlgorithm: pick(sigAlgs, rand),
      keySize: pick([2048, 4096, 256, 384], rand),
    }
  })
}

function deriveDevices(packets: MockPacket[]): MockDevice[] {
  const rand = seededRandom(73)
  const macs = ["00:1a:2b:3c:4d:01", "00:1a:2b:3c:4d:02", "00:1a:2b:3c:4d:03", "ac:de:48:12:34:56", "b8:27:eb:ab:cd:ef", "00:0a:95:9d:68:16", "3c:97:0e:12:34:56", "d4:85:64:ab:cd:ef"]
  const vendors = ["Cisco Systems", "Juniper Networks", "Hewlett Packard", "Dell Inc.", "Apple Inc.", "Intel Corporate", "Raspberry Pi Foundation", "TP-Link Technologies"]
  const oss = ["Linux 6.2", "Windows 11", "macOS 14.3", "FreeBSD 13.2", "iOS 17.4", "Android 14", "Ubuntu 22.04", "Debian 12"]
  const hostnames = ["gateway.local", "web-server", "dns-resolver", "mail-server", "dhcp-server", "nas-01", "workstation-1", "laptop-2", "phone-3", "printer-4"]
  // Only SRC_IPS are LAN hosts; DST_IPS are public, and the real analyzer
  // gives public hosts no MAC/vendor/hostname/OS — fabricating them for
  // 203.0.113.x would claim L2 visibility we never had (QA).
  const localIps = new Set(SRC_IPS)
  // Counts come from the actual packets (min/max timestamps, per-IP packet
  // and byte totals) — the previous random packets/bytes contradicted the
  // packet rows on the Devices page (QA: "483 packets" for a 3-packet host).
  const stats = new Map<string, { firstSeen: string; lastSeen: string; packets: number; bytes: number }>()
  for (const p of packets) {
    for (const ip of [p.srcIp, p.dstIp]) {
      const s = stats.get(ip) ?? { firstSeen: p.timestamp, lastSeen: p.timestamp, packets: 0, bytes: 0 }
      if (p.timestamp < s.firstSeen) s.firstSeen = p.timestamp
      if (p.timestamp > s.lastSeen) s.lastSeen = p.timestamp
      s.packets += 1
      s.bytes += p.length
      stats.set(ip, s)
    }
  }
  const devices: MockDevice[] = []
  for (const [ip, s] of stats) {
    const local = localIps.has(ip)
    devices.push({
      id: `dev-${devices.length + 1}`,
      ip,
      mac: local ? pick(macs, rand) : '\u2014',
      hostname: local ? pick(hostnames, rand) : '',
      vendor: local ? pick(vendors, rand) : '',
      os: local ? pick(oss, rand) : '',
      firstSeen: s.firstSeen,
      lastSeen: s.lastSeen,
      packets: s.packets,
      bytes: s.bytes,
      addresses: ip === "192.168.1.1" ? ["fd00::1", "192.168.1.254"] : [],
    })
  }
  return devices
}

function deriveThreats(packets: MockPacket[]): MockThreat[] {
  // Mirrors the local analyzer (lib/analysis.ts) and Rust engine: each rule
  // carries its own confidence and writes detector-specific evidence — never
  // one generic "Repeated X traffic" template for every signature.
  const signatures: { sig: string; cat: string; sev: number; ruleId: string; conf: number; evidence: (p: MockPacket) => string }[] = [
    { sig: "Port Scan Detected", cat: "Reconnaissance", sev: 3, ruleId: "PORT-SCAN-001", conf: 70, evidence: (p) => `${p.srcIp} sent SYN probes to ${p.dstIp} across multiple ports (e.g. ${p.dstPort}) — port scanning behavior` },
    { sig: "SYN Flood Attempt", cat: "DoS", sev: 4, ruleId: "SYN-FLOOD-001", conf: 65, evidence: (p) => `${p.srcIp} sent a sustained burst of SYN packets to ${p.dstIp}:${p.dstPort} without completing handshakes` },
    { sig: "DNS Tunneling", cat: "Exfiltration", sev: 5, ruleId: "DNS-TUNNEL-001", conf: 80, evidence: (p) => `DNS queries from ${p.srcIp} to ${p.dstIp}:53 carried unusually long or high-entropy labels (encoded data pattern)` },
    { sig: "Suspicious TLS Version", cat: "Anomaly", sev: 2, ruleId: "TLS-SUSPICIOUS-001", conf: 75, evidence: (p) => `TLS handshake from ${p.srcIp} to ${p.dstIp}:${p.dstPort} negotiated a deprecated TLS version` },
    { sig: "Repeated HTTP Errors", cat: "Web Attack", sev: 3, ruleId: "HTTP-CREDS-001", conf: 60, evidence: (p) => `${p.srcIp} generated repeated HTTP error responses (4xx/5xx) against ${p.dstIp}:${p.dstPort}` },
    { sig: "Credential Brute Force", cat: "Authentication", sev: 4, ruleId: "CRED-LEAK-001", conf: 75, evidence: (p) => `${p.srcIp} made multiple rapid authentication attempts against ${p.dstIp}:${p.dstPort} in a short window` },
    { sig: "ICMP Tunneling", cat: "Exfiltration", sev: 5, ruleId: "DATA-EXFIL-001", conf: 70, evidence: (p) => `ICMP traffic from ${p.srcIp} to ${p.dstIp} with oversized payloads — possible covert channel` },
    { sig: "SSL Certificate Mismatch", cat: "Anomaly", sev: 2, ruleId: "TLS-SUSPICIOUS-001", conf: 60, evidence: (p) => `Certificate chain presented by ${p.dstIp}:${p.dstPort} did not match the expected hostname` },
    { sig: "DNS Query to Suspicious Domain", cat: "C2", sev: 4, ruleId: "C2-BEACON-001", conf: 75, evidence: (p) => `DNS query from ${p.srcIp} to ${p.dstIp} for a known-bad or high-entropy domain` },
    { sig: "Unusual Port Traffic", cat: "Policy Violation", sev: 2, ruleId: "PORT-SCAN-001", conf: 55, evidence: (p) => `${p.srcIp} communicated with ${p.dstIp} on non-standard port ${p.dstPort} (${p.protocol})` },
  ]
  const rand = seededRandom(97)
  return packets.filter(() => rand() > 0.985).slice(0, 25).map((p, i) => {
    const s = pick(signatures, rand)
    return {
      id: `alert-${i + 1}`,
      timestamp: p.timestamp,
      signature: s.sig,
      category: s.cat,
      severity: s.sev,
      confidence: s.conf,
      ruleId: s.ruleId,
      srcIp: p.srcIp,
      dstIp: p.dstIp,
      srcPort: p.srcPort,
      dstPort: p.dstPort,
      protocol: p.protocol,
      evidence: s.evidence(p),
    }
  })
}

function deriveTimeline(packets: MockPacket[]): MockTimelineEntry[] {
  const buckets = new Map<string, MockTimelineEntry>()
  for (const p of packets) {
    const d = new Date(p.timestamp)
    const key = `${d.getHours().toString().padStart(2, "0")}:${String(Math.floor(d.getMinutes() / 5) * 5).padStart(2, "0")}`
    if (!buckets.has(key)) {
      buckets.set(key, { time: key, packets: 0, bytes: 0, tcp: 0, udp: 0, dns: 0, tls: 0 })
    }
    const b = buckets.get(key)!
    b.packets++
    b.bytes += p.length
    if (p.protocol === "TCP") b.tcp++
    else if (p.protocol === "UDP") b.udp++
    else if (p.protocol === "DNS") b.dns++
    else if (p.protocol === "TLS") b.tls++
  }
  return Array.from(buckets.values()).sort((a, b) => a.time.localeCompare(b.time))
}

function deriveBandwidth(packets: MockPacket[]): MockBandwidthPoint[] {
  const buckets = new Map<string, MockBandwidthPoint>()
  for (const p of packets) {
    const d = new Date(p.timestamp)
    const key = `${d.getHours().toString().padStart(2, "0")}:${String(Math.floor(d.getMinutes() / 5) * 5).padStart(2, "0")}`
    if (!buckets.has(key)) {
      buckets.set(key, { time: key, in: 0, out: 0 })
    }
    const b = buckets.get(key)!
    if (SRC_IPS.includes(p.srcIp)) b.out += p.length
    else b.in += p.length
  }
  return Array.from(buckets.values()).sort((a, b) => a.time.localeCompare(b.time))
}

const _mockPackets = generateMockPackets()
const _mockFlows = deriveFlows(_mockPackets)
const _mockSessions = deriveSessions(_mockPackets)
const _mockDns = deriveDns(_mockPackets)
const _mockHttp = deriveHttp(_mockPackets)
const _mockTls = deriveTls(_mockPackets)
const _mockFiles = deriveFiles(_mockPackets)
const _mockCredentials = deriveCredentials(_mockPackets)
const _mockCertificates = deriveCertificates(_mockPackets)
const _mockDevices = deriveDevices(_mockPackets)
const _mockThreats = deriveThreats(_mockPackets)
const _mockTimeline = deriveTimeline(_mockPackets)
const _mockBandwidth = deriveBandwidth(_mockPackets)

export const mockPackets = _mockPackets
export const mockFlows = _mockFlows
export const mockSessions = _mockSessions
export const mockDns = _mockDns
export const mockHttp = _mockHttp
export const mockTls = _mockTls
export const mockFiles = _mockFiles
export const mockCredentials = _mockCredentials
export const mockCertificates = _mockCertificates
export const mockDevices = _mockDevices
export const mockTimeline = _mockTimeline
export const mockBandwidth = _mockBandwidth

// Honest demo metrics derived from the actual mock packets. The previous
// hand-written values claimed a 4.1 MB exfiltration across 3 flows and
// top talkers with LAN-dst bytes that no packet in the dataset can produce —
// the fabricated DATA-EXFIL alert inflated the demo risk score (QA).
function deriveMockMetrics(): AnalysisAdvancedMetrics {
  const times = _mockPackets.map((p) => Date.parse(p.timestamp))
  const firstTs = Math.min(...times)
  const duration = Math.max((Math.max(...times) - firstTs) / 1000, 1)
  const talkerMap = new Map<string, { bytesOut: number; bytesIn: number; packetsOut: number; packetsIn: number }>()
  const buckets = new Map<number, number>()
  const localIps = new Set(SRC_IPS)
  let totalBytes = 0
  for (const p of _mockPackets) {
    const bytes = p.length
    totalBytes += bytes
    if (localIps.has(p.srcIp)) {
      const t = talkerMap.get(p.srcIp) ?? { bytesOut: 0, bytesIn: 0, packetsOut: 0, packetsIn: 0 }
      t.bytesOut += bytes; t.packetsOut++
      talkerMap.set(p.srcIp, t)
    } else {
      const t = talkerMap.get(p.dstIp) ?? { bytesOut: 0, bytesIn: 0, packetsOut: 0, packetsIn: 0 }
      t.bytesIn += bytes; t.packetsIn++
      talkerMap.set(p.dstIp, t)
    }
    const sec = Math.floor((Date.parse(p.timestamp) - firstTs) / 1000)
    buckets.set(sec, (buckets.get(sec) ?? 0) + bytes)
  }
  const throughputAvg = totalBytes / duration
  let throughputPeak = 0
  for (const b of buckets.values()) if (b > throughputPeak) throughputPeak = b
  // Same burst rule as the real analyzer: a contiguous run above 2× average.
  // The mock's synthetic capture mixes upload/download traffic, so the burst
  // is direction-neutral (outboundDominant: true keeps the curated score).
  let burst: AnalysisAdvancedMetrics["burst"] = { detected: false, peakThroughput: throughputPeak, averageThroughput: throughputAvg, ratio: throughputAvg > 0 ? throughputPeak / throughputAvg : 0, start: 0, end: 0, duration: 0, outboundDominant: true }
  if (totalBytes > 10000 && buckets.size >= 2 && throughputPeak > throughputAvg * 2) {
    let peakSec = 0, peakBytes = 0
    for (const [sec, bytes] of buckets) if (bytes > peakBytes) { peakBytes = bytes; peakSec = sec }
    const threshold = throughputAvg * 2
    let start = peakSec, end = peakSec
    while (start - 1 >= 0 && (buckets.get(start - 1) ?? 0) > threshold) start--
    while ((buckets.get(end + 1) ?? 0) > threshold) end++
    burst = { detected: true, peakThroughput: throughputPeak, averageThroughput: throughputAvg, ratio: throughputPeak / Math.max(throughputAvg, 1), start, end, duration: end - start + 1, outboundDominant: true }
  }
  const talkers = [...talkerMap.entries()]
    .sort((a, b) => (b[1].bytesOut + b[1].bytesIn) - (a[1].bytesOut + a[1].bytesIn))
    .slice(0, 2)
  return {
    // Canonical capture metrics (same shape the real engine emits): the mock
    // has real timestamps, so it is always VALID with numeric rates.
    rates: { quality: "VALID", durationSec: duration, avgPacketsSec: _mockPackets.length / duration, avgBps: throughputAvg, peakBps: throughputPeak, bucketCount: buckets.size },
    throughputAvg,
    throughputPeak,
    burst,
    beaconDetected: false,
    dnsTunnelingSuspected: false,
    dataExfiltrationSuspected: false,
    torVpnProxyDetected: false,
    portScanEnhanced: true, // demo dataset ships with the curated PORT-SCAN-001 below
    ja3Suspicious: false,
    topTalkers: talkers.map(([ip, t]) => ({ ip, bytesOut: t.bytesOut, bytesIn: t.bytesIn, packetsOut: t.packetsOut, packetsIn: t.packetsIn })),
    iocs: [],
    mitreMappings: [],
  }
}

export const mockAdvancedMetrics = deriveMockMetrics()

// The mock's behavioral flags stand in for the Rust engine's anomaly rules —
// emit the matching signature alerts so risk stays a pure function of alerts
// (same inputs the old buildRiskInputs(_, flags) pushed).
// Mock packets are AnalysisPacket-shaped (no tcpFlags), so the SYN-probe
// port-scan detector cannot derive a scan from them — the demo dataset is
// curated, so the scan is supplied explicitly (same evidence format the
// detector emits on real captures).
const _mockPortScanAlert: AnalysisThreat = {
  id: "alert-1",
  timestamp: new Date(REFERENCE_TIME + 120_000).toISOString(),
  signature: "Port Scan Detected", category: "Reconnaissance", severity: 3,
  confidence: 70, ruleId: "PORT-SCAN-001",
  srcIp: "192.168.1.1", dstIp: "203.0.113.5", srcPort: 0, dstPort: 0,
  protocol: "TCP",
  evidence: "192.168.1.1 scanned 25 ports on 1 host(s) over 60.0s (25 SYN, 0 RST, 0 FIN; e.g. 135, 139, 445, 1433, 3389, 5000)",
}

const _mockFlagThreats = deriveFlagThreats(mockAdvancedMetrics, _mockThreats.length + 1, _mockPackets[0] ? new Date(_mockPackets[0].timestamp).getTime() / 1000 : undefined)
// Re-number all threats to ensure unique IDs after combining
const allThreats = [_mockPortScanAlert, ..._mockThreats, ..._mockFlagThreats]
export const mockThreats = allThreats.map((t, i) => ({ ...t, id: `alert-${i + 1}` }))

export const mockJob = {
  id: "demo-7f9c8e2a-4b1d-4f8c-9e3a-2d5f7b8c9a0e",
  filename: "capture.pcapng",
  fileSize: 12_345_678,
  status: "done" as const,
  progress: 100,
  stage: "complete",
  totalPackets: _mockPackets.length,
  totalFlows: _mockFlows.length,
  conversations: _mockSessions.length,
  devices: _mockDevices.length,
  externalIps: new Set(_mockPackets.map((p) => p.dstIp)).size,
  countries: 0,
  domains: new Set(_mockDns.map((d) => d.query)).size,
  protocols: [...new Set(_mockPackets.map((p) => p.protocol))],
  alerts: mockThreats.length,
  riskScore: computeRisk(
    buildRiskInputs(mockThreats),
    burstConfidenceBoost(mockAdvancedMetrics)
  ),
  captureDuration: 3600,
  createdAt: new Date(REFERENCE_TIME).toISOString(),
}

export const mockJobInfo = {
  isDemo: true,
  analyzerVersion: `v${ANALYZER_VERSION}`,
  ruleVersion: "2024.08",
  riskSpecVersion: "1.3",
  geoDbVersion: "2024-07",
}
