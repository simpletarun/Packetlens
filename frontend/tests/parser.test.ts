import { describe, it, expect } from "vitest"
import { parsePcap } from "@/lib/pcap"

describe("PCAP parser", () => {
  it("parses a minimal valid PCAP file", async () => {
    const buf = Buffer.from([
      0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ])
    const result = await parsePcap(buf)
    expect(result.stats?.totalPackets ?? 0).toBe(0)
  })

  it("rejects non-PCAP files", async () => {
    const buf = Buffer.from("not a pcap file")
    const result = await parsePcap(buf)
    expect(result.stats?.totalPackets ?? 0).toBe(0)
  })

  it("rejects empty buffer", async () => {
    const result = await parsePcap(Buffer.alloc(0))
    expect(result.stats?.totalPackets ?? 0).toBe(0)
  })

  it("handles truncated PCAP gracefully", async () => {
    const buf = Buffer.from([0xd4, 0xc3, 0xb2, 0xa1])
    const result = await parsePcap(buf)
    expect(result.stats?.totalPackets ?? 0).toBe(0)
  })

  it("handles PCAPNG format gracefully", async () => {
    const buf = Buffer.from([
      0x0a, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
    ])
    const result = await parsePcap(buf)
    expect(result.stats?.totalPackets ?? 0).toBe(0)
  })

  it("parses DNS answers (A + PTR) and response code", async () => {
    const buf = buildDnsPcap(true)
    const result = await parsePcap(buf)
    expect(result.stats?.totalPackets ?? 0).toBe(1)
    const pkt = result.packets[0]
    expect(pkt.dnsQuery).toBe("router.lan")
    expect(pkt.dnsRcode).toBe(0)
    expect(pkt.dnsAnswers).toEqual([
      { name: "router.lan", ip: "10.0.0.1" },
      { name: "phone.lan", ip: "10.0.0.9" },
    ])
  })

  it("marks DNS packets as query (QR=0) vs response (QR=1)", async () => {
    const query = await parsePcap(buildDnsPcap(false))
    expect(query.packets[0].dnsQr).toBe(false)
    const response = await parsePcap(buildDnsPcap(true))
    expect(response.packets[0].dnsQr).toBe(true)
  })

  it("reads the question TYPE from the field after the name (A = 1, AAAA = 28) even on pure queries", async () => {
    // Regression: dnsQtype was read at the NAME START (label-length byte +
    // first char), so queries fell back to a hardcoded "A" while responses
    // showed A/AAAA by answer IP — client rows read {A, A} when the second
    // query per socket was really AAAA.
    const a = await parsePcap(buildDnsQueryPcap(1))
    expect(a.packets[0].dnsQtype).toBe(1)
    expect(a.packets[0].dnsQr).toBe(false)
    const aaaa = await parsePcap(buildDnsQueryPcap(28))
    expect(aaaa.packets[0].dnsQtype).toBe(28)
    expect(aaaa.packets[0].dnsQr).toBe(false)
    expect(aaaa.packets[0].dnsAnswers).toBeUndefined()
  })

  it("records link type + decoded count for Ethernet captures", async () => {
    const result = await parsePcap(buildArpPcap())
    expect(result.stats?.linkTypes).toEqual([1])
    expect(result.stats?.decodedPackets).toBe(1)
    expect(result.packets[0].srcIp).toBe("192.168.1.10")
  })

  it("flags snaplen-truncated frames (captured length < original length)", async () => {
    const frame = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00, 0x45, 0x00]
    const cut = frame.slice(0, 10) // only 10 of 16 captured bytes present
    const buf = Buffer.from([
      0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      ...little32(1), ...little32(0), ...little32(cut.length), ...little32(frame.length),
      ...cut,
    ])
    const result = await parsePcap(buf)
    expect(result.stats?.totalPackets).toBe(1)
    expect(result.stats?.truncatedPackets).toBe(1)
    expect(result.packets[0].length).toBe(10)
    expect(result.packets[0].origLength).toBe(16)
    expect(result.stats?.fileTruncated).toBeFalsy()
  })

  it("flags frames too short for their own Ethernet header as malformed", async () => {
    const buf = Buffer.from([
      0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      ...little32(1), ...little32(0), ...little32(10), ...little32(10),
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd,
    ])
    const result = await parsePcap(buf)
    expect(result.stats?.totalPackets).toBe(1)
    expect(result.stats?.malformedPackets).toBe(1)
    expect(result.stats?.decodedPackets).toBe(0)
    expect(result.stats?.fileTruncated).toBeFalsy()
  })

  it("flags a file that ends mid-record as truncated (declared length past EOF)", async () => {
    const buf = Buffer.from([
      0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      ...little32(1), ...little32(0), ...little32(60), ...little32(60),
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // file ends 6 bytes into a 60-byte frame
    ])
    const result = await parsePcap(buf)
    expect(result.stats?.totalPackets).toBe(1)
    expect(result.stats?.truncatedPackets).toBe(1)
    expect(result.stats?.fileTruncated).toBe(true)
  })

  it("decodes RAW IP headers (DLT 12/101) since v3.2 (F-01)", async () => {
    // 20-byte IPv4 header + 8-byte UDP, no Ethernet header.
    const raw = [0x45, 0x00, ...be16(28), ...be16(7), ...be16(0), 64, 17, 0x00, 0x00, 10, 0, 0, 5, 203, 0, 113, 9, ...be16(0), ...be16(0), ...be16(8), 0, 0]
    for (const dlt of [12, 101]) {
      const result = await parsePcap(buildDltPcap(dlt, raw))
      expect(result.stats?.linkTypes).toEqual([dlt])
      expect(result.stats?.decodedPackets).toBe(1)
      expect(result.packets[0].srcIp).toBe("10.0.0.5")
      expect(result.packets[0].dstIp).toBe("203.0.113.9")
      expect(result.packets[0].protocol).toBe("UDP")
    }
  })

  it("decodes NULL/loopback captures (DLT 0/108) by address family", async () => {
    const v4 = [0x02, 0x00, 0x00, 0x00, 0x45, 0x00, ...be16(28), ...be16(7), ...be16(0), 64, 17, 0x00, 0x00, 127, 0, 0, 1, 127, 0, 0, 1, ...be16(0), ...be16(0), ...be16(8), 0, 0]
    for (const dlt of [0, 108]) {
      const v4res = await parsePcap(buildDltPcap(dlt, v4))
      expect(v4res.stats?.decodedPackets).toBe(1)
      expect(v4res.packets[0].srcIp).toBe("127.0.0.1")
      expect(v4res.packets[0].dstIp).toBe("127.0.0.1")
    }
    // AF_INET6 family (24) → IPv6 header (::1 → ::1)
    const v6 = [0x18, 0x00, 0x00, 0x00, 0x60, 0, 0, 0, ...be16(8), 17, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, ...be16(5353), ...be16(5353), ...be16(8), 0, 0]
    const v6res = await parsePcap(buildDltPcap(0, v6))
    expect(v6res.stats?.decodedPackets).toBe(1)
    expect(v6res.packets[0].srcIp).toBe("0:0:0:0:0:0:0:1")
    expect(v6res.packets[0].protocol).toBe("UDP")
  })

  it("decodes Linux cooked captures (SLL 113 / SLL2 276) and their source MACs", async () => {
    const ip = [0x45, 0x00, ...be16(28), ...be16(7), ...be16(0), 64, 17, 0x00, 0x00, 10, 0, 0, 5, 203, 0, 113, 9, ...be16(0), ...be16(0), ...be16(8), 0, 0]
    const sll1 = [0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x08, 0x00, ...ip]
    const res1 = await parsePcap(buildDltPcap(113, sll1))
    expect(res1.stats?.decodedPackets).toBe(1)
    expect(res1.packets[0].srcMac).toBe("aa:bb:cc:dd:ee:ff")
    expect(res1.packets[0].srcIp).toBe("10.0.0.5")

    const sll2 = [0x08, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, ...ip]
    const res2 = await parsePcap(buildDltPcap(276, sll2))
    expect(res2.stats?.decodedPackets).toBe(1)
    expect(res2.packets[0].srcMac).toBe("aa:bb:cc:dd:ee:ff")
    expect(res2.packets[0].srcIp).toBe("10.0.0.5")
  })

  it("still never decodes unknown DLTs (lengths + timestamps only)", async () => {
    const v4 = [0x45, 0x00, ...be16(28), ...be16(7), ...be16(0), 64, 17, 0x00, 0x00, 10, 0, 0, 5, 203, 0, 113, 9, ...be16(0), ...be16(0), ...be16(8), 0, 0]
    const result = await parsePcap(buildDltPcap(999, v4))
    expect(result.stats?.linkTypes).toEqual([999])
    expect(result.stats?.decodedPackets ?? 0).toBe(0)
    expect(result.packets[0].srcIp).toBeUndefined()
    expect(result.packets[0].dstIp).toBeUndefined()
  })

  it("honors a link type override for otherwise-undecodable captures", async () => {
    const v4 = [0x45, 0x00, ...be16(28), ...be16(7), ...be16(0), 64, 17, 0x00, 0x00, 10, 0, 0, 5, 203, 0, 113, 9, ...be16(0), ...be16(0), ...be16(8), 0, 0]
    const result = await parsePcap(buildDltPcap(999, v4), 101)
    expect(result.stats?.linkTypes).toEqual([101])
    expect(result.stats?.decodedPackets).toBe(1)
    expect(result.packets[0].srcIp).toBe("10.0.0.5")
  })

  it("never fabricates headers when an override is wrong for the bytes", async () => {
    // Forcing an Ethernet capture as Raw IP hits the version-nibble guard, so
    // nothing decodes — an honest "undecodable", not fake headers.
    const result = await parsePcap(buildArpPcap(), 101)
    expect(result.packets[0].srcIp).toBeUndefined()
  })

  it("labels UDP traffic from a known service port even when it is the source (STUN/QUIC responses)", async () => {
    const stun = await parsePcap(buildUdpPcap(3478, 40000, stunBindingResponse()))
    expect(stun.packets[0].appProtocol).toBe("STUN")
    const quic = await parsePcap(buildUdpPcap(443, 40000))
    expect(quic.packets[0].appProtocol).toBe("QUIC")
  })

  it("confirms STUN only when the RFC 5389 magic cookie is present (audit)", async () => {
    // Same port, non-STUN payload (game/custom UDP): no cookie → plain UDP.
    const junk = await parsePcap(buildUdpPcap(3478, 40000, new Array(20).fill(0x00)))
    expect(junk.packets[0].appProtocol).toBe("UDP")
    // HTTP-shaped payloads still win by content, even on a STUN port.
    const http = await parsePcap(buildUdpPcap(3478, 40000, [...Buffer.from("GET /")]))
    expect(http.packets[0].appProtocol).toBe("HTTP")
    // Empty payload on the port is a length-only packet, never "STUN".
    const empty = await parsePcap(buildUdpPcap(40000, 3478, []))
    expect(empty.packets[0].appProtocol).toBe("UDP")
    // Payload with the cookie at offset 4, from the client side too.
    const req = await parsePcap(buildUdpPcap(40000, 3478, stunBindingResponse()))
    expect(req.packets[0].appProtocol).toBe("STUN")
  })

  it("walks IPv6 extension headers to the real transport (HOPOPT → TCP)", async () => {
    const tcp = [...be16(40000), ...be16(443), 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]
    const hopopt = [0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06] // next=TCP, HdrExtLen=0
    const result = await parsePcap(buildIpv6Pcap(0, [...hopopt, ...tcp], v6Local(), v6Remote()))
    const pkt = result.packets[0]
    expect(pkt.protocol).toBe("TCP")
    expect(pkt.srcPort).toBe(40000)
    expect(pkt.dstPort).toBe(443)
    expect(pkt.srcIp).toBe("0:0:0:0:0:0:0:1")
  })

  it("walks an IPv6 AH header (length in 32-bit words minus 2) to UDP", async () => {
    const udp = [...be16(3478), ...be16(40000), ...be16(28), 0, 0, ...stunBindingResponse()]
    const ah = [0x11, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78] // next=UDP, PayloadLen 0 → 8 bytes
    const result = await parsePcap(buildIpv6Pcap(51, [...ah, ...udp], v6Local(), v6Remote()))
    expect(result.packets[0].protocol).toBe("UDP")
    expect(result.packets[0].dstPort).toBe(40000)
    expect(result.packets[0].appProtocol).toBe("STUN")
  })

  it("never parses ports from a non-first IPv6 fragment (no fabricated headers)", async () => {
    const frag = [0x06, 0x00, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78] // offset=1 unit, next=TCP
    const junk = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
    const result = await parsePcap(buildIpv6Pcap(44, [...frag, ...junk], v6Local(), v6Remote()))
    expect(result.packets[0].protocol).toBe("TCP")
    expect(result.packets[0].srcPort).toBeUndefined()
  })

  it("bails out of an over-long IPv6 extension chain without hanging", async () => {
    const chain = Array.from({ length: 10 }, () => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).flat()
    const result = await parsePcap(buildIpv6Pcap(0, [...chain, ...be16(40000), ...be16(443)], v6Local(), v6Remote()))
    expect(result.packets[0].srcIp).toBe("0:0:0:0:0:0:0:1")
    expect(result.packets[0].srcPort).toBeUndefined()
  })

  it("parses SIP signalling and RTP media from real UDP payloads (F-02)", async () => {
    const invite = [
      ...[...Buffer.from("INVITE sip:bob@192.0.2.20 SIP/2.0\r\n")],
      ...[...Buffer.from("Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK74bf9\r\n")],
      ...[...Buffer.from("From: \"Alice\" <sip:alice@203.0.113.9>;tag=9fxced76sl\r\n")],
      ...[...Buffer.from("To: \"Bob\" <sip:bob@192.0.2.20>\r\n")],
      ...[...Buffer.from("Call-ID: 2xTb9vxSit55XU7p8@203.0.113.9\r\n")],
      ...[...Buffer.from("User-Agent: Yealink-T19P\r\n")],
      ...[...Buffer.from("Content-Type: application/sdp\r\n\r\n")],
      ...[...Buffer.from("m=audio 7078 RTP/AVP 0 101\r\n")],
    ]
    const sip = await parsePcap(buildUdpPcap(5060, 5060, invite))
    const s = sip.packets[0].sip
    expect(sip.packets[0].appProtocol).toBe("SIP")
    expect(s).toBeDefined()
    expect(s!.method).toBe("INVITE")
    expect(s!.callId).toBe("2xTb9vxSit55XU7p8@203.0.113.9")
    expect(s!.fromUser).toBe("alice")
    expect(s!.toUser).toBe("bob")
    expect(s!.viaIp).toBe("203.0.113.9")
    expect(s!.userAgent).toBe("Yealink-T19P")
    expect(s!.rtpPort).toBe(7078)

    const rtpBytes = [0x80, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x61, 0x62, 0x63]
    const rtp = await parsePcap(buildUdpPcap(7078, 40000, rtpBytes))
    const r = rtp.packets[0].rtp
    expect(r).toBeDefined()
    expect(r!.payloadType).toBe(120)
    expect(r!.ssrc).toBe(0xdeadbeef)
    expect(r!.sequence).toBe(1)
  })

  it("never flags plain UDP payloads as SIP or RTP", async () => {
    const junk = await parsePcap(buildUdpPcap(40000, 50000, [...Buffer.from("HELLO world\r\n")]))
    expect(junk.packets[0].sip).toBeUndefined()
    const zeros = await parsePcap(buildUdpPcap(40000, 50000, new Array(20).fill(0x00)))
    expect(zeros.packets[0].rtp).toBeUndefined()
  })

  it("labels LAN discovery protocols from either port side", async () => {
    const mdns = await parsePcap(buildUdpPcap(5353, 40000))
    expect(mdns.packets[0].appProtocol).toBe("mDNS")
    const llmnr = await parsePcap(buildUdpPcap(40000, 5355))
    expect(llmnr.packets[0].appProtocol).toBe("LLMNR")
  })

    it("parses the X.509 leaf certificate from a TLS Certificate handshake", async () => {
    const cert = buildTestCert()
    // Handshake length covers: cert-list length(3) + cert-entry length(3) + cert.
    const hsLen = 6 + cert.length
    const record = [0x16, 0x03, 0x03, ...be16(4 + hsLen)]
    const hs = [0x0b, (hsLen >> 16) & 0xff, (hsLen >> 8) & 0xff, hsLen & 0xff]
    const certListLen = 3 + cert.length
    const certEntry = [(cert.length >> 16) & 0xff, (cert.length >> 8) & 0xff, cert.length & 0xff]
    const result = await parsePcap(buildTcpPcap(40000, 443, [...record, ...hs, (certListLen >> 16) & 0xff, (certListLen >> 8) & 0xff, certListLen & 0xff, ...certEntry, ...cert]))
    const c = result.packets[0].tlsCert
    expect(c).toBeDefined()
    expect(c!.subject).toBe("example.com")
    expect(c!.issuer).toBe("Test Issuer CA")
    expect(c!.serial).toBe("01020304")
    expect(c!.signatureAlgorithm).toBe("sha256WithRSA")
    expect(c!.keySize).toBe(2048)
    expect(c!.san).toEqual(["example.com", "93.184.216.34"])
    expect(new Date(c!.notBefore).getUTCFullYear()).toBe(2025)
    expect(new Date(c!.notAfter).getUTCFullYear()).toBe(2028)
  })

  it("extracts the SNI from a QUIC Initial packet's CRYPTO frame", async () => {
    const result = await parsePcap(buildQuicInitialPcap("example.com"))
    const pkt = result.packets[0]
    expect(pkt.appProtocol).toBe("QUIC")
    expect(pkt.tlsSni).toBe("example.com")
  })

  it("never mistakes QUIC short-header packets for TLS records", async () => {
    const short = [0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]
    const result = await parsePcap(buildUdpPcap(40000, 443, short))
    expect(result.packets[0].tlsSni).toBeUndefined()
    expect(result.packets[0].appProtocol).toBe("QUIC")
  })

  it("labels uncommon IP protocols with friendly names, never internal 'IPn' codes", async () => {
    const gre = await parsePcap(buildRawIpPcap(47))
    expect(gre.packets[0].protocol).toBe("GRE")
    const esp = await parsePcap(buildRawIpPcap(50))
    expect(esp.packets[0].protocol).toBe("ESP")
    const unknown = await parsePcap(buildRawIpPcap(137))
    expect(unknown.packets[0].protocol).toBe("Other (137)")
    expect(unknown.packets[0].srcPort).toBeUndefined()
  })

  it("decodes ARP as its own protocol (not 'Other'/'unknown') with sender/target IPs", async () => {
    const arp = await parsePcap(buildArpPcap())
    expect(arp.packets.length).toBe(1)
    const pkt = arp.packets[0]
    expect(pkt.protocol).toBe("ARP")
    expect(pkt.appProtocol).toBe("ARP-Request")
    expect(pkt.srcIp).toBe("192.168.1.10")
    expect(pkt.dstIp).toBe("192.168.1.1")
    expect(pkt.srcMac).toBe("aa:bb:cc:dd:ee:ff")
    expect(pkt.dstMac).toBe("00:11:22:33:44:55")
    expect(pkt.srcPort).toBeUndefined()
  })
})

function little32(n: number): number[] {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]
}
// Network byte order (big-endian) for IP/UDP/DNS fields.
function be16(n: number): number[] {
  return [(n >> 8) & 0xff, n & 0xff]
}
function be32(n: number): number[] {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]
}
function dnsName(name: string): number[] {
  const bytes: number[] = []
  for (const label of name.split(".")) {
    bytes.push(label.length)
    for (const ch of label) bytes.push(ch.charCodeAt(0))
  }
  bytes.push(0)
  return bytes
}

export function buildDnsPcap(isResponse = true): Buffer {
  const flags = isResponse ? [0x81, 0x80] : [0x01, 0x00]
  const q1 = [...dnsName("router.lan"), ...be16(1), ...be16(1)] // A
  const q2 = [...dnsName("9.0.0.10.in-addr.arpa"), ...be16(12), ...be16(1)] // PTR
  const a1 = [0xc0, 0x0c, ...be16(1), ...be16(1), ...be32(300), ...be16(4), 10, 0, 0, 1]
  const target = dnsName("phone.lan")
  const a2 = [...be16(0xc000 | (12 + q1.length)), ...be16(12), ...be16(1), ...be32(300), ...be16(target.length), ...target]
  const dns = [0x12, 0x34, ...flags, ...be16(2), ...be16(2), ...be16(0), ...be16(0), ...q1, ...q2, ...a1, ...a2]

  const udpLen = 8 + dns.length
  const ipTotal = 20 + udpLen
  const ip = [0x45, 0x00, ...be16(ipTotal), ...be16(1), ...be16(0), 64, 17, 0x00, 0x00, 10, 0, 0, 5, 10, 0, 0, 1]
  const udp = [...be16(53), ...be16(53), ...be16(udpLen), 0x00, 0x00]
  const frame = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00, ...ip, ...udp, ...dns]

  const pcap = [
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ...little32(1), ...little32(0), ...little32(frame.length), ...little32(frame.length),
    ...frame,
  ]
  return Buffer.from(pcap)
}

// Single DNS QUERY packet (no answers) asking for example.com with the given
// question TYPE — exercises the question-section qtype parser, not the
// answer-based fallback.
function buildDnsQueryPcap(qtype: number): Buffer {
  const q1 = [...dnsName("example.com"), ...be16(qtype), ...be16(1)]
  const dns = [0xab, 0xcd, 0x01, 0x00, ...be16(1), ...be16(0), ...be16(0), ...be16(0), ...q1]
  const udpLen = 8 + dns.length
  const ipTotal = 20 + udpLen
  const ip = [0x45, 0x00, ...be16(ipTotal), ...be16(4), ...be16(0), 64, 17, 0x00, 0x00, 10, 0, 0, 5, 203, 0, 113, 9]
  const udp = [...be16(53123), ...be16(53), ...be16(udpLen), 0x00, 0x00, ...dns]
  const frame = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00, ...ip, ...udp]
  return Buffer.from([
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ...little32(1), ...little32(0), ...little32(frame.length), ...little32(frame.length),
    ...frame,
  ])
}

// Single UDP packet from srcIp:sport to dstIp:dport with an optional payload.
function buildUdpPcap(srcPort: number, dstPort: number, payload: number[] = [0x00]): Buffer {
  const udpLen = 8 + payload.length
  const ipTotal = 20 + udpLen
  const ip = [0x45, 0x00, ...be16(ipTotal), ...be16(2), ...be16(0), 64, 17, 0x00, 0x00, 10, 0, 0, 5, 203, 0, 113, 9]
  const udp = [...be16(srcPort), ...be16(dstPort), ...be16(udpLen), 0x00, 0x00, ...payload]
  const frame = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00, ...ip, ...udp]
  return Buffer.from([
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ...little32(1), ...little32(0), ...little32(frame.length), ...little32(frame.length),
    ...frame,
  ])
}

// Minimal real STUN message (RFC 5389): binding response header with the
// magic cookie 0x2112A442 at offset 4 and a 12-byte transaction ID.
function stunBindingResponse(): number[] {
  return [0x01, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
}

function v6Local(): number[] {
  return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] // ::1
}

function v6Remote(): number[] {
  return [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] // 2001:db8::1
}

// Single Ethernet-frame IPv6 packet with the given next-header and payload.
function buildIpv6Pcap(nextHdr: number, payload: number[], src: number[], dst: number[]): Buffer {
  const v6 = [0x60, 0x00, 0x00, 0x00, ...be16(payload.length), nextHdr, 64, ...src, ...dst, ...payload]
  const frame = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x86, 0xdd, ...v6]
  return Buffer.from([
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ...little32(1), ...little32(0), ...little32(frame.length), ...little32(frame.length),
    ...frame,
  ])
}

// IPv4 packet with a raw IP protocol number (no port-bearing transport).
function buildRawIpPcap(proto: number): Buffer {
  const ip = [0x45, 0x00, ...be16(28), ...be16(3), ...be16(0), 64, proto, 0x00, 0x00, 10, 0, 0, 5, 203, 0, 113, 9]
  const frame = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00, ...ip, ...be16(8), ...be16(0), ...be16(8), 0, 0]
  return Buffer.from([
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ...little32(1), ...little32(0), ...little32(frame.length), ...little32(frame.length),
    ...frame,
  ])
}

// Single packet in a PCAP with an explicit link type (default Ethernet=1).
// DLT 12 (RAW) / 101 (Raw IP) carry no Ethernet header, so the parser must
// record lengths + timestamps but never decode headers (QA: large/verylarge
// — the decode-rate gate and link-type diagnostics depend on this split).
function buildDltPcap(linkType: number, payload: number[]): Buffer {
  return Buffer.from([
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, ...little32(linkType),
    ...little32(0), ...little32(0), ...little32(payload.length), ...little32(payload.length),
    ...payload,
  ])
}

// Ethernet + ARP request (RFC 826): sender 192.168.1.10 → who-has 192.168.1.1.
function buildArpPcap(): Buffer {
  const arp = [
    ...be16(0x0001), // htype: Ethernet
    ...be16(0x0800), // ptype: IPv4
    0x06, 0x04,      // hlen 6, plen 4
    ...be16(0x0001), // op: request
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // sender MAC
    192, 168, 1, 10,  // sender IP
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC (zero for solicitation)
    192, 168, 1, 1,   // target IP
  ]
  const frame = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x06, ...arp]
  return Buffer.from([
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ...little32(1), ...little32(0), ...little32(frame.length), ...little32(frame.length),
    ...frame,
  ])
}

// Ethernet + IPv4 + TCP with the given flag byte and optional payload.
// Defaults to an ephemeral client port → 80 (the port-inferred HTTP case).
function buildFlagTcpPcap(flags: number, payload: number[] = [], srcPort = 50000, dstPort = 80): Buffer {
  const ipLen = 20 + 20 + payload.length
  const ip = [
    0x45, 0x00, ...be16(ipLen), ...be16(7), ...be16(0), 64, 6, 0x00, 0x00,
    192, 168, 1, 5, 8, 8, 8, 8,
  ]
  const tcp = [
    ...be16(srcPort), ...be16(dstPort), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    (5 << 4) | (flags >> 8 & 0x0f), flags & 0xff,
    ...be16(65535), ...be16(0), 0x00, 0x00,
    ...payload,
  ]
  const frame = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00, ...ip, ...tcp]
  return Buffer.from([
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ...little32(1), ...little32(0), ...little32(frame.length), ...little32(frame.length),
    ...frame,
  ])
}

describe("protocol honesty — payload vs port-inferred labels", () => {
  it("a pure SYN to :80 is HTTP BY PORT, never payload-confirmed", async () => {
    const result = await parsePcap(buildFlagTcpPcap(0x02))
    expect(result.packets[0].appProtocol).toBe("HTTP")
    expect(result.packets[0].appPayloadConfirmed).toBeUndefined()
    expect(result.packets[0].httpMethod).toBeUndefined()
  })

  it("a GET request is payload-confirmed HTTP", async () => {
    const payload = [...Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")]
    const result = await parsePcap(buildFlagTcpPcap(0x18, payload))
    expect(result.packets[0].appProtocol).toBe("HTTP")
    expect(result.packets[0].appPayloadConfirmed).toBe(true)
    expect(result.packets[0].httpMethod).toBe("GET")
  })

  it("a TLS ClientHello on :443 is payload-confirmed TLS", async () => {
    // TLS record (0x16) + handshake ClientHello (0x01, len 39+2 for SNI).
    const hello = [0x16, 0x03, 0x01, 0x00, 0x29, 0x01, 0x00, 0x00, 0x29, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    const result = await parsePcap(buildFlagTcpPcap(0x18, hello, 50000, 443))
    expect(result.packets[0].appProtocol).toBe("TLS")
    expect(result.packets[0].appPayloadConfirmed).toBe(true)
  })
})

// Minimal pcapng: SHB + IDB (with optional if_tsresol) + one EPB per packet.
// tsRaw is in the interface's resolution units (default µs, resol 10^9 = ns).
// Extreme timestamps pass explicit {hi, lo} — computing 2^64-1 in JS doubles
// rounds to a value whose hi/lo split becomes 0x00000000/0x00000000 (QA: the
// overflow fixture silently became epoch 1970).
function buildPcapNg(records: Array<{ tsRaw?: number; hi?: number; lo?: number; payload: number[] }>, resol = 1_000_000): Buffer {
  const body: number[] = []
  const shb = [
    0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00,
    0x4d, 0x3c, 0x2b, 0x1a, 0x01, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  ]
  body.push(...shb, ...little32(28))
  const resolByte = resol === 1_000_000 ? 6 : 9 // if_tsresol: 10^6 or 10^9
  const idb = [
    0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
    0x09, 0x00, 0x01, 0x00, resolByte, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
  ]
  body.push(...idb, ...little32(32))
  for (const r of records) {
    const padded = Math.ceil(r.payload.length / 4) * 4
    const len = 32 + padded
    const hi = r.hi ?? Math.floor((r.tsRaw ?? 0) / 4294967296)
    const lo = r.lo ?? (r.tsRaw ?? 0) % 4294967296
    const epb = [
      0x06, 0x00, 0x00, 0x00, ...little32(len),
      0x00, 0x00, 0x00, 0x00,
      ...little32(hi), ...little32(lo),
      ...little32(r.payload.length), ...little32(r.payload.length),
      ...r.payload,
    ]
    while (epb.length < len - 4) epb.push(0)
    body.push(...epb, ...little32(len))
  }
  return Buffer.from(body)
}

// Ethernet frame carrying 10.0.0.5:50000 → 8.8.8.8:80 (payload bytes as given).
function etherTcp(payload: number[], flags = 0x18): number[] {
  const tcpLen = 20 + payload.length
  const ipLen = 20 + tcpLen
  const ip = [
    0x45, 0x00, ...be16(ipLen), ...be16(3), ...be16(0), 64, 6, 0x00, 0x00,
    10, 0, 0, 5, 8, 8, 8, 8,
  ]
  const tcp = [...be16(50000), ...be16(80), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (5 << 4) | flags, flags, ...be16(65535), ...be16(0), 0x00, 0x00, ...payload]
  return [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00, ...ip, ...tcp]
}

describe("timestamp robustness — pcapng ns precision, out-of-order, extremes", () => {
  it("ns-resolution timestamps convert exactly (tsRaw / 1e9)", async () => {
    const r = await parsePcap(buildPcapNg([{ tsRaw: 123456789, payload: etherTcp([]) }], 1_000_000_000))
    expect(Math.abs(r.packets[0].timestamp - 0.123456789)).toBeLessThan(1e-12)
  })

  it("default µs resolution converts to seconds", async () => {
    const r = await parsePcap(buildPcapNg([{ tsRaw: 1_500_000, payload: etherTcp([]) }]))
    expect(r.packets[0].timestamp).toBe(1.5)
  })

  it("out-of-order timestamps: duration = max-min, file order preserved", async () => {
    const r = await parsePcap(buildPcapNg([
      { tsRaw: 5_000_000, payload: etherTcp([]) },
      { tsRaw: 1_000_000, payload: etherTcp([]) },
    ]))
    expect(r.packets[0].timestamp).toBe(5)
    expect(r.packets[1].timestamp).toBe(1)
    expect(r.stats.startTime).toBe(1)
    expect(r.stats.endTime).toBe(5)
    expect(r.stats.duration).toBe(4)
  })

  it("maximum pcapng timestamp (year 2554) parses and analyzes without crashing", async () => {
    const r = await parsePcap(buildPcapNg([{ hi: 0xffffffff, lo: 0xffffffff, payload: etherTcp([]) }]))
    expect(Number.isFinite(r.packets[0].timestamp)).toBe(true)
    expect(r.packets[0].timestamp).toBeGreaterThan(1e13)
    const { analyzePcap } = await import("@/lib/analysis")
    const a = analyzePcap(r)
    expect(a.flows[0].startTime).toBeDefined()
    // Clamped to the Date range by safeIso — the analysis never crashes and
    // never fabricates epoch 1970 for an extreme capture time.
    expect(new Date(a.flows[0].startTime).getTime()).toBeGreaterThan(0)
  })

  it("missing timestamps (zero) parse cleanly", async () => {
    const r = await parsePcap(buildPcapNg([{ tsRaw: 0, payload: etherTcp([]) }]))
    expect(r.packets[0].timestamp).toBe(0)
  })
})

// ── DER helpers + hand-crafted X.509 certificate for parser tests ──────────

function derLen(n: number): number[] {
  if (n < 0x80) return [n]
  const bytes: number[] = []
  let v = n
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256) }
  return [0x80 | bytes.length, ...bytes]
}
function tlv(tag: number, content: number[] | number[][]): number[] { const flat = content.flat(); return [tag, ...derLen(flat.length), ...flat] }
function seq(content: number[] | number[][]): number[] { return tlv(0x30, content) }
function setOf(content: number[] | number[][]): number[] { return tlv(0x31, content) }
function ctx(tag: number, content: number[]): number[] { return tlv(0x80 | tag, content) }
function oid(bytes: number[]): number[] { return tlv(0x06, bytes) }
function utf8(s: string): number[] { return tlv(0x0c, [...Buffer.from(s)]) }
function asciiBytes(s: string): number[] { return [...Buffer.from(s)] }
function utcTime(s: string): number[] { return tlv(0x17, asciiBytes(s)) }
function integer(bytes: number[]): number[] { return tlv(0x02, bytes) }
function bitString(content: number[]): number[] { return tlv(0x03, content) }
function octetString(content: number[]): number[] { return tlv(0x04, content) }
function nullTlv(): number[] { return [0x05, 0x00] }

// Minimal self-signed-style v3 cert: CNs in issuer-then-subject order, RSA
// 2048-bit SPKI, SAN extension, sha256WithRSA signature OID.
export function buildTestCert(): number[] {
  const cnIssuer = seq([oid([0x55, 0x04, 0x03]), utf8("Test Issuer CA")])
  const cnSubject = seq([oid([0x55, 0x04, 0x03]), utf8("example.com")])
  const issuer = seq([setOf([cnIssuer])])
  const validity = seq([utcTime("250101000000Z"), utcTime("280101000000Z")])
  const subject = seq([setOf([cnSubject])])
  const sanExt = seq([oid([0x55, 0x1d, 0x11]), octetString(seq([ctx(2, asciiBytes("example.com")), ctx(7, [93, 184, 216, 34])]))])
  const extensions = seq([sanExt])
  const rsaOid = oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
  const modulus = integer(Array(256).fill(0xab))
  const exponent = integer([0x01, 0x00, 0x01])
  const spki = seq([seq([rsaOid, nullTlv()]), bitString([0x00, ...seq([modulus, exponent])])])
  const sigAlg = seq([oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), nullTlv()])
  const tbs = seq([tlv(0xa0, [integer([0x02])]), integer([0x01, 0x02, 0x03, 0x04]), sigAlg, issuer, validity, subject, spki, extensions])
  return seq([tbs, sigAlg, bitString([0x00, ...asciiBytes("fake-signature")])])
}

// Single TCP packet srcIp:sport → dstIp:dport with a payload.
export function buildTcpPcap(srcPort: number, dstPort: number, payload: number[]): Buffer {
  const tcpTotal = 20 + payload.length
  const ipTotal = 20 + tcpTotal
  const ip = [0x45, 0x00, ...be16(ipTotal), ...be16(3), ...be16(0), 64, 6, 0x00, 0x00, 10, 0, 0, 5, 203, 0, 113, 9]
  const tcp = [...be16(srcPort), ...be16(dstPort), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, ...payload]
  const frame = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00, ...ip, ...tcp]
  return Buffer.from([
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ...little32(1), ...little32(0), ...little32(frame.length), ...little32(frame.length),
    ...frame,
  ])
}

// QUIC Initial packet (long header, v1): one CRYPTO frame carrying a TLS
// ClientHello whose SNI extension names the given host.
export function buildQuicInitialPcap(sni: string): Buffer {
  // RFC 6066: server_name_list_length covers type(1)+nameLen(2)+name; the
  // ext length field itself is NOT part of it.
  const sniName = [0x00, ...be16(sni.length), ...asciiBytes(sni)]
  const sniList = [...be16(sniName.length), ...sniName]
  const sniExt = [...be16(0x0000), ...be16(2 + sniList.length), ...sniList]
  const random = Array(32).fill(0x42)
  const chBody = [0x03, 0x03, ...random, 0x00, ...be16(2), 0x13, 0x01, 0x01, 0x00, ...be16(sniExt.length), ...sniExt]
  const hsMsg = [0x01, (chBody.length >> 16) & 0xff, (chBody.length >> 8) & 0xff, chBody.length & 0xff, ...chBody]
  // QUIC varint: values >= 64 need the 2-byte form (0x40 | hi, lo).
  const lenVar = chBody.length + 4 >= 64 ? [0x40 | ((chBody.length + 4) >> 8), (chBody.length + 4) & 0xff] : [chBody.length + 4]
  const crypto = [0x06, 0x00, ...lenVar, ...hsMsg]
  const header = [0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x00, 0x00, 0x01]
  return buildUdpPcap(40000, 443, [...header, ...crypto])
}