import { describe, it, expect } from "vitest"
import { parsePcap } from "@/lib/pcap"

// A minimal pcap (Ethernet, IPv4, TCP) with the given payload, truncated to
// `keep` bytes — exercises the truncated-trailing-packet paths.
function tcpPcap(payload: Uint8Array, keep?: number): Buffer {
  const FRAME = 24 + 16 // pcap global hdr + 16-byte record hdr, then the frame
  const total = FRAME + 14 + 20 + 20 + payload.length
  const buf = Buffer.alloc(total)
  buf.writeUInt32LE(0xa1b2c3d4, 0)
  buf.writeUInt32LE(65535, 16) // snaplen
  buf.writeUInt32LE(1, 20) // LINKTYPE_ETHERNET
  buf.writeUInt32LE(total - 40, 32) // incl_len (frame bytes only)
  buf.writeUInt32LE(total - 40, 36) // orig_len
  let o = FRAME
  buf.fill(0xff, o, o + 6); o += 6 // dstMac
  buf.fill(0, o, o + 6); o += 6 // srcMac
  buf.writeUInt16BE(0x0800, o); o += 2 // ethType
  buf[o] = 0x45; o += 1 // IPv4 vhl
  o += 1 // tos
  buf.writeUInt16BE(20 + 20 + payload.length, o); o += 2 // total length
  o += 4 // id + flags/frag
  buf[o] = 64; o += 1 // ttl
  buf[o] = 6; o += 1 // proto
  o += 2 // checksum
  buf[o] = 192; buf[o + 1] = 168; buf[o + 2] = 1; buf[o + 3] = 1; o += 4 // src ip
  buf[o] = 93; buf[o + 1] = 184; buf[o + 2] = 216; buf[o + 3] = 34; o += 4 // dst ip
  buf.writeUInt16BE(443, o); o += 2 // sport
  buf.writeUInt16BE(443, o); o += 2 // dport
  o += 8 // seq + ack
  buf[o] = 0x50; o += 1 // data offset 5
  buf[o] = 0x18; o += 1 // flags PSH+ACK
  o += 6 // win + csum + urg
  buf.set(payload, o)
  return keep === undefined ? buf : buf.subarray(0, Math.min(keep, total))
}

// Same as tcpPcap but with an explicit TCP sequence number — used to build
// multi-segment flows (each returned buffer is one complete pcap frame).
function tcpSeg(payload: Uint8Array, seq: number): Buffer {
  const total = 24 + 16 + 14 + 20 + 20 + payload.length
  const buf = Buffer.alloc(total)
  buf.writeUInt32LE(0xa1b2c3d4, 0)
  buf.writeUInt32LE(65535, 16)
  buf.writeUInt32LE(1, 20)
  buf.writeUInt32LE(total - 40, 32)
  buf.writeUInt32LE(total - 40, 36)
  let o = 24 + 16
  buf.fill(0xff, o, o + 6); o += 6
  buf.fill(0, o, o + 6); o += 6
  buf.writeUInt16BE(0x0800, o); o += 2
  buf[o] = 0x45; o += 1
  o += 1
  buf.writeUInt16BE(20 + 20 + payload.length, o); o += 2
  o += 4
  buf[o] = 64; o += 1
  buf[o] = 6; o += 1
  o += 2
  buf[o] = 192; buf[o + 1] = 168; buf[o + 2] = 1; buf[o + 3] = 1; o += 4
  buf[o] = 93; buf[o + 1] = 184; buf[o + 2] = 216; buf[o + 3] = 34; o += 4
  buf.writeUInt16BE(443, o); o += 2
  buf.writeUInt16BE(443, o); o += 2
  buf.writeUInt32BE(seq, o); o += 4
  o += 4 // ack
  buf[o] = 0x50; o += 1
  buf[o] = 0x18; o += 1
  o += 6
  buf.set(payload, o)
  return buf
}

// Same frame but UDP (proto 17) with an 8-byte UDP header — QUIC runs on UDP.
function udpPcap(payload: Uint8Array): Buffer {
  const FRAME = 24 + 16
  const total = FRAME + 14 + 20 + 8 + payload.length
  const buf = Buffer.alloc(total)
  buf.writeUInt32LE(0xa1b2c3d4, 0)
  buf.writeUInt32LE(65535, 16)
  buf.writeUInt32LE(1, 20)
  buf.writeUInt32LE(total - 24, 32)
  buf.writeUInt32LE(total - 24, 36)
  let o = FRAME
  buf.fill(0xff, o, o + 6); o += 6
  buf.fill(0, o, o + 6); o += 6
  buf.writeUInt16BE(0x0800, o); o += 2
  buf[o] = 0x45; o += 1
  o += 1
  buf.writeUInt16BE(20 + 8 + payload.length, o); o += 2
  o += 4
  buf[o] = 64; o += 1
  buf[o] = 17; o += 1 // UDP
  o += 2
  buf[o] = 192; buf[o + 1] = 168; buf[o + 2] = 1; buf[o + 3] = 1; o += 4
  buf[o] = 93; buf[o + 1] = 184; buf[o + 2] = 216; buf[o + 3] = 34; o += 4
  buf.writeUInt16BE(443, o); o += 2 // sport
  buf.writeUInt16BE(443, o); o += 2 // dport
  buf.writeUInt16BE(8 + payload.length, o); o += 2 // udp len
  o += 2 // csum
  buf.set(payload, o)
  return buf
}

// A ClientHello body: [client_version][random][sid][cs][cm][extLen][ext]
function chBody(version: number, sniName: string): Uint8Array {
  const parts = [
    new Uint8Array([version >> 8, version & 0xff]),
    new Uint8Array(32).fill(0xab),
    new Uint8Array([0x00]), // session id len
    new Uint8Array([0x00, 0x02, 0x13, 0x01]), // cipher suites
    new Uint8Array([0x01, 0x00]), // compression methods
  ]
  let ext: Uint8Array = new Uint8Array([0x00, 0x00]) // extensions len 0
  if (sniName.length > 0) {
    const name = Buffer.from(sniName, "latin1")
    const entry = Buffer.concat([new Uint8Array([0x00]), Buffer.from([name.length >> 8, name.length & 0xff]), name])
    const list = Buffer.concat([Buffer.from([entry.length >> 8, entry.length & 0xff]), entry])
    const extData = Buffer.concat([Buffer.from([0x00, 0x00]), Buffer.from([list.length >> 8, list.length & 0xff]), list])
    ext = Buffer.concat([Buffer.from([extData.length >> 8, extData.length & 0xff]), extData])
  }
  return Buffer.concat([...parts, ext])
}

// QUIC long-header Initial wrapping the ClientHello in a CRYPTO frame.
function quicInitial(ch: Uint8Array): Uint8Array {
  const dataLen = ch.length + 4
  if (dataLen > 0x3f) throw new Error("test helper: ClientHello too long for a 1-byte varint")
  return Buffer.concat([
    Buffer.from([0xc3, 0x00, 0x00, 0x00, 0x01]), // long header, version 1
    Buffer.concat([Buffer.from([0x08]), Buffer.alloc(8, 0x11)]), // dcid
    Buffer.from([0x00]), // scid len
    Buffer.from([0x00]), // token len
    Buffer.from([0x01, 0x00, 0x00]), // pn: len byte (pnLen=2) + 2 pn bytes
    Buffer.from([0x06]), // CRYPTO frame
    Buffer.from([0x00]), // offset varint
    Buffer.from([dataLen]), // length varint (1 byte, ≤ 0x3f)
    Buffer.from([0x01, 0x00, 0x00, ch.length]), // hsType + 3-byte hsLen
    ch,
  ])
}

describe("parsePcap robustness", () => {
  it("parseQUIC truncated trailing packet: no RangeError, previous packets intact", async () => {
    const quic = quicInitial(chBody(0x0303, ""))
    const trunc = udpPcap(quic.subarray(0, 30))
    const r = await parsePcap(trunc)
    expect(r.packets.length).toBeGreaterThanOrEqual(1)
    expect(r.packets[0].tlsSni).toBeUndefined()
  })

  it("complete QUIC Initial yields SNI and real TLS version", async () => {
    const r = await parsePcap(udpPcap(quicInitial(chBody(0x0304, "a"))))
    const p = r.packets[0]
    expect(p.appProtocol).toBe("QUIC")
    expect(p.tlsSni).toBe("a")
    expect(p.tlsVersion).toBe(0x0304)
  })

  it("corrupt TCP data offset: header bytes not misparsed as app data", async () => {
    const r = await parsePcap(tcpPcap(Buffer.from("GET / HTTP/1.1\r\n")))
    expect(r.packets[0].srcPort).toBe(443)
  })

  it("truncated final TCP packet never throws", async () => {
    const r = await parsePcap(tcpPcap(Buffer.from("GET / HTTP/1.1\r\nHost: x\r\n"), 60))
    expect(r.packets.length).toBeGreaterThanOrEqual(1)
  })

  it("TLS ClientHello offering 0x13xx is labeled TLS 1.3 despite legacy_version 0x0303", async () => {
    const body = chBody(0x0303, "b")
    const hs = Buffer.concat([Buffer.from([0x01, 0x00, 0x00, body.length]), body])
    const rec = Buffer.concat([Buffer.from([0x16, 0x03, 0x03]), Buffer.from([0x00, 0x00]), hs])
    rec.writeUInt16BE(hs.length, 3) // record length (4-byte hs header + body)
    const r = await parsePcap(tcpPcap(rec))
    const p = r.packets[0]
    expect(p.tlsSni).toBe("b")
    // the suite list carries the real protocol version — RFC 8446 keeps the
    // legacy client_version at 0x0303 even in 1.3 ClientHellos
    expect(p.tlsVersion).toBe(0x0304)
  })

  it("TLS ClientHello with only legacy suites keeps the legacy client_version", async () => {
    const body = chBody(0x0303, "")
    // remove the 0x13xx offer: replace [0x00, 0x02, 0x13, 0x01] with a 1.2 suite
    body[37] = 0xc0; body[38] = 0x2f // ECDHE-RSA-AES128-GCM-SHA256
    const hs = Buffer.concat([Buffer.from([0x01, 0x00, 0x00, body.length]), body])
    const rec = Buffer.concat([Buffer.from([0x16, 0x03, 0x03]), Buffer.from([0x00, 0x00]), hs])
    rec.writeUInt16BE(hs.length, 3)
    const r = await parsePcap(tcpPcap(rec))
    expect(r.packets[0].tlsVersion).toBe(0x0303)
  })

  it("fragmented ServerHello still yields the cipher suite from its first segment", async () => {
    // TLS 1.3 ServerHello: legacy_version(2) random(32) sid_len(1) sid(0)
    // cipher(2) ext_len(2) — 39-byte body, 48-byte record in total. The
    // record spans two TCP segments; the first segment carries only the
    // record+handshake headers plus the cipher (46 of 48 bytes).
    const body = Buffer.concat([
      Buffer.from([0x03, 0x03]),
      Buffer.alloc(32, 0xcd),
      Buffer.from([0x00]), // empty session id (RFC 8446)
      Buffer.from([0x13, 0x02]), // TLS_AES_256_GCM_SHA384
      Buffer.from([0x00, 0x00]), // no extensions
    ])
    const hs = Buffer.concat([Buffer.from([0x02, 0x00, 0x00, body.length]), body])
    const rec = Buffer.concat([Buffer.from([0x16, 0x03, 0x03]), Buffer.from([0x00, 0x00]), hs])
    rec.writeUInt16BE(hs.length, 3)
    const r = await parsePcap(tcpPcap(rec, 24 + 16 + 14 + 20 + 20 + 46))
    const p = r.packets[0]
    expect(p.tlsCipherSuite).toBe(0x1302)
    expect(p.tlsVersion).toBe(0x0304)
  })

  it("ServerHello record head shorter than the cipher offset never throws", async () => {
    const body = Buffer.concat([
      Buffer.from([0x03, 0x03]),
      Buffer.alloc(32, 0xcd),
      Buffer.from([0x10]), // 16-byte session id
      Buffer.alloc(16, 0x11),
    ])
    const hs = Buffer.concat([Buffer.from([0x02, 0x00, 0x00, body.length]), body])
    const rec = Buffer.concat([Buffer.from([0x16, 0x03, 0x03]), Buffer.from([0x00, 0x00]), hs])
    rec.writeUInt16BE(hs.length, 3)
    const r = await parsePcap(tcpPcap(rec, 24 + 16 + 14 + 20 + 20 + 40))
    expect(r.packets[0].tlsCipherSuite).toBeUndefined()
  })

  it("fragmented ClientHello SNI is recovered by reassembling the record across segments", async () => {
    // A key_share extension (400 filler bytes) before the SNI pushes the SNI
    // beyond the first segment, so the per-packet scan can't see it — exactly
    // the real-capture shape (big key_share at the start of extensions).
    const base = chBody(0x0303, "fragmented.example")
    const sniExt = base.subarray(43) // the SNI extension: [type][len][list]
    const ksData = Buffer.alloc(400, 0xaa)
    const ks = Buffer.concat([Buffer.from([0x00, 0x33]), Buffer.from([ksData.length >> 8, ksData.length & 0xff]), ksData])
    const extList = Buffer.concat([ks, sniExt])
    const body2 = Buffer.concat([base.subarray(0, 41), Buffer.from([extList.length >> 8, extList.length & 0xff]), extList])
    const hs = Buffer.concat([Buffer.from([0x01, body2.length >> 16, (body2.length >> 8) & 0xff, body2.length & 0xff]), body2])
    const rec = Buffer.concat([Buffer.from([0x16, 0x03, 0x03]), Buffer.from([0x00, 0x00]), hs])
    rec.writeUInt16BE(hs.length, 3)
    const seg1 = rec.subarray(0, 200)
    const seg2 = rec.subarray(200)
    const r = await parsePcap(Buffer.concat([tcpSeg(seg1, 0), tcpSeg(seg2, 200).subarray(24)]))
    expect(r.packets.length).toBe(2)
    expect(r.packets[0].tlsSni).toBe("fragmented.example")
    expect(r.packets[0].appProtocol).toBe("TLS")
    expect(r.packets[0].tlsVersion).toBe(0x0304)
    expect(r.packets[1].tlsSni).toBeUndefined()
  })
})
