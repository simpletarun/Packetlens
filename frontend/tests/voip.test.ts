import { describe, it, expect } from "vitest"
import { analyzePcap } from "@/lib/analysis"
import { buildPCAP, makePacket } from "./fixtures/builder"

describe("VoIP calls (F-02)", () => {
  it("builds a call from an INVITE dialog + RTP media", () => {
    const parsed = buildPCAP([
      makePacket({
        num: 1, timestamp: 1_000_000, protocol: "UDP", srcIp: "203.0.113.9", dstIp: "192.0.2.20",
        srcPort: 5060, dstPort: 5060, payload: "00",
        sip: { method: "INVITE", statusCode: 0, callId: "2xTb9vxSit55XU7p8@203.0.113.9", fromUser: "alice", toUser: "bob", viaIp: "203.0.113.9", userAgent: "Yealink-T19P", rtpPort: 7078 },
      }),
      makePacket({
        num: 2, timestamp: 1_000_004, protocol: "UDP", srcIp: "192.0.2.20", dstIp: "203.0.113.9",
        srcPort: 5060, dstPort: 5060, payload: "00",
        sip: { method: "SIP/2.0", statusCode: 200, callId: "2xTb9vxSit55XU7p8@203.0.113.9", fromUser: "", toUser: "", viaIp: "", userAgent: "", rtpPort: 0 },
      }),
      makePacket({
        num: 3, timestamp: 1_000_001, protocol: "UDP", srcIp: "203.0.113.9", dstIp: "192.0.2.20",
        srcPort: 7078, dstPort: 40000, payload: "00", rtp: { payloadType: 120, ssrc: 0xdeadbeef, sequence: 1 },
      }),
    ])
    const a = analyzePcap(parsed)
    expect(a.calls.length).toBe(1)
    const call = a.calls[0]
    expect(call.from).toBe("alice")
    expect(call.to).toBe("bob")
    expect(call.status).toBe("SIP 200")
    expect(call.rtpPackets).toBe(1)
    expect(call.rtpPayloadType).toBe(120)
    expect(call.durationSec).not.toBeNull()
  })

  it("ends a call on BYE and reports the duration", () => {
    const parsed = buildPCAP([
      makePacket({ num: 1, timestamp: 100, protocol: "UDP", srcIp: "203.0.113.9", dstIp: "192.0.2.20", srcPort: 5060, dstPort: 5060, payload: "00", sip: { method: "INVITE", statusCode: 0, callId: "id1", fromUser: "alice", toUser: "bob", viaIp: "", userAgent: "", rtpPort: 0 } }),
      makePacket({ num: 2, timestamp: 130, protocol: "UDP", srcIp: "203.0.113.9", dstIp: "192.0.2.20", srcPort: 5060, dstPort: 5060, payload: "00", sip: { method: "BYE", statusCode: 0, callId: "id1", fromUser: "", toUser: "", viaIp: "", userAgent: "", rtpPort: 0 } }),
    ])
    const call = analyzePcap(parsed).calls[0]
    expect(call.durationSec).toBe(30)
  })

  it("makes no calls without SIP signalling", () => {
    const parsed = buildPCAP([
      makePacket({ num: 1, timestamp: 1, protocol: "UDP", srcIp: "10.0.0.1", dstIp: "8.8.8.8", dstPort: 53, payload: "00" }),
    ])
    expect(analyzePcap(parsed).calls.length).toBe(0)
  })

  it("aggregates BOTH RTP directions into the call (streams are per-ssrc)", () => {
    const parsed = buildPCAP([
      makePacket({
        num: 1, timestamp: 1_000_000, protocol: "UDP", srcIp: "203.0.113.9", dstIp: "192.0.2.20",
        srcPort: 5060, dstPort: 5060, payload: "00",
        sip: { method: "INVITE", statusCode: 0, callId: "2xTb9vxSit55XU7p8@203.0.113.9", fromUser: "alice", toUser: "bob", viaIp: "203.0.113.9", userAgent: "Yealink-T19P", rtpPort: 7078 },
      }),
      makePacket({
        num: 2, timestamp: 1_000_001, protocol: "UDP", srcIp: "203.0.113.9", dstIp: "192.0.2.20",
        srcPort: 7078, dstPort: 40000, payload: "00", rtp: { payloadType: 120, ssrc: 0xdeadbeef, sequence: 1 },
      }),
      makePacket({
        num: 3, timestamp: 1_000_002, protocol: "UDP", srcIp: "192.0.2.20", dstIp: "203.0.113.9",
        srcPort: 40000, dstPort: 7078, payload: "00", rtp: { payloadType: 120, ssrc: 0x1234abcd, sequence: 1 },
      }),
    ])
    const call = analyzePcap(parsed).calls[0]
    expect(call.rtpPackets).toBe(2)
  })

  it("does not pair RTP to a call when the SDP port differs", () => {
    const parsed = buildPCAP([
      makePacket({ num: 1, timestamp: 100, protocol: "UDP", srcIp: "203.0.113.9", dstIp: "192.0.2.20", srcPort: 5060, dstPort: 5060, payload: "00", sip: { method: "INVITE", statusCode: 0, callId: "id2", fromUser: "alice", toUser: "bob", viaIp: "", userAgent: "", rtpPort: 7078 } }),
      makePacket({ num: 2, timestamp: 101, protocol: "UDP", srcIp: "203.0.113.9", dstIp: "192.0.2.20", srcPort: 9000, dstPort: 40000, payload: "00", rtp: { payloadType: 120, ssrc: 1, sequence: 1 } }),
    ])
    const call = analyzePcap(parsed).calls[0]
    expect(call.rtpPackets).toBe(0)
  })
})