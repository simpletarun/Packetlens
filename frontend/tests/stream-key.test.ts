import { describe, it, expect } from "vitest"
import { streamConversationKey } from "@/lib/utils"

describe("streamConversationKey", () => {
  it("keeps each port glued to its IP (regression: Array.sort() on the mixed-type tuple reordered ports away from their IPs lexically and the Stream tab matched nothing)", () => {
    const p = { srcIp: "1.1.1.1", srcPort: 443, dstIp: "2.2.2.2", dstPort: 80 }
    expect(streamConversationKey(p)).toBe("1.1.1.1:443|2.2.2.2:80")
  })

  it("is stable across the reverse direction of the same conversation", () => {
    const a = { srcIp: "10.0.0.5", srcPort: 50000, dstIp: "8.8.8.8", dstPort: 53 }
    const b = { srcIp: "8.8.8.8", srcPort: 53, dstIp: "10.0.0.5", dstPort: 50000 }
    expect(streamConversationKey(a)).toBe(streamConversationKey(b))
  })

  it("tolerates missing fields (gateway rows)", () => {
    expect(streamConversationKey({ srcIp: "10.0.0.5", dstIp: "8.8.8.8" })).toBe("10.0.0.5:|8.8.8.8:")
  })
})
