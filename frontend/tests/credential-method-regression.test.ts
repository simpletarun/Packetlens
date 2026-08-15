import { describe, it, expect } from "vitest"
import { readFileSync } from "fs"
import { join } from "path"
import { parsePcap } from "@/lib/pcap"
import { analyzePcap } from "@/lib/analysis"

describe("credential method on REAL captures — frame headers never leak into HTTP parsing (QA: minor.pcapng 'l\"-EL@P')", () => {
  it("login.pcapng: method reads POST, not frame-header ASCII garbage", async () => {
    const parsed = await parsePcap(readFileSync(join(__dirname, "fixtures", "corpus", "login.pcapng")))
    const a = analyzePcap(parsed)
    expect(a.credentials.length).toBeGreaterThan(0)
    for (const c of a.credentials) {
      // Pre-fix: the payload was decoded from byte 0 of the FRAME (Ethernet
      // header included), so method merged header bytes ('EFN@de-)P6;skPuPOST')
      // or read as the destination MAC ('l"-EL@P' on minor.pcapng).
      expect(c.method).toBe("POST")
      expect(c.path).toBe("/login/login_results.asp")
    }
    // The evidence line in the alert must carry the true method.
    for (const t of a.threats) {
      if (t.ruleId === "HTTP-CREDS-001") expect(t.evidence).toContain("method POST")
    }
  })
})