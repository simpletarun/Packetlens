import { describe, it, expect } from "vitest"
import { NextRequest } from "next/server"
import { sameOrigin } from "@/lib/request-guard"
import { sanitizeFilename } from "@/app/api/v1/upload/route"

function req(origin: string | null, host = "localhost:3456"): NextRequest {
  const headers = new Headers({ host })
  if (origin !== null) headers.set("origin", origin)
  return new NextRequest("http://localhost:3456/api/v1/upload", { method: "POST", headers })
}

describe("sameOrigin (CSRF guard)", () => {
  it("allows same-origin browser requests", () => {
    expect(sameOrigin(req("http://localhost:3456"))).toBe(true)
  })

  it("rejects cross-origin requests", () => {
    expect(sameOrigin(req("https://evil.example"))).toBe(false)
  })

  it("rejects origin matching host of a different port", () => {
    expect(sameOrigin(req("http://localhost:9999"))).toBe(false)
  })

  it("allows non-browser clients without an Origin header", () => {
    expect(sameOrigin(req(null))).toBe(true)
  })

  it("rejects malformed Origin values", () => {
    expect(sameOrigin(req("not a url"))).toBe(false)
  })
})

describe("sanitizeFilename", () => {
  it("strips path separators and traversal attempts", () => {
    expect(sanitizeFilename("../../etc/passwd.pcap")).toBe(".._.._etc_passwd.pcap")
    expect(sanitizeFilename("a\\b\\c.pcapng")).toBe("a_b_c.pcapng")
  })

  it("keeps safe characters", () => {
    expect(sanitizeFilename("my-capture_1.2.pcap")).toBe("my-capture_1.2.pcap")
  })

  it("caps length at 255", () => {
    expect(sanitizeFilename("a".repeat(300) + ".pcap").length).toBe(255)
  })
})
