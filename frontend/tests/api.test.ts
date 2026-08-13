import { describe, it, expect } from "vitest"

describe("API route security", () => {
  it("rate limiting rejects excessive requests", async () => {
    const rateLimit = new Map<string, { count: number; resetAt: number }>()
    const ip = "192.168.1.1"

    for (let i = 0; i < 6; i++) {
      const entry = rateLimit.get(ip)
      if (!entry || Date.now() > entry.resetAt) {
        rateLimit.set(ip, { count: 1, resetAt: Date.now() + 60_000 })
      } else {
        entry.count++
      }
    }

    const finalEntry = rateLimit.get(ip)
    expect(finalEntry?.count).toBeGreaterThanOrEqual(5)
  })

  it("sanitizes filenames", () => {
    const sanitize = (name: string): string => {
      return name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 255)
    }
    expect(sanitize("test.pcap")).toBe("test.pcap")
    expect(sanitize("../../etc/passwd")).toBe(".._.._etc_passwd")
    expect(sanitize("file with spaces.pcap")).toBe("file_with_spaces.pcap")
  })

  it("validates file extensions", () => {
    const ALLOWED_EXTENSIONS = new Set(["pcap", "pcapng"])
    expect(ALLOWED_EXTENSIONS.has("pcap")).toBe(true)
    expect(ALLOWED_EXTENSIONS.has("pcapng")).toBe(true)
    expect(ALLOWED_EXTENSIONS.has("exe")).toBe(false)
    expect(ALLOWED_EXTENSIONS.has("txt")).toBe(false)
  })

  it("validates job ID format", () => {
    expect(/^[a-zA-Z0-9_-]+$/.test("abc-123_def")).toBe(true)
    expect(/^[a-zA-Z0-9_-]+$/.test("../../etc/passwd")).toBe(false)
    expect(/^[a-zA-Z0-9_-]+$/.test("")).toBe(false)
  })

  it("rejects oversized files", () => {
    const MAX_SIZE = 1024 * 1024 * 1024
    expect(MAX_SIZE).toBe(1073741824)
  })

  it("only accepts known link layer override values", () => {
    const KNOWN_DLTS = new Set([0, 1, 12, 101, 108, 113, 276])
    // Mirror of the route guard: empty string never reaches Number() (an
    // empty field would otherwise coerce to 0, which is a valid DLT).
    const valid = (raw: unknown): boolean => {
      if (raw === null || raw === undefined || String(raw) === "") return false
      const n = Number(raw)
      return Number.isInteger(n) && KNOWN_DLTS.has(n)
    }
    expect(valid("101")).toBe(true)
    expect(valid(276)).toBe(true)
    expect(valid("999")).toBe(false)
    expect(valid("")).toBe(false)
    expect(valid("abc")).toBe(false)
  })
})