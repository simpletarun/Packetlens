import { describe, it, expect, afterEach, vi } from "vitest"
import { resolveGeoBatch, resolveHomeLocation, setOnlineGeoAllowed } from "@/lib/geo"
import { lookupOfflineGeo } from "@/lib/mmdb"

afterEach(() => {
  setOnlineGeoAllowed(false)
  vi.unstubAllGlobals()
})

describe("geo resolution layers", () => {
  it("never calls ipwho.is when the online fallback is disabled (NFR-3)", async () => {
    setOnlineGeoAllowed(false)
    const calls: string[] = []
    vi.stubGlobal("fetch", vi.fn(async (url: unknown) => {
      calls.push(String(url))
      if (String(url).includes("/api/v1/geo/db")) return new Response(null, { status: 404 })
      throw new Error("third-party network access must not happen")
    }))
    const map = await resolveGeoBatch(["45.33.32.156"])
    expect(map.get("45.33.32.156")?.country).toBe("Unknown")
    expect(calls.some((u) => u.includes("ipwho.is"))).toBe(false)
    // the offline DB probe is local and still happens
    expect(calls.some((u) => u.includes("geo/db"))).toBe(true)
  })

  it("resolves private IPs to Local Network without any network calls", async () => {
    const calls: string[] = []
    vi.stubGlobal("fetch", vi.fn(async (url: unknown) => { calls.push(String(url)); throw new Error("no network") }))
    const map = await resolveGeoBatch(["192.168.1.10", "10.0.0.5"])
    expect(map.get("192.168.1.10")?.country).toBe("Local Network")
    expect(map.get("192.168.1.10")?.isPrivate).toBe(true)
    expect(calls).toHaveLength(0)
  })

  it("resolves known static IPs without any network calls", async () => {
    const calls: string[] = []
    vi.stubGlobal("fetch", vi.fn(async (url: unknown) => { calls.push(String(url)); throw new Error("no network") }))
    const map = await resolveGeoBatch(["8.8.8.8"])
    expect(map.get("8.8.8.8")?.country).toBe("United States")
    expect(calls).toHaveLength(0)
  })

  it("does not fabricate a city/ASN for example.com or documentation TEST-NET ranges", async () => {
    const calls: string[] = []
    vi.stubGlobal("fetch", vi.fn(async (url: unknown) => { calls.push(String(url)); throw new Error("no network") }))
    const map = await resolveGeoBatch(["93.184.216.34", "203.0.113.5", "198.51.100.2"])
    // example.com's 93.184.216.34 is EdgeCast US, never Google LLC London.
    expect(map.get("93.184.216.34")?.org).not.toBe("Google LLC")
    expect(map.get("93.184.216.34")?.country).toBe("United States")
    // Documentation ranges (RFC 5737) must NOT resolve to a real New York.
    expect(map.get("203.0.113.5")?.country).not.toBe("United States")
    expect(map.get("198.51.100.2")?.country).not.toBe("United States")
    // The offline MMDB probe is local; no ipwho.is third-party lookup happens.
    expect(calls.some((u) => u.includes("ipwho.is"))).toBe(false)
  })

  it("skips the undecodable placeholder in batches (it is never a peer)", async () => {
    const map = await resolveGeoBatch(["\u2014", "8.8.8.8"])
    expect(map.has("\u2014")).toBe(false)
    expect(map.get("8.8.8.8")?.country).toBe("United States")
  })

  it("home location requires the online fallback", async () => {
    setOnlineGeoAllowed(false)
    expect(await resolveHomeLocation()).toBeNull()
  })

  it("degrades gracefully when the offline database is absent or corrupt", async () => {
    // corrupt: server returns 200 with garbage (empty) buffer — Reader throws
    // on open and the loader must swallow it rather than reject.
    vi.stubGlobal("fetch", vi.fn(async () => new Response(new ArrayBuffer(0), { status: 200 })))
    setOnlineGeoAllowed(false)
    expect(await lookupOfflineGeo("45.33.32.156")).toBeNull()
  })
})