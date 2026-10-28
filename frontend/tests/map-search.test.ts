import { describe, it, expect } from "vitest"
import { nodeSearchHaystack } from "@/lib/map-data"

describe("nodeSearchHaystack", () => {
  const node = {
    ip: "8.8.8.8", country: "United States", countryCode: "US", city: "Mountain View",
    asn: "AS15169", org: "Google LLC", hostname: "dns.google",
  }

  it("matches by IP, city, ASN, org and hostname", () => {
    const hay = nodeSearchHaystack(node)
    expect(hay.includes("8.8.8.8")).toBe(true)
    expect(hay.includes("mountain view")).toBe(true)
    expect(hay.includes("as15169")).toBe(true)
    expect(hay.includes("google llc")).toBe(true)
    expect(hay.includes("dns.google")).toBe(true)
  })

  it("returns an empty string for unknown nodes", () => {
    expect(nodeSearchHaystack(undefined)).toBe("")
  })
})
