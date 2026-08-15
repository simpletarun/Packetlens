import { describe, it, expect } from "vitest"
import { lookupVendor, vendorLabel, isUnicastMac, displayMac } from "@/lib/oui"
import { formatEndpoint } from "@/lib/map-data"

describe("lookupVendor / vendorLabel — resolved names vs display placeholders", () => {
  const table = new Map<string, string>([["8C902D", "TP-Link Technologies Co."]])

  it("lookupVendor returns ONLY real vendor names — placeholders never count", () => {
    expect(lookupVendor("8c:90:2d:ca:b4:d5", table)).toBe("TP-Link Technologies Co.")
    expect(lookupVendor("00:1a:2b:3c:4d:5e", table)).toBe("") // unknown, NOT "Unknown vendor"
    expect(lookupVendor("02:00:00:00:00:00", table)).toBe("") // locally administered, NOT a vendor
  })

  it("vendorLabel keeps the informative placeholders for DISPLAY without counting them", () => {
    expect(vendorLabel("TP-Link Technologies Co.", "8c:90:2d:ca:b4:d5")).toBe("TP-Link Technologies Co.")
    expect(vendorLabel("", "00:1a:2b:3c:4d:5e")).toBe("Unknown vendor")
    expect(vendorLabel("", "02:00:00:00:00:00")).toBe("Locally administered")
    expect(vendorLabel("", "—")).toBe("") // no real MAC → no placeholder either
    expect(vendorLabel("", "")).toBe("")
  })
})

describe("formatEndpoint — port 0 is 'no port', never rendered", () => {
  it("renders ip:port only for a real port", () => {
    expect(formatEndpoint("192.168.1.5", 443)).toBe("192.168.1.5:443")
    expect(formatEndpoint("192.168.1.5", 0)).toBe("192.168.1.5") // ICMP/ARP
    expect(formatEndpoint("192.168.1.5", null)).toBe("192.168.1.5")
    expect(formatEndpoint("192.168.1.5", undefined)).toBe("192.168.1.5")
    expect(formatEndpoint("\u2014", 0)).toBe("\u2014")
  })
})

describe("isUnicastMac / displayMac — broadcast and multicast MACs are never device identities", () => {
  it("accepts only unicast, nonzero hardware addresses", () => {
    expect(isUnicastMac("8c:90:2d:ca:b4:d5")).toBe(true)
    expect(isUnicastMac("AA-BB-CC-DD-EE-FF")).toBe(true) // separators normalize
    expect(isUnicastMac("ff:ff:ff:ff:ff:ff")).toBe(false) // broadcast (ARP target)
    expect(isUnicastMac("FF:FF:FF:FF:FF:FF")).toBe(false) // case-insensitive
    expect(isUnicastMac("01:00:5e:00:00:01")).toBe(false) // multicast
    expect(isUnicastMac("33:33:00:00:00:01")).toBe(false) // IPv6 solicited-node
    expect(isUnicastMac("00:00:00:00:00:00")).toBe(false) // zero
    expect(isUnicastMac("")).toBe(false)
    expect(isUnicastMac(undefined)).toBe(false)
    expect(isUnicastMac("garbage")).toBe(false)
  })

  it("displayMac renders the MAC itself or the '—' placeholder, never a broadcast address", () => {
    expect(displayMac("8c:90:2d:ca:b4:d5")).toBe("8c:90:2d:ca:b4:d5")
    expect(displayMac("ff:ff:ff:ff:ff:ff")).toBe("\u2014")
    expect(displayMac("00:00:00:00:00:00")).toBe("\u2014")
    expect(displayMac("01:00:5e:00:00:01")).toBe("\u2014")
    expect(displayMac(undefined)).toBe("\u2014")
  })
})