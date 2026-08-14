import { describe, it, expect } from "vitest"
import { formatBytes } from "@/lib/map-data"

describe("formatBytes — the single byte formatter (1024 tiers, honest IEC labels)", () => {
  it("sub-KB values round, never float-noise", () => {
    expect(formatBytes(0)).toBe("0 B")
    expect(formatBytes(832.2682926829268)).toBe("832 B")
    expect(formatBytes(1023)).toBe("1023 B")
  })

  it("KiB/MiB/GiB/TiB tiers use 1024 divisors with one decimal", () => {
    expect(formatBytes(1024)).toBe("1.0 KiB")
    expect(formatBytes(1536)).toBe("1.5 KiB")
    expect(formatBytes(1048576)).toBe("1.0 MiB")
    expect(formatBytes(1073741824)).toBe("1.0 GiB")
  })

  it("multi-GiB values stay GiB (QA: 3174.4 MB on the file card)", () => {
    expect(formatBytes(3.5 * 1073741824)).toBe("3.5 GiB")
    // One TiB crosses into the TiB tier — a TiB label is honest for it (a
    // "1024.0 GiB" label would break the KiB → MiB → GiB → TiB progression).
    expect(formatBytes(1073741824 * 1024)).toBe("1.0 TiB")
  })

  it("non-finite input renders em-dash, never NaN", () => {
    expect(formatBytes(NaN)).toBe("—")
    expect(formatBytes(Infinity)).toBe("—")
  })

  it("tiers progress B → KiB → MiB → GiB and never regress within a tier", () => {
    // 1023.9 B → 1.0 KiB: the number shrinks but the unit grows — that is the
    // correct display, so compare the TIER, not the raw label.
    const tier = (s: string) => (s.endsWith("KiB") ? 1 : s.endsWith("MiB") ? 2 : s.endsWith("GiB") ? 3 : 0)
    expect(tier(formatBytes(1023))).toBe(0)
    expect(tier(formatBytes(1024))).toBe(1)
    expect(tier(formatBytes(1048575))).toBe(1)
    expect(tier(formatBytes(1048576))).toBe(2)
    expect(tier(formatBytes(1073741823))).toBe(2)
    expect(tier(formatBytes(1073741824))).toBe(3)
    // Within the KiB tier the displayed number must not shrink as bytes grow
    // (one decimal of precision → allow 0.1 rounding slack).
    let prev = 0
    for (let b = 1024; b < 1048576; b += 4096) {
      const v = Number.parseFloat(formatBytes(b))
      expect(v).toBeGreaterThanOrEqual(prev - 0.1)
      prev = v
    }
  })
})