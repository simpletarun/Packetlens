import { describe, it, expect } from "vitest"
import { sanitizeDisplayPrefs, zoomStepFactor } from "@/components/analysis/investigation-graph"

const defaults = sanitizeDisplayPrefs(null)

describe("graph display prefs sanitizing", () => {
  it("clamps out-of-range persisted values to the slider limits", () => {
    const p = sanitizeDisplayPrefs({ zoomSpeed: 0.15, nodeSize: 500, edgeOpacity: -3 })
    expect(p.zoomSpeed).toBe(1)
    expect(p.nodeSize).toBe(80)
    expect(p.edgeOpacity).toBe(10)
  })

  it("fills missing keys with defaults", () => {
    const p = sanitizeDisplayPrefs({ zoomSpeed: 2 })
    expect(p.labelSize).toBe(defaults.labelSize)
    expect(p.labelMode).toBe(defaults.labelMode)
    expect(p.graphSpacing).toBe(defaults.graphSpacing)
  })

  it("keeps valid values unchanged", () => {
    const p = sanitizeDisplayPrefs({ zoomSpeed: 2.4, nodeOpacity: 60, graphSpacing: 1.2 })
    expect(p.zoomSpeed).toBe(2.4)
    expect(p.nodeOpacity).toBe(60)
    expect(p.graphSpacing).toBe(1.2)
  })

  it("rejects NaN", () => {
    const p = sanitizeDisplayPrefs({ zoomSpeed: Number.NaN })
    expect(p.zoomSpeed).toBe(defaults.zoomSpeed)
  })

  it("rejects garbage non-numeric prefs — a bad labelMode must not silently hide every label", () => {
    const p = sanitizeDisplayPrefs({ labelMode: "banana" as never, edgeStyle: "warp" as never, bgPreset: "neon" as never })
    expect(p.labelMode).toBe(defaults.labelMode)
    expect(p.edgeStyle).toBe(defaults.edgeStyle)
    expect(p.bgPreset).toBe(defaults.bgPreset)
  })

  it("rejects non-boolean persisted booleans (string 'false' is truthy — animations would stay on)", () => {
    const p = sanitizeDisplayPrefs({ animateLayout: "false" as never, showMinimap: 0 as never })
    expect(p.animateLayout).toBe(defaults.animateLayout)
    expect(p.showMinimap).toBe(defaults.showMinimap)
  })

  it("keeps valid non-numeric values unchanged", () => {
    const p = sanitizeDisplayPrefs({ labelMode: "hover", edgeStyle: "taxi", animateLayout: false })
    expect(p.labelMode).toBe("hover")
    expect(p.edgeStyle).toBe("taxi")
    expect(p.animateLayout).toBe(false)
  })
})

describe("zoom button step factor", () => {
  it("is never <= 1 even at the slider minimum (old bug: speed=1 made zoom a no-op)", () => {
    expect(zoomStepFactor(1)).toBeGreaterThan(1)
    expect(zoomStepFactor(3)).toBeGreaterThan(zoomStepFactor(1))
  })

  it("clamps out-of-range speed input", () => {
    expect(zoomStepFactor(0)).toBe(zoomStepFactor(1))
    expect(zoomStepFactor(99)).toBe(zoomStepFactor(3))
  })
})
