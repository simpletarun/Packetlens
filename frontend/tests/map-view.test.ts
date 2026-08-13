import { describe, it, expect } from "vitest"
import { zoomView, MIN_K, MAX_K, type MapView } from "@/lib/map-view"

// Regression: wheel/button zoom must anchor — a world point keeps its screen
// position (wx*k + x) fixed across zoom steps, or the map drifts out of the box.
// The anchor is passed in screen units (the same space the view's x/y live in).

const ID: MapView = { k: 1, x: 0, y: 0 }
const screenPos = (v: MapView, ax: number, ay: number) => [ax * v.k + v.x, ay * v.k + v.y]

describe("zoomView", () => {
  it("keeps the anchor's screen position fixed from any prior view", () => {
    const v = { k: 2, x: -100, y: -80 }
    const next = zoomView(v, 1.3, 300, 200)
    expect(next.k).toBeCloseTo(2.6)
    const [sx, sy] = screenPos(next, (300 - v.x) / v.k, (200 - v.y) / v.k)
    expect(sx).toBeCloseTo(300)
    expect(sy).toBeCloseTo(200)
  })

  it("keeps the map center fixed when anchored at it (button zoom)", () => {
    const next = zoomView(ID, 1.3, 800, 430)
    expect(next.k).toBeCloseTo(1.3)
    const [sx, sy] = screenPos(next, 800, 430)
    expect(sx).toBeCloseTo(800)
    expect(sy).toBeCloseTo(430)
  })

  it("never drifts across repeated wheel steps at the same cursor", () => {
    let v = ID
    for (let i = 0; i < 5; i++) {
      v = zoomView(v, 1.3, 400, 300)
      const [sx, sy] = screenPos(v, (400 - v.x) / v.k, (300 - v.y) / v.k)
      expect(sx).toBeCloseTo(400)
      expect(sy).toBeCloseTo(300)
    }
  })

  it("round-trips back out to the original view (same anchor)", () => {
    const zin = zoomView(ID, 1.3, 800, 430)
    const zout = zoomView(zin, 1 / 1.3, 800, 430)
    expect(zout.k).toBeCloseTo(1)
    expect(zout.x).toBeCloseTo(0)
    expect(zout.y).toBeCloseTo(0)
  })

  it("clamps the scale to [0.8, 8] — zoom-out works below 1×", () => {
    expect(zoomView(ID, 0.001, 800, 430).k).toBe(MIN_K)
    expect(zoomView(ID, 1000, 800, 430).k).toBe(MAX_K)
    const zout = zoomView(ID, 1 / 1.3, 800, 430)
    // 1/1.3 = 0.769 falls under the floor — the clamp must hold the anchor too.
    expect(zout.k).toBeCloseTo(MIN_K)
    const [sx, sy] = screenPos(zout, 800, 430)
    expect(sx).toBeCloseTo(800)
    expect(sy).toBeCloseTo(430)
  })
})