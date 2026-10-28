// Pure view-model for the world map's pan/zoom: zooming must keep the world
// point under the cursor fixed on screen (screenX = wx*k + x), or the map
// drifts away from the interaction point on every wheel tick / button press.

export interface MapView {
  k: number
  x: number
  y: number
}

export const MIN_K = 0.8
export const MAX_K = 8

export function zoomView(v: MapView, factor: number, cx: number, cy: number): MapView {
  const k = Math.min(MAX_K, Math.max(MIN_K, v.k * factor))
  const s = k / v.k
  return { k, x: cx - (cx - v.x) * s, y: cy - (cy - v.y) * s }
}