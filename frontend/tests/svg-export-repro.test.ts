import { describe, it, expect, beforeAll } from "vitest"
import cytoscape from "cytoscape"
import svgPlugin from "cytoscape-svg"

// Reproduction: the SVG export console error "Attempted to apply path command
// to node 'text'" comes from cytoscape-svg's canvas2svg replay when a
// fill/stroke lands while the context's current element is a <text> node.
// This test recreates the InvestigationGraph's exact stylesheet + node types
// and exports SVG, counting console errors.

cytoscape.use(svgPlugin)

const BASE_COLORS: Record<string, string> = {
  pcap: "#6366f1", ip: "#3b82f6", asn: "#8b5cf6", country: "#22c55e",
  protocol: "#eab308", dns: "#8b5cf6", http: "#06b6d4", tls: "#a855f7",
  file: "#10b981", credential: "#ec4899", certificate: "#f97316",
  device: "#14b8a6", alert: "#ef4444",
}

const NODE_SHAPES: Record<string, { shape: string; size: [number, number] }> = {
  pcap: { shape: "ellipse", size: [1.7, 1.7] },
  ip: { shape: "ellipse", size: [1, 1] },
  asn: { shape: "rectangle", size: [0.9, 0.9] },
  country: { shape: "round-diamond", size: [1, 1] },
  protocol: { shape: "round-rectangle", size: [1.15, 0.85] },
  dns: { shape: "diamond", size: [0.9, 0.9] },
  http: { shape: "tag", size: [1.15, 0.85] },
  tls: { shape: "triangle", size: [1, 1] },
  file: { shape: "bottom-round-rectangle", size: [1.15, 0.85] },
  credential: { shape: "round-pentagon", size: [1.05, 1.05] },
  certificate: { shape: "hexagon", size: [1.1, 1.1] },
  device: { shape: "rectangle", size: [1.05, 1.05] },
  alert: { shape: "octagon", size: [1.8, 1.8] },
}

function shade(hex: string, factor: number): string {
  const n = parseInt(hex.slice(1), 16)
  const r = Math.min(255, Math.round(((n >> 16) & 0xff) * factor))
  const g = Math.min(255, Math.round(((n >> 8) & 0xff) * factor))
  const b = Math.min(255, Math.round((n & 0xff) * factor))
  return `#${((1 << 24) | (r << 16) | (g << 8) | b).toString(16).slice(1)}`
}

describe("SVG export (cytoscape-svg) on the InvestigationGraph stylesheet", () => {
  const errors: string[] = []
  const pushError = (...a: unknown[]) => { errors.push(a.map(String).join(" ")) }

  beforeAll(() => {
    const orig = console.error
    console.error = pushError
    const cy = cytoscape({
      headless: false,
      elements: [
        ...Object.keys(NODE_SHAPES).map((type, i) => ({
          data: { id: `${type}-n`, type, label: `${type} node` },
          position: { x: i * 120, y: 0 },
        })),
        ...Object.keys(NODE_SHAPES).slice(1).map((type) => ({
          data: { id: `${type}-e`, source: "pcap-n", target: `${type}-n`, label: "flow" },
        })),
      ],
      style: [
        { selector: "node", style: { "background-color": "#6b7280", label: "data(label)", "font-size": 12, "text-valign": "bottom", "text-margin-y": 2, "text-wrap": "ellipsis", "text-max-width": "120px", "min-zoomed-font-size": 5, width: 28, height: 28 } },
        ...Object.entries(NODE_SHAPES).map(([type, s]) => ({
          selector: `node[type='${type}']`,
          style: {
            "background-color": BASE_COLORS[type] || "#6b7280",
            shape: s.shape,
            width: 28 * s.size[0],
            height: 28 * s.size[1],
            "background-gradient-direction": "to-bottom-right",
            "background-gradient-stop-colors": [shade(BASE_COLORS[type], 1.45), BASE_COLORS[type]],
            "background-gradient-stop-positions": [0, 1],
            "border-width": 1.5,
            "border-color": shade(BASE_COLORS[type], 0.55),
            "shadow-blur": 7,
            "shadow-color": BASE_COLORS[type],
            "shadow-opacity": 0.28,
          },
        })),
        { selector: "edge", style: { width: 2, "line-color": "#4b5563", label: "data(label)", "font-size": 9, "text-background-color": "#1f2937", "text-background-opacity": 0.8, "text-background-padding": "2px" } },
      ],
    })
    cy.layout({ name: "preset", positions: undefined, fit: true } as cytoscape.LayoutOptions).run()
    cy.zoom(0.8)
    try {
      const svg = (cy as unknown as { svg(o: { full: boolean; scale: number; bg: string }): string }).svg({ full: true, scale: 4, bg: "#1f2937" })
      expect(typeof svg).toBe("string")
    } catch (e) { errors.push("THREW: " + String(e)) }
    cy.destroy()
    console.error = orig
  })

  it("does not produce the 'path command to node text' error", () => {
    const pathErrors = errors.filter(e => e.includes("Attempted to apply path command"))
    expect(pathErrors).toEqual([])
  })
})
