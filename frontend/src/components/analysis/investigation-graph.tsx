"use client"

import { useEffect, useRef, useState, useMemo, useCallback, type CSSProperties } from "react"
import cytoscape, { Core, ElementDefinition, NodeSingular } from "cytoscape"
import svgPlugin from "cytoscape-svg"
import { FileImage, File as FileSvg, Search, X, ZoomIn, ZoomOut, LayoutGrid, AlertCircle, Settings, Gauge, SlidersHorizontal, Minus, BarChart3 } from "lucide-react"
import { computeVisibleIds } from "@/lib/graph-filter"
import { buildGraphElements } from "@/lib/graph-data"
import { useAnalysisStore } from "@/stores/analysis"
import { useTheme } from "next-themes"

cytoscape.use(svgPlugin)

const TYPE_LABELS = [
  { value: "all", label: "All" },
  { value: "pcap", label: "PCAP" },
  { value: "ip", label: "IPs" },
  { value: "asn", label: "ASNs" },
  { value: "country", label: "Countries" },
  { value: "protocol", label: "Protocols" },
  { value: "dns", label: "DNS" },
  { value: "http", label: "HTTP" },
  { value: "tls", label: "TLS" },
  { value: "file", label: "Files" },
  { value: "credential", label: "Credentials" },
  { value: "certificate", label: "Certificates" },
  { value: "device", label: "Devices" },
  { value: "alert", label: "Alerts" },
]

// Lighten (>1) or darken (<1) a #rrggbb color for gradients/borders.
function shade(hex: string, factor: number): string {
  const n = parseInt(hex.slice(1), 16)
  const r = Math.min(255, Math.round(((n >> 16) & 0xff) * factor))
  const g = Math.min(255, Math.round(((n >> 8) & 0xff) * factor))
  const b = Math.min(255, Math.round((n & 0xff) * factor))
  return `#${((1 << 24) | (r << 16) | (g << 8) | b).toString(16).slice(1)}`
}

const BASE_COLORS: Record<string, string> = {
  pcap: "#6366f1",
  ip: "#3b82f6",
  asn: "#8b5cf6",
  country: "#22c55e",
  protocol: "#eab308",
  dns: "#8b5cf6",
  http: "#06b6d4",
  tls: "#a855f7",
  file: "#10b981",
credential: "#ec4899",
  certificate: "#f97316",
  device: "#84cc16",
  alert: "#ef4444",
}

// One distinct shape per type so the legend and the graph are easy to read:
// pcap/IP/country are roundish, hosts are boxy, findings are angular.
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

// Only cytoscape's built-in layouts are offered — the switch in layoutConfig
// implements exactly these (dagre/elk/cola/force/fr/radial were listed here
// but had no case, so selecting them silently ran breadthfirst instead).
const LAYOUTS = [
  { name: "breadthfirst", label: "Breadthfirst" },
  { name: "cose", label: "COSE" },
  { name: "concentric", label: "Concentric" },
  { name: "circle", label: "Circle" },
  { name: "grid", label: "Grid" },
  { name: "layers", label: "Layered" },
  { name: "random", label: "Random" },
]

const DEFAULT_DISPLAY_PREFS: Required<DisplayPrefs> = {
  nodeSize: 28,
  labelSize: 12,
  edgeThickness: 2,
  graphSpacing: 1.2,
  zoomSpeed: 1.5,
  nodeOpacity: 100,
  edgeOpacity: 100,
// "zoom" keeps NODE labels visible at every zoom level (scaled down to a
  // 5px floor, never hidden — the old binary hide below 1.5× left the graph
  // bare at fit/zoom-out); edge labels still appear above 1.5× so dense
  // graphs don't overprint at a glance (B-51). Users who want every label
  // pinned can switch to "always" in Display.
labelMode: "zoom" as LabelMode,
  animateLayout: true,
  pulseAlerts: true,
  edgeFlow: true,
  showMinimap: true,
  edgeStyle: "bezier",
  bgPreset: "auto",
}

// Slider limits — prefs are user-editable and persisted; a stale/out-of-range
// value (old build, hand-edited localStorage) must never reach the controls
// or the zoom math. Range inputs clamp the THUMB but not the stored value,
// so a zoomSpeed of 0.15 would silently invert the zoom buttons.
const PREF_LIMITS: Record<string, [number, number]> = {
  nodeSize: [10, 80],
  labelSize: [8, 24],
  edgeThickness: [1, 10],
  graphSpacing: [0.5, 3],
  zoomSpeed: [1, 3],
  nodeOpacity: [20, 100],
  edgeOpacity: [10, 100],
}

// Non-numeric prefs need allowlists too: a garbage labelMode would silently
// hide every label (no check matches → "none" behavior) with no recovery
// short of Reset, and a bogus edgeStyle would reach cytoscape's curve-style.
const LABEL_MODES = ["always", "hover", "zoom", "none"]
const EDGE_STYLES = ["bezier", "straight", "taxi", "segments", "haystack"]
const BOOL_KEYS = ["animateLayout", "pulseAlerts", "edgeFlow", "showMinimap"]

export function sanitizeDisplayPrefs(raw: Partial<DisplayPrefs> | null | undefined): DisplayPrefs {
  const out: Record<string, unknown> = { ...DEFAULT_DISPLAY_PREFS, ...(raw ?? {}) }
  for (const [key, [min, max]] of Object.entries(PREF_LIMITS)) {
    const v = out[key]
    out[key] = typeof v === "number" && !Number.isNaN(v) ? Math.min(max, Math.max(min, v)) : DEFAULT_DISPLAY_PREFS[key as keyof DisplayPrefs]
  }
  if (!LABEL_MODES.includes(out.labelMode as string)) out.labelMode = DEFAULT_DISPLAY_PREFS.labelMode
  if (!EDGE_STYLES.includes(out.edgeStyle as string)) out.edgeStyle = DEFAULT_DISPLAY_PREFS.edgeStyle
  if (!(String(out.bgPreset) in BG_PRESETS)) out.bgPreset = DEFAULT_DISPLAY_PREFS.bgPreset
  for (const key of BOOL_KEYS) if (typeof out[key] !== "boolean") out[key] = DEFAULT_DISPLAY_PREFS[key as keyof DisplayPrefs]
  return out as unknown as DisplayPrefs
}

// Zoom buttons step by (1 + 0.3·speed)× per click — monotonic with the Zoom
// Speed setting but NEVER a no-op. The old code zoomed by raw zoomSpeed
// (1.5×), so dragging the slider to its minimum (1) made both buttons do
// nothing at all (zoom ×1), which read as "zoom buttons broken".
export function zoomStepFactor(zoomSpeed: number): number {
  return 1 + 0.3 * Math.min(3, Math.max(1, zoomSpeed))
}

type LabelMode = "always" | "hover" | "zoom" | "none"

// Background presets pair a canvas color with readable label/outline/edge
// colors — a raw color picker would strand light text on a light canvas.
// "auto" follows the app theme (dark/light).
const BG_PRESETS: Record<string, { label: string; canvas: string; text: string; outline: string; edge: string; bubble: string; dots: "light" | "dark" }> = {
  auto: { label: "Theme", canvas: "", text: "", outline: "", edge: "", bubble: "", dots: "light" },
  dark: { label: "Dark", canvas: "#1f2937", text: "#e5e7eb", outline: "#1f2937", edge: "#9ca3af", bubble: "#1f2937", dots: "light" },
  navy: { label: "Navy", canvas: "#0b1424", text: "#dbeafe", outline: "#0b1424", edge: "#93c5fd", bubble: "#12203a", dots: "light" },
  graphite: { label: "Graphite", canvas: "#111318", text: "#e5e7eb", outline: "#111318", edge: "#9ca3af", bubble: "#111318", dots: "light" },
  light: { label: "Light", canvas: "#f8fafc", text: "#111827", outline: "#ffffff", edge: "#64748b", bubble: "#ffffff", dots: "dark" },
}

function isDarkHex(c: string): boolean {
  const n = parseInt(c.slice(1), 16)
  return ((0.299 * ((n >> 16) & 0xff)) + (0.587 * ((n >> 8) & 0xff)) + (0.114 * (n & 0xff))) < 140
}

interface DisplayPrefs {
  nodeSize: number
  labelSize: number
  edgeThickness: number
  graphSpacing: number
  zoomSpeed: number
  nodeOpacity: number
  edgeOpacity: number
  labelMode: LabelMode
  animateLayout: boolean
  pulseAlerts: boolean
  edgeFlow: boolean
  showMinimap: boolean
  edgeStyle: string
  bgPreset: string
}

interface InvGraphProps {
  packets: { srcIp?: string; dstIp?: string; protocol?: string; srcPort?: number; dstPort?: number }[]
  flows: { srcIp: string; dstIp: string; protocol: string; packets: number; bytesTotal: number; duration?: number }[]
  dns: { query: string; srcIp: string; dstIp: string; type: string; responseCode?: string; isResponse?: boolean }[]
  http: { method: string; uri: string; host: string; srcIp: string; dstIp: string }[]
  tls: { sni: string; srcIp: string; dstIp: string; version: string }[]
  files: { filename: string; srcIp: string; dstIp: string; size: number }[]
  credentials: { username: string; protocol: string; srcIp: string; dstIp: string; service?: string }[]
  certificates: { subject: string; issuer: string; san: string[] }[]
  devices: { ip: string; hostname: string; mac: string; vendor: string; os: string }[]
  alerts: { signature: string; srcIp: string; dstIp: string; severity: number }[]
  className?: string
}

const LEGEND_ITEMS = [
  { label: "PCAP", color: BASE_COLORS.pcap, shape: "ellipse" },
  { label: "IP", color: BASE_COLORS.ip, shape: "ellipse" },
  { label: "ASN", color: BASE_COLORS.asn, shape: "rect" },
  { label: "Country", color: BASE_COLORS.country, shape: "round-diamond" },
  { label: "Protocol", color: BASE_COLORS.protocol, shape: "round-rect" },
  { label: "DNS", color: BASE_COLORS.dns, shape: "diamond" },
  { label: "HTTP", color: BASE_COLORS.http, shape: "tag" },
  { label: "TLS", color: BASE_COLORS.tls, shape: "triangle" },
  { label: "File", color: BASE_COLORS.file, shape: "bottom-round-rect" },
  { label: "Credential", color: BASE_COLORS.credential, shape: "pentagon" },
  { label: "Certificate", color: BASE_COLORS.certificate, shape: "hexagon" },
  { label: "Device", color: BASE_COLORS.device, shape: "rect" },
  { label: "Alert", color: BASE_COLORS.alert, shape: "octagon" },
]

// Legend glyph styles — each shape must match the cytoscape node shape.
const LEGEND_STYLES: Record<string, CSSProperties> = {
  ellipse: { borderRadius: "9999px" },
  rect: {},
  "round-diamond": { borderRadius: "3px", transform: "rotate(45deg)" },
  "round-rect": { borderRadius: "3px" },
  diamond: { transform: "rotate(45deg)" },
  tag: { clipPath: "polygon(0% 0%, 100% 0%, 100% 62%, 50% 88%, 0% 62%)" },
  triangle: { clipPath: "polygon(50% 0%, 0% 100%, 100% 100%)" },
  "bottom-round-rect": { borderRadius: "0 0 4px 4px" },
  pentagon: { clipPath: "polygon(50% 0%, 100% 38%, 82% 100%, 18% 100%, 0% 38%)" },
  hexagon: { clipPath: "polygon(25% 0%, 75% 0%, 100% 50%, 75% 100%, 25% 100%, 0% 50%)" },
  octagon: { clipPath: "polygon(30% 0%, 70% 0%, 100% 30%, 100% 70%, 70% 100%, 30% 100%, 0% 70%, 0% 30%)" },
}

export function InvestigationGraph({
  packets, flows, dns, http, tls, files, credentials, certificates, devices, alerts, className,
}: InvGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const rootRef = useRef<HTMLDivElement>(null)
  const miniMapRef = useRef<HTMLCanvasElement>(null)
  const cyRef = useRef<Core | null>(null)
  const layoutRef = useRef<ReturnType<Core["layout"]> | null>(null)
  const pulseIdRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const flowIdRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const flowOffsetRef = useRef(0)
  const infoHideTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
const lastGraphDataRef = useRef<{ data: unknown; all: ElementDefinition[] } | null>(null)
  const lastLayoutRef = useRef<unknown>(null)
  // Tracks whether "zoom" mode currently shows edge labels (above 1.5×), so
  // the zoom handler only touches edges when the threshold is crossed — never
  // per zoom frame.
  const edgeLabelsShownRef = useRef<boolean | null>(null)
  const firstDataRef = useRef(true)
  const prevSearchRef = useRef("")
  const [selectedInfo, setSelectedInfo] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState("")
  const [filterTypes, setFilterTypes] = useState<Set<string>>(new Set(TYPE_LABELS.map(t => t.value)))
  const [visibleCount, setVisibleCount] = useState(0)
  const [layoutName, setLayoutName] = useState<string>(() => {
    try {
      const stored = localStorage.getItem("packetlens-graph-layout")
      return LAYOUTS.some(l => l.name === stored) && stored ? stored : "breadthfirst"
    } catch { return "breadthfirst" }
  })
  const [displayPrefs, setDisplayPrefs] = useState<DisplayPrefs>(() => {
    try {
      const stored = localStorage.getItem("packetlens-graph-display-prefs")
      if (stored) return sanitizeDisplayPrefs(JSON.parse(stored) as Partial<DisplayPrefs>)
    } catch { /* ignore */ }
    return { ...DEFAULT_DISPLAY_PREFS }
  })
  const [displayControlsOpen, setDisplayControlsOpen] = useState(false)
  const [cyReady, setCyReady] = useState(false)
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; nodeId: string; locked: boolean } | null>(null)
  // Beginner mode masks IPs (privacy); Expert mode (default) shows full
  // addresses like every other page, so the topology is unambiguous.
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  // GeoIP rows for every unique IP, resolved once in the job layout. Country
  // and ASN nodes (and their chips) are built from this — a graph that shows
  // "External · BR" labels without Country/ASN nodes reads as geo being ignored.
  const geoMap = useAnalysisStore((s) => s.geoMap)

  // Light/dark palette for canvas, labels, edges and exports. Cytoscape's
  // stylesheet is built at mount, so the active palette is mirrored into a ref
  // for that effect; the re-apply effect below refreshes per-element colors on
  // theme flips (B-53: canvas stayed dark-navy in the light theme).
  const { resolvedTheme } = useTheme()
  const dark = resolvedTheme !== "light"
  const palette = useMemo(
    () => dark
      ? { canvas: "#1f2937", label: "#e5e7eb", outline: "#1f2937", edge: "#9ca3af", bubble: "#1f2937" }
      : { canvas: "#f8fafc", label: "#111827", outline: "#ffffff", edge: "#64748b", bubble: "#ffffff" },
    [dark],
  )
  const paletteRef = useRef(palette)
  // The effective palette: a chosen background preset wins, otherwise the theme.
  const effPalette = useMemo(() => {
    const p = BG_PRESETS[displayPrefs.bgPreset]
    if (!p || p.canvas === "") return palette
    return { canvas: p.canvas, label: p.text, outline: p.outline, edge: p.edge, bubble: p.bubble }
  }, [displayPrefs.bgPreset, palette])
  useEffect(() => { paletteRef.current = effPalette }, [effPalette])

  // Mirror of displayPrefs for the mount-only cytoscape effect: its handlers
  // capture the initial prefs at mount, so later control changes (labelMode,
  // pulseAlerts) would otherwise be stuck reading the stale closure.
  const displayPrefsRef = useRef(displayPrefs)
  useEffect(() => { displayPrefsRef.current = displayPrefs }, [displayPrefs])

  const handleLayoutChange = useCallback((name: string) => {
    setLayoutName(name)
    try { localStorage.setItem("packetlens-graph-layout", name) } catch { /* ignore */ }
  }, [])

  const updateDisplayPrefs = useCallback((updates: Partial<DisplayPrefs>) => {
    setDisplayPrefs(prev => {
      const next = sanitizeDisplayPrefs({ ...prev, ...updates })
      try { localStorage.setItem("packetlens-graph-display-prefs", JSON.stringify(next)) } catch { /* ignore */ }
      return next
    })
  }, [])

  // Info panels opened by right-click actions (Highlight/Focus/Search) are
  // temporary: hide them once the work is done. Node taps cancel the timer so
  // deliberate inspection stays open.
  const scheduleInfoAutoHide = useCallback(() => {
    if (infoHideTimerRef.current) clearTimeout(infoHideTimerRef.current)
    infoHideTimerRef.current = setTimeout(() => setSelectedInfo(null), 1500)
  }, [])

  const graphData = useMemo(() => {
    const { nodes, edges } = buildGraphElements({ packets, flows, dns, http, tls, files, credentials, certificates, devices, alerts, geoMap, beginnerMode })
    return { nodes, edges, all: [...nodes, ...edges] }
  }, [packets, flows, dns, http, tls, files, credentials, certificates, devices, alerts, beginnerMode, geoMap])

  // How many nodes each type has in this capture — used to render only chips
  // whose type actually has nodes (empty types are hidden, not struck out).
  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const n of graphData.nodes) {
      const t = n.data.type as string
      counts[t] = (counts[t] || 0) + 1
    }
    return counts
  }, [graphData])

  const layoutConfig = useMemo(() => {
    const animate = displayPrefs.animateLayout
    const spacingFactor = displayPrefs.graphSpacing
const base = {
      animate,
      animationDuration: animate ? 400 : 0,
      fit: true,
      padding: 40,
    }
    switch (layoutName) {
      case "layers": {
        const layerOrder = ["pcap", "device", "ip", "country", "asn", "protocol", "dns", "http", "tls", "file", "credential", "certificate", "alert"]
        const perLayer = new Map<string, number>()
        for (const el of graphData.nodes) {
          const t = el.data.type as string
          perLayer.set(t, (perLayer.get(t) || 0) + 1)
        }
        const idx = new Map<string, number>()
        const positions: Record<string, { x: number; y: number }> = {}
        for (const el of graphData.nodes) {
          const t = el.data.type as string
          const i = idx.get(t) || 0
          idx.set(t, i + 1)
          const count = perLayer.get(t) || 1
          positions[el.data.id as string] = { x: (i - (count - 1) / 2) * 130 * spacingFactor, y: layerOrder.indexOf(t) * 110 }
        }
        return { ...base, name: "preset", positions: (n: NodeSingular) => positions[n.id()] || { x: 0, y: 0 } }
      }
      case "cose":
        // ponytail: cose's continuous animation loop re-schedules its own rAF
        // even after stop(), so a pending frame can fire on a destroyed core
        // and throw "Cannot read properties of null (reading 'notify')".
        // animate:false runs it synchronously through the destroy-safe path,
        // and every stop()/run() below is additionally wrapped in try/catch
        // so a stale cose frame can never kill the React tree.
        return { ...base, name: "cose", nodeRepulsion: () => 15000 * spacingFactor, idealEdgeLength: () => 150 * spacingFactor, gravity: 0.5, numIter: 1200, coolingFactor: 0.92, animate: false }
      case "breadthfirst":
        return { ...base, name: "breadthfirst", directed: true, spacingFactor: 2.5 * spacingFactor, roots: ["pcap"], animate }
      case "concentric":
        return { ...base, name: "concentric", concentric: (n: NodeSingular) => n.data("degree") || 1, levelWidth: () => 1.5 * spacingFactor, animate }
      case "circle":
        return { ...base, name: "circle", animate }
      case "grid":
        return { ...base, name: "grid", spacingFactor, animate }
      case "random":
        return { ...base, name: "random", animate }
      default:
        return { ...base, name: "breadthfirst", directed: true, spacingFactor: 2.5 * spacingFactor, roots: ["pcap"], animate }
    }
  }, [layoutName, graphData, displayPrefs.animateLayout, displayPrefs.graphSpacing])

  // Mount-only: create the empty core once, attach all interactions, and keep
  // the container sharp when the sidebar/breakpoints resize it.
  useEffect(() => {
    if (!containerRef.current || cyRef.current) return
    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      pixelRatio: Math.min(window.devicePixelRatio || 1, 2),
      minZoom: 0.05,
      maxZoom: 8,
      // NOTE: wheelSensitivity is intentionally NOT set — cytoscape warns on
      // ANY explicit value (even its own default of 1), and omitting it gives
      // exactly the default behavior with zero console noise.
      textureOnViewport: false,
      motionBlur: false,
      style: [
        // Theme-aware palette: labels/outlines/edge text follow the app theme
        // instead of a hardcoded dark-navy (B-53). The palette is read from a
        // ref so the mount-only effect sees the CURRENT theme.
        { selector: "node", style: { "background-color": "#6b7280", label: "data(label)", color: paletteRef.current.label, "font-size": displayPrefs.labelSize, "text-valign": "bottom", "text-margin-y": 2, "text-wrap": "ellipsis", "text-max-width": "120px", "text-outline-width": 2, "text-outline-color": paletteRef.current.outline, // Labels scale with zoom but never shrink below 5px — zooming out (or the
          // initial fit at ~0.4×) keeps every node's metadata readable instead of
          // fading to 1px unreadable dots (the "no metadata when zoomed out" bug:
          // the old zoom-mode hid labels entirely below 1.5×).
          "min-zoomed-font-size": 5, width: displayPrefs.nodeSize, height: displayPrefs.nodeSize, opacity: displayPrefs.nodeOpacity / 100, "transition-property": "background-color, border-color, border-width, line-color, target-arrow-color, shadow-blur, shadow-color", "transition-duration": 250, "transition-timing-function": "ease-out" } },
        ...Object.entries(NODE_SHAPES).map(([type, s]) => {
          const color = BASE_COLORS[type] || "#6b7280"
          return {
            selector: `node[type='${type}']`,
            style: {
              "background-color": color,
              shape: s.shape as cytoscape.Css.Node["shape"],
              width: displayPrefs.nodeSize * s.size[0],
              height: displayPrefs.nodeSize * s.size[1],
              // Depth: diagonal highlight gradient + darker rim + colored glow.
              "background-gradient-direction": "to-bottom-right",
              "background-gradient-stop-colors": [shade(color, 1.45), color],
              "background-gradient-stop-positions": [0, 1],
              "border-width": 1.5,
              "border-color": shade(color, 0.55),
              "shadow-blur": 7,
              "shadow-color": color,
              "shadow-opacity": 0.28,
            },
          }
        }),
        { selector: "node[type='pcap']", style: { "border-width": 2, "border-color": "#a5b4fc" } },
        { selector: "node[type='alert']", style: { "border-width": 3, "border-color": "#ef4444" } },
        { selector: "edge", style: { width: displayPrefs.edgeThickness, "line-color": "#4b5563", "curve-style": displayPrefs.edgeStyle as "bezier" | "straight" | "taxi" | "segments" | "haystack", "target-arrow-shape": "none", "target-arrow-color": "#4b5563", label: displayPrefs.labelMode === "always" ? "data(label)" : "", "font-size": displayPrefs.labelSize - 3, color: paletteRef.current.edge, "text-wrap": "ellipsis", "text-max-width": "140px", "min-zoomed-font-size": 5, "text-background-color": paletteRef.current.bubble, "text-background-opacity": 0.8, "text-background-padding": "2px", opacity: displayPrefs.edgeOpacity / 100, "transition-property": "line-color, target-arrow-color, border-color, border-width, width", "transition-duration": 250, "transition-timing-function": "ease-out" } },
        // Edge hierarchy (kind is set in graph-data): flow edges carry actual
        // traffic and thicken/colorize by weight (mapData scales with the flow
        // volume); struct edges are the quiet pcap-hub spine; relation edges
        // are observed findings — each reads distinctly instead of all-gray
        // uniform lines with arrows on everything.
        { selector: "edge[kind='flow']", style: { width: "mapData(weight, 0, 50, 0.4, 3)", "line-color": "mapData(weight, 0, 50, #94a3b8, #2563eb)", "target-arrow-shape": "triangle", "target-arrow-color": "mapData(weight, 0, 50, #94a3b8, #2563eb)", "arrow-scale": 0.9 } },
        { selector: "edge[kind='relation']", style: { "line-style": "dashed", "target-arrow-shape": "none", "line-color": "#8b5cf6", width: 1.2 } },
        { selector: "edge[kind='struct']", style: { "line-style": "dotted", "target-arrow-shape": "none", "line-color": "#9ca3af", width: 1 } },
        { selector: "edge[kind='identity']", style: { "line-style": "dashed", "target-arrow-shape": "none", "line-color": "#14b8a6" } },
        { selector: "node.highlight", style: { "border-width": 3, "border-color": "#fbbf24" } },
        { selector: "node.hover, edge.hover", style: { "border-width": 3, "border-color": "#fbbf24", "line-color": "#fbbf24", "target-arrow-color": "#fbbf24" } },
        { selector: "node.faded, edge.faded", style: { opacity: 0.15 } },
        { selector: "node.path, edge.path", style: { "background-color": "#fbbf24", "line-color": "#fbbf24", "border-color": "#fbbf24", "target-arrow-color": "#fbbf24", width: displayPrefs.nodeSize + 10, "font-size": displayPrefs.labelSize + 5 } },
        { selector: "edge:selected, node:selected", style: { "line-color": "#fbbf24", "target-arrow-color": "#fbbf24", "border-width": 3, "border-color": "#fbbf24" } },
      ],
    })

    cyRef.current = cy

    cy.on("tap", "node", (evt) => {
      const node = evt.target
      // A deliberate tap cancels any pending auto-hide from a right-click action.
      if (infoHideTimerRef.current) { clearTimeout(infoHideTimerRef.current); infoHideTimerRef.current = null }
      setSelectedInfo(node.data().info || node.data().label || node.data().id)
    })

    cy.on("cxttap", "node", (evt) => {
      setContextMenu({ x: evt.originalEvent.clientX, y: evt.originalEvent.clientY, nodeId: evt.target.id(), locked: evt.target.locked() })
    })

    cy.on("cxttap", (evt) => {
      if (evt.target === cy) setContextMenu(null)
    })

    cy.on("tap", (evt) => {
      if (evt.target === cy) { setSelectedInfo(null); setContextMenu(null) }
    })

    cy.on("mouseover", "node", (evt) => {
      const node = evt.target
      // Batch: the hover label pass touches every connected edge's style, and
      // unbatched style() calls repaint per element → cursor stutter.
      cy.batch(() => {
        if (displayPrefsRef.current.labelMode === "hover") {
          node.style("label", node.data("label") as string)
          node.connectedEdges().forEach((e: cytoscape.EdgeSingular) => e.style("label", e.data("label") as string))
        }
        node.addClass("hover")
        node.connectedEdges().addClass("hover")
        node.connectedEdges().connectedNodes().addClass("hover")
      })
    })

    cy.on("mouseout", "node", (evt) => {
      const node = evt.target
      cy.batch(() => {
        if (displayPrefsRef.current.labelMode === "hover") {
          node.style("label", "")
          node.connectedEdges().forEach((e: cytoscape.EdgeSingular) => e.style("label", ""))
        }
        cy.elements().removeClass("hover")
      })
    })

    // labelMode "zoom": NODE labels stay visible at every zoom (they scale
    // down but never below min-zoomed-font-size — the old binary hide
    // below 1.5× wiped all metadata off the graph at fit/zoom-out). Edge
    // labels are the overprint noise, so they stay gated at 1.5×; re-evaluate
    // only when the threshold is actually crossed (never per zoom frame).
    cy.on("zoom", () => {
      if (displayPrefsRef.current.labelMode !== "zoom") { edgeLabelsShownRef.current = null; return }
      const show = cy.zoom() > 1.5
      if (edgeLabelsShownRef.current === show) return
      edgeLabelsShownRef.current = show
      cy.batch(() => {
        cy.edges().forEach((e) => {
          if (e.removed()) return
          e.style("label", show ? (e.data("label") as string) : "")
        })
      })
    })

    // Always keep the interval running; gating on the ref makes the pulseAlerts
    // toggle effective without remounting the graph.
let pulseOn = false
    let pulseOff = false
    pulseIdRef.current = setInterval(() => {
      const alerts = cy.$("node[type='alert']")
      if (alerts.length === 0) return
      if (!displayPrefsRef.current.pulseAlerts) {
        // Disabling the pulse mid-animation left alert borders stuck at the
        // pulse's 2px/5px instead of the sheet's 3px — restore once, then
        // stay quiet (a per-tick re-animate would spin rAF forever).
        if (!pulseOff) {
          pulseOff = true
          alerts.animate({ style: { "border-width": 3, "border-color": "#ef4444" } }, { duration: 300, queue: false })
        }
        return
      }
      pulseOff = false
      pulseOn = !pulseOn
      alerts.animate({ style: { "border-width": pulseOn ? 5 : 2, "border-color": pulseOn ? "#f87171" : "#fca5a5" } }, { duration: 550, queue: false })
    }, 1100)

    // Flowing-traffic edges: a dotted dash pattern cycles its offset so flow
    // edges read as packets travelling along the line. Style changes are
    // batched per tick; an 80ms tick at ~5px is calm, not strobe-y.
    flowIdRef.current = setInterval(() => {
      if (!displayPrefsRef.current.edgeFlow) return
      const cy2 = cyRef.current
      if (!cy2 || cy2.destroyed()) return
      const flowEdges = cy2.$("edge[kind='flow']")
      if (flowEdges.length === 0) return
      flowOffsetRef.current = (flowOffsetRef.current + 12) % 24
      cy2.batch(() => flowEdges.forEach((e) => { if (!e.removed()) e.style("line-dash-offset", flowOffsetRef.current) }))
    }, 85)

    // Keep the backing canvas sized to the container: the sidebar toggle and
    // the sm:h-96 breakpoint resize the container without a window resize, so
    // cytoscape's stale canvas would otherwise stretch (blurry) or letterbox.
    const ro = new ResizeObserver(() => {
      if (cyRef.current && !cyRef.current.destroyed()) cyRef.current.resize()
    })
    if (containerRef.current) ro.observe(containerRef.current)

    setCyReady(true)

return () => {
      if (pulseIdRef.current) clearInterval(pulseIdRef.current)
      if (flowIdRef.current) clearInterval(flowIdRef.current)
      ro.disconnect()
      // The cose layout (and any animated layout) runs an rAF animation loop
      // that RE-SCHEDULES ITSELF even after stop() — a frame already queued
      // will still fire. cy.destroy() nulls the renderer synchronously, so a
      // frame that lands after destroy calls renderer.notify() on null and
      // throws "Cannot read properties of null (reading 'notify')".
      // Stop the layout, then defer destroy by one frame: the queued frame
      // runs its final pass against the LIVE renderer, and only then is the
      // core torn down. This kills the crash on every path — StrictMode
      // double-mount, HMR re-mounts, and mid-animation unmounts.
      try { layoutRef.current?.stop() } catch { /* ignore */ }
      try { cy.elements().stop() } catch { /* ignore */ }
      cyRef.current = null
      layoutRef.current = null
      requestAnimationFrame(() => {
        try { cy.destroy() } catch { /* ignore */ }
      })
      // StrictMode double-mounts effects (mount → cleanup → mount): without
      // this reset the data effect's lastGraphDataRef guard would survive the
      // cleanup and skip loading elements into the freshly re-created core,
      // leaving the graph empty with "No nodes match your search or filters".
      lastGraphDataRef.current = null
      firstDataRef.current = true
      setCyReady(false)
    }
    // Mount-only effect: reads initial props via refs; updates handled by dedicated effects below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Interacting with anything outside the graph (the page's other sidebars,
  // navigation, other controls) closes the context menu and the info panel —
  // they should not linger after the user moves on.
  useEffect(() => {
    const onPointerDown = (e: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        if (infoHideTimerRef.current) { clearTimeout(infoHideTimerRef.current); infoHideTimerRef.current = null }
        setContextMenu(null)
        setSelectedInfo(null)
      }
    }
    document.addEventListener("pointerdown", onPointerDown)
    return () => {
      document.removeEventListener("pointerdown", onPointerDown)
      if (infoHideTimerRef.current) { clearTimeout(infoHideTimerRef.current); infoHideTimerRef.current = null }
    }
  }, [])

  // Data + layout effect: replace elements only when the data actually
  // changed; a layout switch (or spacing/edge-style pref that affects the
  // layout config) re-runs the layout on the existing elements so
  // pins/highlights/search visibility survive. Layouts are instant for
  // switches (real-time response), animated once for the initial load.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || cy.destroyed()) return
    // Prefs come from the ref, not the deps: this effect never acts on a pref
    // change alone (the guard returns), and keeping the deps array small and
    // constant-length avoids React's "effect deps changed size" HMR error.
    const prefs = displayPrefsRef.current
    const dataChanged = lastGraphDataRef.current?.data !== graphData
    // A freshly re-created core (StrictMode re-mount) has no elements even
    // though the data ref matches — treat it as data-changed and reload.
    const freshCore = cy.elements().length === 0 && graphData.all.length > 0
    const layoutChanged = lastLayoutRef.current !== layoutConfig
    if (!dataChanged && !freshCore && !layoutChanged) return
    if (dataChanged || freshCore) {
      lastGraphDataRef.current = { data: graphData, all: graphData.all }
      try { cy.json({ elements: graphData.all }) } catch { return }
    }
    lastLayoutRef.current = layoutConfig
    try { layoutRef.current?.stop() } catch { /* ignore */ }
    const wasFirstLoad = firstDataRef.current
    // A layout switch is the user asking for a full re-fit; a background data
    // change must NOT yank the viewport — the old code re-ran the layout with
    // fit:true (animated per pref) on every graphData refresh (geoMap arrival,
    // store updates), so the graph visibly zoomed in/out by itself, fast
    // (instant fits) and slow (400ms animated fits) in sequence ("automatic
    // zoom" bug). Data refreshes are silent: positions replace, zoom/pan
    // stays where the user left it.
    const layoutSwitch = layoutChanged && !dataChanged
    try {
      // First load (and every StrictMode re-run) runs layouts instantly — no
      // rAF loop may outlive the core. And cose NEVER animates: its continuous
      // rAF re-schedules itself even after stop(), so a pending frame on a
      // destroyed core throws "Cannot read properties of null (reading
      // 'notify')". Switches/re-layouts animate per the pref.
      const options = {
        ...layoutConfig,
        // First load + layout switches fit the graph instantly (the graph is
        // ALWAYS in view — a fitted viewport is never skipped for the fly-in
        // below, which only ADDS a cinematic pull-back/dive on the fitted
        // view. A timed fly that fails must not leave the graph unframed.)
        fit: wasFirstLoad || layoutSwitch,
        animate: wasFirstLoad || layoutConfig.name === "cose"
          ? false
          : layoutSwitch && prefs.animateLayout,
      } as cytoscape.LayoutOptions
      layoutRef.current = cy.layout(options)
      layoutRef.current.run()
    } catch { /* ignore */ }
    firstDataRef.current = false
    if (wasFirstLoad && prefs.animateLayout) {
      // Pop-in entrance: nodes scale up + fade in, edges fade in, staggered.
      // Delayed so a StrictMode cleanup/destroy (run 1) happens before this
      // fires and the no-op guard skips the dead core; run 2 animates the
      // fresh one.
      setTimeout(() => {
        if (cy.destroyed()) return
        cy.nodes().forEach((n, i) => {
          if (n.removed()) return
          const type = n.data("type") as string
          const dims = NODE_SHAPES[type]?.size ?? [1, 1]
          const w = prefs.nodeSize * dims[0]
          const h = prefs.nodeSize * dims[1]
          n.style({ width: w * 0.15, height: h * 0.15, opacity: 0.05 })
          n.animate({ style: { width: w, height: h, opacity: prefs.nodeOpacity / 100 } }, { duration: 450, delay: i * 7 } as unknown as { duration: number; delay: number })
        })
        cy.edges().forEach((e, i) => {
          if (e.removed()) return
          e.style("opacity", 0)
          e.animate({ style: { opacity: prefs.edgeOpacity / 100 } }, { duration: 450, delay: i * 7 } as unknown as { duration: number; delay: number })
        })
        // Cinematic dive: zoom slightly OUT of the fitted view, then glide back
        // into the whole graph — motion without ever leaving the graph out of
        // view (a failed fly is merely a brief zoomed-out frame, not a blank
        // canvas).
        cy.zoom(cy.zoom() * 0.55)
        cy.animate({ fit: { eles: cy.elements(), padding: 40 }, duration: 650, easing: "ease-out-cubic" })
      }, 0)
    }
  }, [graphData, layoutConfig])

  // Filter effect: instant show/hide via per-element display styles — never a
  // re-layout, so search/type chips stay real-time on large graphs and the
  // layout positions are preserved while filtering.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || cy.destroyed()) return
    const visible = computeVisibleIds(graphData.all, filterTypes, searchQuery)
    cy.batch(() => {
      cy.nodes().forEach((n) => {
        if (n.removed()) return
        n.style("display", visible.has(n.id()) ? "element" : "none")
      })
      cy.edges().forEach((e) => {
        if (e.removed()) return
        const s = e.source(); const t = e.target()
        e.style("display", visible.has(s.id()) && visible.has(t.id()) ? "element" : "none")
      })
    })
    setVisibleCount(cy.nodes(":visible").length)
    // Snap the viewport to the results when the query changes (not per
    // keystroke re-fit of the same query).
    if (prevSearchRef.current !== searchQuery) {
      prevSearchRef.current = searchQuery
      if ((searchQuery.trim().length >= 2 || searchQuery.trim() === "") && cy.nodes(":visible").length > 0) {
        // Animated fit: queue:false cancels the previous fit so rapid typing
        // glides instead of stacking zoom animations.
        try { cy.animate({ fit: { eles: cy.elements(":visible"), padding: 60 }, duration: 350, queue: false }) } catch { /* ignore */ }
      }
    }
  }, [graphData, filterTypes, searchQuery])

  useEffect(() => {
    if (!cyRef.current || cyRef.current.destroyed()) return
    const cy = cyRef.current

function applyLabelVisibility(eles: cytoscape.Collection) {
      eles.forEach((el) => {
        if (el.removed()) return
        const label = el.data("label") as string
        const isEdge = el.isEdge()
        if (displayPrefs.labelMode === "always") {
          el.style("label", label)
        } else if (displayPrefs.labelMode === "zoom") {
          // Nodes: always visible (min-zoomed-font-size keeps them
          // readable when zoomed out). Edges: only above 1.5× zoom.
          el.style("label", !isEdge || cy.zoom() > 1.5 ? label : "")
        } else {
          el.style("label", "")
        }
      })
      // Keep the threshold tracker in sync with the zoom-mode edge gate so
      // the zoom handler knows the current state without re-scanning.
      edgeLabelsShownRef.current = displayPrefs.labelMode === "zoom" ? cy.zoom() > 1.5 : null
    }

    // Size/opacity/edge-style prefs are baked into the mount-time stylesheet,
    // so the controls would otherwise do nothing after mount — re-apply then
    // per element, mirroring the type-specific overrides from that sheet. Also
    // re-applies the theme palette colors so a light↔dark flip re-colors the
    // canvas without recreating the core (B-53).
    function applyStylePrefs() {
      cy.nodes().forEach((n) => {
        if (n.removed()) return
        const type = n.data("type") as string
        const dims = NODE_SHAPES[type]?.size ?? [1, 1]
        const extra: Record<string, unknown> = {}
        if (type === "pcap") extra["font-size"] = displayPrefs.labelSize + 2
        else if (type === "alert") extra["font-size"] = displayPrefs.labelSize + 1
        n.style({ width: displayPrefs.nodeSize * dims[0], height: displayPrefs.nodeSize * dims[1], opacity: displayPrefs.nodeOpacity / 100, color: effPalette.label, "text-outline-color": effPalette.outline, ...extra })
      })
      cy.edges().forEach((e) => {
        if (e.removed()) return
        const s: Record<string, unknown> = {
          "curve-style": displayPrefs.edgeStyle as "bezier" | "straight" | "taxi" | "segments" | "haystack",
          opacity: displayPrefs.edgeOpacity / 100,
          "font-size": displayPrefs.labelSize - 3,
          color: effPalette.edge,
          "text-background-color": effPalette.bubble,
        }
        // flow/relation/struct widths are set by the kind-specific overrides
        // (weight-driven) — a flat thickness here would erase them.
        const kinds = e.data("kind") as string
        if (kinds !== "flow" && kinds !== "relation" && kinds !== "struct") s.width = displayPrefs.edgeThickness
        if (kinds === "flow") {
          s["line-dash-pattern"] = displayPrefs.edgeFlow ? [2, 4] : []
          if (!displayPrefs.edgeFlow) s["line-dash-offset"] = 0
        }
        e.style(s)
      })
    }

    // Event-driven minimap redraw: cy fires "render" on every canvas repaint
    // (pan/zoom/layout/style), which replaces the old infinite rAF loop that
    // redrew at 60fps forever even when the graph was completely idle.
    function draw() {
      const canvas = miniMapRef.current
      if (!cyRef.current || cyRef.current.destroyed() || !canvas || !displayPrefs.showMinimap) return
      const ctx = canvas.getContext("2d")
      if (!ctx) return
      ctx.clearRect(0, 0, canvas.width, canvas.height)
      const extent = cy.extent()
      if (extent.x2 <= extent.x1 || extent.y2 <= extent.y1) return
      const scale = Math.min(canvas.width / extent.w, canvas.height / extent.h) * 0.95
      const ox = (canvas.width - extent.w * scale) / 2 - extent.x1 * scale
      const oy = (canvas.height - extent.h * scale) / 2 - extent.y1 * scale
      cy.edges().forEach((edge) => {
        if (!edge.visible()) return
        const srcNode = edge.source() as unknown as { removed: () => boolean; position: () => { x: number; y: number } }
        const dstNode = edge.target() as unknown as { removed: () => boolean; position: () => { x: number; y: number } }
        if (!srcNode || !dstNode || srcNode.removed() || dstNode.removed()) return
        const src = srcNode.position(); const dst = dstNode.position()
        ctx.strokeStyle = "rgba(255,255,255,0.25)"
        ctx.lineWidth = displayPrefs.edgeThickness * scale * 0.3
        ctx.beginPath()
        ctx.moveTo(src.x * scale + ox, src.y * scale + oy)
        ctx.lineTo(dst.x * scale + ox, dst.y * scale + oy)
        ctx.stroke()
      })
      cy.nodes().forEach((node) => {
        if (!node.visible() || node.removed()) return
        // Minimap parity (B-52): every node type draws with its own color and
        // shape proportions — the old map only painted blue IP squares, so
        // device/protocol/DNS nodes were invisible in the overview.
        const type = node.data("type") as string
        const dims = NODE_SHAPES[type]?.size ?? [1, 1]
        const p = node.position()
        ctx.fillStyle = BASE_COLORS[type] || "#60a5fa"
        const w = 7 * dims[0]
        const h = 7 * dims[1]
        ctx.fillRect(p.x * scale + ox - w / 2, p.y * scale + oy - h / 2, w, h)
      })
    }

    if (cyRef.current && !cyRef.current.destroyed()) {
      applyLabelVisibility(cyRef.current.elements() as unknown as cytoscape.Collection)
      applyStylePrefs()
      draw()
    }
    cy.on("render", draw)
    return () => { cy.off("render", draw) }
  }, [cyReady, displayPrefs, dark, effPalette])

  // Zoom about the VIEWPORT CENTER (not the top-left, which cytoscape's bare
  // cy.animate({ zoom }) does — the graph visibly slid away on every click)
  // and never by a factor <= 1, so both buttons always do something.
  const zoomBy = useCallback((dir: 1 | -1) => {
    const cy = cyRef.current
    if (!cy) return
    const cur = cy.zoom() || 1
    const factor = zoomStepFactor(displayPrefs.zoomSpeed)
    const next = dir === 1
      ? Math.min(cur * factor, cy.maxZoom())
      : Math.max(cur / factor, cy.minZoom())
    const k = next / cur
    const c = { x: cy.width() / 2, y: cy.height() / 2 }
    const p = cy.pan()
    cy.animate({
      zoom: next,
      pan: { x: c.x - (c.x - p.x) * k, y: c.y - (c.y - p.y) * k },
      duration: 150,
    })
  }, [displayPrefs.zoomSpeed])

  const handleZoomIn = useCallback(() => zoomBy(1), [zoomBy])

  const handleZoomOut = useCallback(() => zoomBy(-1), [zoomBy])

  const handleFit = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.animate({ fit: { eles: cy.elements(":visible"), padding: 40 }, duration: 250 })
  }, [])

  // Search/filter reset shared by the "Clear" and empty-state "Reset filters"
  // buttons. Restores context-menu-hidden nodes too (QA: resetting filters
  // while a hidden node stayed hidden read as "Reset doesn't work").
  const clearFilters = useCallback(() => {
    const cy = cyRef.current
    if (cy) cy.elements().style("visibility", "visible")
    setFilterTypes(new Set(TYPE_LABELS.map(t => t.value)))
    setSearchQuery("")
  }, [])

const handleReset = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    // Reset also restores context-menu-hidden nodes — resetting filters while
    // a hidden node stayed hidden read as "Reset doesn't work" (QA).
    cy.elements().style("visibility", "visible")
    setFilterTypes(new Set(TYPE_LABELS.map(t => t.value)))
    setSearchQuery("")
    try { layoutRef.current?.stop() } catch { /* ignore */ }
    try {
      layoutRef.current = cy.layout({ ...layoutConfig } as cytoscape.LayoutOptions)
      layoutRef.current.run()
    } catch { /* ignore */ }
    setVisibleCount(cy.nodes(":visible").length)
  }, [layoutConfig])

  const exportPng = useCallback((scale = 4) => {
    const cy = cyRef.current
    if (!cy) return
    const dataUrl = cy.png({ scale, full: true, bg: paletteRef.current.canvas })
    const a = document.createElement("a")
    a.href = dataUrl
    a.download = `investigation-graph-${scale}x.png`
    a.click()
  }, [])

  const exportSvg = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    const svg = (cy as unknown as { svg(opts: { full: boolean; scale: number; bg: string }): string }).svg({ full: true, scale: 4, bg: paletteRef.current.canvas })
    const blob = new Blob([svg], { type: "image/svg+xml" })
    const a = document.createElement("a")
    a.href = URL.createObjectURL(blob)
    a.download = "investigation-graph.svg"
    a.click()
    URL.revokeObjectURL(a.href)
  }, [])

  const handleContextMenuAction = useCallback((action: string) => {
    if (!contextMenu || !cyRef.current) { setContextMenu(null); return }
    const cy = cyRef.current
    const node = cy.getElementById(contextMenu.nodeId)
    if (node.length === 0 || node.removed()) { setContextMenu(null); return }
    if (action === "highlight-neighbors") {
      cy.elements().removeClass("highlight faded")
      node.addClass("highlight")
      node.connectedEdges().addClass("highlight")
      node.connectedEdges().connectedNodes().addClass("highlight")
      cy.elements().not(node.connectedEdges().connectedNodes().add(node)).addClass("faded")
      node.connectedEdges().not(node.connectedEdges().connectedNodes()).addClass("faded")
      setSelectedInfo(node.data().info || node.data().label || node.data().id)
      scheduleInfoAutoHide()
    } else if (action === "hide-node") {
      node.style("visibility", "hidden")
      node.connectedEdges().style("visibility", "hidden")
      // Keep the counter equal to what the canvas actually draws — these
      // actions change visibility without a filter change, so the count
      // would otherwise go stale ("N shown" while the canvas loses a node).
      setVisibleCount(cy.nodes(":visible").length)
    } else if (action === "pin-node") {
      if (node.locked()) node.unlock()
      else node.lock()
    } else if (action === "show-all") {
      cy.elements().style("visibility", "visible")
      setVisibleCount(cy.nodes(":visible").length)
    } else if (action === "focus") {
      // Focus mode: smoothly center on the node and zoom in. (A bare
      // cy.center() + cy.zoom() zooms around the top-left corner, so the
      // node visibly jumped away — that was the "focus not working" bug.)
      cy.elements().removeClass("highlight")
      node.addClass("highlight")
      setSelectedInfo(node.data().info || node.data().label || node.data().id)
      scheduleInfoAutoHide()
      cy.animate({ center: { eles: node }, zoom: Math.max(cy.zoom(), 2) }, { duration: 400 })
    } else if (action === "search-highlight") {
      // Match the same fields as the search box (id/info/label/type) — the
      // short label alone never matches a full IP, which made "Search
      // Highlight" silently fail for IP nodes.
      const d = node.data() as Record<string, string>
      const hay = [d.id, d.info, d.label, d.type].join(" ").toLowerCase()
      const q = searchQuery.trim().toLowerCase()
      if (!q || hay.includes(q)) {
        node.addClass("highlight")
        setSelectedInfo(d.info || d.label || d.id)
        scheduleInfoAutoHide()
        cy.animate({ fit: { eles: node, padding: 40 }, duration: 350 })
      }
    }
    setContextMenu(null)
  }, [contextMenu, searchQuery, scheduleInfoAutoHide])

  const toggleFilterType = useCallback((type: string) => {
    setFilterTypes(prev => {
      const allValues = new Set(TYPE_LABELS.filter(t => t.value !== "all").map(t => t.value))
      if (type === "all") {
        // "All" is a master switch: always resets to every type visible
        // (never the empty set — empty must not mean "hide everything").
        return allValues
      }
      // From "everything active", clicking a chip isolates that type. (The
      // old toggle deleted it instead, so clicking "IPs" silently hid IPs
      // while every other chip stayed lit — the "plural chips don't work"
      // symptom. Values are canonical node types; labels are just display.)
      const allSelected = prev.has("all") || prev.size === allValues.size
      if (allSelected) return new Set([type])
      const next = new Set(prev)
      if (next.has(type)) next.delete(type)
      else next.add(type)
      return next
    })
  }, [])

  return (
    <div ref={rootRef} className={className}>
      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
        <span className="font-semibold text-sm">Investigation Graph</span>
        <div className="flex items-center gap-1">
          <button onClick={() => setDisplayControlsOpen(!displayControlsOpen)} className="p-1.5 rounded hover:bg-accent text-xs" title="Display Controls">
            <Settings className="h-3.5 w-3.5" />
          </button>
          <button onClick={() => exportPng(4)} className="p-1.5 rounded hover:bg-accent text-xs" title="Export PNG"><FileImage className="h-3.5 w-3.5" /></button>
          <button onClick={exportSvg} className="p-1.5 rounded hover:bg-accent text-xs" title="Export SVG"><FileSvg className="h-3.5 w-3.5" /></button>
          <button onClick={handleZoomIn} className="p-1.5 rounded hover:bg-accent text-xs" title="Zoom In"><ZoomIn className="h-3.5 w-3.5" /></button>
          <button onClick={handleZoomOut} className="p-1.5 rounded hover:bg-accent text-xs" title="Zoom Out"><ZoomOut className="h-3.5 w-3.5" /></button>
          <button onClick={handleFit} className="p-1.5 rounded hover:bg-accent text-xs" title="Fit View">Fit</button>
          <button onClick={handleReset} className="p-1.5 rounded hover:bg-accent text-xs" title="Re-layout"><LayoutGrid className="h-3.5 w-3.5" /></button>
        </div>
      </div>

      {displayControlsOpen && (
        <div className="mb-3 p-3 border rounded-md bg-background">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <h4 className="text-xs font-medium mb-2 flex items-center gap-1"><BarChart3 className="h-3 w-3" /> Node Size</h4>
              <div className="flex items-center gap-2">
                <input type="range" min="10" max="80" value={displayPrefs.nodeSize} onChange={e => updateDisplayPrefs({ nodeSize: parseInt(e.target.value) })} className="w-full" />
                <span className="text-[10px] w-10 text-right">{displayPrefs.nodeSize}px</span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-medium mb-2 flex items-center gap-1"><AlertCircle className="h-3 w-3" /> Label Size</h4>
              <div className="flex items-center gap-2">
                <input type="range" min="8" max="24" value={displayPrefs.labelSize} onChange={e => updateDisplayPrefs({ labelSize: parseInt(e.target.value) })} className="w-full" />
                <span className="text-[10px] w-10 text-right">{displayPrefs.labelSize}px</span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-medium mb-2 flex items-center gap-1"><Minus className="h-3 w-3" /> Edge Thickness</h4>
              <div className="flex items-center gap-2">
                <input type="range" min="1" max="10" value={displayPrefs.edgeThickness} onChange={e => updateDisplayPrefs({ edgeThickness: parseInt(e.target.value) })} className="w-full" />
                <span className="text-[10px] w-10 text-right">{displayPrefs.edgeThickness}px</span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-medium mb-2 flex items-center gap-1"><Gauge className="h-3 w-3" /> Graph Spacing</h4>
              <div className="flex items-center gap-2">
                <input type="range" min="50" max="300" value={Math.round(displayPrefs.graphSpacing * 100)} onChange={e => updateDisplayPrefs({ graphSpacing: parseInt(e.target.value) / 100 })} className="w-full" />
                <span className="text-[10px] w-10 text-right">{displayPrefs.graphSpacing.toFixed(1)}x</span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-medium mb-2 flex items-center gap-1"><SlidersHorizontal className="h-3 w-3" /> Zoom Speed</h4>
              <div className="flex items-center gap-2">
                <input type="range" min="1" max="3" step="0.1" value={displayPrefs.zoomSpeed} onChange={e => updateDisplayPrefs({ zoomSpeed: parseFloat(e.target.value) })} className="w-full" />
                <span className="text-[10px] w-10 text-right">{displayPrefs.zoomSpeed.toFixed(1)}x</span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-medium mb-2">Node Opacity</h4>
              <div className="flex items-center gap-2">
                <input type="range" min="20" max="100" value={displayPrefs.nodeOpacity} onChange={e => updateDisplayPrefs({ nodeOpacity: parseInt(e.target.value) })} className="w-full" />
                <span className="text-[10px] w-10 text-right">{displayPrefs.nodeOpacity}%</span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-medium mb-2">Edge Opacity</h4>
              <div className="flex items-center gap-2">
                <input type="range" min="10" max="100" value={displayPrefs.edgeOpacity} onChange={e => updateDisplayPrefs({ edgeOpacity: parseInt(e.target.value) })} className="w-full" />
                <span className="text-[10px] w-10 text-right">{displayPrefs.edgeOpacity}%</span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-medium mb-2">Label Visibility</h4>
              <div className="flex flex-col gap-1">
                <label className="flex items-center gap-2 text-xs">
                  <input type="radio" name="label-mode" checked={displayPrefs.labelMode === "always"} onChange={() => updateDisplayPrefs({ labelMode: "always" })} />
                  <span>Always</span>
                </label>
                <label className="flex items-center gap-2 text-xs">
                  <input type="radio" name="label-mode" checked={displayPrefs.labelMode === "hover"} onChange={() => updateDisplayPrefs({ labelMode: "hover" })} />
                  <span>Hover</span>
                </label>
                <label className="flex items-center gap-2 text-xs">
                  <input type="radio" name="label-mode" checked={displayPrefs.labelMode === "zoom"} onChange={() => updateDisplayPrefs({ labelMode: "zoom" })} />
                  <span>Zoom (labels stay readable)</span>
                </label>
                <label className="flex items-center gap-2 text-xs">
                  <input type="radio" name="label-mode" checked={displayPrefs.labelMode === "none"} onChange={() => updateDisplayPrefs({ labelMode: "none" })} />
                  <span>Hidden</span>
                </label>
              </div>
            </div>

<div>
              <h4 className="text-xs font-medium mb-2 flex items-center gap-1"><Settings className="h-3 w-3" /> Animations</h4>
              <div className="flex flex-col gap-1">
                <label className="flex items-center gap-2 text-xs">
                  <input type="checkbox" checked={displayPrefs.animateLayout} onChange={e => updateDisplayPrefs({ animateLayout: e.target.checked })} />
                  <span>Animated Layouts</span>
                </label>
                <label className="flex items-center gap-2 text-xs">
                  <input type="checkbox" checked={displayPrefs.edgeFlow} onChange={e => updateDisplayPrefs({ edgeFlow: e.target.checked })} />
                  <span>Flowing Edges</span>
                </label>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-medium mb-2 flex items-center gap-1"><Settings className="h-3 w-3" /> Minimap</h4>
              <label className="flex items-center gap-2 text-xs">
                <input type="checkbox" checked={displayPrefs.showMinimap} onChange={e => updateDisplayPrefs({ showMinimap: e.target.checked })} />
                <span>Show Minimap</span>
              </label>
            </div>

            <div>
              <h4 className="text-xs font-medium mb-2 flex items-center gap-1"><span className="inline-block w-3 h-3 rounded-full border" style={{ backgroundColor: effPalette.canvas, borderColor: "currentColor" }} /> Background</h4>
              <select value={displayPrefs.bgPreset} onChange={e => updateDisplayPrefs({ bgPreset: e.target.value })} className="w-full h-7 text-xs border rounded bg-background px-1">
                {Object.entries(BG_PRESETS).map(([key, p]) => <option key={key} value={key}>{p.label}</option>)}
              </select>
            </div>

            <div>
              <h4 className="text-xs font-medium mb-2">Edge Style</h4>
              <select value={displayPrefs.edgeStyle} onChange={e => updateDisplayPrefs({ edgeStyle: e.target.value })} className="w-full h-7 text-xs border rounded bg-background px-1">
                <option value="bezier">Bezier</option>
                <option value="straight">Straight</option>
                <option value="taxi">Taxi</option>
                <option value="segments">Segments</option>
                <option value="haystack">Haystack</option>
              </select>
            </div>
          </div>

          <div className="flex gap-2 mt-4">
            <button onClick={() => updateDisplayPrefs(DEFAULT_DISPLAY_PREFS)} className="h-7 text-xs border rounded px-2 hover:bg-accent">Reset Display</button>
          </div>
        </div>
      )}

      <div className="flex flex-wrap gap-2 mb-2 items-center">
        <div className="relative flex-1 min-w-[120px] max-w-[200px]">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
          <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)} placeholder="Search IPs, hosts, alerts..." className="w-full h-7 pl-7 pr-2 text-xs border rounded bg-background" maxLength={100} />
        </div>
        <select value={layoutName} onChange={e => handleLayoutChange(e.target.value)} className="h-7 text-xs border rounded bg-background px-1 max-w-[100px]">
          {LAYOUTS.map(l => <option key={l.name} value={l.name}>{l.label}</option>)}
        </select>
        <span className="text-[10px] text-muted-foreground whitespace-nowrap">{graphData.nodes.length} nodes{visibleCount !== graphData.nodes.length ? ` · ${visibleCount} shown` : ""}</span>
        {searchQuery && <button onClick={clearFilters} className="text-[10px] text-primary hover:underline">Clear</button>}
      </div>

      <div className="flex flex-wrap gap-1 mb-2">
        {TYPE_LABELS.filter(t => t.value === "all" || (typeCounts[t.value] || 0) > 0).map(t => {
          // Only non-empty types render (B-53): a struck-through disabled chip
          // for every absent type is noise. "all" always renders.
          // The "All" chip stays lit while every type is active — including the
          // post-toggle state (all 13 selected, no "all" key) — so it never
          // shows unlit while the graph is showing everything.
          const allTypesActive = filterTypes.size === 0 || filterTypes.has("all") || filterTypes.size === TYPE_LABELS.length - 1
          const active = t.value === "all" ? allTypesActive : filterTypes.has(t.value)
          return (
            <button key={t.value} onClick={() => toggleFilterType(t.value)}
              className={`h-5 px-1.5 text-[10px] rounded border transition-colors ${active ? "bg-primary/10 border-primary/30 text-primary" : "bg-muted/50 border-muted text-muted-foreground"}`}>{t.label}</button>
          )
        })}
      </div>

      <div className="relative">
        <div ref={containerRef} className="h-80 sm:h-96 w-full rounded-md border" style={{
          backgroundColor: effPalette.canvas,
          // Faint engineering-grid dots behind the transparent cytoscape
          // canvas — gives the flat panel depth at zero render cost. Dot
          // color follows the chosen background's brightness, not just theme.
          backgroundImage: isDarkHex(effPalette.canvas) ? "radial-gradient(circle, rgba(255,255,255,0.05) 1px, transparent 1px)" : "radial-gradient(circle, rgba(15,23,42,0.06) 1px, transparent 1px)",
          backgroundSize: "22px 22px",
        }} />
        {/* Soft vignette so the edges of the panel recede instead of a hard flat wall. */}
        <div className="absolute inset-0 rounded-md pointer-events-none" style={{ background: isDarkHex(effPalette.canvas) ? "radial-gradient(ellipse at center, transparent 55%, rgba(0,0,0,0.28))" : "radial-gradient(ellipse at center, transparent 60%, rgba(15,23,42,0.10))" }} />
        {!cyReady && (
          <div className="absolute inset-0 flex items-center justify-center rounded-md" style={{ backgroundColor: effPalette.canvas, opacity: 0.85 }}>
            <span className="text-sm animate-pulse" style={{ color: effPalette.label, opacity: 0.6 }}>Rendering graph...</span>
          </div>
        )}
        {cyReady && visibleCount === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 rounded-md" style={{ backgroundColor: effPalette.canvas, opacity: 0.85 }}>
            <span className="text-sm" style={{ color: effPalette.label, opacity: 0.6 }}>{graphData.nodes.length === 0 ? "No network data to display" : `0 of ${graphData.nodes.length} nodes match your search or filters`}</span>
            {(searchQuery.trim() !== "" || filterTypes.size !== 0) && (
              <button onClick={clearFilters} className="text-xs text-primary hover:underline">
                Reset filters
              </button>
            )}
          </div>
        )}
        {displayPrefs.showMinimap && (
          // Display-only overlay: translucent so graph nodes/labels beneath
          // stay readable, and pointer-events-none so it never blocks pan/zoom
          // (QA: minimap box sat on top of the OTHER node and its label).
          <div className="absolute bottom-2 right-2 border border-white/10 rounded bg-black/40 overflow-hidden pointer-events-none" style={{ width: 140, height: 100 }}>
            {/* 2x backing store: the old 140x100 canvas upscaled to the CSS
                box, so the minimap lines looked smeared on hi-dpi screens. */}
            <canvas ref={miniMapRef} width={280} height={200} className="h-full w-full" />
          </div>
        )}
      </div>

{contextMenu && (
        // Clamped into the viewport: on narrow windows Math.min can go NEGATIVE
        // (window.innerWidth < menu width), pushing the menu off-screen (QA).
        <div className="fixed z-50 bg-background border rounded shadow-lg py-1 min-w-[160px]" style={{ left: Math.max(0, Math.min(contextMenu.x, Math.max(0, window.innerWidth - 176))), top: Math.max(0, Math.min(contextMenu.y, Math.max(0, window.innerHeight - 240))) }}>
          <button onClick={() => handleContextMenuAction("highlight-neighbors")} className="block w-full text-left px-3 py-1.5 text-xs hover:bg-accent">Highlight Neighbors</button>
          <button onClick={() => handleContextMenuAction("search-highlight")} className="block w-full text-left px-3 py-1.5 text-xs hover:bg-accent">Search Highlight</button>
          <button onClick={() => handleContextMenuAction("focus")} className="block w-full text-left px-3 py-1.5 text-xs hover:bg-accent">Focus Node</button>
          <button onClick={() => handleContextMenuAction("pin-node")} className="block w-full text-left px-3 py-1.5 text-xs hover:bg-accent">{contextMenu.locked ? "Unpin Node" : "Pin Node"}</button>
          <hr className="my-1 border-border/50" />
          <button onClick={() => handleContextMenuAction("hide-node")} className="block w-full text-left px-3 py-1.5 text-xs hover:bg-accent">Hide Node</button>
          <button onClick={() => handleContextMenuAction("show-all")} className="block w-full text-left px-3 py-1.5 text-xs hover:bg-accent">Show All</button>
        </div>
      )}

      {selectedInfo && (
        <div className="mt-2 border rounded p-3 text-xs space-y-1 bg-background relative">
          <button onClick={() => setSelectedInfo(null)} className="absolute top-1 right-1 p-0.5 rounded hover:bg-accent"><X className="h-3 w-3" /></button>
          <pre className="whitespace-pre-wrap break-all text-muted-foreground pr-5 font-mono text-[11px]">{selectedInfo}</pre>
        </div>
      )}

{/* Only types actually present in this capture — a legend full of
          zero-count types read as missing data (QA). */}
      <div className="flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-muted-foreground mt-1.5 items-center">
        {LEGEND_ITEMS.filter(item => (typeCounts[item.label.toLowerCase()] || 0) > 0).map(item => (
          <span key={item.label} className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 inline-block shrink-0" style={{ backgroundColor: item.color, ...LEGEND_STYLES[item.shape] }} />
            {item.label}
          </span>
        ))}
      </div>
    </div>
  )
}
