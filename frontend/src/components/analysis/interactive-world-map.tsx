"use client"

// World Map — paper & navy global connection (v3.2). ONE flat SVG from ONE
// projection: the Natural Earth continents (public/world-countries.geojson,
// public domain) are projected with geoNaturalEarth1 into a fixed 1600×860
// canvas, and every PIN and ARC lives in that same projected space — arc
// endpoints are [x,y] of the two pins, so they can never detach at any zoom.
// Pan/zoom transforms the single group (no second map layer to drift); PNG/
// SVG exports serialize the same DOM, so exports match the live view.
//
// Tokens: light = cream paper + navy land; dark = navy + charcoal. Arcs:
// blue = HOME→peer outbound, green = peer→HOME inbound, width =
// clamp(1.5, 1 + log10(1+bytes)/2, 6), solid round caps + thin animated dash
// overlay. Home hub = double orange ring + radial bloom. Cluster badge when
// ≥2 public IPs share a city. Captions: DRAWN/CAPTURE small-caps strip.
// Legend chips: Home / Destination / Outbound / Inbound.

import { useEffect, useMemo, useRef, useState, useCallback, type MouseEvent as ReactMouseEvent, type PointerEvent as ReactPointerEvent } from "react"
import { geoNaturalEarth1, geoPath, geoGraticule10 } from "d3-geo"
import { useTheme } from "next-themes"
import { Maximize2, ZoomIn, ZoomOut, Maximize, Search, X } from "lucide-react"
import { clusterByCity, clampLat, clampLon, deriveMapData, formatBytes, mapPanels, nodeSearchHaystack, homeAnchorFromOwnedPublic, type MapData, type MapNode } from "@/lib/map-data"
import { packetProtocolCounts } from "@/lib/analysis"
import { zoomView } from "@/lib/map-view"
import { resolveGeoBatch, setOnlineGeoAllowed, type GeoLocation } from "@/lib/geo"
import { useAnalysisStore } from "@/stores/analysis"
import { MapChrome } from "./map-chrome"
import AnimatedFlows from "./animated-flows"

interface WorldPalette {
  ocean: string
  land: string
  border: string
  out: string
  in: string
  pin: string
  pinRing: string
  badgeFill: string
  badgeBorder: string
  badgeText: string
  label: string
  footer: string
  graticule: string
}

const PALETTES: Record<"light" | "dark", WorldPalette> = {
  light: {
    ocean: "#F4EEDF",
    land: "#16283C",
    border: "rgba(255,255,255,0.25)",
    out: "#2E6FB7",
    in: "#3E9B6E",
    pin: "#2E6FB7",
    pinRing: "#ffffff",
    badgeFill: "#ffffff",
    badgeBorder: "#16283C",
    badgeText: "#16283C",
    label: "#16283C",
    footer: "rgba(22,40,60,0.75)",
    graticule: "rgba(22,40,60,0.10)",
  },
  dark: {
    ocean: "#0B1219",
    land: "#2A343C",
    border: "rgba(255,255,255,0.25)",
    out: "#4FC3F7",
    in: "#6EE7A0",
    pin: "#4FC3F7",
    pinRing: "#ffffff",
    badgeFill: "#12203A",
    badgeBorder: "rgba(79,195,247,0.7)",
    badgeText: "#e5e7eb",
    label: "#e5e7eb",
    footer: "rgba(229,231,235,0.72)",
    graticule: "rgba(255,255,255,0.07)",
  },
}

const HUB_COLOR = "#F97316"
// Neutral ocean point used only when local↔public flows exist but home is
// unknown — positions their arcs without ever drawing a marker there.
const LOCAL_ANCHOR_POS = { lat: -30, lon: -15 }
// ViewBox 1600×900 = exactly 16/9, so the frame's aspectRatio never leaves
// letterbox bands above/below the map (the old 1600×860 sat inside a 16/9
// frame with the svg fit-to-width, banding ~2% top AND bottom).
const SVG_W = 1600
const SVG_H = 900
// Shrunk from 60 so the landmass renders larger, and the fit box is nudged
// 18px down: with Antarctica filtered the world's bbox sits a touch high
// (measured land y-extent 111..738 of 860), leaving a big southern-ocean
// wash below the globe.
const PAD = 30

interface WorldMapProps {
  packets: { srcIp?: string; dstIp?: string; protocol?: string; length?: number; timestamp?: string | number }[]
  alerts?: { srcIp?: string; dstIp?: string; signature?: string }[]
  localDevices?: number
  localAliases?: ReadonlySet<string>
  homeAnchor?: { lat: number; lon: number } | null
  className?: string
}

interface Painter {
  land: string
  graticule: string
  px: (lat: number, lon: number) => [number, number]
}

interface Pin {
  x: number
  y: number
  r: number
  ip: string
  countryCode: string
  alert: boolean
  n: MapNode
}

interface Arc {
  pts: [number, number][]
  color: string
  w: number
  bytes: number
  protocol: string
  srcIp: string
  dstIp: string
}

function nodeRadius(maxBytes: number, bytes: number): number {
  return Math.min(13, Math.max(5, 4 + 6 * Math.sqrt(bytes / Math.max(maxBytes, 1))))
}

function arcWidth(bytes: number): number {
  return Math.min(6, Math.max(1.5, 1 + Math.log10(1 + bytes) / 2))
}

// Projected-space arc between two pins: a quadratic bézier bowing SOUTH (away
// from the frame top). Great circles were replaced because between mid-lat
// endpoints (India ↔ US west coast) the shortest path climbs over the pole
// and renders as a flat near-horizontal line hugging the map top — read as
// "wrong routes". A deterministic per-pair lateral fan (±24% of the bow)
// separates parallel bundles (many home→same-region arcs otherwise overlay
// into one line), and endpoints ARE the pin coordinates, so every line lands
// exactly on its marker.
function arcCurvePts(sx: number, sy: number, dx: number, dy: number, seed: string, steps = 28): [number, number][] {
  const vx = dx - sx, vy = dy - sy
  const dist = Math.hypot(vx, vy)
  if (dist < 1e-6) return [[sx, sy], [dx, dy]]
  let nx = -vy / dist, ny = vx / dist
  if (ny < 0) { nx = -nx; ny = -ny }
  let h = 0
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0
  const bow = Math.min(110, dist * 0.16) * (1 + ((h % 9) - 4) * 0.12)
  const cx = (sx + dx) / 2 + nx * bow
  const cy = (sy + dy) / 2 + ny * bow
  const pts: [number, number][] = []
  for (let i = 0; i <= steps; i++) {
    const t = i / steps
    const u = 1 - t
    pts.push([u * u * sx + 2 * u * t * cx + t * t * dx, u * u * sy + 2 * u * t * cy + t * t * dy])
  }
  return pts
}

function nodeLabelOf(n: MapNode): string {
  if (n.isPrivate) return "Local Network"
  return n.countryCode !== "??" ? `${n.city ? `${n.city}, ` : ""}${n.country}` : "Unknown"
}

// Natural Earth 110m country polygons — fetched once, projected once, cached
// for the lifetime of the app (graph and map views share the projection).
let cachedWorld: Painter | null = null
let worldFetch: Promise<Painter> | null = null
function loadWorld(): Promise<Painter> {
  if (cachedWorld) return Promise.resolve(cachedWorld)
  if (!worldFetch) {
    worldFetch = fetch("/world-countries.geojson")
      .then((r) => {
        if (!r.ok) throw new Error(`world geojson ${r.status}`)
        return r.json()
      })
      .then((geo: { features: { geometry: unknown; properties?: { CONTINENT?: string } }[] }) => {
        const features = geo.features.filter((f) => f.properties?.CONTINENT !== "Antarctica")
        const proj = geoNaturalEarth1().fitExtent([[PAD, PAD - 18], [SVG_W - PAD, SVG_H - PAD + 18]], { type: "FeatureCollection", features } as never)
        const path = geoPath(proj)
        cachedWorld = {
          land: features.map((f) => path(f as never) || "").join(""),
          graticule: path(geoGraticule10()) || "",
          px: (lat, lon) => {
            const p = proj([clampLon(lon), clampLat(lat)]) as [number, number] | null
            return p ?? [0, 0]
          },
        }
        return cachedWorld
      })
      .catch((e) => { worldFetch = null; throw e })
  }
  return worldFetch
}

export function InteractiveWorldMap({ packets, alerts = [], localDevices, localAliases, homeAnchor, className }: WorldMapProps) {
  const frameRef = useRef<HTMLDivElement>(null)
  const [geoMap, setGeoMap] = useState<Map<string, GeoLocation>>(new Map())
  const [world, setWorld] = useState<Painter | null>(null)
  const [hoverPin, setHoverPin] = useState<Pin | null>(null)
  const [hoverPinPos, setHoverPinPos] = useState<{ x: number; y: number } | null>(null)
  const [hoverArc, setHoverArc] = useState<Arc | null>(null)
  const [hoverArcPos, setHoverArcPos] = useState<{ x: number; y: number } | null>(null)
  const [fullscreen, setFullscreen] = useState(false)
  const [view, setView] = useState({ k: 1, x: 0, y: 0 })
  const viewRef = useRef(view)
  useEffect(() => { viewRef.current = view }, [view])
  const dragRef = useRef<{ sx: number; sy: number; vx: number; vy: number; active: boolean } | null>(null)
  const [focusCountry, setFocusCountry] = useState<string | null>(null)
  const [search, setSearch] = useState("")
  const q = search.trim().toLowerCase()
  const [hoverHub, setHoverHub] = useState(false)
  const [hoverHubPos, setHoverHubPos] = useState<{ x: number; y: number } | null>(null)

  const toggleFullscreen = () => {
    const el = frameRef.current
    if (!el) return
    if (document.fullscreenElement) { document.exitFullscreen() } else { el.requestFullscreen?.().catch(() => {}) }
  }
  useEffect(() => {
    const onFs = () => setFullscreen(Boolean(document.fullscreenElement))
    document.addEventListener("fullscreenchange", onFs)
    return () => document.removeEventListener("fullscreenchange", onFs)
  }, [])

  const { resolvedTheme } = useTheme()
  const pal = resolvedTheme !== "light" ? PALETTES.dark : PALETTES.light
  // Subscribed, not getState()-at-render: the footer's mode line and the
  // geo batch must react to a Settings toggle without a remount (QA).
  const onlineGeo = useAnalysisStore((s) => s.settings.onlineGeo)

  const uniqueIps = useMemo(() => {
    const s = new Set<string>()
    for (const p of packets) { if (p.srcIp) s.add(p.srcIp); if (p.dstIp) s.add(p.dstIp) }
    return [...s].filter(Boolean)
  }, [packets])

  useEffect(() => {
    let cancelled = false
    setOnlineGeoAllowed(onlineGeo)
    resolveGeoBatch(uniqueIps).then((m) => { if (!cancelled) setGeoMap(m) }).catch(() => {})
    return () => { cancelled = true }
  }, [uniqueIps, onlineGeo])

  useEffect(() => {
    let cancelled = false
    loadWorld().then((w) => { if (!cancelled) setWorld(w) }).catch(() => {})
    return () => { cancelled = true }
  }, [])

  const mapData = useMemo<MapData>(() => deriveMapData(packets, geoMap, localAliases), [packets, geoMap, localAliases])
  const panels = useMemo(() => mapPanels(mapData), [mapData])
  // Home anchor: manual settings win, else an owned public address in the
  // capture, else — when local↔public traffic exists but home is unknown —
  // a neutral ocean anchor so the connection lines still draw. The anchor is
  // purely geometric: NO hub ring, label, or tooltip is rendered for it, so
  // the map stays "public pins only" (no fake local marker on the globe).
  const anchor = useMemo<{ lat: number; lon: number; synthetic: boolean } | null>(() => {
    if (homeAnchor) return { ...homeAnchor, synthetic: false }
    const owned = homeAnchorFromOwnedPublic(localAliases, geoMap)
    if (owned) return { ...owned, synthetic: false }
    return mapData.localPublicFlows.length > 0 ? { ...LOCAL_ANCHOR_POS, synthetic: true } : null
  }, [homeAnchor, localAliases, geoMap, mapData.localPublicFlows.length])
  const anchorSynthetic = anchor?.synthetic === true
  const anchorDerived = Boolean(anchor) && !homeAnchor && !anchorSynthetic
  const localHosts = localDevices ?? panels.localHosts
  const protoCounts = useMemo(() => [...Object.entries(packetProtocolCounts(packets))].sort((a, b) => b[1] - a[1]), [packets])
  const protoTotal = protoCounts.reduce((s, [, c]) => s + c, 0)

  const durationS = useMemo(() => {
    let first = Infinity, last = -Infinity
    for (const p of packets) {
      const t = typeof p.timestamp === "number" ? p.timestamp : typeof p.timestamp === "string" ? new Date(p.timestamp).getTime() / 1000 : NaN
      if (!Number.isFinite(t)) continue
      first = Math.min(first, t); last = Math.max(last, t)
    }
    return first > last ? 0 : Math.round(last - first)
  }, [packets])

  // ---- the single geometry pass: pins, badges, arcs in the one projection.
  // Search filters pins/badges/arcs by IP, city, country, ASN, org and
  // hostname (the shared haystack — a pin's tooltip shows its org, so
  // searching "Google" or "AS15169" must find it too).
  const matchedNodes = useMemo(() => {
    if (!q) return mapData.nodes
    return mapData.nodes.filter((n) => nodeSearchHaystack(n).includes(q))
  }, [mapData.nodes, q])

  const pins = useMemo<Pin[]>(() => {
    if (!world) return []
    // Folded max, not Math.max(...spread): mapData.nodes grows one entry per
    // geocoded public IP — past ~125k nodes the spread throws RangeError and
    // the pins memo dies (QA, same class as graph-data.ts:163).
    let maxBytes = 1
    for (const n of mapData.nodes) if (n.bytes > maxBytes) maxBytes = n.bytes
    const alertIps = new Set(alerts.flatMap((a) => [a.srcIp, a.dstIp]).filter((ip): ip is string => !!ip))
    return matchedNodes.map((n) => {
      const [x, y] = world.px(n.lat, n.lon)
      return { x, y, r: nodeRadius(maxBytes, n.bytes), ip: n.ip, countryCode: n.countryCode, alert: alertIps.has(n.ip), n }
    })
  }, [world, matchedNodes, alerts, mapData.nodes])

  const clusters = useMemo(() => {
    if (!world) return []
    // 1°-cell clusters (city-level) plus left-over single pins as groups;
    // groups whose projected markers sit within MARKER_MERGE_PX of each other
    // merge into one badge (QA: distinct metros Bengaluru/Chennai still
    // overprinted into a blob 12px apart).
    const cells = clusterByCity(matchedNodes)
    const inACell = new Set(cells.flatMap((c) => c.ips))
    const groups: { ips: string[]; lat: number; lon: number; n: number }[] = [
      ...cells.map((c) => ({ ips: [...c.ips], lat: c.lat, lon: c.lon, n: c.ips.length })),
      ...matchedNodes.filter((n) => !inACell.has(n.ip)).map((n) => ({ ips: [n.ip], lat: n.lat, lon: n.lon, n: 1 })),
    ]
    const pos = (g: (typeof groups)[number]) => world.px(g.lat, g.lon)
    for (let changed = true; changed;) {
      changed = false
      // ponytail: one-pass pair merge (groups rarely exceed a few dozen on
      // world zoom); re-ball the pass if a capture ever draws 1000+ peers.
      for (let i = 0; i < groups.length && !changed; i++) {
        const [ax, ay] = pos(groups[i])
        for (let j = i + 1; j < groups.length; j++) {
          const [bx, by] = pos(groups[j])
          if (Math.hypot(ax - bx, ay - by) < 24) {
            const gi = groups[i], gj = groups[j]
            gi.ips.push(...gj.ips)
            gi.lat = (gi.lat * gi.n + gj.lat * gj.n) / (gi.n + gj.n)
            gi.lon = (gi.lon * gi.n + gj.lon * gj.n) / (gi.n + gj.n)
            gi.n += gj.n
            groups.splice(j, 1)
            changed = true
            break
          }
        }
      }
    }
    return groups
      .filter((g) => g.ips.length > 1)
      .map((g) => {
        const [x, y] = pos(g)
        return { x, y, ips: g.ips }
      })
  }, [world, matchedNodes])

  const hubPos = useMemo<[number, number] | null>(() => (anchor && !anchorSynthetic && world ? world.px(anchor.lat, anchor.lon) : null), [anchor, anchorSynthetic, world])

  // ip → drawn XY: cluster members resolve to the badge centroid (their own
  // pins are hidden UNDER the badge), singles to their pin. Arcs and home
  // arcs both consult this, so a line always terminates exactly on the
  // marker the user actually sees.
  const drawnXY = useMemo<Map<string, [number, number]>>(() => {
    const m = new Map<string, [number, number]>()
    for (const c of clusters) for (const ip of c.ips) m.set(ip, [c.x, c.y])
    for (const p of pins) if (!m.has(p.ip)) m.set(p.ip, [p.x, p.y])
    return m
  }, [clusters, pins])

  // Pins of cluster members would pile into a blob UNDER the badge — the
  // badge stands in for them. Pins ON the hub are the home's own address
  // (the hub ring already marks it); their arcs are sub-15px and dropped.
  const visiblePins = useMemo(() => {
    const clustered = new Set(clusters.flatMap((c) => c.ips))
    return pins.filter((p) => {
      if (clustered.has(p.ip)) return false
      if (hubPos && Math.hypot(p.x - hubPos[0], p.y - hubPos[1]) < 18) return false
      return true
    })
  }, [pins, clusters, hubPos])

  // Peers without a drawn marker (unresolved country) get NO arc — endpoints
  // must sit exactly on pins (spec: never draw floating ends).
  const arcJobs = useMemo(() => {
    if (!world) return []
    const jobs: { lat1: number; lon1: number; lat2: number; lon2: number; color: string; bytes: number; protocol: string; srcIp: string; dstIp: string }[] = []
    // Home-anchored arcs, split by direction: outbound (home→peer) = blue,
    // inbound (peer→home) = green — each direction gets its own arc.
    if (anchor) {
      for (const f of mapData.localPublicFlows) {
        if (!drawnXY.has(f.peerIp)) continue
        const n = mapData.nodeMap.get(f.peerIp)
        if (!n) continue
        if (f.outBytes > 0) jobs.push({ lat1: anchor.lat, lon1: anchor.lon, lat2: n.lat, lon2: n.lon, color: pal.out, bytes: f.outBytes, protocol: `${f.protocol} ↦`, srcIp: "HOME", dstIp: f.peerIp })
        if (f.inBytes > 0) jobs.push({ lat1: n.lat, lon1: n.lon, lat2: anchor.lat, lon2: anchor.lon, color: pal.in, bytes: f.inBytes, protocol: `${f.protocol} ↤`, srcIp: f.peerIp, dstIp: "HOME" })
      }
    }
    // Public↔public arcs keep their protocol colors.
    for (const a of mapData.arcs) {
      if (!drawnXY.has(a.srcIp) || !drawnXY.has(a.dstIp)) continue
      jobs.push({ lat1: a.coordinates[0][0], lon1: a.coordinates[0][1], lat2: a.coordinates[a.coordinates.length - 1][0], lon2: a.coordinates[a.coordinates.length - 1][1], color: a.color, bytes: a.bytes, protocol: a.protocol, srcIp: a.srcIp, dstIp: a.dstIp })
    }
    return jobs
  }, [world, drawnXY, mapData, anchor, pal])

  const arcs = useMemo<Arc[]>(() => {
    if (!world) return []
    // HOME isn't a pin: home-anchored jobs resolve to the anchor's own
    // projected position (synthetic ocean anchor included), so local↔public
    // lines draw even when no hub ring is rendered.
    const anchorXY = anchor ? world.px(anchor.lat, anchor.lon) : null
    const out: Arc[] = []
    for (const j of arcJobs) {
      const s = j.srcIp === "HOME" ? anchorXY : drawnXY.get(j.srcIp)
      const d = j.dstIp === "HOME" ? anchorXY : drawnXY.get(j.dstIp)
      if (!s || !d) continue
      // Sub-marker arcs (the home's own ISP-edge pins) are specks shorter
      // than the pin itself — drawing them reads as stray "broken" lines.
      if (Math.hypot(d[0] - s[0], d[1] - s[1]) < 15) continue
      const pts = arcCurvePts(s[0], s[1], d[0], d[1], `${j.srcIp}→${j.dstIp}`)
      pts[pts.length - 1] = [d[0], d[1]]
      out.push({ pts, color: j.color, w: arcWidth(j.bytes), bytes: j.bytes, protocol: j.protocol, srcIp: j.srcIp, dstIp: j.dstIp })
    }
    return out
  }, [arcJobs, world, drawnXY, anchor])

  // Home hub metadata: when the anchor was derived from an owned public IP,
  // its geo record carries the city/country for the hub tooltip.
  const homeMeta = useMemo(() => {
    if (homeAnchor || !localAliases) return null
    for (const ip of localAliases) {
      const loc = geoMap.get(ip)
      if (loc && !loc.isPrivate && loc.countryCode && loc.countryCode !== "??") return loc
    }
    return null
  }, [homeAnchor, localAliases, geoMap])

  // Pan/zoom over the one group. Zoom anchors at a point in SVG space so the
  // content stays under the cursor instead of blowing away from the corner.
  const zoomAt = useCallback((factor: number, cx: number, cy: number) => {
    setView((prev) => zoomView(prev, factor, cx, cy))
  }, [])

  const clientToSvg = useCallback((cx: number, cy: number): [number, number] => {
    const el = frameRef.current
    if (!el) return [SVG_W / 2, SVG_H / 2]
    const r = el.getBoundingClientRect()
    const s = Math.min(r.width / SVG_W, r.height / SVG_H)
    const ox = (r.width - SVG_W * s) / 2
    const oy = (r.height - SVG_H * s) / 2
    return [(cx - r.left - ox) / s, (cy - r.top - oy) / s]
  }, [])

  // React attaches `wheel` as a passive listener (preventDefault is a no-op),
  // so zooming scrolled the page too — bind a native one instead.
  useEffect(() => {
    const el = frameRef.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      if ((e.target as Element).closest("input")) return
      e.preventDefault()
      const [sx, sy] = clientToSvg(e.clientX, e.clientY)
      zoomAt(Math.exp(-e.deltaY * 0.0012), sx, sy)
    }
    el.addEventListener("wheel", onWheel, { passive: false })
    return () => el.removeEventListener("wheel", onWheel)
  }, [clientToSvg, zoomAt])

  // Drag-pan, but only capture the pointer once the gesture is a real drag
  // (>3px). setPointerCapture on every pointerdown retargets the synthesized
  // click to the frame, which silently killed the zoom / fit / fullscreen
  // buttons and pin clicks.
  const onPointerDown = useCallback((e: ReactPointerEvent<HTMLDivElement>) => {
    if (e.button !== 0 || (e.target as HTMLElement).closest("input")) return
    dragRef.current = { sx: e.clientX, sy: e.clientY, vx: viewRef.current.x, vy: viewRef.current.y, active: false }
  }, [])
  const onPointerMove = useCallback((e: ReactPointerEvent<HTMLDivElement>) => {
    const dr = dragRef.current
    if (!dr) return
    if (!dr.active) {
      if (Math.hypot(e.clientX - dr.sx, e.clientY - dr.sy) < 3) return
      dr.active = true
      e.currentTarget.setPointerCapture(e.pointerId)
    }
    setView((prev) => ({ ...prev, x: dr.vx + e.clientX - dr.sx, y: dr.vy + e.clientY - dr.sy }))
  }, [])
  const onPointerUp = useCallback(() => { dragRef.current = null }, [])
  const handleFit = useCallback(() => setView({ k: 1, x: 0, y: 0 }), [])

  // Pin/arc tooltip placement: the wrapped element carries the cursor point
  // as the tooltip's anchor (SVG space × view scale).
  // Tooltip placement from a mouse event: frame-relative CSS pixels.
  const posFromEvent = (e: ReactMouseEvent) => {
    const el = frameRef.current
    if (!el) return null
    const r = el.getBoundingClientRect()
    return { x: e.clientX - r.left, y: e.clientY - r.top }
  }

  // Count what the SVG actually draws — the `arcs` memo already applied the
  // drawnXY/unresolved and >=15px filters. The raw mapData sums counted
  // peers with no pin (no arc renders) and local flows once per peer while
  // two directional arcs are drawn (QA: "DRAWN 500 pkts · 40 FLOWS" for
  // 80 drawn arcs).
  const flowsDrawn = arcs.length
  const bytesDrawn = arcs.reduce((s, a) => s + a.bytes, 0)

  return (
    <MapChrome
      publicIps={mapData.nodes.length}
      flows={flowsDrawn}
      trafficBytes={bytesDrawn}
      homeValue={anchor && !anchorSynthetic ? `${anchor.lat.toFixed(1)}°, ${anchor.lon.toFixed(1)}°` : "Not set"}
      homeSub={anchorSynthetic ? "set Home in Settings for exact lines" : anchorDerived ? "roamed from your router" : "where local arcs anchor"}
      privateHosts={localHosts}
      topCountries={panels.topCountries}
      protoCounts={protoCounts}
      protoTotal={protoTotal}
      hiddenProtocols={new Set()}
      unresolved={mapData.undrawnPublic}
      undecodable={mapData.undecodable}
      focusCountry={focusCountry}
      info={{
        mapType: "Painted · Natural Earth",
        geoDb: onlineGeo ? "Geo-IP + online lookup" : "Geo-IP (offline DB)",
        dataSource: "Local analysis",
      }}
      className={className}
    >
      <div
        ref={frameRef}
        className="flow-map-frame relative overflow-hidden rounded-2xl border"
        style={{ aspectRatio: fullscreen ? undefined : "16 / 9", backgroundColor: pal.ocean }}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={onPointerUp}
      >
        <div className="h-full w-full cursor-grab active:cursor-grabbing" style={{ touchAction: "none" }}>
          {world ? (
            <svg viewBox={`0 0 ${SVG_W} ${SVG_H}`} className="h-full w-full" style={{ userSelect: "none" }}>
              <defs>
                <radialGradient id="hubGrad" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor={HUB_COLOR} stopOpacity="0.55" />
                  <stop offset="100%" stopColor={HUB_COLOR} stopOpacity="0" />
                </radialGradient>
              </defs>
              <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`} style={{ transformOrigin: "0 0" }}>
                <path d={world.graticule} fill="none" stroke={pal.graticule} strokeWidth={0.75} />
                <path d={world.land} fill={pal.land} stroke={pal.border} strokeWidth={0.9} strokeLinejoin="round" />
                {arcs.map((a, i) => {
                  const points = a.pts.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ")
                  const len = a.pts.reduce((s, p, j) => (j > 0 ? s + Math.hypot(p[0] - a.pts[j - 1][0], p[1] - a.pts[j - 1][1]) : 0), 0)
                  const d = Math.min(400 + i * 50, 900)
                  return (
                    <g key={`arc-${i}`}>
                      <polyline points={points} fill="none" stroke="transparent" strokeWidth={Math.max(10, a.w + 8)} vectorEffect="non-scaling-stroke"
                        style={{ pointerEvents: "auto" }}
                        onMouseEnter={(e) => { setHoverArc(a); setHoverArcPos(posFromEvent(e)) }}
                        onMouseLeave={() => { setHoverArc(null); setHoverArcPos(null) }} />
                      <polyline className="arc-draw" points={points} fill="none" stroke={a.color} strokeWidth={a.w} strokeOpacity={0.9} strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke"
                        style={{ strokeDasharray: len, strokeDashoffset: len, animationDelay: `${d}ms`, ["--draw-len" as string]: len }} />
                      <polyline className="arc-overlay" points={points} fill="none" stroke={pal.pinRing} strokeWidth={Math.max(0.8, a.w * 0.35)} strokeOpacity={0.45} strokeLinecap="round" vectorEffect="non-scaling-stroke"
                        style={{ pointerEvents: "none", animationDelay: `${d}ms, ${d + 450}ms` }} />
                    </g>
                  )
                })}
                <AnimatedFlows arcs={arcs} scale={1 / view.k} />
                {hubPos !== null && (
                  <g transform={`translate(${hubPos[0]} ${hubPos[1]}) scale(${1 / view.k})`} style={{ pointerEvents: "auto", cursor: "help" }}
                    onMouseEnter={(e) => { setHoverHub(true); setHoverHubPos(posFromEvent(e)) }}
                    onMouseLeave={() => { setHoverHub(false); setHoverHubPos(null) }}>
                    <g className="pin-pop">
                      <circle cx={0} cy={0} r={44} fill="url(#hubGrad)" opacity={0.6} />
                      <circle className="hub-pulse" cx={0} cy={0} r={13} fill="none" stroke={HUB_COLOR} strokeWidth={2.5} />
                      <circle cx={0} cy={0} r={6.5} fill={HUB_COLOR} stroke={pal.pinRing} strokeWidth={1.4} />
                    </g>
                  </g>
                )}
                {clusters.map((c, i) => (
                  <g key={`c-${i}`} className="cursor-pointer" style={{ pointerEvents: "auto" }}
                    onClick={() => { /* badge: no single country to focus */ }}
                    onMouseEnter={() => setHoverPin(null)} onMouseLeave={() => {}}>
                    <g transform={`translate(${c.x} ${c.y}) scale(${1 / view.k})`}>
                      <g className="pin-pop" style={{ animationDelay: `${Math.min(250 + i * 40, 650)}ms`, pointerEvents: "none" }}>
                        <circle cx={0} cy={0} r={15} fill={pal.badgeFill} stroke={pal.badgeBorder} strokeWidth={1.5} />
                        <text x={0} y={0} textAnchor="middle" dominantBaseline="central" fontSize="14" fontWeight="700" fill={pal.badgeText}>
                          {c.ips.length}
                        </text>
                      </g>
                    </g>
                  </g>
                ))}
                {visiblePins.map((p, i) => (
                  <g key={p.ip} data-pin-ip={p.ip} className="cursor-pointer" style={{ pointerEvents: "auto" }}
                    onClick={() => setFocusCountry((prev) => (p.countryCode && prev === p.countryCode ? null : (p.countryCode || null)))}
                    onMouseEnter={(e) => { setHoverPin(p); setHoverPinPos(posFromEvent(e)) }}
                    onMouseLeave={() => { setHoverPin(null); setHoverPinPos(null) }}>
                    {/* Pins counter-scale with 1/zoom so they hold constant size
                        on screen — the world grows under them, they don't.
                        pointerEvents auto here so a direct hit on the circles
                        drives hover + focus in every engine */}
                    <g transform={`translate(${p.x} ${p.y}) scale(${1 / view.k})`}>
                      <g className="pin-pop" style={{ animationDelay: `${Math.min(i * 30, 300)}ms`, pointerEvents: "auto" }}>
                        <circle cx={0} cy={0} r={p.r + 1.5} fill="#000000" opacity={0.18} />
                        <circle cx={0} cy={0} r={p.r} fill={pal.pin} stroke={p.alert ? "#ef4444" : pal.pinRing} strokeWidth={p.alert ? 2.5 : 1.5} />
                      </g>
                    </g>
                  </g>
                ))}
              </g>
            </svg>
          ) : (
            <div className="flex h-full items-center justify-center">
              <span className="text-sm animate-pulse" style={{ color: pal.label, opacity: 0.6 }}>Rendering map...</span>
            </div>
          )}
        </div>

        {/* Zoom controls */}
        <div className="absolute left-2 top-2 z-10 flex flex-col gap-1 rounded-full border bg-background/90 p-1 shadow-sm">
          <button onClick={() => zoomAt(1.4, SVG_W / 2, SVG_H / 2)} className="h-6 w-6 flex items-center justify-center rounded-full hover:bg-accent text-muted-foreground" title="Zoom in"><ZoomIn className="h-3.5 w-3.5" /></button>
          <button onClick={handleFit} className="h-6 w-6 flex items-center justify-center rounded-full hover:bg-accent text-muted-foreground" title="Fit world"><Maximize className="h-3.5 w-3.5" /></button>
          <button onClick={() => zoomAt(0.72, SVG_W / 2, SVG_H / 2)} className="h-6 w-6 flex items-center justify-center rounded-full hover:bg-accent text-muted-foreground" title="Zoom out"><ZoomOut className="h-3.5 w-3.5" /></button>
        </div>
        <button onClick={toggleFullscreen} title={fullscreen ? "Exit fullscreen" : "View fullscreen"} className="absolute right-2 top-2 z-10 h-8 w-8 flex items-center justify-center rounded-full border bg-background/90 text-muted-foreground shadow-sm hover:bg-accent transition-colors">
          <Maximize2 className="h-3.5 w-3.5" />
        </button>

        {/* IP / location search filter */}
        <div className="absolute left-1/2 top-2 z-10 flex -translate-x-1/2 items-center gap-1.5 rounded-full border bg-background/90 px-3 py-1 shadow-sm">
          <Search className="h-3 w-3 shrink-0 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter IP, city, country…"
            className="h-5 w-36 sm:w-44 bg-transparent text-[11px] text-foreground outline-none placeholder:text-muted-foreground"
            title="Show only pins and flows matching this IP or location"
          />
          {q && <button onClick={() => setSearch("")} className="shrink-0 text-muted-foreground hover:text-foreground" title="Clear filter"><X className="h-3 w-3" /></button>}
          {q && <span className="shrink-0 text-[9px] tabular-nums text-muted-foreground">{matchedNodes.length}</span>}
        </div>

        {/* Legend chips — float ABOVE the captions row (bottom-10) so the
            chips never sit on the caption text (QA: HOME/DESTINATION chips
            crushed the "CAPTURE · HOME …" caption at bottom-4). */}
        <div className="pointer-events-none absolute right-4 bottom-10 z-10 flex max-w-[46%] flex-wrap justify-end gap-x-2.5 gap-y-1.5">
          {[
            { label: "Home", glyph: <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: HUB_COLOR, boxShadow: `0 0 0 2px ${pal.pinRing}` }} /> },
            { label: "Destination", glyph: <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: pal.pin, boxShadow: "0 0 0 2px #fff" }} /> },
            { label: "Outbound", glyph: <span className="inline-block h-0.5 w-4 rounded-full" style={{ background: pal.out }} /> },
            { label: "Inbound", glyph: <span className="inline-block h-0.5 w-4 rounded-full" style={{ background: pal.in }} /> },
          ].map((chip) => (
            <span key={chip.label} className="flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] uppercase tracking-wide bg-background/90 text-foreground">
              {chip.glyph} {chip.label}
            </span>
          ))}
        </div>

        {/* Captions: drawn bytes vs capture span. Legend floats ABOVE this
            row now, so the old pr-48 clearance is gone; bumped to text-sm
            (QA: bottom-left read too small). */}
        <div className="pointer-events-none absolute inset-x-0 bottom-4 z-10 flex justify-between px-3 text-sm font-medium uppercase tracking-widest" style={{ color: pal.footer }}>
          <span className="font-mono tabular-nums">DRAWN {formatBytes(bytesDrawn)} · {mapData.totalPackets.toLocaleString()} PKTS · {flowsDrawn.toLocaleString()} FLOWS</span>
          <span className="font-mono tabular-nums hidden sm:inline">CAPTURE {durationS}s · HOME {anchor && !anchorSynthetic ? `${anchor.lat.toFixed(1)} ${anchor.lon.toFixed(1)}` : "—"}{anchorDerived ? " (DERIVED)" : ""}</span>
        </div>

        {/* Tooltips */}
        {anchor && hoverHub && hoverHubPos && (
          <div className="pointer-events-none absolute z-30 max-w-[240px] rounded-md border bg-background/95 px-3 py-2 text-[11px] shadow-lg"
            style={{ left: `${hoverHubPos.x}px`, top: `${hoverHubPos.y}px`, transform: "translateY(-50%)" }}>
            <div className="font-semibold">Home Network</div>
            {homeMeta && <div className="text-xs">{homeMeta.city ? `${homeMeta.city}, ` : ""}{homeMeta.country}</div>}
            <div className="text-muted-foreground">⇢ {anchor.lat.toFixed(3)}°, {anchor.lon.toFixed(3)}°</div>
            <div className="text-muted-foreground">{anchorDerived ? "anchor derived from your router's public address" : "anchor set in Settings"}</div>
          </div>
        )}
        {hoverPin && hoverPinPos && (
          <div className="pointer-events-none absolute z-30 max-w-[240px] rounded-md border bg-background/95 px-3 py-2 text-[11px] shadow-lg"
            style={{ left: `${hoverPinPos.x}px`, top: `${hoverPinPos.y}px`, transform: "translateY(-50%)" }}>
            <div className="font-mono font-semibold">{hoverPin.ip}</div>
            <div className="text-xs">{nodeLabelOf(hoverPin.n)}</div>
            <div className="text-muted-foreground">{formatBytes(hoverPin.n.bytes)} · {hoverPin.n.packets.toLocaleString()} pkts · {hoverPin.n.connections} conns</div>
            <div className="text-muted-foreground">⇣ {formatBytes(hoverPin.n.bytesRecv)} in ⇡ {formatBytes(hoverPin.n.bytesSent)} out</div>
            {hoverPin.n.localConns ? <div className="text-warning">↔ your local network ({hoverPin.n.localConns} conns)</div> : null}
            {Object.entries(hoverPin.n.protocols).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([p, c]) => `${p} ×${c}`).join(", ") && (
              <div className="text-muted-foreground">{Object.entries(hoverPin.n.protocols).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([p, c]) => `${p} ×${c}`).join(", ")}</div>
            )}
          </div>
        )}
        {hoverArc && hoverArcPos && (
          <div className="pointer-events-none absolute z-30 max-w-[260px] rounded-md border bg-background/95 px-2.5 py-1.5 text-[10px] shadow"
            style={{ left: `${hoverArcPos.x}px`, top: `${hoverArcPos.y}px` }}>
            <span className="font-mono font-semibold">{hoverArc.srcIp} → {hoverArc.dstIp}</span>
            <span className="text-muted-foreground"> · {hoverArc.protocol} · {formatBytes(hoverArc.bytes)}</span>
          </div>
        )}

        {/* Footer note */}
        <p className="pointer-events-none absolute inset-x-0 bottom-0 px-2 py-0.5 pr-40 text-[9px]" style={{ color: pal.footer, opacity: 0.65 }}>
          Private-IP nodes are never drawn on the map — they have no geography.
        </p>
      </div>
    </MapChrome>
  )
}