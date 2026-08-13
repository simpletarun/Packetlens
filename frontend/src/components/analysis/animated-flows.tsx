// Animated IP→IP flow overlay: a glowing packet travels each arc from source
// to destination, trailed by a fading blue ribbon (#3DAFFF head → #0057FF
// glow), and the destination pin swells once on arrival. One shared rAF loop
// writes DOM attributes directly (no React render per frame = 60fps). Trail =
// two stroked paths with pathLength={1} so a single dash [0, T] slides along
// the path via strokeDashoffset. Restart is clean because the trails hide
// during the destination pulse.
// ponytail: no SVG blur filter — two opacity layers fake the glow, add the
// filter only if the visuals demand it.

import { useEffect, useMemo, useRef, useState } from "react"

const SPEED = 120        // base px/s along the path — moderate, consistent
const SPEED_SPREAD = 0.6 // per-flow speed factor varies 0.7×–1.3× of base
const STAGGER = 0.8      // s between consecutive flow starts
const START_DELAY = 1.1  // s: wait for the arc's draw-in (max 0.9s) + margin —
                         // a dot running on a not-yet-drawn line reads as a
                         // stray dot disconnected from the routes
const PULSE_S = 0.45     // destination hold before restart
const HEAD_F = 0.09      // bright head trail as fraction of path length
const GLOW_F = 0.3       // wider, dimmer outer trail
const HEAD_COLOR = "#3DAFFF"
const GLOW_COLOR = "#0057FF"
const MAX_FLOWS = 48

interface FlowArc {
  pts: [number, number][]
  bytes: number
  srcIp?: string
  dstIp?: string
}

interface FlowEls {
  glow: SVGPathElement | null
  head: SVGPathElement | null
  halo: SVGCircleElement | null
  dot: SVGCircleElement | null
}

interface Flow {
  pts: [number, number][]
  cum: number[]
  total: number
  speed: number
  phase: number
  idx: number
  arrived: boolean
  dstIp?: string
}

function cumLengths(pts: [number, number][]) {
  const cum = [0]
  for (let i = 1; i < pts.length; i++) cum.push(cum[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]))
  return cum
}

function pointAt(f: Flow, d: number): [number, number] {
  const { pts, cum } = f
  let i = Math.max(1, f.idx)
  while (i < cum.length - 1 && cum[i] < d) i++
  while (i > 1 && cum[i - 1] > d) i--
  f.idx = i
  const t = (d - cum[i - 1]) / (cum[i] - cum[i - 1])
  return [pts[i - 1][0] + (pts[i][0] - pts[i - 1][0]) * t, pts[i - 1][1] + (pts[i][1] - pts[i - 1][1]) * t]
}

// Destination pin pulse: reuses the pin element the map already renders
// (found by the data-pin-ip marker) so arrival feedback stays on the map's
// own markers — the overlay never draws its own. HOME has no pin; its hub
// already breathes.
function pulseDestinationPin(e: FlowEls, dstIp?: string) {
  if (!dstIp || dstIp === "HOME") return
  const svg = e.dot?.ownerSVGElement
  const pin = svg?.querySelector<SVGGElement>(`[data-pin-ip="${dstIp}"]`)
  if (!pin) return
  const cs = pin.querySelectorAll("circle")
  const circle = cs[cs.length - 1]
  if (!circle) return
  circle.style.setProperty("--pin-r", circle.getAttribute("r") ?? "3")
  circle.classList.remove("pin-arrival")
  void circle.getBoundingClientRect() // reflow so a rapid re-arrival retriggers
  circle.classList.add("pin-arrival")
  setTimeout(() => circle.classList.remove("pin-arrival"), 600)
}

function updateFlow(f: Flow, e: FlowEls | null, t: number, s: number) {
  if (!e) return
  const travel = f.total / f.speed
  const cycle = travel + PULSE_S
  // Before the flow's staggered start the dot waits at the SOURCE. The
  // double-modulo wrapped negative times to cycle-end — dots spawned near
  // their destination and pulsed the pin on mount (QA).
  const pos = t < f.phase ? 0 : (t - f.phase) % cycle
  let p: number
  let pul = 0
  if (pos >= travel) { p = 1; pul = Math.min(1, (pos - travel) / PULSE_S) } else p = pos / travel
  if (pul > 0 && !f.arrived) { f.arrived = true; pulseDestinationPin(e, f.dstIp) }
  else if (p < 1) f.arrived = false
  const [x, y] = pointAt(f, p * f.total)
  if (p < 1) {
    e.glow?.setAttribute("stroke-dashoffset", `${-p}`)
    e.head?.setAttribute("stroke-dashoffset", `${-p}`)
    e.glow?.setAttribute("stroke-opacity", "0.18")
    e.head?.setAttribute("stroke-opacity", "0.95")
  } else {
    e.glow?.setAttribute("stroke-opacity", "0")
    e.head?.setAttribute("stroke-opacity", "0")
  }
  const swell = Math.sin(pul * Math.PI)
  e.halo?.setAttribute("transform", `translate(${x} ${y}) scale(${s})`)
  e.halo?.setAttribute("r", `${6.5 + 4 * swell}`)
  e.halo?.setAttribute("opacity", `${0.4 - 0.15 * pul}`)
  e.dot?.setAttribute("transform", `translate(${x} ${y}) scale(${s})`)
  e.dot?.setAttribute("r", `${2.6 + 1.8 * swell}`)
}

export default function AnimatedFlows({ arcs, scale }: { arcs: FlowArc[]; scale: number }) {
  const flowArcs = useMemo(
    () => [...arcs].sort((a, b) => b.bytes - a.bytes).slice(0, MAX_FLOWS),
    [arcs],
  )
  const [reduced] = useState(() => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches)
  const layerRef = useRef<SVGGElement | null>(null)
  const elsRef = useRef<(FlowEls | null)[]>([])
  const flowsRef = useRef<Flow[]>([])
  const scaleRef = useRef(scale)
  const reducedRef = useRef(false)

  useEffect(() => {
    reducedRef.current = window.matchMedia("(prefers-reduced-motion: reduce)").matches
  }, [])

  useEffect(() => {
    scaleRef.current = scale
  }, [scale])

  // Rebuild whenever the connection set changes: new analysis, search filter,
  // geo re-resolution — stale flows would animate lines that no longer exist.
  useEffect(() => {
    flowsRef.current = flowArcs
      .map((a) => ({ pts: a.pts, cum: cumLengths(a.pts), total: cumLengths(a.pts)[a.pts.length - 1] ?? 0, srcIp: a.srcIp, dstIp: a.dstIp }))
      .filter((f) => f.total >= 1)
      .map((f, i) => ({
        ...f,
        speed: SPEED * (0.7 + (i % 7) * SPEED_SPREAD / 6),
        phase: START_DELAY + i * STAGGER,
        idx: 1,
        arrived: false,
      }))
    const els: (FlowEls | null)[] = []
    for (const g of layerRef.current?.querySelectorAll<SVGGElement>("g[data-flow]") ?? []) {
      els.push({
        glow: g.querySelector<SVGPathElement>("[data-role=glow]"),
        head: g.querySelector<SVGPathElement>("[data-role=head]"),
        halo: g.querySelector<SVGCircleElement>("[data-role=halo]"),
        dot: g.querySelector<SVGCircleElement>("[data-role=dot]"),
      })
    }
    elsRef.current = els
  }, [flowArcs])

  useEffect(() => {
    if (reducedRef.current) return
    let raf = 0
    const t0 = performance.now()
    const tick = (now: number) => {
      const t = (now - t0) / 1000
      const els = elsRef.current
      const flows = flowsRef.current
      for (let i = 0; i < flows.length; i++) updateFlow(flows[i], els[i] ?? null, t, scaleRef.current)
      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [])

  if (flowArcs.length === 0 || reduced) return null

  return (
    <g ref={layerRef} pointerEvents="none" aria-hidden>
      {flowArcs.map((a, i) => {
        const d = a.pts.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ")
        return (
          <g key={i} data-flow>
            <path data-role="glow" d={d} pathLength={1} fill="none" stroke={GLOW_COLOR} strokeWidth={5} vectorEffect="non-scaling-stroke"
              strokeLinecap="round" strokeLinejoin="round" strokeOpacity={0.12}
              strokeDasharray={`${GLOW_F} ${1 - GLOW_F}`} strokeDashoffset={0} />
            <path data-role="head" d={d} pathLength={1} fill="none" stroke={HEAD_COLOR} strokeWidth={3.2} vectorEffect="non-scaling-stroke"
              strokeLinecap="round" strokeLinejoin="round" strokeOpacity={0.95}
              strokeDasharray={`${HEAD_F} ${1 - HEAD_F}`} strokeDashoffset={0} />
            <circle data-role="halo" r={6.5} fill={HEAD_COLOR} opacity={0.4} transform={`translate(${a.pts[0][0]} ${a.pts[0][1]})`} />
            <circle data-role="dot" r={2.6} fill="#ffffff" transform={`translate(${a.pts[0][0]} ${a.pts[0][1]})`} />
          </g>
        )
      })}
    </g>
  )
}
