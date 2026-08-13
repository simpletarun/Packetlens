import { describe, it, expect, beforeAll, afterEach, vi } from "vitest"
import { render, cleanup, screen, fireEvent, waitFor, act } from "@testing-library/react"
import { StrictMode } from "react"
import cytoscape from "cytoscape"
import { InvestigationGraph } from "@/components/analysis/investigation-graph"

// jsdom has no canvas/ResizeObserver: cytoscape's renderer and the
// component's observer need these stubs to run headless.
beforeAll(() => {
  if (!(globalThis as unknown as Record<string, unknown>).ResizeObserver) {
    ;(globalThis as unknown as Record<string, unknown>).ResizeObserver = class { observe() {} unobserve() {} disconnect() {} }
  }
  ;(globalThis as unknown as Record<string, unknown>).__ctxStub = new Proxy({}, {
    get: (_, prop) => {
      if (prop === "measureText") return () => ({ width: 10, actualBoundingBoxLeft: 0, actualBoundingBoxRight: 10 })
      if (prop === "canvas") return undefined
      if (prop === "getImageData") return () => ({ data: [] })
      return () => ({ addColorStop: () => {} })
    },
    set: () => true,
  })
  HTMLCanvasElement.prototype.getContext = (() => (globalThis as unknown as Record<string, unknown>).__ctxStub) as unknown as typeof HTMLCanvasElement.prototype.getContext
})

const PROPS = {
  packets: [
    { srcIp: "192.168.1.5", dstIp: "8.8.8.8", protocol: "TCP", srcPort: 50000, dstPort: 443 },
    { srcIp: "192.168.1.5", dstIp: "8.8.4.4", protocol: "UDP", srcPort: 5353, dstPort: 53 },
  ],
  flows: [
    { srcIp: "192.168.1.5", dstIp: "8.8.8.8", protocol: "TCP", packets: 12, bytesTotal: 10240, duration: 3.2 },
    { srcIp: "192.168.1.5", dstIp: "8.8.4.4", protocol: "UDP", packets: 3, bytesTotal: 512, duration: 0.5 },
  ],
  dns: [{ query: "example.com", srcIp: "192.168.1.5", dstIp: "8.8.8.8", type: "A" }],
  http: [{ method: "GET", uri: "/", host: "example.com", srcIp: "192.168.1.5", dstIp: "93.184.216.34" }],
  tls: [{ sni: "example.com", srcIp: "192.168.1.5", dstIp: "93.184.216.34", version: "TLSv1.3" }],
  files: [],
  credentials: [],
  certificates: [],
  devices: [{ ip: "192.168.1.5", hostname: "laptop", mac: "aa:bb:cc:dd:ee:ff", vendor: "Intel", os: "Windows" }],
  alerts: [{ signature: "SYN Flood Attempt", srcIp: "192.168.1.5", dstIp: "8.8.8.8", severity: 4 }],
}

function spyOnErrors() {
  const spy = vi.spyOn(console, "error").mockImplementation(() => {})
  return spy
}

describe("InvestigationGraph render pipeline (StrictMode)", () => {
  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
  })

  it("loads elements and shows the real node count, not '0 shown'", async () => {
    const spy = spyOnErrors()
    render(
      <StrictMode>
        <InvestigationGraph {...PROPS} />
      </StrictMode>,
    )
    // Expected nodes: pcap, 3 ip (192.168.1.5, 8.8.8.8, 8.8.4.4),
    // proto:TCP, proto:UDP, dns, http, tls, device, alert = 11
    // All visible → counter reads "11 nodes" (no " · N shown" suffix).
    const counter = await screen.findByText(/^11 nodes(?: · \d+ shown)?$/)
    expect(counter.textContent).not.toContain("· 0 shown")
    // The misleading empty-state must not appear.
    expect(screen.queryByText(/0 of \d+ nodes match/)).toBeNull()
    expect(screen.queryByText("No network data to display")).toBeNull()
    // PDF export was removed from the graph toolbar; PNG/SVG remain.
    expect(screen.queryByTitle("Export PDF")).toBeNull()
    expect(screen.queryByTitle("Export PNG")).not.toBeNull()
    expect(screen.queryByTitle("Export SVG")).not.toBeNull()
    // No unhandled errors during mount, data load, layout, and filtering.
    const realErrors = spy.mock.calls.filter((args) =>
      !String(args[0]).includes("act(") && !String(args[0]).includes("StrictMode"),
    )
    expect(realErrors).toHaveLength(0)
  })

  it("switches layout in real time via the dropdown", async () => {
    // cytoscape's Core class is not exported; spy on the shared core prototype.
    const probe = cytoscape({ headless: true })
    const layoutSpy = vi.spyOn(Object.getPrototypeOf(probe), "layout")
    probe.destroy()
    spyOnErrors()
    render(
      <StrictMode>
        <InvestigationGraph {...PROPS} />
      </StrictMode>,
    )
    await screen.findByText(/^11 nodes(?: · \d+ shown)?$/)
    const callsBefore = layoutSpy.mock.calls.length
    expect(callsBefore).toBeGreaterThan(0)

    fireEvent.change(screen.getByDisplayValue("Breadthfirst"), { target: { value: "random" } })

    // The layout must actually re-run with the new name — not be swallowed
    // by the data-unchanged guard (that was the real-time switch bug).
    expect(layoutSpy.mock.calls.length).toBeGreaterThan(callsBefore)
    const lastCall = layoutSpy.mock.calls[layoutSpy.mock.calls.length - 1]
    expect((lastCall[0] as { name?: string }).name).toBe("random")
    // Nodes stay visible after the switch.
    const counter = await screen.findByText(/^11 nodes(?: · \d+ shown)?$/)
    expect(counter.textContent).not.toContain("· 0 shown")
  })

  it("cose never runs animated — its rAF loop would crash on a destroyed core", async () => {
    // Persisted layout from a previous session (user had selected COSE).
    localStorage.setItem("packetlens-graph-layout", "cose")
    const probe = cytoscape({ headless: true })
    const layoutSpy = vi.spyOn(Object.getPrototypeOf(probe), "layout")
    probe.destroy()
    spyOnErrors()
    render(
      <StrictMode>
        <InvestigationGraph {...PROPS} />
      </StrictMode>,
    )
    await screen.findByText(/^11 nodes(?: · \d+ shown)?$/)
    const coseCalls = layoutSpy.mock.calls.filter(
      (call) => (call[0] as { name?: string }).name === "cose",
    )
    expect(coseCalls.length).toBeGreaterThan(0)
    for (const call of coseCalls) {
      // The data effect must never override cose's animate:false — that
      // re-armed its continuous rAF loop and crashed after core destroy.
      expect((call[0] as { animate?: unknown }).animate).toBe(false)
    }
    localStorage.removeItem("packetlens-graph-layout")
  })

  it("context-menu guard uses valid element API — elements have no destroyed()", () => {
    const cy = cytoscape({ headless: true })
    cy.add({ data: { id: "a", type: "ip" } })
    const node = cy.getElementById("a")
    // Regression: the old guard called node.destroyed(), which only exists on
    // the core, so every right-click menu click threw "node.destroyed is not
    // a function". Elements expose removed() instead.
    expect(typeof (node as unknown as Record<string, unknown>).destroyed).toBe("undefined")
    expect(typeof node.removed).toBe("function")
    expect(node.removed()).toBe(false)
    node.remove()
    expect(node.removed()).toBe(true)
    cy.destroy()
  })

  it("info panel auto-hides after right-click actions and closes on outside interaction", async () => {
    // Capture the live core + its node-contextmenu handler (cytoscape's
    // trigger() strips custom event fields, so the delegated handler is
    // invoked directly with a synthetic event instead).
    const probe = cytoscape({ headless: true })
    const proto = Object.getPrototypeOf(probe) as unknown as { on: (...a: unknown[]) => unknown; json: (...a: unknown[]) => unknown }
    const origOn = proto.on
    const origJson = proto.json
    let live: cytoscape.Core | null = null
    let cxtHandler: ((evt: unknown) => void) | null = null
    const captureCore = (c: cytoscape.Core) => { live = c }
    vi.spyOn(proto, "json").mockImplementation(function (this: cytoscape.Core, ...args: unknown[]) {
      captureCore(this)
      return origJson.apply(this, args as never) as never
    })
    vi.spyOn(proto, "on").mockImplementation(function (this: cytoscape.Core, ...args: unknown[]) {
      const evt = args[0] as string
      const selOrFn = args[1] as string | ((evt: unknown) => void)
      if (evt === "cxttap" && typeof selOrFn === "string" && typeof args[2] === "function") {
        cxtHandler = args[2] as (evt: unknown) => void
      }
      return origOn.apply(this, args as never) as never
    })
    probe.destroy()
    spyOnErrors()
    const { container } = render(
      <StrictMode>
        <InvestigationGraph {...PROPS} />
      </StrictMode>,
    )
    await screen.findByText(/^11 nodes(?: · \d+ shown)?$/)
    expect(live).not.toBeNull()
    expect(cxtHandler).not.toBeNull()
    const node = live!.$("node").first()
    const openContextMenu = () => {
      act(() => { cxtHandler!({ target: node, originalEvent: { clientX: 100, clientY: 100 } }) })
    }
    const infoPanel = () => container.querySelector("pre")

    // Right-click a node → Focus Node → the panel appears...
    openContextMenu()
    fireEvent.click(screen.getByText("Focus Node"))
    expect(infoPanel()).not.toBeNull()
    // ...then hides itself once the work is done (the auto-hide bug: it
    // stayed open forever until the user clicked the X or the background).
    await waitFor(() => expect(infoPanel()).toBeNull(), { timeout: 3000 })

    // Interacting with UI outside the graph hides the panel too.
    openContextMenu()
    fireEvent.click(screen.getByText("Highlight Neighbors"))
    expect(infoPanel()).not.toBeNull()
    act(() => { document.body.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true })) })
    expect(infoPanel()).toBeNull()
  })

  it("background data changes must re-layout WITHOUT fit/animation (no auto-zoom)", async () => {
    spyOnErrors()
    const probe = cytoscape({ headless: true })
    const layoutSpy = vi.spyOn(Object.getPrototypeOf(probe), "layout")
    probe.destroy()
    const { rerender } = render(
      <StrictMode>
        <InvestigationGraph {...PROPS} />
      </StrictMode>,
    )
    await screen.findByText(/^11 nodes(?: · \d+ shown)?$/)
    const callsBefore = layoutSpy.mock.calls.length
    expect(callsBefore).toBeGreaterThan(0)
    // A background refresh: a new alert arrives (a new node, new edges).
    const moreAlerts = { ...PROPS, alerts: [...PROPS.alerts, { signature: "Port Scan Detected", srcIp: "192.168.1.5", dstIp: "1.1.1.1", severity: 3 }] }
    rerender(
      <StrictMode>
        <InvestigationGraph {...moreAlerts} />
      </StrictMode>,
    )
    await waitFor(() => {
      expect(layoutSpy.mock.calls.length).toBeGreaterThan(callsBefore)
    })
    // The refresh layout must be silent: no fit (viewport stays where the
    // user zoomed), no animation (no slow zoom glide) — the old code re-ran
    // every data refresh with fit:true/animate per pref = the "automatic
    // zoom in and out, fast and slow" bug.
    const [refreshCall] = layoutSpy.mock.calls.slice(-1)[0] as [Record<string, unknown>]
    expect(refreshCall.fit).toBe(false)
    expect(refreshCall.animate).toBe(false)
  })

  it("chip toggle isolates a type from the all-active state, then toggles additively", async () => {
    spyOnErrors()
    // Capture the live core so the header count can be checked against what
    // the renderer actually draws (counter == rendered policy).
    const probe = cytoscape({ headless: true })
    const proto = Object.getPrototypeOf(probe) as unknown as { json: (...a: unknown[]) => unknown }
    const origJson = proto.json
    let live: cytoscape.Core | null = null
    const captureCore = (c: cytoscape.Core) => { live = c }
    vi.spyOn(proto, "json").mockImplementation(function (this: cytoscape.Core, ...args: unknown[]) {
      captureCore(this)
      return origJson.apply(this, args as never) as never
    })
    probe.destroy()
    render(
      <StrictMode>
        <InvestigationGraph {...PROPS} />
      </StrictMode>,
    )
    // Default: all 11 node types active → counter without suffix.
    const counter = await screen.findByText(/^11 nodes(?: · \d+ shown)?$/)
    expect(counter.textContent).not.toContain("·")
    expect(live).not.toBeNull()

    // Click "DNS" with everything active → isolates DNS (1 DNS node shown).
    // (The old toggle deleted the clicked type instead, so "IPs" hid IPs
    // while every other chip stayed lit — the "plural chips don't work" bug.)
    fireEvent.click(screen.getByRole("button", { name: "DNS" }))
    expect((await screen.findByText(/^11 nodes · \d+ shown$/)).textContent).toContain("· 1 shown")
    // Counter == rendered: exactly the DNS node is drawn.
    expect(live!.nodes(":visible").length).toBe(1)

    // Click "IPs" → adds the type: DNS node + 3 IP nodes = 4 shown.
    fireEvent.click(screen.getByRole("button", { name: "IPs" }))
    expect((await screen.findByText(/^11 nodes · \d+ shown$/)).textContent).toContain("· 4 shown")
    expect(live!.nodes(":visible").length).toBe(4)

    // Click "DNS" again → removed: only the 3 IP nodes shown.
    fireEvent.click(screen.getByRole("button", { name: "DNS" }))
    expect((await screen.findByText(/^11 nodes · \d+ shown$/)).textContent).toContain("· 3 shown")
    expect(live!.nodes(":visible").length).toBe(3)

    // "All" restores the full set.
    fireEvent.click(screen.getByRole("button", { name: "All" }))
    const allCounter = await screen.findByText(/^11 nodes(?: · \d+ shown)?$/)
    expect(allCounter.textContent).not.toContain("·")
    expect(live!.nodes(":visible").length).toBe(11)

    // The DNS node aggregates ALL record types for the domain, not just the
    // first record's type.
    const info = live!.getElementById("dns:example.com").data("info") as string
    expect(info).toContain("Records: A ×1")
    expect(info).toContain("Queries: 1")
  })

  it("search spotlight renders neighbor context and counts it (counter == rendered)", async () => {
    spyOnErrors()
    const probe = cytoscape({ headless: true })
    const proto = Object.getPrototypeOf(probe) as unknown as { json: (...a: unknown[]) => unknown }
    const origJson = proto.json
    let live: cytoscape.Core | null = null
    const captureCore = (c: cytoscape.Core) => { live = c }
    vi.spyOn(proto, "json").mockImplementation(function (this: cytoscape.Core, ...args: unknown[]) {
      captureCore(this)
      return origJson.apply(this, args as never) as never
    })
    probe.destroy()
    render(
      <StrictMode>
        <InvestigationGraph {...PROPS} />
      </StrictMode>,
    )
    await screen.findByText(/^11 nodes(?: · \d+ shown)?$/)

    // "example.com" matches the DNS/HTTP/TLS nodes (3) — spotlight keeps
    // their 1-hop IP neighbors: 8.8.8.8 is a real node (in flows), while
    // 93.184.216.34 is not (PROPS flows only have 192.168.1.5→8.8.8.8), so
    // 4 nodes render AND are counted: the header may not say "3 shown"
    // while the canvas draws 4 (the old counter-vs-canvas disagreement).
    fireEvent.change(screen.getByPlaceholderText("Search IPs, hosts, alerts..."), { target: { value: "example.com" } })
    const counter = await screen.findByText(/^11 nodes · \d+ shown$/)
    expect(counter.textContent).toContain("· 4 shown")
    expect(live!.nodes(":visible").length).toBe(4)
  })

  it("chips for empty types are hidden entirely (B-53); excluded non-empty types are dimmed but never struck", async () => {
    // PROPS have no files/credentials/certificates — those chips must not
    // render at all (the old struck+disabled style still cluttered the bar).
    spyOnErrors()
    render(
      <StrictMode>
        <InvestigationGraph {...PROPS} />
      </StrictMode>,
    )
    await screen.findByText(/^11 nodes(?: · \d+ shown)?$/)
    for (const label of ["Files", "Credentials", "Certificates"]) {
      expect(screen.queryByRole("button", { name: label })).toBeNull()
    }
    // Non-empty types stay enabled.
    expect((screen.getByRole("button", { name: "DNS" }) as HTMLButtonElement).disabled).toBe(false)
    expect((screen.getByRole("button", { name: "IPs" }) as HTMLButtonElement).disabled).toBe(false)

    // Excluded-but-non-empty must read differently from empty: after
    // isolating DNS, IPs (non-empty, excluded) is dimmed but NOT struck —
    // the old style struck it exactly like a zero-node type ("same state,
    // two looks" the other way).
    fireEvent.click(screen.getByRole("button", { name: "DNS" }))
    const ipsChip = screen.getByRole("button", { name: "IPs" }) as HTMLButtonElement
    expect(ipsChip.disabled).toBe(false)
    expect(ipsChip.className).not.toContain("line-through")
  })
})
