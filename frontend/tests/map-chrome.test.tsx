import { render } from "@testing-library/react"
import { describe, it, expect } from "vitest"
import { ProtoDonut, MapChrome } from "@/components/analysis/map-chrome"

describe("ProtoDonut", () => {
  it("renders real color stops in the conic-gradient (QA: string destructure emitted character garbage, donut had no slices)", () => {
    const { container } = render(<ProtoDonut protoCounts={[["TCP", 60], ["UDP", 30], ["DNS", 10]]} protoTotal={100} />)
    const ring = container.querySelector("[role=img]")
    expect(ring).not.toBeNull()
    const style = (ring as HTMLElement).getAttribute("style") ?? ""
    // jsdom normalizes hex to rgb() in the serialized attribute; the shape is
    // what matters — real color stops at the right percents (the old bug
    // emitted character garbage like "C P  " and dropped the declaration).
    expect(style).toContain("conic-gradient(from -90deg, rgb(59, 130, 246) 0.00% 60.00%, rgb(34, 197, 94) 60.00% 90.00%, rgb(234, 179, 8) 90.00% 100.00%)")
    // The center must show the packet total.
    expect(container.textContent).toContain("100")
  })

  it("dims hidden protocols to muted-foreground and shows the visible total", () => {
    const { container } = render(<ProtoDonut protoCounts={[["TCP", 70], ["UDP", 30]]} protoTotal={100} hidden={new Set(["TCP"])} />)
    const style = (container.querySelector("[role=img]") as HTMLElement).getAttribute("style") ?? ""
    expect(style).toContain("var(--muted-foreground) 0.00% 70.00%")
    expect(style).toContain("#22c55e 70.00% 100.00%")
    expect(container.textContent).toContain("30")
  })

  it("shows the empty state for zero packets", () => {
    const { container } = render(<ProtoDonut protoCounts={[]} protoTotal={0} />)
    expect(container.textContent).toContain("No packets")
  })
})

describe("MapChrome KPI bar", () => {
  it("renders all five KPI chips with label + value + sub (QA: chips showed only sub fragments, no titles or values)", () => {
    const { container } = render(
      <MapChrome
        publicIps={5}
        flows={7}
        trafficBytes={10813}
        homeValue="Not set"
        homeSub="not set — local↔internet arcs are not drawn"
        privateHosts={2}
        topCountries={[{ name: "United States", code: "US", bytes: 10813 }]}
        protoCounts={[["TCP", 100]]}
        protoTotal={100}
        hiddenProtocols={new Set()}
        unresolved={[]}
        undecodable={null}
        info={{ mapType: "Globe", geoDb: "GeoIP2", dataSource: "Test" }}
      >
        <div data-testid="map-slot" />
      </MapChrome>
    )
    const text = container.textContent ?? ""
    // Label / value / sub triples — every chip must show all three parts.
    expect(text).toContain("Public IPs")
    expect(text).toContain("5")
    expect(text).toContain("drawn on the map")
    expect(text).toContain("Flows Drawn")
    expect(text).toContain("7")
    expect(text).toContain("one arc per peer, per direction")
    expect(text).toContain("Total Traffic")
    expect(text).toContain("10.6 KiB")
    expect(text).toContain("sum across drawn arcs")
    expect(text).toContain("Home Network")
    expect(text).toContain("Not set")
    expect(text).toContain("not set — local↔internet arcs are not drawn")
    expect(text).toContain("Private Hosts")
    expect(text).toContain("2")
  })
})