"use client"

import { useMemo } from "react"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { cn } from "@/lib/utils"
import { binPackets, buildBandwidth, packetEpochSec } from "@/lib/report"
import { formatBytes } from "@/lib/map-data"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Zap } from "lucide-react"

function fmtClock(sec: number): string {
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = Math.round(sec % 60)
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`
}
export default function TimelinePage() {
  const timeline = useAnalysisStore((s) => s.timeline)
  const bandwidth = useAnalysisStore((s) => s.bandwidth)
  const packets = useAnalysisStore((s) => s.packets)
  const decode = useAnalysisStore((s) => s.decode)
  const burst = useAnalysisStore((s) => s.burst)
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  // Undecodable captures (unsupported link type) carry no addresses, so the
  // in/out direction split would be fabricated (every byte lands in "in").
  // Same gate as the report verdict: <5% decoded → direction unknown.
  const undecodable = useMemo(() => {
    if (decode && decode.total > 0) return decode.decoded / decode.total < 0.05
    if (packets.length === 0) return false
    return packets.filter((p) => p.srcIp !== "\u2014" || p.dstIp !== "\u2014").length / packets.length < 0.05
  }, [decode, packets])

  // The store timeline is 5-minute buckets — for short captures that
  // collapses an 88s capture into ONE bar. Rebin from the packets (1s/5s bins
  // like the report) so the page matches the report's shape (M4).
  const durationSec = useMemo(() => {
    if (packets.length < 2) return 1
    const span = packetEpochSec(packets[packets.length - 1]) - packetEpochSec(packets[0])
    return Math.max(Math.round(span), 1)
  }, [packets])

  const displayTimeline = useMemo(
    () => (durationSec > 600 && timeline.length >= 2 ? timeline : binPackets(packets, durationSec)),
    [timeline, packets, durationSec]
  )
  // buildBandwidth always: long captures keep the store's 5-min series (with
  // each bucket divided by its real overlap), short ones rebin — the raw
  // store path rendered 5-min SUMS as "/s", 300x the true rate (QA).
  const displayBandwidth = useMemo(
    () => buildBandwidth(packets, bandwidth, durationSec),
    [bandwidth, packets, durationSec]
  )

  // Folded loops, not Math.max(...spread): bins are capped at 120 by
  // binPackets but the store timeline grows with capture length — a spread
  // over >~125k entries throws RangeError on very long captures.
  let maxPkts = 1
  for (const t of displayTimeline) if (t.packets > maxPkts) maxPkts = t.packets
  let maxBw = 1
  for (const b of displayBandwidth) if (b.in + b.out > maxBw) maxBw = b.in + b.out

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          <div>
            <h1 className="text-lg font-bold mb-1">{beginnerMode ? "Activity Timeline" : "Timeline"}</h1>
            <p className="text-xs text-muted-foreground">Network activity over time</p>
          </div>

          {burst?.detected && (
            <Card className="border-danger/30">
              <CardContent className="flex items-center gap-3 py-3 text-xs">
                <Zap className="h-4 w-4 text-danger shrink-0" />
                <span className="font-semibold text-danger">Traffic Burst</span>
                <span className="text-muted-foreground">·</span>
                <span className="font-mono">{burst.ratio.toFixed(1)}× average</span>
                <span className="text-muted-foreground">·</span>
                <span className="font-mono">{burst.duration.toFixed(1)} s</span>
                <span className="text-muted-foreground">·</span>
                <span className="font-mono">+{fmtClock(burst.start)} – +{fmtClock(burst.end)}</span>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle className="text-base">{beginnerMode ? "Packet Activity" : "Packets Over Time"}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-1">
                <div className="flex text-xs text-muted-foreground mb-2">
                  <span className="w-14">Time</span>
                  <span className="flex-1">Packets</span>
                </div>
                {displayTimeline.map((t) => (
                  <div key={t.time} className="flex items-center gap-3 text-xs">
                    <span className="w-14 text-muted-foreground font-mono">{t.time}</span>
                    <div className="flex-1 h-5 bg-muted rounded-sm overflow-hidden flex">
                      <div className="h-full bg-info transition-all" style={{ width: (t.packets / maxPkts * 100) + "%" }} />
                    </div>
                    <span className="w-16 text-right text-muted-foreground">{t.packets} pkts</span>
                    <span className="w-14 text-right text-muted-foreground">{formatBytes(t.bytes)}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">{beginnerMode ? "Traffic Breakdown" : "Protocol Distribution Over Time"}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-1">
                <div className="flex text-xs text-muted-foreground mb-2">
                  <span className="w-14">Time</span>
                  <span className="flex-1">Protocols</span>
                  <span className="w-8 text-right">TCP</span>
                  <span className="w-8 text-right">UDP</span>
                  <span className="w-8 text-right">DNS</span>
                  <span className="w-8 text-right">TLS</span>
                  <span className="w-10 text-right">Other</span>
                </div>
                {displayTimeline.map((t) => {
                  const other = Math.max(t.packets - t.tcp - t.udp - t.dns - t.tls, 0)
                  const total = t.packets || 1
                  return (
                    <div key={t.time} className="flex items-center gap-3 text-xs">
                      <span className="w-14 text-muted-foreground font-mono">{t.time}</span>
                      <div className="flex-1 h-5 bg-muted rounded-sm overflow-hidden flex">
                        <div className="h-full bg-info" style={{ width: (t.tcp / total * 100) + "%" }} title={"TCP (other): " + t.tcp} />
                        <div className="h-full bg-success" style={{ width: (t.udp / total * 100) + "%" }} title={"UDP: " + t.udp} />
                        <div className="h-full bg-warning" style={{ width: (t.dns / total * 100) + "%" }} title={"DNS: " + t.dns} />
                        <div className="h-full bg-chart-3" style={{ width: (t.tls / total * 100) + "%" }} title={"TLS: " + t.tls} />
                        <div className="h-full bg-muted" style={{ width: (other / total * 100) + "%" }} title={"OTHER: " + other} />
                      </div>
                      <span className="w-8 text-right text-muted-foreground">{t.tcp}</span>
                      <span className="w-8 text-right text-muted-foreground">{t.udp}</span>
                      <span className="w-8 text-right text-muted-foreground">{t.dns}</span>
                      <span className="w-8 text-right text-muted-foreground">{t.tls}</span>
                      <span className="w-10 text-right text-muted-foreground">{other}</span>
                    </div>
                  )
                })}
              </div>
              <div className="flex gap-4 mt-3 text-xs text-muted-foreground flex-wrap">
                <span><span className="inline-block w-2 h-2 bg-info rounded-sm mr-1" />TCP (non-TLS: handshakes, other ports)</span>
                <span><span className="inline-block w-2 h-2 bg-success rounded-sm mr-1" />UDP</span>
                <span><span className="inline-block w-2 h-2 bg-warning rounded-sm mr-1" />DNS</span>
                <span><span className="inline-block w-2 h-2 bg-chart-3 rounded-sm mr-1" />TLS (SNI handshakes)</span>
                <span><span className="inline-block w-2 h-2 bg-muted rounded-sm mr-1" />Other (ICMP, ARP, undecodable…)</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">{beginnerMode ? "Bandwidth Usage" : "Bandwidth Over Time"}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-1">
                <div className="flex text-xs text-muted-foreground mb-2">
                  <span className="w-14">Time</span>
                  <span className="flex-1">Bandwidth</span>
                  {!undecodable && <span className="w-20 text-right">Out</span>}
                  {!undecodable && <span className="w-20 text-right">In</span>}
                  {undecodable && <span className="w-44 text-right">Direction unknown</span>}
                </div>
                {displayBandwidth.map((b) => (
                  <div key={b.time} className="flex items-center gap-3 text-xs">
                    <span className="w-14 text-muted-foreground font-mono">{b.time}</span>
                    <div className="flex-1 h-5 bg-muted rounded-sm overflow-hidden flex">
                      <div className="h-full bg-chart-1 transition-all" style={{ width: ((b.in + b.out) / maxBw * 100) + "%" }} />
                    </div>
                    {undecodable ? (
                      <span className="w-44 text-right text-muted-foreground">{formatBytes(b.in + b.out)}/s — undecodable</span>
                    ) : (
                      <>
                        <span className="w-20 text-right text-muted-foreground">{formatBytes(b.out)}/s</span>
                        <span className="w-20 text-right text-muted-foreground">{formatBytes(b.in)}/s</span>
                      </>
                    )}
                  </div>
                ))}
              </div>
              {undecodable && <p className="text-[10px] text-muted-foreground mt-2">Direction is unknown for undecodable traffic (no addresses parsed) — a single total is shown instead of a fabricated in/out split.</p>}
            </CardContent>
          </Card>
        </main>
      </div>
    </div>
  )
}
