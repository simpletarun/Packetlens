"use client"

import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { useAnalysisStore } from "@/stores/analysis"
import { formatDuration } from "@/lib/stats"
import { formatBytes } from "@/lib/map-data"
import { riskLevel, riskColorClass } from "@/lib/risk"
import { buildReportAnalysis, decodeRateOf } from "@/lib/report"
import { useMemo } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import {
  Package, GitFork, Monitor, Globe, AlertTriangle,
  Shield, BarChart3, Clock, HardDrive, Loader2
} from "lucide-react"

const beginnerLabels: Record<string, string> = {
  "Total Packets": "Total Packets",
  "Total Flows": "Total Conversations",
  "Devices": "Devices Found",
  "Local Devices": "Devices Found",
  "External IPs": "External Addresses",
  "Countries": "Countries",
  "Domains": "Websites Visited",
  "Protocols": "Protocols Used",
  "Alerts": "Suspicious Events",
  "Risk Score": "Risk Level",
  "Capture Duration": "Time Span",
  "File Size": "File Size",
}

// Sessions == flows by construction (one session per conversation) — showing
// both cards as "Connections"/"Total Conversations" duplicated the same number.
// The flows card is the keeper.
const summaryCards = [
  { key: "totalPackets", label: "Total Packets", icon: Package, color: "text-info", chip: "bg-info/10" },
  { key: "totalFlows", label: "Total Flows", icon: GitFork, color: "text-chart-2", chip: "bg-chart-2/10" },
  { key: "devices", label: "Local Devices", icon: Monitor, color: "text-chart-1", chip: "bg-chart-1/10" },
  { key: "externalIps", label: "External IPs", icon: Globe, color: "text-chart-4", chip: "bg-chart-4/10" },
  { key: "countries", label: "Countries", icon: Globe, color: "text-chart-5", chip: "bg-chart-5/10" },
  { key: "domains", label: "Domains", icon: Globe, color: "text-info", chip: "bg-info/10" },
  { key: "protocols", label: "Protocols", icon: BarChart3, color: "text-chart-2", chip: "bg-chart-2/10" },
  { key: "alerts", label: "Alerts", icon: AlertTriangle, color: "text-danger", chip: "bg-danger/10" },
  { key: "riskScore", label: "Risk Score", icon: Shield, color: "text-warning", chip: "bg-warning/10" },
  { key: "captureDuration", label: "Capture Duration", icon: Clock, color: "text-chart-3", chip: "bg-chart-3/10" },
  { key: "fileSize", label: "File Size", icon: HardDrive, color: "text-chart-1", chip: "bg-chart-1/10" },
]

export default function AnalysisPage() {
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const sidebarOpen = useAnalysisStore((s) => s.sidebarOpen)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const job = useAnalysisStore((s) => s.currentJob)
  const stats = useAnalysisStore((s) => s.stats)
  const alerts = useAnalysisStore((s) => s.alerts)
  const packets = useAnalysisStore((s) => s.packets)
  const flows = useAnalysisStore((s) => s.flows)
  const sessions = useAnalysisStore((s) => s.sessions)
  const tls = useAnalysisStore((s) => s.tls)
  const http = useAnalysisStore((s) => s.http)
  const timeline = useAnalysisStore((s) => s.timeline)
  const bandwidth = useAnalysisStore((s) => s.bandwidth)
  const advancedMetrics = useAnalysisStore((s) => s.advancedMetrics)
  const jobInfo = useAnalysisStore((s) => s.jobInfo)
  const decode = useAnalysisStore((s) => s.decode)

  const report = useMemo(() => buildReportAnalysis({
    job, jobInfo, alerts, packets, flows, sessions, tls, http, timeline, bandwidth, advancedMetrics,
  }), [job, jobInfo, alerts, packets, flows, sessions, tls, http, timeline, bandwidth, advancedMetrics])

  // Same verdict gate as the reports page: <5% decoded → no verdict, so the
  // badge/card must not read "0/100 SAFE" on undecodable traffic (QA).
  const undecodable = useMemo(() => decodeRateOf(decode, packets) < 0.05, [decode, packets])
  const riskScore = report.risk?.normalizedScore ?? job?.riskScore ?? 0
  // Verdict label from the report: the score band FLOORED by the strongest
  // finding severity. The raw band alone would label a capture carrying a
  // HIGH-severity alert "LOW" at 39/100 — the dashboard badge must agree
  // with the report verdict (QA).
  const riskLabel = report.risk?.levelLabel ?? riskLevel(riskScore).label
  const riskColor = report.risk?.levelColor ?? riskLevel(riskScore).color
  const riskLevelObj = { label: riskLabel, color: riskColor }
  const displayTimeline = report.timeline
  // Folded loop: Math.max(...spread) over thousands of timeline bins throws
  // RangeError on very long captures (QA).
  let maxTimelinePackets = 1
  for (const x of displayTimeline) if (x.packets > maxTimelinePackets) maxTimelinePackets = x.packets

  if (!job) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-sm text-muted-foreground">Loading analysis...</p>
        </div>
      </div>
    )
  }

  const sevColors: Record<number, string> = { 5: "destructive", 4: "destructive", 3: "warning", 2: "default", 1: "default" }
  const topThreats = alerts.slice(0, 5)

  return (
    <div className="flex h-screen">
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />
      <div className={cn("flex-1 flex flex-col transition-all duration-300 min-w-0", sidebarOpen ? "lg:ml-56" : "lg:ml-16")}>
        <Header />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold">Dashboard</h1>
              <p className="text-sm text-muted-foreground">
                {job.filename} &mdash; {beginnerMode ? "Analysis Results" : "Network Traffic Analysis"}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant={undecodable ? "secondary" : riskColor === "red" ? "destructive" : riskColor === "orange" || riskColor === "yellow" ? "warning" : "success"}>
                {undecodable ? "UNKNOWN / INSUFFICIENT DATA" : `${riskScore}/100 ${riskLevelObj.label}`}
              </Badge>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
            {summaryCards.map((card) => {
              const raw = card.key === "fileSize" ? job.fileSize : card.key === "riskScore" ? riskScore : stats[card.key as keyof typeof stats]
              let val: string
              if (card.key === "fileSize") val = formatBytes(Number(raw))
              else if (card.key === "captureDuration") val = formatDuration(Number(raw))
              else if (card.key === "riskScore") val = undecodable ? "N/A — insufficient data" : `${raw}/100 ${riskLevelObj.label}`
              else if (card.key === "countries" && Number(raw) === 0) val = stats.externalIps === 0 ? "No public IPs" : "GeoIP unavailable"
              else if (card.key === "protocols") val = (raw as string[])?.length ? (raw as string[]).join(", ") : "—"
              else val = String(raw ?? "—")
              const label = beginnerMode ? (beginnerLabels[card.label] || card.label) : card.label
              const color = card.key === "riskScore" ? (undecodable ? "text-muted-foreground" : riskColorClass(riskLevelObj)) : card.color
              return (
                <Card
                  key={card.key}
                  className="transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md hover:border-primary/30"
                >
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
                    <span className={cn("p-1.5 rounded-md", card.chip)}>
                      <card.icon className={cn("h-4 w-4", color)} />
                    </span>
                  </CardHeader>
                  <CardContent>
                    <div className={card.key === "riskScore" ? cn("text-2xl font-bold", color) : "text-2xl font-bold"}>{val}</div>
                  </CardContent>
                </Card>
              )
            })}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-lg">{beginnerMode ? "Activity" : "Traffic Timeline"}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1">
                  {displayTimeline.length === 0 && (
                    <p className="py-6 text-center text-xs text-muted-foreground">No timeline data in this capture</p>
                  )}
                  {displayTimeline.slice(0, 12).map((t) => (
                    <div key={t.time} className="flex items-center gap-3 text-xs">
                      <span className="w-10 text-muted-foreground font-mono">{t.time}</span>
                    <div className="flex-1 h-4 bg-muted rounded-full overflow-hidden flex">
                      <div
                        className="h-full bg-info bg-gradient-to-r from-info to-chart-2 rounded-full transition-all"
                        style={{ width: (t.packets / maxTimelinePackets * 100) + "%" }}
                      />
                    </div>
                      <span className="w-8 text-right text-muted-foreground">{t.packets}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-lg">{beginnerMode ? "Recent Alerts" : "Alerts"}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {topThreats.length > 0 ? topThreats.map((a) => (
                  <div key={a.id} className="text-xs space-y-1 pb-2 border-b border-border/50 last:border-0">
                    <div className="flex items-center gap-2">
                      <Badge variant={sevColors[a.severity] as "destructive" | "warning" | "default"} className="text-[10px] px-1 py-0">
                        {a.category}
                      </Badge>
                      <span className="text-muted-foreground">{a.signature}</span>
                      <span className="ml-auto text-[10px] text-muted-foreground font-mono whitespace-nowrap">conf {a.confidence}%</span>
                    </div>
                    <p className="text-muted-foreground">{a.srcIp} &rarr; {a.dstIp}</p>
                    {/* The dashboard must show WHY an alert fired, not just
                        that it did (QA). */}
                    {a.evidence && <p className="text-muted-foreground/80 leading-snug">{a.evidence}</p>}
                  </div>
                )) : (
                  <p className="text-sm text-muted-foreground">No {beginnerMode ? "suspicious activity" : "alerts"} detected.</p>
                )}
              </CardContent>
            </Card>
          </div>
        </main>
      </div>
    </div>
  )
}
