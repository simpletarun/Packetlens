// Scratch agent-audit probe (not a test). Usage: npx tsx tests/temp-agent-probe.ts <file1> <file2> ...
// Prints a compact per-capture summary from the engine for semantic review.
import { readFileSync } from "node:fs"
import { parsePcap } from "../src/lib/pcap"
import { analyzePcap } from "../src/lib/analysis"
import { computeStats } from "../src/lib/stats"
import { buildReportAnalysis } from "../src/lib/report"
import type { JobSummary } from "../src/stores/analysis"

const jobSummary = (j: ReturnType<typeof analyzePcap>["job"]): JobSummary =>
  ({ ...j, status: "done", progress: 100, stage: "complete" })

async function main() {
  const files = process.argv.slice(2)
  for (const file of files) {
    const name = file.split(/[\\/]/).pop() ?? file
    try {
      const parsed = await parsePcap(readFileSync(file))
      const a = analyzePcap(parsed)
      const stats = computeStats({
        job: jobSummary(a.job), packets: a.packets, flows: a.flows, sessions: a.sessions,
        dns: a.dns, devices: a.devices, alerts: a.threats, geo: new Map(),
      })
      const report = buildReportAnalysis({
        job: jobSummary(a.job), jobInfo: { isDemo: false },
        alerts: a.threats, packets: a.packets, flows: a.flows,
        sessions: a.sessions, tls: a.tls, http: a.http,
        timeline: a.timeline, bandwidth: a.bandwidth, advancedMetrics: a.advancedMetrics,
      })
      const proto = new Map<string, number>()
      for (const p of a.packets) proto.set(p.protocol ?? "?", (proto.get(p.protocol ?? "?") ?? 0) + 1)
      const topProto = [...proto.entries()].sort((x, y) => y[1] - x[1]).slice(0, 4).map(([p, c]) => `${p}:${c}`).join(" ")
      const alerts = a.threats.map((t) => `${t.ruleId}#${t.severity}/${t.confidence} ${t.srcIp}->${t.dstIp} "${(t.evidence ?? "").slice(0, 110).replace(/"/g, "'")}"`).join(" || ")
      const risk = report.risk
      console.log(JSON.stringify({
        name,
        packets: a.packets.length, flows: a.flows.length, sessions: a.sessions.length,
        localDevices: stats.devices, externalIps: stats.externalIps,
        durationSec: +(a.job.captureDuration || 0).toFixed(1),
        dnsQueries: a.packets.filter((p) => (p.appProtocol ?? p.protocol) === "DNS").length, dnsLookups: a.dns.length,
        http: a.http.length, tls: a.tls.length, files: a.files.length, creds: a.credentials.length,
        certs: a.certificates.length, calls: a.calls.length,
        topProto,
        alerts: a.threats.length,
        risk: { score: a.job.riskScore, level: risk?.levelLabel ?? "-", burst: risk?.burstApplied ?? false, raw: +(risk?.rawScore ?? 0).toFixed(1) },
        iocs: report.iocs.map((i) => `${i.type}(${i.severity})`).join(",") || "-",
        mitre: report.mitre.map((m) => m.id).join(",") || "-",
        recs: report.recommendations.length,
        issues: (risk?.items ?? []).filter((i) => Number.isNaN(i.contribution) || !Number.isFinite(i.contribution)).length,
      }))
    } catch (e) {
      console.log(JSON.stringify({ name, ERROR: String(e).slice(0, 200) }))
    }
  }
}

main()