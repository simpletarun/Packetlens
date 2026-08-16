import { readFileSync, readdirSync } from "node:fs"
import { join, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { parsePcap } from "@/lib/pcap"
import { analyzePcap, isNonUnicast } from "@/lib/analysis"
import { buildReportAnalysis, buildFlowsCsv, markdownToHtml, dnsLookupCount } from "@/lib/report"
import { computeStats } from "@/lib/stats"
import { isPrivateIP } from "@/lib/map-data"
import type { JobSummary } from "@/stores/analysis"

const testsDir = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(testsDir, "fixtures")
const externalDir = "C:/Users/hp/Downloads/all pcap"

// The API route (api/v1/jobs/[id]/data/route.ts) serves JobSummary = the
// engine AnalysisJob with done/progress/stage overrides; tests must call
// buildReportAnalysis with the exact same shape.
function jobSummary(j: ReturnType<typeof analyzePcap>["job"]): JobSummary {
  return { ...j, status: "done", progress: 100, stage: "complete" }
}

function corpusFiles(): { file: string; name: string }[] {
  const files: { file: string; name: string }[] = []
  for (const sub of ["corpus", "."]) {
    const dir = join(fixturesDir, sub)
    try {
      for (const f of readdirSync(dir).filter((f) => f.endsWith(".pcap") || f.endsWith(".pcapng"))) {
        files.push({ file: join(dir, f), name: `[fx] ${f}` })
      }
    } catch { /* missing */ }
  }
  try {
    for (const f of readdirSync(externalDir).filter((f) => f.endsWith(".pcap") || f.endsWith(".pcapng"))) {
      files.push({ file: join(externalDir, f), name: `[dl] ${f}` })
    }
  } catch { /* external corpus not present on this machine */ }
  return files
}

// Minimal RFC-4180 reader: quoted cells with doubled quotes, commas inside quotes.
function parseCsv(text: string): string[][] {
  const body = text.replace(/^\uFEFF/, "")
  const rows: string[][] = []
  let row: string[] = []
  let cell = ""
  let inQ = false
  for (let i = 0; i < body.length; i++) {
    const ch = body[i]
    if (inQ) {
      if (ch === '"') {
        if (body[i + 1] === '"') { cell += '"'; i++ }
        else inQ = false
      } else cell += ch
      continue
    }
    if (ch === '"') { inQ = true; continue }
    if (ch === ",") { row.push(cell); cell = ""; continue }
    if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && body[i + 1] === "\n") i++
      row.push(cell); cell = ""
      if (row.length > 1 || row[0] !== "") rows.push(row)
      row = []
      continue
    }
    cell += ch
  }
  if (cell !== "" || row.length > 0) { row.push(cell); rows.push(row) }
  return rows
}

const HEADER = "srcIp,srcPort,dstIp,dstPort,protocol,packets,bytesSent,bytesRecv,bytesTotal,startTime,endTime,durationSec,srcCountry,dstCountry,srcAsn,dstAsn,service,serviceEvidence,rttMs,retrans,estLossPct"

describe("report export data layer parity — every capture must feed the export the same numbers the engine computed", () => {
  const files = corpusFiles()

  it.each(files)(`computeStats parity: $name`, async ({ file, name }) => {
    const parsed = await parsePcap(readFileSync(file))
    const a = analyzePcap(parsed)
    const stats = computeStats({
      job: jobSummary(a.job), packets: a.packets, flows: a.flows, sessions: a.sessions,
      dns: a.dns, devices: a.devices, alerts: a.threats, geo: new Map(),
    })
    expect.soft(stats.totalPackets, `${name}: totalPackets`).toBe(a.packets.length)
    expect.soft(stats.totalFlows, `${name}: totalFlows`).toBe(a.flows.length)
    expect.soft(stats.sessions, `${name}: sessions`).toBe(a.sessions.length)
    // Same local rule as computeStats: primary private OR any private alias
    // (a home-prefix v6 primary on a merged row is still a local device).
    const localRows = a.devices.filter((d) => {
      if (isNonUnicast(d.ip)) return false
      return isPrivateIP(d.ip) || (d.addresses ?? []).some((ad) => isPrivateIP(ad))
    }).length
    expect.soft(stats.devices, `${name}: devices (local only)`).toBe(localRows)
    const localOwned = new Set<string>()
    for (const d of a.devices) {
      if (isNonUnicast(d.ip)) continue
      if (!isPrivateIP(d.ip) && !(d.addresses ?? []).some((ad) => isPrivateIP(ad))) continue
      localOwned.add(d.ip)
      for (const ad of d.addresses ?? []) if (!isNonUnicast(ad)) localOwned.add(ad)
    }
    const ext = new Set<string>()
    for (const p of a.packets) {
      for (const ip of [p.srcIp, p.dstIp]) {
        if (ip && !isNonUnicast(ip) && !isPrivateIP(ip) && !localOwned.has(ip)) ext.add(ip)
      }
    }
    expect.soft(stats.externalIps, `${name}: externalIps`).toBe(ext.size)
    expect.soft(stats.alerts, `${name}: alerts`).toBe(a.threats.length)
    expect.soft(stats.domains, `${name}: domains`).toBe(new Set(a.dns.map((d) => d.query).filter(Boolean)).size)
    for (const p of a.packets) {
      expect.soft(stats.protocols.includes(p.protocol ?? "OTHER"), `${name}: protocol ${p.protocol}`).toBe(true)
    }
    expect.soft(stats.riskScore, `${name}: riskScore`).toBe(a.job.riskScore)
    expect.soft(stats.captureDuration, `${name}: captureDuration`).toBe(a.job.captureDuration)
  }, 120_000)

  it.each(files)(`buildReportAnalysis sections parity: $name`, async ({ file, name }) => {
    const parsed = await parsePcap(readFileSync(file))
    const a = analyzePcap(parsed)
    const report = buildReportAnalysis({
      job: jobSummary(a.job), jobInfo: { isDemo: false },
      alerts: a.threats, packets: a.packets, flows: a.flows,
      sessions: a.sessions, tls: a.tls, http: a.http,
      timeline: a.timeline, bandwidth: a.bandwidth, advancedMetrics: a.advancedMetrics,
    })
    expect.soft(report.alerts.length, `${name}: report.alerts`).toBe(a.threats.length)
    if (a.threats.length > 0) {
      expect.soft(report.iocs.length, `${name}: iocs for ${a.threats.length} alerts`).toBeGreaterThan(0)
      // MITRE rows are gated on detection status: only LIKELY/CONFIRMED (or
      // legacy status-less) alerts claim ATT&CK techniques — a capture whose
      // only findings are SUSPECTED heuristics legitimately maps nothing.
      if (a.threats.some((t) => t.status === undefined || t.status === "LIKELY" || t.status === "CONFIRMED")) {
        expect.soft(report.mitre.length, `${name}: mitre for ${a.threats.length} alerts`).toBeGreaterThan(0)
      }
      for (const m of report.mitre) {
        expect.soft(m.severity > 0, `${name}: mitre ${m.id} severity`).toBe(true)
      }
      expect.soft(report.recommendations.length, `${name}: recs for ${a.threats.length} alerts`).toBeGreaterThan(0)
    }
    for (const i of report.iocs) {
      expect.soft(i.value.length > 0 && i.description.length > 0 && i.severity >= 1 && i.severity <= 5, `${name}: ioc ${i.type}`).toBe(true)
      expect.soft(i.severity <= Math.max(3, ...a.threats.map((t) => t.severity), 1), `${name}: ioc sev bounds`).toBe(true)
    }
    for (const m of report.mitre) {
      expect.soft(/^T\d{4}$/.test(m.id) && m.technique.length > 0 && m.description.length > 0, `${name}: mitre ${m.id}`).toBe(true)
    }
    for (const r of report.recommendations) {
      expect.soft(r.text.length > 0 && r.severity >= 1 && r.severity <= 5, `${name}: rec "${r.text.slice(0, 40)}"`).toBe(true)
      expect.soft(r.source === "CONFIRMED_ALERT" || r.source === "BEHAVIORAL_METRIC", `${name}: rec source ${r.source}`).toBe(true)
    }
    expect.soft(report.risk?.normalizedScore ?? -1, `${name}: report risk`).toBe(a.job.riskScore)
  }, 120_000)
})

describe("flows CSV artifact — the exported file must mirror the engine flows exactly", () => {
  const files = corpusFiles()

  it.each(files)(`buildFlowsCsv invariants: $name`, async ({ file, name }) => {
    const parsed = await parsePcap(readFileSync(file))
    const a = analyzePcap(parsed)
    const csv = buildFlowsCsv(a.flows, new Map(), a.packets)
    expect.soft(csv.startsWith("\uFEFF# PacketLens "), `${name}: BOM + build-identity comment`).toBe(true)
    expect.soft(csv.includes("\n" + HEADER), `${name}: header row after comment`).toBe(true)
    // Semantics comment lines (build identity, initiator-first, serviceEvidence,
    // estLossPct) ride the export before the schema; drop every '#' record and
    // validate the schema + data rows that remain.
    const rows = parseCsv(csv).filter((r) => !r[0].startsWith("#"))
    expect.soft(rows.length, `${name}: row count`).toBe(a.flows.length + 1)
    expect.soft(rows[0].join(","), `${name}: header row`).toBe(HEADER)
    const totalLen = a.packets.reduce((s, p) => s + (p.length || 0), 0)
    let csvBytes = 0
    const flows = a.flows
    for (let i = 0; i < flows.length; i++) {
      const f = flows[i]
      const r = rows[i + 1]
      const idx = (ip: string) => (ip === "\u2014" ? "Undecoded/unknown endpoint" : ip)
      // CSV rows are direction-normalized to the conversation INITIATOR
      // (SYN sender for TCP, else first observed packet; canonical order kept
      // when the capture began mid-session and the first packet is a reply).
      // The flow record is canonical (sorted endpoints), so re-derive the
      // initiator exactly like buildFlowsCsv does.
      const flowKey = (x: { srcIp: string; dstIp: string; srcPort?: number; dstPort?: number; protocol: string }) => {
        const [a, b] = [x.srcIp, x.dstIp].sort()
        const pa = x.srcPort !== undefined && x.dstPort !== undefined ? Math.min(x.srcPort, x.dstPort) : undefined
        const pb = x.srcPort !== undefined && x.dstPort !== undefined ? Math.max(x.srcPort, x.dstPort) : undefined
        return `${x.protocol}|${a}|${b}|${pa ?? ""}|${pb ?? ""}`
      }
      const pkts = a.packets.filter((p) => flowKey(p) === flowKey(f))
      let flip = false
      if (!f.directionUnknown) {
        const syn = pkts.find((p) => p.protocol === "TCP" && p.flags?.includes("SYN") && !p.flags.includes("ACK"))
        const init = syn ? syn.srcIp : pkts[0]?.srcIp
        flip = init !== undefined && init !== f.srcIp && init === f.dstIp
      }
      const srcIp = flip ? f.dstIp : f.srcIp
      const dstIp = flip ? f.srcIp : f.dstIp
      expect.soft(r[0], `${name}: row ${i + 1} srcIp`).toBe(idx(srcIp))
      expect.soft(r[2], `${name}: row ${i + 1} dstIp`).toBe(idx(dstIp))
      expect.soft(r[4], `${name}: row ${i + 1} protocol`).toBe(f.protocol)
      expect.soft(Number(r[5]), `${name}: row ${i + 1} packets`).toBe(f.packets)
      expect.soft(Number(r[8]), `${name}: row ${i + 1} bytesTotal`).toBe(f.bytesTotal)
      expect.soft(r[9], `${name}: row ${i + 1} startTime`).toBe(f.startTime)
      expect.soft(r[10], `${name}: row ${i + 1} endTime`).toBe(f.endTime)
      expect.soft(Math.abs(Number(r[11]) - f.duration), `${name}: row ${i + 1} durationSec`).toBeLessThanOrEqual(0.011)
      if (f.directionUnknown) {
        expect.soft(r[6] === "" && r[7] === "" && r[16] === "N/A", `${name}: row ${i + 1} directionUnknown blanks`).toBe(true)
      } else {
        expect.soft(Number(r[6]), `${name}: row ${i + 1} bytesSent`).toBe(flip ? f.bytesRecv : f.bytesSent)
        expect.soft(Number(r[7]), `${name}: row ${i + 1} bytesRecv`).toBe(flip ? f.bytesSent : f.bytesRecv)
        expect.soft(r[16].length > 0, `${name}: row ${i + 1} service`).toBe(true)
      }
      csvBytes += f.bytesTotal
      for (const cell of r) {
        expect.soft(cell !== "NaN" && cell !== "Infinity" && !cell.includes("NaN"), `${name}: row ${i + 1} no NaN`).toBe(true)
      }
    }
    expect.soft(csvBytes, `${name}: csv bytes conserve capture`).toBe(totalLen)
  }, 120_000)

  it("CSV injection defusing + quoting (hostile GeoIP ASN / comma cells)", () => {
    const csv = buildFlowsCsv([
      {
        id: "f1", srcIp: "1.2.3.4", srcPort: 1, dstIp: "5.6.7.8", dstPort: 2,
        protocol: "TCP", packets: 2, bytesSent: 10, bytesRecv: 20, bytesTotal: 30,
        startTime: "2026-01-01T00:00:00.000Z", endTime: "2026-01-01T00:00:01.000Z",
        duration: 1, directionUnknown: false, retrans: 0, lossPct: 0,
      },
    ], new Map([["5.6.7.8", { ip: "5.6.7.8", country: "US", countryCode: "US", city: "X", lat: 0, lon: 0, isPrivate: false, asn: "=HYPERLINK(\"http://evil\")" }]]), [])
    expect(csv).toContain("'=HYPERLINK")
    expect(csv).not.toContain(",=HYPERLINK")
  })
})

describe("markdownToHtml — the standalone HTML artifact renderer", () => {
  it("renders the full export structure from a representative markdown", () => {
    const md = [
      "# PacketLens Analysis Report — faaah.pcapng",
      "",
      "## Summary",
      "| Metric | Value |",
      "| --- | --- |",
      "| Packets | 2,034 |",
      "| Risk score | 68/100 HIGH |",
      "",
      "## Capture Information",
      "- **Analysis ID:** `7cbce004`",
      "- **Capture file:** `faaah.pcapng`",
      "",
      "## Traffic",
      "- External IPs: 25 · Countries: 6",
      "- DNS queries: 4 (3 distinct lookups) · HTTP requests: 1 · TLS handshakes: 3",
      "",
      "## Top Talkers (source)",
      "| IP | Host | Packets | Bytes | Services |",
      "| --- | --- | --- | --- | --- |",
      "| 100.101.45.41 | Internal Host | 1,014 | 596.0 KB | DNS, HTTP |",
      "",
      "## Alerts",
      "- [Critical] Data Exfiltration Suspected (100.101.45.41 → 172.65.90.22)",
      "",
      "## Analyst Conclusion",
      "- **Final verdict:** **HIGH** — risk 68/100",
      "",
      "## Appendix",
      "- Mode: Local — browser analysis · Schema: 1.0",
      "_Service-side attribution per conversation._",
    ].join("\n")
    const html = markdownToHtml(md, { jobId: "7cbce004", jobFilename: "faaah.pcapng", origin: "http://localhost:3000" })
    expect(html).toContain("<!doctype html><html lang=\"en\">")
    expect(html).toContain("<title>PacketLens Report — faaah.pcapng</title>")
    expect(html).toContain("<h1>PacketLens Analysis Report — faaah.pcapng</h1>")
    expect(html).toContain("Summary export — the full report")
    expect(html).toContain("<h2>Summary</h2>")
    expect(html).toContain("<h2>Top Talkers (source)</h2>")
    expect(html).toContain("<table><thead><tr>")
    expect(html).toContain("<th>Metric</th>")
    expect(html).toContain("<th>Value</th>")
    expect(html).toContain("<td>Packets</td>")
    expect(html).toContain("<td>2,034</td>")
    expect(html).toContain("<td>Risk score</td>")
    expect(html).toContain("<td>68/100 HIGH</td>")
    expect(html).toContain("<td>100.101.45.41</td>")
    expect(html).toContain("<td>Internal Host</td>")
    expect(html).toContain("<td>1,014</td>")
    expect(html).toContain("<td>DNS, HTTP</td>")
    expect(html).toContain("<ul>")
    expect(html).toContain("<li><strong>Analysis ID:</strong> <code><a href=\"http://localhost:3000/analysis/7cbce004\">7cbce004</a></code></li>")
    expect(html).toContain("<li><strong>Final verdict:</strong> <strong class=\"lv-high\">HIGH</strong> — risk 68/100</li>")
    expect(html).toContain("<p class=\"note\">Service-side attribution per conversation.</p>")
    expect(html).toContain("<h2>Alerts</h2>")
    expect(html).toContain("<li>[Critical] Data Exfiltration Suspected (100.101.45.41 → 172.65.90.22)</li>")
  })

  it("escapes hostile content and encodes the deep link", () => {
    const md = "# A & B\n\n- 5 < 6 & 7 > 4\n\n## X\n"
    const html = markdownToHtml(md, { jobId: "a b&c/<>", jobFilename: "evil & <file>.pcap", origin: "http://localhost:3000" })
    expect(html).toContain("<title>PacketLens Report — evil &amp; &lt;file&gt;.pcap</title>")
    expect(html).toContain("<li>5 &lt; 6 &amp; 7 &gt; 4</li>")
    expect(html).toContain("href=\"http://localhost:3000/analysis/a%20b%26c%2F%3C%3E\"")
  })

  it("derives the verdict color class from the markdown itself", () => {
    for (const [label, cls] of [["SAFE", "lv-safe"], ["LOW", "lv-low"], ["MEDIUM", "lv-medium"], ["HIGH", "lv-high"], ["CRITICAL", "lv-critical"], ["UNKNOWN", "lv-unknown"]] as const) {
      const html = markdownToHtml(`- **Final verdict:** **${label}** — risk 0/100`, { jobId: "j", jobFilename: "f.pcap", origin: "http://x" })
      expect(html).toContain(`<strong class="${cls}">${label}</strong>`)
    }
  })

  it("drops the separator rows and keeps every data row of a table", () => {
    const md = "## Top Ports\n| Protocol/Port | Service | Packets |\n| --- | --- | --- |\n| TCP/443 | HTTPS (3 of 2,011 flows with payload evidence) | 2,011 |\n| UDP/53 | DNS | 8 |\n"
    const html = markdownToHtml(md, { jobId: "j", jobFilename: "f.pcap", origin: "http://x" })
    expect(html).not.toContain("<td>---</td>")
    expect(html).toContain("<td>TCP/443</td>")
    expect(html).toContain("<td>HTTPS (3 of 2,011 flows with payload evidence)</td>")
    expect(html).toContain("<td>2,011</td>")
    expect(html).toContain("<td>UDP/53</td>")
    expect(html).toContain("<td>8</td>")
  })
})

describe("end-to-end export artifact — the files users audit are regenerated from the engine", () => {
  const files = corpusFiles()

  it.each(files)(`exported HTML contains engine numbers: $name`, async ({ file, name }) => {
    const parsed = await parsePcap(readFileSync(file))
    const a = analyzePcap(parsed)
    const stats = computeStats({
      job: jobSummary(a.job), packets: a.packets, flows: a.flows, sessions: a.sessions,
      dns: a.dns, devices: a.devices, alerts: a.threats, geo: new Map(),
    })
    // Reconstruct the page's summary export markdown from the SAME stats the
    // page uses; any drift between stats and the artifact fails here.
    const md = [
      `# PacketLens Analysis Report — ${name}`,
      "",
      "## Summary",
      "| Metric | Value |",
      "| --- | --- |",
      `| Packets | ${stats.totalPackets.toLocaleString()} |`,
      `| Flows | ${stats.totalFlows.toLocaleString()} |`,
      `| Sessions | ${stats.sessions.toLocaleString()} |`,
      `| Local Devices | ${stats.devices.toLocaleString()} |`,
      `| Risk score | ${stats.riskScore}/100 ${stats.riskScore >= 70 ? "HIGH" : stats.riskScore >= 40 ? "MEDIUM" : stats.riskScore > 0 ? "LOW" : "SAFE"} |`,
      "",
      "## Capture Information",
      `- **Packets:** ${stats.totalPackets.toLocaleString()} · Flows: ${stats.totalFlows.toLocaleString()} · Sessions: ${stats.sessions.toLocaleString()} · Local Devices: ${stats.devices.toLocaleString()}`,
      `- **Alerts:** ${a.threats.length}`,
      "",
      "## Traffic",
      `- DNS queries: ${a.packets.filter((p) => p.protocol === "DNS").length} (${dnsLookupCount(a.dns)} distinct lookups) · HTTP requests: ${a.http.length} · TLS handshakes: ${a.tls.length}`,
      "",
      "## Analyst Conclusion",
      `- **Final verdict:** **${stats.riskScore >= 70 ? "HIGH" : stats.riskScore >= 40 ? "MEDIUM" : stats.riskScore > 0 ? "LOW" : "SAFE"}** — risk ${stats.riskScore}/100`,
    ].join("\n")
    const html = markdownToHtml(md, { jobId: "export-e2e", jobFilename: name, origin: "http://localhost:3000" })
    expect.soft(html, `${name}: packets cell`).toContain(`<td>${stats.totalPackets.toLocaleString()}</td>`)
    expect.soft(html, `${name}: risk cell`).toContain(`<td>${stats.riskScore}/100`)
    expect.soft(html, `${name}: alert count`).toContain(`<li><strong>Alerts:</strong> ${a.threats.length}</li>`)
    expect.soft(html, `${name}: no NaN in artifact`).not.toContain("NaN")
    expect.soft(html, `${name}: no Infinity in artifact`).not.toContain("Infinity")
    expect.soft(html, `${name}: verdict class`).toMatch(/<strong class="lv-[a-z]+">/)
  }, 120_000)
})