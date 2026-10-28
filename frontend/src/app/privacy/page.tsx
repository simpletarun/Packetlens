import Link from "next/link"
import { Lock, Server, Scale } from "lucide-react"

// Static privacy policy. Facts below are kept in sync with:
//   - frontend/src/app/api/v1/upload/route.ts      (web upload: memory only, 500 MB cap, same-origin, 5/min rate limit)
//   - frontend/src/lib/job-store.ts                (server disk job list, MAX_JOBS = 20, oldest evicted, 0700 dir / 0600 file)
//   - frontend/src/app/api/v1/jobs/[id]/data/route.ts (job reload endpoint; no delete endpoint exists)
//   - frontend/src/stores/analysis.ts              (settings.onlineGeo default false; settings in localStorage)
//   - frontend/src/lib/geo.ts, lib/mmdb.ts         (offline MMDB first; ipwho.is only when the toggle is on)
//   - frontend/src/lib/geo-db-install.ts, lib/db-registry.ts (auto DB-IP City Lite download to ~/.packetlens/geo)

const MATRIX: { data: string; purpose: string; processed: string; stored: string; transferred: string; control: string }[] = [
  {
    data: "Capture files (PCAP / PCAPNG)",
    purpose: "Packet parsing and protocol analysis — the core function of the application.",
    processed: "On the server hosting this deployment.",
    stored: "In server memory for the duration of the request; the capture file itself is not written to disk by the application and is not part of the retained analysis result.",
    transferred: "Uploaded to the hosting server over HTTPS, subject to a 500 MB size limit and rate limiting.",
    control: "Uploading is entirely your choice; the raw file is discarded when the request completes.",
  },
  {
    data: "Network metadata (IP and MAC addresses, ports, protocol headers, timestamps)",
    purpose: "Flow and session reconstruction, device inventory, threat detection, report generation.",
    processed: "On the server hosting this deployment.",
    stored: "As part of the analysis result persisted in the server-side job store.",
    transferred: "Delivered as part of the analysis result to your browser over HTTPS. IP addresses are transmitted to ipwho.is solely when you enable Online GeoIP Lookups (disabled by default).",
    control: "Beginner Mode masks IP addresses in the graph view. Online GeoIP Lookups can be toggled off at any time in Settings.",
  },
  {
    data: "Analysis results (flows, sessions, alerts, credentials, certificates, extracted files)",
    purpose: "Presenting findings in the interface and producing downloadable reports.",
    processed: "On the server hosting this deployment.",
    stored: "Persisted in the server-side job store (~/.packetlens/jobs.json), capped at the 20 most recent analyses with the oldest evicted automatically. The store is not encrypted; the deployment operator can access it.",
    transferred: "None. Results are not transmitted to any third party.",
    control: "Clear Analysis (Settings → Danger Zone) discards the loaded view in your browser only and does not delete the stored results; server-side retention is bounded by the 20-job cap, and the deployment operator can delete the store at any time.",
  },
  {
    data: "Geolocation data (country/city of external IP addresses)",
    purpose: "Geographic attribution on dashboards and map views.",
    processed: "Locally on the server against the offline DB-IP Lite database (CC BY 4.0).",
    stored: "The database is stored on the server in ~/.packetlens/geo; individual lookup results are not retained separately.",
    transferred: "Download of the DB-IP Lite database (~125 MB) on first use; the application does not update or redistribute it. When Online GeoIP Lookups is enabled, only IP addresses not present in the local database are sent to ipwho.is.",
    control: "Leave Online GeoIP Lookups disabled, or remove the database via Settings → GeoIP Database.",
  },
  {
    data: "Application preferences (home coordinates, Beginner Mode, link-layer override, GeoIP toggle)",
    purpose: "Persisting your configuration between sessions.",
    processed: "Locally in your browser (localStorage).",
    stored: "On your device only. Coordinates you enter are stored locally and are never transmitted.",
    transferred: "None.",
    control: "Clear coordinates via Settings → Manual Home Location → Clear; clearing browser storage removes all preferences.",
  },
  {
    data: "Exported reports (HTML, CSV, PDF)",
    purpose: "Downloading analysis results for archival or sharing at your discretion.",
    processed: "Generated entirely in your browser from the analysis data already present.",
    stored: "Only in the file you elect to download.",
    transferred: "None. You determine the destination of any exported file.",
    control: "Exports may embed credentials, certificates, cookies, internal IP addresses, and hostnames from your capture. Treat exported files as sensitive and share them only with people who should see them.",
  },
]

const PROVISIONS: { n: string; title: string; body: string }[] = [
  {
    n: "1",
    title: "Scope and Operator",
    body: "This Privacy Policy describes how PacketLens, a web application, processes data. All processing occurs on the server hosting this deployment; the operator of this deployment acts as the processor for the analysis you initiate, and you decide which captures to submit.",
  },
  {
    n: "2",
    title: "Data We Process",
    body: "The table below is the definitive statement of every category of data the application handles, the purpose of the processing, the location of processing, storage arrangements, any transfers, and the controls available to you.",
  },
  {
    n: "3",
    title: "Purposes and Legal Bases",
    body: "The application processes data solely for the purpose of analyzing the network captures you provide: parsing, protocol decoding, flow and session reconstruction, threat detection, and report generation. Where applicable legal frameworks require a basis (e.g., the GDPR): consent is the basis for analyzing the capture you submit; the legitimate interest of operating a network analysis tool without third-party data sharing is the basis for retaining results, rate limiting, and evicting old jobs. No data is processed for advertising, profiling, or resale.",
  },
  {
    n: "4",
    title: "Processing Locations",
    body: "The capture is transmitted to the hosting server over an encrypted connection; parsing, decoding, and detection execute there, and results are returned to your browser. The application does not employ third-party analytics, telemetry, or advertising services.",
  },
  {
    n: "5",
    title: "Network Communications",
    body: "The application initiates network communications only: (1) the capture upload and job retrieval to this deployment's own server; (2) the optional ipwho.is lookup of unresolved public IP addresses, which occurs exclusively when Online GeoIP Lookups is enabled (disabled by default); and (3) a download of the free DB-IP Lite GeoIP database on first use. All other processing, including DNS resolution used for hostname attribution within your own captures, is performed against data already present in the capture.",
  },
  {
    n: "6",
    title: "Storage and Retention",
    body: "Capture files are held in server memory for the duration of the request and are not written to disk by the application. Completed analyses are persisted in the server-side job store (~/.packetlens/jobs.json), capped at the 20 most recent analyses with the oldest evicted automatically; how long a given analysis remains therefore depends on how frequently new ones are stored. Each stored job is reloadable from its URL; job URLs are unguessable random identifiers and the application has no accounts or login, so anyone in possession of a URL can load the job it points to. The job store is not encrypted, and the deployment operator can access stored analyses and can delete the store at any time by clearing the server's ~/.packetlens directory. Clear Analysis (Settings → Danger Zone) discards the loaded view in your browser only and does not delete stored results. The application itself makes no backups; any backup or replication of the server, including the job store, is the responsibility of the deployment operator.",
  },
  {
    n: "7",
    title: "Your Rights",
    body: "Depending on applicable law, you may have the right to access, rectify, or erase the data processed about you, to restrict or object to processing, and to data portability. The application keeps no account or profile information about you; the network artifacts you submit (for example IP or MAC addresses and hostnames) may constitute personal data in some jurisdictions and are processed as described in this policy. Exercising your rights is therefore equivalent to choosing not to submit captures, relying on the automatic eviction of old jobs, or requesting that the deployment operator clear the server-side job store. If you believe processing violates applicable law, you may also lodge a complaint with your supervisory authority.",
  },
  {
    n: "8",
    title: "Security Measures",
    body: "Transmissions to the hosting server occur over HTTPS. Uploads are restricted to .pcap and .pcapng files, are limited to 500 MB (checked against Content-Length before the body is buffered), are rate-limited per client address, and are rejected from cross-origin callers. The server-side job store is written with file permissions 0600 inside a 0700 directory on platforms that enforce POSIX permissions. Captures are held in memory only, minimizing exposure surface. Note that storage writes can also occur outside the application's control, for example operating-system swap space or temporary buffering by a reverse proxy.",
  },
  {
    n: "9",
    title: "Children's Privacy",
    body: "The application is not directed at children and does not knowingly target anyone under the age of 16. The application does not collect names, email addresses, or other identifiers of natural persons; it processes only network artifacts you choose to submit, which may contain personal data as described in this policy.",
  },
]

export default function PrivacyPage() {
  return (
    <main className="min-h-screen max-w-4xl mx-auto px-4 py-12 space-y-10">
      <header className="space-y-3">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-xs text-muted-foreground">
          <Lock className="h-3 w-3" />
          Privacy Policy
        </div>
        <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight">PacketLens Privacy Policy</h1>
        <p className="text-muted-foreground leading-relaxed">
          This policy governs the processing of data by PacketLens, a network capture analysis web application. It
          describes the categories of data processed, the purposes of processing, processing locations, storage and
          retention, transfers, and the rights available to you. This document is intended to be read in full; Section
          2 contains a complete data handling matrix.
        </p>
      </header>

      <nav className="rounded-lg border p-4 text-sm" aria-label="Table of contents">
        <p className="text-xs uppercase tracking-wide text-muted-foreground mb-2">Contents</p>
        <ol className="list-decimal list-inside space-y-1 text-muted-foreground">
          {PROVISIONS.map((s) => (
            <li key={s.n}>
              <a href={`#s${s.n}`} className="hover:text-foreground underline underline-offset-2">{s.title}</a>
            </li>
          ))}
        </ol>
      </nav>

      <section id="s2" className="space-y-3">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <Scale className="h-5 w-5 text-primary" />
          2. Data Handling Matrix
        </h2>
        <p className="text-sm text-muted-foreground">
          Each row describes one category of data: why it is processed, where, for how long, whether it is
          transferred, and how you can control it.
        </p>
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-left text-sm border-collapse min-w-[880px]">
            <thead>
              <tr className="bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
                <th className="px-3 py-2 border-b">Data</th>
                <th className="px-3 py-2 border-b">Purpose</th>
                <th className="px-3 py-2 border-b">Where processed</th>
                <th className="px-3 py-2 border-b">Storage</th>
                <th className="px-3 py-2 border-b">Transfers</th>
                <th className="px-3 py-2 border-b">Your control</th>
              </tr>
            </thead>
            <tbody>
              {MATRIX.map((row) => (
                <tr key={row.data} className="align-top border-b last:border-b-0 hover:bg-muted/30">
                  <td className="px-3 py-2.5 font-semibold">{row.data}</td>
                  <td className="px-3 py-2.5 text-muted-foreground">{row.purpose}</td>
                  <td className="px-3 py-2.5 text-muted-foreground">{row.processed}</td>
                  <td className="px-3 py-2.5 text-muted-foreground">{row.stored}</td>
                  <td className="px-3 py-2.5 text-muted-foreground">{row.transferred}</td>
                  <td className="px-3 py-2.5 text-muted-foreground">{row.control}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-6">
        {PROVISIONS.filter((s) => s.n !== "2").map((s) => (
          <article key={s.n} id={`s${s.n}`} className="rounded-lg border p-5 space-y-2 scroll-mt-20">
            <h3 className="font-semibold text-lg">
              {s.n}. {s.title}
            </h3>
            <p className="text-sm text-muted-foreground leading-relaxed">{s.body}</p>
          </article>
        ))}
      </section>

      <footer className="pt-6 border-t text-xs text-muted-foreground space-y-2">
        <p className="flex items-center gap-1.5">
          <Server className="h-3 w-3 shrink-0" />
          The application&apos;s processing behavior is documented in its source code: upload handling, job retention,
          GeoIP routing, and the analysis engine are verifiable by inspection.
        </p>
        <p>
          <Link href="/" className="underline underline-offset-2 hover:text-foreground">← Back to PacketLens</Link>
        </p>
      </footer>
    </main>
  )
}