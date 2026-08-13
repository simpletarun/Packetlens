# PacketLens

**Privacy-first, fully local PCAP analysis and security reporting.**

Upload a capture and PacketLens parses it locally and produces a complete
security report — nothing is uploaded to any cloud service, and no account,
telemetry, or analytics are involved.

A capture becomes: a 22-section report (traffic summary, packets, flows,
sessions, DNS, HTTP, TLS, extracted files, VoIP calls, credentials,
certificates, endpoints, timeline, top talkers, alerts, IOCs, MITRE ATT&CK
mappings, a transparent 0–100 risk score, and recommendations), an interactive
investigation graph, a geo-attributed world map, and print-ready
PDF / standalone HTML / SIEM-friendly CSV exports.

## Highlights

- **Fully local analysis** — parsing, detection, and geo attribution all run
  on your machine. The only network touches are opt-in online GeoIP lookups
  (off by default) and a one-time GeoIP database download.
- **Upload analysis** — PCAP/PCAPNG up to 500 MB, rate-limited (5/min per
  address), same-origin guarded, size checked against `Content-Length` before
  buffering.
- **Live demo dataset** — explore every feature without a capture file
  (`/analysis/mock-demo`).
- **Detection & risk** — signature rules (scanning, DNS tunneling, C2
  beaconing, data exfiltration, credential leaks, malware downloads) plus
  behavioral metrics (beacon periodicity, tunneling volume, JA3 anomalies,
  burst detection), unified into a transparent 0–100 risk score
  (risk specification 1.3, published in `frontend/shared/risk-spec.json`).
- **Honest verdicts** — undecodable encapsulations report
  UNKNOWN / INSUFFICIENT DATA instead of a false "clean" score.
- **VoIP & real-time traffic** — SIP (UDP/TCP 5060/5061), RTP/RTCP with SSRC
  tracking, call dialogs unified by Call-ID, SDP `m=` port correlation; STUN
  and QUIC are reported as WebRTC signaling.
- **GeoIP** — auto-installs the free DB-IP City Lite database (~125 MB,
  CC BY 4.0) on first use, or accepts an uploaded MMDB file; online ipwho.is
  lookups are opt-in and off by default.
- **Interactive tools** — a cytoscape investigation graph (search, type
  filters, layouts, display controls, PNG/SVG export) and a d3-geo world map
  (pins sized by traffic, cluster badges, animated arcs, home-anchored
  local↔public flows, pan/zoom/fullscreen).
- **Vendor attribution** — OUI-based device vendor enrichment from the
  bundled registry.
- **Exports** — print-ready PDF report, standalone HTML export, and a
  SIEM-friendly flows CSV (UTF-8 BOM, IPv6-safe split IP/port columns).

## Getting Started

Requires Node.js 20+.

```bash
cd frontend
npm install
npm run dev          # http://localhost:3456
```

Production:

```bash
npm run build        # output: "standalone"
npm start
```

On Windows you can also double-click `start-dev.bat` at the repo root to start
the dev server.

## Architecture

```
packetlens/
├── docs/                        # User guide (HTML + PDF), workboard
└── frontend/
    ├── src/
    │   ├── app/                 # Next.js App Router pages + API routes
    │   │   ├── api/v1/upload/   # PCAP upload + analysis pipeline
    │   │   ├── api/v1/jobs/…    # per-job analysis data
    │   │   └── api/v1/geo/…     # GeoIP DB status / install
    │   ├── lib/                 # pure logic: pcap, analysis, report,
    │   │                         #   risk, map-data, graph-data, geo, mmdb
    │   ├── components/          # UI: report pages, graph, world map, …
    │   └── stores/              # zustand analysis store
    ├── public/                  # world-countries.geojson, OUI registry
    ├── shared/                  # risk spec + parity fixtures
    ├── tests/                   # 353 unit tests (vitest), 29 files
    └── scripts/                 # fetch-geoip, OUI gen, dead-code finders
```

The analysis pipeline is deliberately plain TypeScript on the server
(`parsePcap` → `analyzePcap` → OUI enrichment → job store): no database, no
external services. Job history persists as `~/.packetlens/jobs.json` (capped
at 20 jobs, mode 0600), and the GeoIP database lives in `~/.packetlens/geo/`.

## Scripts

| Command | What it does |
| --- | --- |
| `npm run dev` | Development server on port 3456 |
| `npm run build` | Production build (`output: "standalone"`) |
| `npm start` | Run the production build |
| `npm run lint` | ESLint |
| `npx tsc --noEmit` | Type check |
| `npx vitest run` | Unit tests (analysis, report, parsing, VoIP, exports) |

## Deployment Notes

- Persistent data lives in `~/.packetlens/` (`jobs.json` — analysis history,
  capped at the 20 most recent, mode 0600 — and `geo/` for the GeoIP
  database). Mount a persistent volume there so jobs and the database survive
  restarts.
- Uploads are buffered in memory (500 MB cap): allow ~1.5–2.5 GB RAM per
  concurrent upload.
- Single-instance design: history and rate limiting are per-process.
- Behind a reverse proxy, forward the client address (e.g. `X-Real-IP`) so
  rate limiting keys on real clients.
- The app emits CSP, HSTS, `X-Frame-Options: DENY`, and `nosniff` headers;
  TLS terminates at your proxy.
- Fully offline-capable once built and the GeoIP database is installed — the
  world map uses bundled Natural Earth data, not tile servers.

## Testing

```bash
cd frontend
npx vitest run      # 353 tests across 29 files
npm run lint
npx tsc --noEmit
```

Coverage spans the pcap parser (robustness against malformed captures),
analysis math (flow byte invariants, stream keys, RTT), report generation
(CSV schema, PDF/HTML export), risk scoring parity against the published
spec, GeoIP resolution, graph element building and filtering, map data
derivation, and VoIP call reconstruction.

## Privacy & Security

- All analysis happens locally; uploads are never sent to third parties.
- GeoIP: offline DB-IP MMDB by default; online lookups strictly opt-in.
- Beginner mode masks IP addresses in the investigation graph.
- Same-origin upload guard, per-address rate limiting, strict security
  headers, and no analytics or telemetry.
- See the full [privacy policy](frontend/src/app/privacy/page.tsx).

## Documentation

- [User Guide](docs/PacketLens-User-Guide.html) (PDF in the same folder) —
  covers the report sections, interactive tools, detection & risk model,
  GeoIP, settings, self-hosting, and requirements.
- [Workboard](docs/TODO.md) — delivered fixes, open items, and roadmap.

## Status

- Analyzer version 3.2.0 · report schema 1.0 · risk specification 1.3
- Gates: 353/353 tests, ESLint, TypeScript, production build — all green.