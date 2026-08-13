# PacketLens

> Privacy-first, fully local PCAP analysis and security reporting.

[![Release](https://img.shields.io/badge/release-v3.2.0-blue)](https://github.com/simpletarun/Packetlens/releases/tag/v3.2.0)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-353%20passed-brightgreen)](frontend/tests)
[![Platform](https://img.shields.io/badge/platform-web%20%7C%20offline-lightgrey)](#deployment-notes)

Upload a PCAP/PCAPNG and PacketLens produces a complete security report —
**entirely on your machine**. No cloud, no account, no telemetry.

## How it works

```
┌──────────┐   ┌─────────────┐   ┌──────────────┐   ┌────────────────────────┐
│ You drop │ → │ parsePcap   │ → │ analyzePcap  │ → │ 22-section report +    │
│ a capture│   │ (PCAP/NG)   │   │ + risk score │   │ graph + map + exports  │
└──────────┘   └─────────────┘   └──────────────┘   └────────────────────────┘
```

1. **Upload** — PCAP/PCAPNG up to 500 MB (rate-limited, same-origin guarded)
2. **Parse** — packets, flows, sessions, DNS, HTTP, TLS, files, VoIP, credentials, certificates
3. **Analyze** — detections, behavioral metrics, transparent 0–100 risk score
4. **Explore** — 22-section report, investigation graph, world map
5. **Export** — PDF, standalone HTML, SIEM-friendly CSV

## Quick start

Requires **Node.js 20+**.

```bash
cd frontend
npm install
npm run dev        # → http://localhost:3456
```

Production:

```bash
npm run build && npm start
```

> On Windows, double-click `start-dev.bat` at the repo root instead.

**No capture file?** Open `/analysis/mock-demo` — a built-in demo dataset lets you explore every feature.

## What you get from one capture

| Output | Details |
| --- | --- |
| **Security report** | 22 sections: traffic summary, packets, flows, sessions, DNS, HTTP, TLS, extracted files, VoIP calls, credentials, certificates, endpoints, timeline, top talkers, alerts, IOCs, MITRE ATT&CK mappings, risk score, recommendations |
| **Risk score** | Transparent 0–100 — signature rules + behavioral metrics (risk spec 1.3) |
| **Investigation graph** | Interactive topology — search, type filters, 7 layouts, minimap, PNG/SVG export |
| **World map** | Geo-attributed pins, cluster badges, animated arcs, home-anchored flows — fully offline |
| **Exports** | Print-ready PDF, standalone HTML, SIEM-friendly CSV (UTF-8 BOM, IPv6-safe) |

## Features

### Analysis
- PCAP/PCAPNG upload up to **500 MB** — rate-limited (5/min), same-origin guarded, size checked before buffering
- Flow/session reconstruction with per-direction byte counts and handshake RTT
- VoIP & real-time traffic: **SIP** (UDP/TCP 5060/5061), **RTP/RTCP** with SSRC tracking, call dialogs by Call-ID; STUN/QUIC reported as WebRTC signaling
- **Honest verdicts** — undecodable captures report UNKNOWN instead of a false "clean" score

### Detection & Risk
- Signature rules: scanning, DNS tunneling, C2 beaconing, data exfiltration, credential leaks, malware downloads
- Behavioral metrics: beacon periodicity, tunneling volume, JA3 anomalies, burst detection
- One transparent 0–100 score — spec published at `frontend/shared/risk-spec.json`

### Visualization
- **Investigation graph** — cytoscape: search, type chips, 7 layouts, display controls (sizes, colors, backgrounds), minimap, context menu (focus / pin / hide / highlight)
- **World map** — d3-geo + Natural Earth data: pins sized by traffic, city cluster badges, animated arcs, home-anchored local↔public flows, pan/zoom/fullscreen

### GeoIP & Attribution
- **Offline by default** — auto-installs the free DB-IP City Lite database (~125 MB, CC BY 4.0), or upload your own MMDB
- Online ipwho.is lookups: **opt-in, off by default**
- OUI-based device vendor enrichment from the bundled registry

### Export
- Print-ready PDF, standalone HTML, flows CSV (UTF-8 BOM, split IP/port columns — parses cleanly in Excel, pandas, and SIEMs)

## Who is it for

- **Security analysts & DFIR** — fast triage of a suspicious capture, IOCs, MITRE ATT&CK mappings, exfil detection
- **Network engineers** — traffic health, TCP handshake RTT, top talkers, VoIP verification
- **Students & labs** — learn protocol analysis without sending captures anywhere
- **Air-gapped environments** — analysis, GeoIP, and maps all work with zero internet

## Tech stack

| Layer | Choice |
| --- | --- |
| Framework | Next.js (App Router) + TypeScript |
| State | zustand |
| Graph | cytoscape + cytoscape-svg |
| Map | d3-geo (Natural Earth, bundled — no tile servers) |
| GeoIP | mmdb-lib (DB-IP City Lite) |
| Tests | vitest — **353 tests / 29 files** |

## Project layout

```
packetlens/
├── docs/                 # User guide (HTML + PDF), workboard
└── frontend/
    ├── src/
    │   ├── app/          # Pages + API routes (upload, jobs, geo)
    │   ├── lib/          # Pure logic: pcap, analysis, report, risk,
    │   │                 #   map-data, graph-data, geo, mmdb
    │   ├── components/   # UI: report pages, graph, world map
    │   └── stores/       # zustand analysis store
    ├── public/           # Natural Earth data, OUI registry
    ├── shared/           # Risk spec + parity fixtures
    ├── tests/            # 353 unit tests
    └── scripts/          # fetch-geoip, OUI gen, dead-code finders
```

**How analysis works:** upload → `parsePcap` → `analyzePcap` → OUI enrichment → job store. Plain TypeScript on the server — no database, no external services.

## Deployment notes

- **Persistent data** lives in `~/.packetlens/` (`jobs.json` — 20-job history, mode 0600; `geo/` — the GeoIP database). Mount a volume there to survive restarts.
- **Memory**: uploads buffer in memory (500 MB cap) — allow ~1.5–2.5 GB RAM per concurrent upload.
- **Single instance**: history and rate limiting are per-process.
- **Reverse proxy**: forward the client address (e.g. `X-Real-IP`) so rate limiting keys on real clients.
- **Security headers**: CSP, HSTS, `X-Frame-Options: DENY`, `nosniff` are emitted by the app; TLS terminates at your proxy.
- **Fully offline** once built and the GeoIP DB is installed — the map never needs tile servers.

## FAQ

**Is my capture sent anywhere?**
No. Parsing, analysis, and GeoIP all run locally. The only network touches are opt-in online lookups and a one-time GeoIP database download.

**Can it run without internet?**
Yes — after `npm install`/`npm run build` and the one-time DB-IP download, everything (including the world map) works offline.

**What formats are supported?**
PCAP and PCAPNG (classic + NanoSec link layers).

**Is this a Wireshark replacement?**
Not exactly. Wireshark is for deep packet inspection; PacketLens is for **report generation** — drop a capture, get a structured security report, risk score, and visualizations.

**How many jobs are kept?**
The 20 most recent analyses (in `~/.packetlens/jobs.json`); oldest are evicted automatically.

**Does it need a database or Docker?**
No. It is a single Next.js process with a JSON job store — Node.js 20+ is the only requirement.

## Development

```bash
cd frontend
npm run lint          # ESLint
npx tsc --noEmit      # Type check
npx vitest run        # 353 tests across 29 files
npm run build         # Production build (output: "standalone")
```

Test coverage: pcap parser robustness, analysis math (flow invariants, stream keys, RTT), report generation (CSV/PDF/HTML), risk parity vs the published spec, GeoIP, graph elements/filtering, map data, VoIP call reconstruction.

## Privacy

- All analysis runs locally; captures are never sent to third parties
- GeoIP: offline MMDB by default; online lookups strictly opt-in
- Beginner mode masks IP addresses in the investigation graph
- No analytics, no telemetry, no account
- Full policy: [Privacy Policy](frontend/src/app/privacy/page.tsx)

## Documentation

- [User Guide](docs/PacketLens-User-Guide.html) (PDF alongside) — report sections, interactive tools, detection & risk model, GeoIP, settings, self-hosting
- [Workboard](docs/TODO.md) — delivered fixes and open roadmap items

## Status

Analyzer version **3.2.0** · report schema **1.0** · risk specification **1.3**
Gates: 353/353 tests · ESLint · TypeScript · production build — all green.
Latest release: [v3.2.0](https://github.com/simpletarun/Packetlens/releases/tag/v3.2.0)

## License

[MIT](LICENSE) © 2026 Tarun