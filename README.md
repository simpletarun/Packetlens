# PacketLens

> Drop a PCAP. Get a full security report — **entirely on your machine**.

[![Release](https://img.shields.io/badge/release-v3.2.0-blue)](https://github.com/simpletarun/Packetlens/releases/tag/v3.2.0)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-353%20passed-brightgreen)](frontend/tests)

PacketLens turns a network capture (PCAP/PCAPNG) into a **22-section security report**, an **investigation graph**, a **world map**, and **PDF / HTML / CSV exports**. Everything runs locally — no cloud, no account, no telemetry.

## Quick start

Requires **Node.js 20+**.

```bash
cd frontend
npm install
npm run dev        # → http://localhost:3456
```

Production: `npm run build && npm start`

> No capture file? Open `/analysis/mock-demo` to try the built-in demo dataset.
> On Windows, double-click `start-dev.bat` instead.

## Features

- **Analysis** — PCAP/PCAPNG up to 500 MB; flows, sessions, DNS, HTTP, TLS, files, credentials, certificates, endpoints, timeline, top talkers
- **VoIP** — SIP (5060/5061), RTP/RTCP with SSRC tracking, call dialogs by Call-ID
- **Risk score** — transparent 0–100 from signature rules (scanning, DNS tunneling, C2 beaconing, exfiltration…) + behavioral metrics; undecodable captures report UNKNOWN, never a false "clean"
- **IOCs & MITRE ATT&CK** — every detection mapped to the framework
- **Investigation graph** — search, filters, 7 layouts, minimap, PNG/SVG export
- **World map** — offline (Natural Earth data): pins, cluster badges, animated arcs
- **GeoIP** — offline DB-IP MMDB by default (auto-install or upload); online lookups opt-in
- **Exports** — print-ready PDF, standalone HTML, SIEM-friendly CSV (UTF-8 BOM, IPv6-safe)
- **Privacy** — beginner mode masks IPs; no analytics, no telemetry

## Tech stack

| Layer | Choice |
| --- | --- |
| Framework | Next.js (App Router) + TypeScript |
| Graph | cytoscape |
| Map | d3-geo (Natural Earth, bundled) |
| GeoIP | mmdb-lib (DB-IP City Lite) |
| Tests | vitest — **353 tests / 29 files** |

## Development

```bash
npm run lint && npx tsc --noEmit && npx vitest run && npm run build
```

## FAQ

**Is my capture sent anywhere?** No — parsing, analysis, and GeoIP all run locally.

**Does it need internet?** Only once: `npm install` and the one-time GeoIP database download. The map is fully offline.

**A Wireshark replacement?** Wireshark is for deep inspection; PacketLens is for reports — drop a capture, get analysis and a risk score.

**Docker / database needed?** No. Single Node.js process; history is a JSON file (`~/.packetlens/jobs.json`, last 20 jobs).

## Docs & status

- [User Guide](docs/PacketLens-User-Guide.html) · [Privacy Policy](frontend/src/app/privacy/page.tsx) · [Workboard](docs/TODO.md)
- Analyzer **3.2.0** · report schema **1.0** · risk spec **1.3** · [Release v3.2.0](https://github.com/simpletarun/Packetlens/releases/tag/v3.2.0)

[MIT](LICENSE) © 2026 Tarun