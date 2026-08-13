# PacketLens

PCAP network analysis report tool. Upload a PCAP/PCAPNG capture and PacketLens
parses it on the server and produces a 22-section security report: traffic
summary, packets, flows, sessions, DNS, HTTP, TLS, extracted files, VoIP calls,
credentials, certificates, endpoints, timeline, top talkers, alerts, IOCs,
MITRE ATT&CK mappings, a numerical risk score, and recommendations — plus an
investigation graph, a world map, and PDF/HTML/CSV export.

## Features

- **Upload analysis** — up to 500 MB per capture (PCAP/PCAPNG), rate-limited
  (5/min per address), same-origin guard, 500 MB checked against
  Content-Length before buffering
- **Live demo dataset** — explore every feature without a capture file
- **Detection** — signature rules (scanning, DNS tunneling, C2 beaconing, data
  exfiltration, credential leaks, malware downloads) plus behavioral metrics
  (beacon periodicity, tunneling volume, JA3 anomalies, burst detection),
  unified into a transparent 0–100 risk score (risk spec 1.3)
- **Honest verdicts** — undecodable encapsulations report UNKNOWN /
  INSUFFICIENT DATA instead of a false "clean" score
- **GeoIP** — auto-installs the free DB-IP City Lite database (~125 MB, CC BY
  4.0) on first use, or accepts an uploaded MMDB file; online ipwho.is lookups
  are opt-in and off by default
- **Export** — print-ready PDF report, standalone HTML export, and a
  SIEM-friendly flows CSV (UTF-8 BOM, IPv6-safe columns)

## Getting Started

Requires Node.js 20+.

```bash
cd frontend
npm install
npm run dev        # http://localhost:3456
```

Production:

```bash
npm run build
npm start
```

## Scripts

| Command | What it does |
| --- | --- |
| `npm run dev` | Development server on port 3456 |
| `npm run build` | Production build (`output: "standalone"`) |
| `npm start` | Run the production build |
| `npm run lint` | ESLint |
| `npx tsc --noEmit` | Type check |
| `npx vitest run` | Unit tests (analysis, report, parsing, VoIP, export) |

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
- The app emits CSP, HSTS, X-Frame-Options DENY, and nosniff headers; TLS
  terminates at your proxy.

## Documentation

- [User Guide](../docs/PacketLens-User-Guide.html) (+ PDF in the same folder)
- [Privacy Policy](src/app/privacy/page.tsx)