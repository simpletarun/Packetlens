# TODO / Workboard

## Desktop packaging (Tauri v2, portable exe — delivered)

- `frontend/src-tauri` Tauri v2 shell; `output: "export"` static build (build-static.mjs masks `src/app/api` during export, restores after).
- Analysis pipeline runs in the browser (Tauri mode): `lib/desktop-pipeline.ts` (parse→analyze→OUI enrich→store) + IndexedDB `lib/job-store-browser.ts`; web API path untouched.
- GeoIP DB: Rust commands `geo_db_status`/`geo_db_remove`/`geo_db_download` (DB-IP CMYK, progress via Channel) reading `~/.packetlens/geo`, served to the WebView via a custom `geoip://` protocol.
- Build: `npm run build:desktop` → `frontend/desktop-dist/PacketLens.exe` (self-contained; portable). Repo path contains spaces (`new idea\pcap website`) which breaks the GNU `windres` step, so the Rust build is staged into `%TEMP%\packetlens-build`.

## Closed (verified, gated)

**WS1 — analyzer correctness (backend)**
- IPv6 `is_non_unicast` is parse-based (rejects every unspecified spelling, `::1`, multicast, loopback) — both Rust and frontend `analysis.ts`.
- `external_ips` counts exclude non-unicast IPs (no `::` phantom external peers).
- Per-flow handshake RTT (`rtt_ms`) in Rust: SYN-ACK pairs with the **last** SYN seen (port-reused 4-tuples make the first SYN stale); 1–5000 ms window; column in flow schema + CSV (`rttMs`).
- MAC-merged device identity `addresses` (primary-first) flows end-to-end: Rust `stats::devices` → `DeviceRow` → CH `devices.addresses Array(String)` (+ idempotent ALTER) → Go API → report.
- Timeline TCP(other) SQL fixed (`HTTPS` no longer double-counted as TCP).

**WS1 — report surface** (`reports/page.tsx`)
- §15/16 Top Talkers fold MAC-merged aliases into their owner via `ownerOfDevices` (the 2401:4900:…:308f alias of a local host reads "Internal Host", never "External · IN").
- §13 Endpoints: `::`/unspecified/multicast rows dropped (`endpointRowsOf`); remote card reads "N external IPs · M remote endpoints" with a footnote only when they differ; off-link MAC/vendor suppressed.
- §4 TCP Health: measured-but-all-null RTT → "no handshakes captured (mid-session flows)".

**Map (B-54)**
- Flat MapLibre map renders geo-wired public IPs as dots (size ∝ bytes) and arcs for drawn public↔public flows; private never drawn; unresolvable publics go to "Unresolved Externals".
- Header strip moved ABOVE the canvas (zoom controls can no longer overlap it) and reads "N public IPs plotted · N flows · bytes drawn · local hosts hidden · not drawn".
- Restored the three side cards: Top Countries (by bytes), Top Protocols, Unresolved Externals (reason-branched footnote "no GeoIP" vs "undecodable") — mirrored from the globe via shared `mapPanels`.
- **B-54 (empty canvas)**: nodes/arcs are now a plain SVG overlay projected through `map.project()` — NOT MapLibre geojson circle/line layers, which kept rendering a blank canvas while the React header worked. No style/glyph/data-source pipeline left to silently fail.
- **B-58 (full-form unspecified)**: `0:0:0:0:0:0:0:0` / `0:0:0:0:0:0:0:1` (uncompressed `::`/`::1`) added to `isPrivateIP`, `isLocalHostCandidate`, and `isNonUnicast` — the unspecified address no longer reaches GeoIP, so it stops showing as a fake "no GeoIP" undrawn external and can't inflate `external_ips`.
- **B-59 (protocol chips)**: Top Protocols chips count packets via `packetProtocolCounts` (ONE classifier, same as the Protocol Distribution panel) instead of per-node arc tallies — chips now include LAN-only protocols (ARP/HOPOPT) and always equal the panel.
- **B-46 header count**: header "local hosts hidden" uses the `localDevices` prop (MAC-merged devices, same as the Local Network card + footer), with the raw-IP count as fallback — was showing 11 addresses vs the card's 5 devices.

**Landing (B-57)**
- Stats card "Unlimited File Size" → "Up to 256 MB" (matches the enforced dropzone limit — the contradiction is gone).
- `<main>` is `relative z-10` and the background `NetworkScene` is `pointer-events-none`, so the animated dots can never paint over the dropzone copy.

**Map polish round 2 (B-61…B-67)**
- **B-61 census drift 5→6**: "local host / LAN traffic" is now private UNICAST (`isPrivateIP && !isNonUnicast`) everywhere: `stats.ts` device count + `localOwned`, and the Visualizations LAN card. The DHCPv6 client (`0:0:0:0:0:0:0:0`), the DHCPv4 pair (`0.0.0.0`/`255.255.255.255`) and multicast peers pass `isPrivateIP` but are never LAN peers — the full-form `::` becoming "private" (B-58) had leaked 3 DHCPv6 packets into the LAN census. Pinned in `ws-regressions.test.ts` (private-unicast predicate + `stats.devices` with an unspecified-address device row) and Rust's existing device-filter tests.
- **B-62/NFR-3 tiles offline**: tile failures escalate to the globe (the bundled offline basemap — world-110m.json, zero network) only on 3+ errors within 6 s or a 12 s style-load watchdog; a single transient tile error is left to MapLibre's built-in retry so one lost tile never nukes the map into seams (B-67). Attribution: MapLibre's AttributionControl + the header badge already name OSM/CARTO; the globe's own attribution menu covers the fallback. CSP already lists `basemaps.cartocdn.com` + `tile.openstreetmap.org` in both `img-src` and `connect-src` (next.config.ts) — confirmed. NOTE: no bundled raster textures exist in the repo ("the four textures") — the fallback is the globe; point me at the textures if you want a raster fallback instead.
- **B-63 dot pile-up**: below zoom 4 the map draws one count bubble per city cluster (`clusterByCity` in map-data.ts — centroid + bubble with the IP count; click lists the member IPs) instead of overprinted dots.
- **B-64 arc sweep**: arcs whose every projected point lies outside the canvas (×2 margin) are culled at high zoom.
- **B-65 Top Countries clip**: label gets `min-w-0 flex-1 truncate`, bytes stay `shrink-0` — "United States" no longer truncates into the byte bar.
- **B-66 header clarity**: "N public↔public flows drawn" (was "N flows … drawn") so the delta vs the connections count is self-explanatory.

**Map/report identity round (B-68, B-69, B-67-ext, nits)**
- **B-68 LAN over-correction**: the LAN-card predicate was "both ends private unicast" (B-61) — that dropped 97 packets of local→multicast/broadcast traffic (mDNS, SSDP, HOPOPT→ff02::) and read 2.4 KB/31 pkts vs the true 13.4 KB/124 (131 − 3 DHCPv6 `::`-sourced − 4 unspecified/broadcast; top host `192.168.1.3`). Now `isLanFlow(src, dst)` in map-data.ts: source must be private UNICAST (the `::`-sourced DHCPv6 client stays excluded), destination must NOT be public-unicast (multicast/broadcast/private destinations are LAN peers). Device census keeps the stricter private-unicast rule. Pinned: predicate rows + the synthetic 131−3=128 calls contract (the real capture's 4 extra exclusions are capture-specific chatter).
- **B-69 local aliases on the map/report**: the map, map panels, and §8 Top Countries plotted the client's own MAC-merged public-IPv6 aliases (`2401:…:308f/f027/234c` + router `2401::1`) as external India nodes — 21 IPs plotted / India 173.3 KB when the true external count is 17. `deriveMapData` now takes the `localOwnedAddresses` set (visualizations page): an alias is skipped everywhere — no node, no undrawn row, no arc — while its peers keep their bytes (verified: India 173.3 → 121.1 KB = exactly −52.2 KB of alias traffic, 17-plotted target). §8 uses the shared `countryCountsByDst(packets, geo, localOwned)` (report.ts) so a local-owned destination never credits an external country. §7 talkers/§12 already folded via `ownerOf` (unchanged). Pinned: alias node/arc/undrawn behavior + `countryCountsByDst` skip.
- **B-71 local↔public connection layer**: B-69 (correctly) reclassified the aliases as local, which left ONLY local↔public flows — and the drawer renders public↔public arcs, so the map read "0 public↔public flows drawn · 0 B" for 52.2 KB of traffic. Now `deriveMapData` aggregates `localPublicFlows` per external peer (directional pair counts, bytes, packets) and stamps `node.localConns`: the header counts them ("N flows drawn (incl. local↔public) · 52.2 KB"), `mapPanels.drawnBytes` includes them, peer dots are sized with them, popups say "↔ your local network (N conns)", and when Home Location is set (manual settings or online self-lookup) each map draws one home-anchored arc per peer (`#94a3b8`). Both maps get the same props (`localAliases`/`homeAnchor`); the interactive overlay's polylines gained the globe's draw-in animation (`map-arc.intro`).
- **B-72 merge completeness (20 → 17 plotted)**: the addresses[]-only rule caught `…:308f`; `…:f027`/`…:234c` (same `/64`, no MAC) and `2401:4900:8910:960f::1` (router global, same MAC as `fe80::1`) still plotted. New `localOwnedAddresses(devices)` in report.ts merges three ways: private-primary + aliases (existing), MAC groups (a device sharing a MAC with an owned device is the same NIC), and `/64` SLAAC ownership via `slaacPrefixesOf` (map-data.ts — first four non-empty hextets, compressed forms handled). `deriveMapData` also applies the /64 prefix skip at packet level, so siblings with no device row at all still stay off the map.
- **B-73 attribution overlap**: the caption "Private-IP nodes are never drawn…" got `pr-32` so MapLibre's bottom-right attribution no longer sits on top of it.
- **B-67-ext transient seams**: a single failed tile now schedules one map recreation (5 s cooldown, pan/zoom restored via `restoreRef`) so a seam is refetched without waiting for interaction; persistent failures still climb to the globe via the 3-in-6 s window.
- **Nits**: `outline-none` on the map container (focus ring gone on canvas click, +/- buttons keep theirs); cluster/node popups pick an anchor by projected position so they never clip under the rounded canvas frame.
- **Gates** — vitest 316 (27 files), eslint, tsc, build all green.

## Open

1. **Runtime verification pass** — restart the dev server (new build stamp) and regen the five captures (testing/test/verylarge/calls/demo), then verify against the accepted outcomes: exfil "2 flow(s)… 2128 KB sent", effective-confidence rows, TLS cipher populated, per-direction Seq, unified CSV schema, GeoIP provenance, OUI footnote on raw-IP captures, map "5 local hosts" + reason-branched hints, the §12/§15/§16 items above, AND the last batches: flat map dots/arcs render on the SVG overlay (B-54), header local hosts = 5 not 11 (B-46), chips == Protocol Distribution panel (B-59), no `0:0:0:0:0:0:0:0` in Unresolved Externals (B-58), landing stats card "Up to 256 MB" and dots never over the dropzone copy (B-57), census back at 5 local / 128 pkts with the LAN card = map footer (B-61), city count bubbles at world zoom + cluster popups (B-63), arcs culled off-viewport (B-64), Top Countries labels unclipped (B-65), "public↔public flows drawn" header (B-66), the offline fallback: devtools-offline / blocked tiles → globe within ~12 s, single-tile drop does not (B-62/B-67) and a one-off seam refetches without interaction (B-67-ext), the LAN card back at 124 pkts/13.4 KB with top host `192.168.1.3` (B-68), 17 IPs plotted / India 173.3 → 121.1 KB (−52.2 KB of alias traffic) with no local alias dots and no local-owned country rows (B-69/B-72), header "N flows drawn (incl. local↔public) · 52.2 KB" with peer dots sized by total bytes, "↔ your local network (N conns)" popups, home-anchored arcs when Home Location is set (both map + globe), restored arc draw-in animation, and no focus ring on canvas click / popups never clipped / attribution clear of the caption (nits). NOTE: the "26 flows drawn" acceptance depends on calls.pcap's exact flow-pair structure — the header formula (public↔public arcs + directional local↔public pairs) is pinned by test; confirm the number on regen.
2. **GeoIP sanity spot-check** — fixture peer `101.2.27.162` resolves IN/Bengaluru in the bundled dbip-city-lite; registry knowledge suggests AU (APNIC block). Confirm against the DB build before flagging either as wrong.
3. **VoIP STUN-correlation fallback** — `calls.pcap` still resolves 0 calls.
4. **PRD-002** — session reconstruction, carving UI, DNS intel UI, JA3, STIX/Zeek exports.

## QA pass round (B-75) � 2026-08-06

External QA review of the live build found: map read "16 public IPs drawn � 0 flows drawn � 0 B drawn" with "No connections to show" on the globe; LAN figures disagreed (14.1 vs 13.4 KB); empty states/+N affordances/capture-window label missing. Also claimed a "Reoorts" typo, "1.f KB" formatting and a nav badge overlap � none exist in the code (sidebar label is "Reports", formatBytes is correct, sidebar has no badge; likely review misreads).

**Fixed (verified on the real 4e745a3f capture via an offline replay harness � real packets + real MMDB through the app's own deriveMapData):**
- **B-75 arcs never drawn**: the capture has 0 public?public flows � everything is local?public (32 flows / 132.3 KB) � and no manual/online Home anchor, so both maps drew nothing. Two fixes: (1) homeAnchorFromOwnedPublic(aliases, geo) in map-data.ts � when no Home is set, the anchor is DERIVED from the LAN's own public addresses (router's delegated /64 geolocates at the ISP PoP) and local?public arcs render offline; both maps use it (interactive via an every-render ref so async geo arrival repaints; static via nchor ?? fallback). (2) The static globe's footer counted only isibleArcs � now lowsDrawn = public arcs + local?public flows and bytes = mapPanels-style drawnBytes (matches the interactive header), and its empty state names local?public traffic instead of "No connections to show".
- **LAN definition unified**: deriveMapData's localSummary used srcPrivate && dstPrivate (14.1 KB/131 pkts) while the page card used isLanFlow (13.4 KB/124 pkts). The map panel now uses isLanFlow too � one definition everywhere; the static "N hosts � LAN traffic" row matches the card. Verified: localSummary = 124 pkts/13.4 KB, top 192.168.1.3.
- **Empty states / affordances**: Alert Severity gets a "No alerts in this capture window" placeholder; interactive Top Countries shows top 7 with a "+N more countries" toggle; the page subtitle shows the capture window ("capture HH:MM:SS ? HH:MM:SS").
- **Runtime numbers on the real calls capture**: 16 public IPs drawn (the earlier "17" acceptance was wrong � the MAC group owns the Facebook 2a03:2880:� IP too), 0 public?public + 32 local?public flows = 32 flows drawn, 132.3 KB drawn, fallback anchor non-null, LAN 124/13.4 KB everywhere, no 2401:4900:8910:960f:* dots.
- Tests: homeAnchorFromOwnedPublic (owned-public ? point; private-only ? null; no geo ? null), LAN-definition pin, map-data LAN parity. Gates: vitest 326 (28 files), tsc, eslint, build all green. The replay harness was deleted (machine-specific temp paths); numbers recorded here.

**Deferred (noted, not in the QA priority list):** cross-filtering/deep-links, legend rows for ICMPv6/HOPOPT/ARP/OTHER, per-panel export, IP anonymization/masking toggle, credentials gating behind Expert mode, risk heuristics for unusual geo/protocol. Home-location offline story already exists (bundled MMDB + manual pin in Settings).
**Deferred (noted, not in the QA priority list):** cross-filtering/deep-links, legend rows for ICMPv6/HOPOPT/ARP/OTHER, per-panel export, IP anonymization/masking toggle, credentials gating behind Expert mode, risk heuristics for unusual geo/protocol. Home-location offline story already exists (bundled MMDB + manual pin in Settings).

## B-76: globe never centered on the traffic - 2026-08-06

Reported: the world map is never set in the center, every time it mismatches - the static globe opened on a fixed tilt (DEFAULT_ROTATION {20,-10}) while the capture nodes could sit anywhere, so an India-heavy capture rendered near the sphere rim.

**Fixed:** fitRotationToNodes() in map-globe.ts centers the globe on the node cluster - longitudes average as unit vectors (a plain mean jumps to the wrong side of the antimeridian), latitudes as a clamped mean (drag range -75..75); verified convention rotate([-lon,-lat]) puts (lon,lat) at the sphere center. The static map applies it exactly once, inside the existing resolveGeoBatch .then (the codebase-sanctioned async-callback path - react-hooks/set-state-in-effect forbids a plain setState effect) using the exported isGeocoded predicate so the centroid matches the nodes deriveMapData will draw. resetView now refits instead of restoring the static tilt, so double-click / Reset re-center the traffic. The wheel/zoom anchor math itself was already correct (unit-tested) - the mismatch was purely the initial view never honoring where the traffic is.

The interactive (MapLibre) path already had fitBounds on data, so only the static fallback globe changed.

- Tests: fitRotationToNodes single-node center, antimeridian wrap (Fiji+Samoa midpoint at 177, not the naive 0), same-side cluster, empty returns DEFAULT, tilt clamp. Gates: vitest 325 (27 files), tsc, eslint, build all green. Dev server verified up at http://localhost:3000.
## B-77/B-78: review round 2 - header search, CSV schema, shared labels, HTML export - 2026-08-06

External review of the rendered artifacts (CSV in a spreadsheet + HTML report) found:

**Header:** removed the global search icon AND the GlobalSearch component entirely (button, Ctrl/Cmd+K hotkey, modal) - dead code deleted, no dangling hotkeys. Per-page map search untouched.

**CSV serializer (buildFlowsCsv in lib/report.ts):** now emits a UTF-8 BOM; IPs/ports are SEPARATE columns (srcIp,srcPort,dstIp,dstPort) so IPv6 rows parse in Excel/pandas/SIEMs (the old "ip:port" produced 9-group "2401:...:308f:61153" addresses); the "—" placeholder is never emitted (undecodable endpoints get empty IP cells); consistent documented null policy (empty = not applicable, 0 = computed zero); added startTime/endTime/durationSec/srcCountry/dstCountry/srcAsn/dstAsn/service columns (geo map passed from the Reports page). Risk column skipped - the data model has no per-flow risk score.

**Shared labeling layer (one code path -> UI + PDF + HTML + CSV):**
- 224.0.0.7 and other multicast/broadcast endpoints now read "Multicast", not "Internal Host" (isNonUnicast checked before isPrivateIP in hostLabel and talkerRow).
- "1 unique domain" grammar fix (pluralization on stats.domains).
- Phantom HTTP service: talker Services no longer claim port-derived "HTTP" unless the decoder actually saw HTTP on that endpoint (real capture: one 3-packet TCP flow to :80 with 0 HTTP requests had shown "HTTP").
- GeoLite2 mislabel -> "GeoIP (DB-IP City Lite)" in the appendix line, the in-app appendix card, and the install hint text.

**HTML export:** labeled "Summary export - see PacketLens for the full report (Packets/Flows/Sessions/DNS/TCP Health/Endpoints/Timeline/Risk/IOCs/MITRE)" with a View-in-PacketLens link, and the Analysis ID is now a deep link back into the app.

Tests: report.test.ts CSV test rewritten for the new schema (BOM, split columns, IPv6 row, em-dash absence, geo country/ASN, empty N/A cells). Gates: vitest 325 (27 files), tsc, eslint, build all green; dev server verified on the live job page.
## B-80 Mac attribution parity fix
- TS analysis.ts deriveDevices: internal l2 key for home-prefix fold; exposed MAC only on isPrivateIp hosts (remote /64 sourced by >=2 LAN MACs no longer inherits a local MAC). Regression test added.

## B-81 Reviewer batch verification (28-item tracker)
- FIXED: #3 VoIP contradiction (observation now says 'STUN/QUIC signaling (WebRTC/real-time communication handshakes — not SIP calls)' — matches section 10); #4 Peak Bandwidth label uses the real dynamic interval, burst bonus clarified to C2/exfil/DNS-rules-only, appendix burst no longer rounds KB; #8 license CC BY-SA 4.0 -> CC BY 4.0 (db-registry const, settings fallback, fetch script); #6 Upload/Replace .mmdb always visible; #5 fetch-geoip dir hint (script exists; ENOENT was from repo root where no package.json lives)
- VERIFIED NOT BUGS / misreads: #9 N-badge, #10 Export/gear header, #11 sidebar double-active, #12 Connections 'local' protocol, #13 ASN column (DB-IP Lite carries no ASN data), #23 graph labels zoom-mode default, #24 default layout breadthfirst, #25 legend already filtered
- VERIFIED ALREADY FIXED: #1 Endpoint Packets 1.0K pkts, #2 dangling comma gate, #7 home location Apply/Clear+validation, #14-16 shared formatters, #17-20 devices cards/OTHER union/file size, #26 zero colors, #27 Show passwords hidden at 0, #28 files copy, #29-30 CSV+HTML exports, #31 B-80 MAC
- Gates: vitest 326, tsc, next build all green
