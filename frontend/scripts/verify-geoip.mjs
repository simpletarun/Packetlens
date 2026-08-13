// Verify the installed DB-IP Lite .mmdb against well-known anchor IPs.
//
// A wrong-vintage, wrong-seller or corrupted database used to repaint the
// whole globe (one 88%-of-bytes STUN peer swung continents on a stale DB).
// This exits non-zero when an anchor contradicts the DB so the mismatch is
// caught at install time, not in a 3am screenshot.
//
// Run: npm run verify-geoip     (exit 0 = DB sane, 1 = anchors mismatch, 2 = none installed)

import { createRequire } from "node:module"
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { pathToFileURL } from "node:url"

const require = createRequire(import.meta.url)
const { Reader } = require("mmdb-lib")

// Anchors with the countries this DB family (DB-IP Lite) actually assigns.
// Some are deliberately loose — 1.1.1.1 is AU in DB-IP's data but US in
// MaxMind's, 93.184.216.34 is GB here, US in MaxMind — the check catches
// gross breaks (wrong continent/vintage), not DB-IP's own known quirks.
export const ANCHORS = [
  { ip: "8.8.8.8", ok: ["US"], label: "Google DNS" },
  { ip: "9.9.9.9", ok: ["US"], label: "Quad9" },
  { ip: "208.67.222.222", ok: ["US"], label: "OpenDNS" },
  { ip: "1.1.1.1", ok: ["US", "AU"], label: "Cloudflare (DB-IP assigns AU)" },
  { ip: "93.184.216.34", ok: ["US", "GB"], label: "example.com (DB-IP assigns GB)" },
]

// Reported-IP spot checks (informational; their "true" country is debated).
export const SPOT_CHECKS = ["101.2.27.162", "178.104.82.79"]

const geoDir = () => join(homedir(), ".packetlens", "geo")

export function installedGeoDbFile() {
  const dir = geoDir()
  if (!existsSync(dir)) return ""
  const dbs = readdirSync(dir).filter((f) => f.endsWith(".mmdb"))
  return dbs.length ? join(dir, dbs[0]) : ""
}

function lookup(reader, ip) {
  const rec = reader.get(ip)
  if (!rec) return { country: "", code: "", city: "" }
  return {
    country: rec.country?.names?.en || "",
    code: rec.country?.iso_code || "",
    city: rec.city?.names?.en || "",
  }
}

// Returns the anchor mismatches as [{ ip, got, expected }]; empty = DB sane.
export function checkGeoDb(file) {
  const reader = new Reader(readFileSync(file))
  const issues = []
  for (const { ip, ok } of ANCHORS) {
    const got = lookup(reader, ip).code
    if (!ok.includes(got)) issues.push({ ip, got, expected: ok.join("|") })
  }
  return issues
}

function main() {
  const file = installedGeoDbFile()
  if (!file) {
    console.log("No GeoIP database installed — run `npm run fetch-geoip` first.")
    process.exit(2)
  }
  const stamp = statSync(file).mtime.toISOString()
  const reader = new Reader(readFileSync(file))
  const lines = []
  const missing = []
  for (const { ip, ok, label } of ANCHORS) {
    const { code, city } = lookup(reader, ip)
    const pass = ok.includes(code)
    lines.push(`${pass ? "PASS" : "FAIL"}  ${ip}  ${label}: ${code} (${city}) — expected ${ok.join("|")}`)
    if (!pass) missing.push({ ip, got: code, expected: ok.join("|") })
  }
  console.log(`GeoIP DB: ${file}`)
  console.log(`Modified: ${stamp}`)
  console.log("Anchors:")
  console.log(lines.join("\n"))
  for (const ip of SPOT_CHECKS) {
    const { country, code, city } = lookup(reader, ip)
    console.log(`INFO   ${ip}: ${country} (${code}) — ${city}`)
  }
  if (missing.length) {
    const details = missing.map((m) => `  ${m.ip}: got ${m.got}, expected ${m.expected}`).join("\n")
    console.error(`\n${missing.length} anchor mismatch(es) — the DB looks wrong or stale.\n${details}\nRe-fetch with: npm run fetch-geoip`)
    process.exit(1)
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main()