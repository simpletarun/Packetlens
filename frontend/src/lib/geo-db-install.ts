// Auto-installs the free DB-IP Lite city database on first use, so
// non-technical users never have to run fetch-geoip or upload a file. The
// server downloads the current month's DB-IP build once, validates the
// MaxMind magic, and saves it to the same ~/.packetlens/geo slot the upload
// path uses. Single-flight: concurrent requests share one download; failures
// release the lock so the next request retries.
// ponytail: no progress events — the download is ~125 MB and just awaits
// inside the /db request; add streaming if first-run latency ever matters.

import { gunzipSync } from "node:zlib"
import { saveGeoDb, getGeoDbInfo } from "./db-registry"

const MAX_BYTES = 300 * 1024 * 1024
const DOWNLOAD_TIMEOUT_MS = 5 * 60 * 1000

function dbIpUrl(): string {
  const now = new Date()
  const month = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`
  return `https://download.db-ip.com/free/dbip-city-lite-${month}.mmdb.gz`
}

let install: Promise<string | null> | null = null
// Outcome of the last attempt, so /geo/status can tell "installing right
// now" from "the auto-install already failed" — the settings page was stuck
// on "downloading…" forever when the server had no network (QA).
let lastAttemptFailed = false

export function geoDbInstallInProgress(): boolean {
  return install !== null
}

export function geoDbLastAttemptFailed(): boolean {
  return lastAttemptFailed
}

// Resolves null on success, an error message on failure.
export function ensureGeoDb(): Promise<string | null> {
  if (getGeoDbInfo().present) return Promise.resolve(null)
  if (!install) {
    lastAttemptFailed = false
    install = (async () => {
      try {
        const res = await fetch(dbIpUrl(), { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) })
        if (!res.ok) throw new Error(`Download failed (HTTP ${res.status})`)
        const raw = new Uint8Array(await res.arrayBuffer())
        if (raw.length > MAX_BYTES) throw new Error("Downloaded database exceeds 300 MB limit")
        // maxOutputLength caps decompressed size — a malicious gzip stream
        // (zip bomb) otherwise expands without bound.
        const bytes =
          raw[0] === 0x1f && raw[1] === 0x8b
            ? gunzipSync(raw, { maxOutputLength: MAX_BYTES })
            : raw
        saveGeoDb("dbip-city-lite.mmdb", bytes)
        return null
      } catch (err) {
        lastAttemptFailed = true
        return err instanceof Error ? err.message : "Download failed"
      } finally {
        install = null
      }
    })()
  }
  return install
}
