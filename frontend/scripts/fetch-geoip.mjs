// Fetches the DB-IP Lite city database and stores it where the server's
// GeoIP registry reads it from (~/.packetlens/geo). No build step — plain
// node, so it can run right after a fresh checkout.
//
//   node scripts/fetch-geoip.mjs [direct-mmdb-url-or-file]
//
// Default URL points at DB-IP's current month (their free downloads are
// month-stamped); fall back to a file path to install an already-downloaded
// database offline.

import { gunzipSync } from "node:zlib"
import { mkdirSync, writeFileSync, existsSync } from "node:fs"
import { join } from "node:path"
import { homedir } from "node:os"

const now = new Date()
const month = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`
const DEFAULT_URL = `https://download.db-ip.com/free/dbip-city-lite-${month}.mmdb.gz`
const MAGIC = [0xab, 0xcd, 0xef, 0x4d, 0x61, 0x78, 0x4d, 0x69, 0x6e, 0x64]

function validate(bytes) {
  // The MaxMind marker (`\xab\xcd\xefMaxMind`) may sit at the start OR at the
  // end of the file: DB-IP's city lite lays the search tree first and the
  // magic/metadata at EOF. Search both regions.
  const hasMagic = (b) => {
    loop: for (let i = 0; i + MAGIC.length <= b.length; i++) {
      for (let j = 0; j < MAGIC.length; j++) {
        if (b[i + j] !== MAGIC[j]) continue loop
      }
      return true
    }
    return false
  }
  const tail = bytes.subarray(Math.max(0, bytes.length - 4096))
  if (!hasMagic(bytes.subarray(0, 4096)) && !hasMagic(tail)) throw new Error("Not a MaxMind database (magic bytes mismatch)")
}

const arg = process.argv[2]
const input = arg ?? DEFAULT_URL

let raw
if (input.startsWith("http")) {
  console.log(`Downloading ${input} …`)
  const res = await fetch(input)
  if (!res.ok) throw new Error(`Download failed (HTTP ${res.status})`)
  raw = new Uint8Array(await res.arrayBuffer())
} else {
  if (!existsSync(input)) throw new Error(`File not found: ${input}`)
  const { readFileSync } = await import("node:fs")
  raw = readFileSync(input)
}

const bytes = input.endsWith(".gz") ? new Uint8Array(gunzipSync(raw)) : raw
validate(bytes)

const dir = join(homedir(), ".packetlens", "geo")
mkdirSync(dir, { recursive: true })
const name = "dbip-city-lite.mmdb"
writeFileSync(join(dir, name), bytes)
console.log(`Installed ${(bytes.length / 1048576).toFixed(1)} MB → ${join(dir, name)}`)
console.log("Attribution: DB-IP Lite (CC BY 4.0)")