// GeoIP database storage for the offline MMDB path (F-02): the server owns
// the uploaded/downloaded DB-IP Lite .mmdb file and serves its bytes to the
// browser worker, which does the lookups offline. Validation here is minimal
// (extension + MaxMind magic bytes) — full decode is the worker's job.
// ponytail: single-database slot (city supersedes country); multi-DB support
// if anyone actually needs country-only to save space.

import fs from "node:fs"
import path from "node:path"
import os from "node:os"

// DB-IP Lite is CC BY 4.0 licensed — surfaced wherever the database is
// shown, per the license terms.
export const GEOIP_ATTRIBUTION = "DB-IP Lite (CC BY 4.0)"

const MMDB_MAGIC = [0xab, 0xcd, 0xef, 0x4d, 0x61, 0x78, 0x4d, 0x69, 0x6e, 0x64]

// DB-IP's city lite lays the search tree first and the magic/metadata at EOF;
// other .mmdb builds put it at the head. Accept either region.
function hasMmdbMagic(bytes: Uint8Array): boolean {
  const scan = (from: number, to: number) => {
    for (let i = from; i + MMDB_MAGIC.length <= to; i++) {
      let match = true
      for (let j = 0; j < MMDB_MAGIC.length; j++) {
        if (bytes[i + j] !== MMDB_MAGIC[j]) { match = false; break }
      }
      if (match) return true
    }
    return false
  }
  return scan(0, Math.min(4096, bytes.length)) || scan(Math.max(0, bytes.length - 4096), bytes.length)
}

export interface GeoDbInfo {
  present: boolean
  name?: string
  size?: number
  modifiedAt?: number
}

export interface GeoDbFile {
  name: string
  bytes: Uint8Array<ArrayBuffer>
  modifiedAt: number
  size: number
}

function dbDir(dir?: string): string {
  return dir ?? path.join(os.homedir(), ".packetlens", "geo")
}

function findDb(dir: string): { file: string; name: string } | null {
  try {
    for (const entry of fs.readdirSync(dir)) {
      if (entry.toLowerCase().endsWith(".mmdb")) {
        return { file: path.join(dir, entry), name: entry }
      }
    }
  } catch { /* dir missing — no database */ }
  return null
}

export function getGeoDbInfo(dir?: string): GeoDbInfo {
  const found = findDb(dbDir(dir))
  if (!found) return { present: false }
  try {
    const st = fs.statSync(found.file)
    return { present: true, name: found.name, size: st.size, modifiedAt: st.mtimeMs }
  } catch {
    return { present: false }
  }
}

export function saveGeoDb(name: string, bytes: Uint8Array, dir?: string): GeoDbInfo {
  if (bytes.length < MMDB_MAGIC.length) throw new Error("Not a MaxMind database (file too small)")
  if (!hasMmdbMagic(bytes)) throw new Error("Not a MaxMind database (magic bytes mismatch)")
  const clean = path.basename(name).replace(/[^a-zA-Z0-9._-]/g, "_")
  if (!clean.endsWith(".mmdb")) throw new Error("Only .mmdb files are supported")
  const dirPath = dbDir(dir)
  fs.mkdirSync(dirPath, { recursive: true })
  for (const existing of findDb(dirPath) ? [findDb(dirPath)!.file] : []) {
    try { fs.unlinkSync(existing) } catch { /* stale file */ }
  }
  fs.writeFileSync(path.join(dirPath, clean), bytes)
  return getGeoDbInfo(dirPath)
}

export function removeGeoDb(dir?: string): void {
  const found = findDb(dbDir(dir))
  if (found) {
    try { fs.unlinkSync(found.file) } catch { /* already gone */ }
  }
}

export function readGeoDb(dir?: string): GeoDbFile | null {
  const found = findDb(dbDir(dir))
  if (!found) return null
  try {
    const bytes = fs.readFileSync(found.file)
    return { name: found.name, bytes, modifiedAt: Date.now(), size: bytes.length }
  } catch {
    return null
  }
}
