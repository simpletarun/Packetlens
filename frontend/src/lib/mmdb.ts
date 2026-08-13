// Offline GeoIP lookups: DB-IP Lite `.mmdb` served by the server and decoded
// in-browser with the maxmind mmdb reader (no network calls, ever). The DB is
// fetched once per page load and the reader cached for the session.
// ponytail: main-thread lazy singleton, not a Web Worker — the one-time DB
// open (~50-150ms) is acceptable; add a worker if it janks low-end devices.

import { Reader, type CityResponse } from "mmdb-lib"
import { Buffer } from "buffer"

export interface OfflineGeo {
  country: string
  countryCode: string
  city: string
  lat: number
  lon: number
}

let loaded: { reader: Reader<CityResponse>; name: string } | null = null
let loading: Promise<{ reader: Reader<CityResponse>; name: string } | null> | null = null

export async function loadOfflineDb(): Promise<{ reader: Reader<CityResponse>; name: string } | null> {
  if (loaded) return loaded
  if (loading) return loading
  loading = (async () => {
    try {
      // The server serves the installed .mmdb from the API route.
      const res = await fetch("/api/v1/geo/db")
      if (!res.ok) return null
      const name = res.headers.get("x-db-name") ?? "dbip.mmdb"
      const reader = new Reader<CityResponse>(Buffer.from(await res.arrayBuffer()))
      loaded = { reader, name }
      return loaded
    } catch {
      return null
    } finally {
      loading = null
    }
  })()
  return loading
}

export async function lookupOfflineGeo(ip: string): Promise<OfflineGeo | null> {
  const db = await loadOfflineDb()
  if (!db) return null
  try {
    const rec = db.reader.get(ip)
    if (!rec) return null
    const country = rec.country?.names?.en ?? rec.country?.iso_code
    const cc = rec.country?.iso_code
    if (!country && !cc) return null
    const loc = rec.location
    return {
      country: country ?? cc ?? "Unknown",
      countryCode: cc || "??",
      city: rec.city?.names?.en ?? "",
      lat: loc?.latitude ?? 0,
      lon: loc?.longitude ?? 0,
    }
  } catch {
    return null
  }
}