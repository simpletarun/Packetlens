import { UNKNOWN_ZONE, isPrivateIP } from "@/lib/map-data"
import { lookupOfflineGeo } from "@/lib/mmdb"

export interface GeoLocation {
  ip: string; country: string; countryCode: string
  city: string; lat: number; lon: number; isPrivate: boolean
  asn?: string; isp?: string; org?: string
}

const GEO_CACHE = new Map<string, GeoLocation>()

// NFR-3: online lookups (ipwho.is) are OFF unless the user explicitly enables
// the online fallback in Settings. Offline MMDB lookups never touch this —
// they are local by construction.
let onlineGeoAllowed = false
export function setOnlineGeoAllowed(v: boolean): void {
  onlineGeoAllowed = v
}

const STATIC_GEO: Record<string, { country: string; cc: string; city: string; lat: number; lon: number; asn?: string; org?: string }> = {
  '8.8.8.8': { country: 'United States', cc: 'US', city: 'Mountain View', lat: 37.386, lon: -122.084, asn: 'AS15169', org: 'Google LLC' },
  '8.8.4.4': { country: 'United States', cc: 'US', city: 'Mountain View', lat: 37.386, lon: -122.084, asn: 'AS15169', org: 'Google LLC' },
  '1.1.1.1': { country: 'United States', cc: 'US', city: 'Los Angeles', lat: 34.052, lon: -118.244, asn: 'AS13335', org: 'Cloudflare, Inc.' },
  '1.0.0.1': { country: 'United States', cc: 'US', city: 'Los Angeles', lat: 34.052, lon: -118.244, asn: 'AS13335', org: 'Cloudflare, Inc.' },
  '208.67.222.222': { country: 'United States', cc: 'US', city: 'San Francisco', lat: 37.775, lon: -122.418, asn: 'AS36692', org: 'OpenDNS, LLC' },
  '208.67.220.220': { country: 'United States', cc: 'US', city: 'San Francisco', lat: 37.775, lon: -122.418, asn: 'AS36692', org: 'OpenDNS, LLC' },
  '93.184.216.34': { country: 'United States', cc: 'US', city: '', lat: 39.043, lon: -77.487, asn: 'AS15133', org: 'EdgeCast Networks, Inc.' },
  '142.250.80.46': { country: 'United States', cc: 'US', city: 'New York', lat: 40.712, lon: -74.006, asn: 'AS15169', org: 'Google LLC' },
  '140.82.121.3': { country: 'United States', cc: 'US', city: 'San Francisco', lat: 37.775, lon: -122.418, asn: 'AS36459', org: 'GitHub, Inc.' },
  '151.101.129.69': { country: 'United States', cc: 'US', city: 'San Francisco', lat: 37.775, lon: -122.418, asn: 'AS54113', org: 'Fastly' },
  '104.16.132.229': { country: 'United States', cc: 'US', city: 'New York', lat: 40.712, lon: -74.006, asn: 'AS13335', org: 'Cloudflare, Inc.' },
  '185.199.108.153': { country: 'United States', cc: 'US', city: 'San Francisco', lat: 37.775, lon: -122.418, asn: 'AS54113', org: 'Fastly' },
  '52.84.122.53': { country: 'United States', cc: 'US', city: 'Seattle', lat: 47.606, lon: -122.332, asn: 'AS16509', org: 'Amazon.com, Inc.' },
  '13.107.42.14': { country: 'United States', cc: 'US', city: 'Redmond', lat: 47.678, lon: -122.131, asn: 'AS8068', org: 'Microsoft Corporation' },
  '204.79.197.200': { country: 'United States', cc: 'US', city: 'Redmond', lat: 47.678, lon: -122.131, asn: 'AS8068', org: 'Microsoft Corporation' },
}

async function resolveGeo(ip: string): Promise<GeoLocation> {
  if (GEO_CACHE.has(ip)) return GEO_CACHE.get(ip)!

  // Private + non-routable (RFC1918, link-local, multicast, CGNAT, ...)
  // never leave the device; the shared rule keeps map and geo in agreement
  if (isPrivateIP(ip)) {
    const loc: GeoLocation = { ip, country: 'Local Network', countryCode: 'LOC', city: 'LAN', lat: 0, lon: 0, isPrivate: true }
    GEO_CACHE.set(ip, loc)
    return loc
  }

  const staticEntry = STATIC_GEO[ip]
  if (staticEntry) {
    const loc: GeoLocation = { ip, country: staticEntry.country, countryCode: staticEntry.cc, city: staticEntry.city, lat: staticEntry.lat, lon: staticEntry.lon, isPrivate: false, asn: staticEntry.asn, org: staticEntry.org }
    GEO_CACHE.set(ip, loc)
    return loc
  }

  if (ip === '\u2014' || !ip) {
    const loc: GeoLocation = { ip, country: 'Unknown', countryCode: '??', city: '', lat: 0, lon: 0, isPrivate: false }
    GEO_CACHE.set(ip, loc)
    return loc
  }

  // Offline MMDB first: the database answer is authoritative and never leaves
  // the device. Falls through when no database is installed on the server.
  const offline = await lookupOfflineGeo(ip)
  if (offline) {
    const loc: GeoLocation = {
      ip, country: offline.country, countryCode: offline.countryCode,
      city: offline.city, lat: offline.lat, lon: offline.lon, isPrivate: false,
    }
    GEO_CACHE.set(ip, loc)
    return loc
  }

  // ipwho.is fallback only when the user opted in (NFR-3: no lookups by default).
  if (!onlineGeoAllowed) return unknownLocation(ip)

  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 3000)
    // ponytail: ipwho.is handles v4+v6 over HTTPS without a key; ip-api's
    // free tier is HTTP-only and 403s on https
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal: controller.signal })
    clearTimeout(timeout)
    if (!res.ok) throw new Error('geo lookup failed')
    const data = await res.json()
    if (data.success === false) throw new Error('geo lookup failed')
    const conn = data.connection || {}
    const loc: GeoLocation = {
      ip,
      country: data.country || 'Unknown',
      countryCode: data.country_code || '??',
      city: data.city || '',
      lat: Number(data.latitude) || 0,
      lon: Number(data.longitude) || 0,
      isPrivate: false,
      asn: conn.asn ? `AS${conn.asn}` : '',
      isp: conn.isp || '',
      org: conn.org || '',
    }
    GEO_CACHE.set(ip, loc)
    return loc
  } catch {
    return unknownLocation(ip)
  }
}

// ponytail: deterministic cluster in the labeled "Unknown Location" zone so
// unresolvable IPs still render instead of scattering fake points.
// Deliberately NOT cached: an "Unknown" is a negative result — a cached
// negative would be served forever, so toggling Online GeoIP on later would
// never re-resolve these IPs (the cache hit in resolveGeo wins before the
// online check).
function unknownLocation(ip: string): GeoLocation {
  let h = 0
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0
  return {
    ip, country: 'Unknown', countryCode: '??', city: '',
    lat: UNKNOWN_ZONE.lat + ((h >>> 8) % 1000) / 1000 * 8 - 4,
    lon: UNKNOWN_ZONE.lon + (h % 1000) / 1000 * 8 - 4,
    isPrivate: false,
  }
}

// The analyst's own location ("Home") — only known from an online self-lookup,
// so it requires the online fallback to be enabled (NFR-3). Result is cached
// for the session.
let homeCache: Promise<GeoLocation | null> | null = null
export async function resolveHomeLocation(): Promise<GeoLocation | null> {
  if (!onlineGeoAllowed) return null
  if (homeCache) return homeCache
  homeCache = (async () => {
    try {
      const res = await fetch('https://ipwho.is/')
      if (!res.ok) return null
      const data = await res.json()
      if (data.success === false) return null
      const conn = data.connection || {}
      return {
        ip: 'me', country: data.country || 'Unknown', countryCode: data.country_code || '??',
        city: data.city || '', lat: Number(data.latitude) || 0, lon: Number(data.longitude) || 0,
        isPrivate: false, asn: conn.asn ? `AS${conn.asn}` : '', isp: conn.isp || '', org: conn.org || '',
      }
    } catch {
      return null
    }
  })()
  return homeCache
}

export async function resolveGeoBatch(ips: string[]): Promise<Map<string, GeoLocation>> {
  const unique = [...new Set(ips.filter(ip => ip && ip !== '\u2014'))]
  const map = new Map<string, GeoLocation>()
  let i = 0
  const worker = async () => {
    while (i < unique.length) {
      const ip = unique[i++]
      map.set(ip, await resolveGeo(ip))
    }
  }
  // ponytail: 8 concurrent lookups max — Promise.all over every unique IP
  // fires hundreds of parallel requests on large captures
  await Promise.all(Array.from({ length: Math.min(8, unique.length) }, worker))
  return map
}
