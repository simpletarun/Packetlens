import type { NextRequest } from 'next/server'

// True only for hostnames a genuine local/LAN client uses: loopback, a
// private-range IPv4 literal, link-local / unique-local IPv6, or localhost.
// A public domain name — which DNS rebinding needs — is rejected.
function isLocalHostname(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (h === 'localhost' || h.endsWith('.localhost')) return true
  if (h === '::1') return true
  if (/^(fe80|fc|fd)[0-9a-f]{0,2}:/.test(h)) return true
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (m) {
    const a = Number(m[1])
    const b = Number(m[2])
    return a === 127 || a === 10 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)
  }
  return false
}

// Same-origin check for state-changing local endpoints. Browsers send Origin
// on cross-origin POST/DELETE; a non-matching host is a CSRF attempt.
// Missing Origin (curl, scripts) is allowed — no cookies, nothing to forge.
//
// Comparing Origin host to Host alone is defeated by DNS rebinding (an
// attacker page whose DNS re-resolves to 127.0.0.1 sends Origin == Host ==
// evil.com). We therefore also require the hostname to be loopback/private —
// a real local or LAN client — so a rebound public domain is rejected. Extra
// names (reverse-proxy or LAN DNS) go in PACKETLENS_ALLOWED_HOSTS.
export function sameOrigin(request: NextRequest): boolean {
  const origin = request.headers.get('origin')
  if (!origin) return true
  try {
    const url = new URL(origin)
    if (url.host !== request.headers.get('host')) return false
    const extra = (process.env.PACKETLENS_ALLOWED_HOSTS ?? '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
    if (extra.includes(url.hostname.toLowerCase())) return true
    return isLocalHostname(url.hostname)
  } catch {
    return false
  }
}
