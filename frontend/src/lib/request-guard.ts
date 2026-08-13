import type { NextRequest } from 'next/server'

// Same-origin check for state-changing local endpoints. Browsers send Origin
// on cross-origin POST/DELETE; a non-matching host is a CSRF attempt.
// Missing Origin (curl, scripts) is allowed — no cookies, nothing to forge.
export function sameOrigin(request: NextRequest): boolean {
  const origin = request.headers.get('origin')
  if (!origin) return true
  try {
    return new URL(origin).host === request.headers.get('host')
  } catch {
    return false
  }
}
