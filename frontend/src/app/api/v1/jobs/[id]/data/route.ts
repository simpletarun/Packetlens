import { NextRequest, NextResponse } from 'next/server'
import { getJob } from '@/lib/job-store'
import { ANALYZER_VERSION } from '@/lib/analysis'
import { getGeoDbInfo } from '@/lib/db-registry'

let cachedGeo: ReturnType<typeof getGeoDbInfo> | null = null
let cachedGeoAt = 0
const GEO_CACHE_TTL = 5000

function getGeoCached() {
  const now = Date.now()
  if (cachedGeo && now - cachedGeoAt < GEO_CACHE_TTL) return cachedGeo
  cachedGeo = getGeoDbInfo()
  cachedGeoAt = now
  return cachedGeo
}

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
): Promise<NextResponse> {
  const { id } = await params

  if (!/^[a-zA-Z0-9_-]+$/.test(id)) {
    return NextResponse.json({ error: 'Invalid job ID' }, { status: 400 })
  }

  const stored = getJob(id)

  if (!stored) {
    return NextResponse.json({ error: 'Job not found' }, { status: 404 })
  }

  const d = stored.data
  const geo = getGeoCached()

  const res = NextResponse.json({
    job: { ...d.job, id: stored.id, filename: stored.filename },
    jobInfo: {
      mode: "local",
      analyzerVersion: ANALYZER_VERSION,
      ...(geo.present ? { geoDbVersion: geo.name } : {}),
    },
    packets: d.packets,
    flows: d.flows,
    sessions: d.sessions,
    dns: d.dns,
    http: d.http,
    tls: d.tls,
    files: d.files,
    calls: d.calls,
    credentials: d.credentials,
    certificates: d.certificates,
    devices: d.devices,
    alerts: d.threats,
    timeline: d.timeline,
    bandwidth: d.bandwidth,
    advancedMetrics: d.advancedMetrics,
    burst: d.advancedMetrics?.burst ?? null,
    decode: d.decode,
    schemaVersion: d.schemaVersion,
    validator: d.validator,
    fileInfo: d.fileInfo,
  })
  res.headers.set('Cache-Control', 'private, max-age=30, stale-while-revalidate=60')
  return res
}