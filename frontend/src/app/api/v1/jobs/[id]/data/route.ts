import { NextRequest, NextResponse } from 'next/server'
import { getJob } from '@/lib/job-store'
import { ANALYZER_VERSION } from '@/lib/analysis'
import { getGeoDbInfo } from '@/lib/db-registry'

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

  const geo = getGeoDbInfo()

  return NextResponse.json({
    job: { ...d.job, id: stored.id, filename: stored.filename },
    jobInfo: {
      mode: "local",
      analyzerVersion: ANALYZER_VERSION,
      // Report appendix + Settings show the ACTUAL installed DB name; when
      // none is present they fall back to a clear "not installed" label
      // (QA: appendix printed "Lookup Unavailable" while §16 resolved 10
      // countries — the two must never disagree).
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
    burst: d.advancedMetrics.burst ?? null,
    decode: d.decode,
    // Canonical contract fields — the export path re-validates the complete
    // result with these before producing HTML/PDF/JSON.
    schemaVersion: d.schemaVersion,
    validator: d.validator,
    fileInfo: d.fileInfo,
  })
}