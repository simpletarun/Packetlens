import { NextRequest, NextResponse } from 'next/server'
import { parsePcap, KNOWN_DLTS } from '@/lib/pcap'
import { analyzePcap, assertValidAnalysisResult } from '@/lib/analysis'
import { enrichDeviceVendors } from '@/lib/oui-server'
import { storeJob } from '@/lib/job-store'
import { sameOrigin } from '@/lib/request-guard'

// 500 MB everywhere: the landing page, the privacy policy and the desktop
// upload cap all state 500 MB — the route must not silently accept 2× that.
const MAX_SIZE = 500 * 1024 * 1024
const ALLOWED_EXTENSIONS = new Set(['pcap', 'pcapng'])

const RATE_LIMIT = new Map<string, { count: number; resetAt: number }>()
const RATE_LIMIT_MAX_ENTRIES = 10_000

function checkRateLimit(ip: string): boolean {
  const now = Date.now()
  if (RATE_LIMIT.size > RATE_LIMIT_MAX_ENTRIES) {
    for (const [key, entry] of RATE_LIMIT) {
      if (now > entry.resetAt) RATE_LIMIT.delete(key)
    }
  }
  const entry = RATE_LIMIT.get(ip)
  if (!entry || now > entry.resetAt) {
    RATE_LIMIT.set(ip, { count: 1, resetAt: now + 60_000 })
    return true
  }
  if (entry.count >= 5) return false
  entry.count++
  return true
}

export function sanitizeFilename(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 255)
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    if (!sameOrigin(request)) {
      return NextResponse.json({ error: 'Cross-origin uploads are not allowed' }, { status: 403 })
    }
    // Last hop of x-forwarded-for: proxies append, so this is the peer that
    // actually talked to Next; a direct attacker still controls the header.
    // ponytail: header-based IP, fine for a local tool; behind a real reverse
    // proxy switch to the proxy's remote-addr header (x-real-ip).
    const ip = request.headers.get('x-forwarded-for')?.split(',').pop()?.trim() || 'unknown'
    if (!checkRateLimit(ip)) {
      return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 })
    }

    // Reject oversized bodies from the Content-Length header BEFORE
    // request.formData() buffers the whole multipart body — otherwise an
    // oversized upload is fully read into memory before the size check runs
    // (up to ~2-3× the file size in peak memory, and a streamed body with no
    // Content-Length could grow until OOM).
    const declaredLength = Number(request.headers.get('content-length') ?? 0)
    if (!declaredLength || declaredLength > MAX_SIZE) {
      return NextResponse.json({ error: 'File exceeds 500 MB limit' }, { status: 413 })
    }

    const formData = await request.formData()
    const file = formData.get('file')

    if (!file || !(file instanceof File)) {
      return NextResponse.json({ error: 'No file uploaded' }, { status: 400 })
    }

    const ext = file.name.split('.').pop()?.toLowerCase()
    if (!ext || !ALLOWED_EXTENSIONS.has(ext)) {
      return NextResponse.json({ error: 'Only .pcap and .pcapng files are supported' }, { status: 400 })
    }

    // Local mode: analysis runs in this process and the whole file is held in
    // memory — keep the desktop cap here.
    if (file.size > MAX_SIZE) {
      return NextResponse.json({ error: 'File exceeds 500 MB limit' }, { status: 413 })
    }

    const buffer = Buffer.from(await file.arrayBuffer())
    const overrideRaw = formData.get('dltOverride')
    let linkTypeOverride: number | undefined
    if (overrideRaw && String(overrideRaw) !== '') {
      const n = Number(overrideRaw)
      if (!Number.isInteger(n) || !KNOWN_DLTS.has(n)) {
        return NextResponse.json({ error: 'Invalid link layer override' }, { status: 400 })
      }
      linkTypeOverride = n
    }
    const parseResult = await parsePcap(buffer, linkTypeOverride)
    if (parseResult.stats.totalPackets === 0) {
      return NextResponse.json({ error: 'No packets found in capture file' }, { status: 400 })
    }
    // Dedupe consecutive duplicate frames BEFORE any detection or risk
    // scoring (double-capture artifacts must never inflate flows, SYN counts
    // or rates); raw/duplicate/analyzed counts ride on the job for the report.
    const analysisResult = analyzePcap(parseResult, { dedupe: true })
    analysisResult.devices = enrichDeviceVendors(analysisResult.devices)
    analysisResult.job.id = crypto.randomUUID()
    analysisResult.job.filename = sanitizeFilename(file.name)
    analysisResult.job.fileSize = file.size
    analysisResult.job.createdAt = new Date().toISOString()

    // Full validation at the API boundary — an invalid result must never be
    // stored or served (pipeline: PCAP → engine → canonical result → FULL
    // VALIDATION → only then → API/UI/export).
    assertValidAnalysisResult(analysisResult)

    const jobId = analysisResult.job.id
    storeJob(jobId, analysisResult.job.filename, analysisResult)

    return NextResponse.json({
      jobId,
      filename: analysisResult.job.filename,
      totalPackets: parseResult.stats.totalPackets,
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Upload failed'
    return NextResponse.json({ error: message }, { status: 500 })
  }
}
