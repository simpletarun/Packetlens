import { NextRequest, NextResponse } from "next/server"
import { saveGeoDb, removeGeoDb, readGeoDb, GEOIP_ATTRIBUTION } from "@/lib/db-registry"
import { ensureGeoDb } from "@/lib/geo-db-install"
import { sameOrigin } from "@/lib/request-guard"

const MAX_DB_SIZE = 200 * 1024 * 1024

export async function GET(): Promise<NextResponse> {
  let db = readGeoDb()
  // First run for non-technical users: the server installs the free DB-IP
  // Lite database by itself instead of demanding a manual download.
  if (!db) {
    const error = await ensureGeoDb()
    db = readGeoDb()
    if (!db) {
      return NextResponse.json({ error: error ?? "No GeoIP database installed" }, { status: 404 })
    }
  }
  return new NextResponse(new Blob([db.bytes]), {
    status: 200,
    headers: {
      "Content-Type": "application/octet-stream",
      "X-DB-Name": db.name,
      "X-DB-Attribution": GEOIP_ATTRIBUTION,
      "Cache-Control": "no-store",
    },
  })
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    if (!sameOrigin(request)) {
      return NextResponse.json({ error: "Cross-origin uploads are not allowed" }, { status: 403 })
    }
    const declaredLength = Number(request.headers.get('content-length') ?? 0)
    if (!declaredLength || declaredLength > MAX_DB_SIZE) {
      return NextResponse.json({ error: "Database exceeds 200 MB limit" }, { status: 400 })
    }
    const form = await request.formData()
    const file = form.get("file")
    if (!file || !(file instanceof File)) {
      return NextResponse.json({ error: "No file uploaded" }, { status: 400 })
    }
    if (file.size > MAX_DB_SIZE) {
      return NextResponse.json({ error: "Database exceeds 200 MB limit" }, { status: 400 })
    }
    const info = saveGeoDb(file.name, new Uint8Array(await file.arrayBuffer()))
    return NextResponse.json({ ...info, attribution: GEOIP_ATTRIBUTION })
  } catch (err) {
    const message = err instanceof Error ? err.message : "Save failed"
    return NextResponse.json({ error: message }, { status: 400 })
  }
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
  if (!sameOrigin(request)) {
    return NextResponse.json({ error: "Cross-origin delete is not allowed" }, { status: 403 })
  }
  removeGeoDb()
  return NextResponse.json({ ok: true })
}