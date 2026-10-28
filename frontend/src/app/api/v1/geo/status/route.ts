import { NextResponse } from "next/server"
import { getGeoDbInfo, GEOIP_ATTRIBUTION } from "@/lib/db-registry"
import { ensureGeoDb, geoDbInstallInProgress, geoDbLastAttemptFailed } from "@/lib/geo-db-install"

export async function GET(): Promise<NextResponse> {
  const info = getGeoDbInfo()
  if (!info.present) {
    // The install already ran and failed (e.g. no server network): report
    // that instead of "downloading…" forever (QA — status was stuck in a
    // 3-second poll loop that never terminated). The check must run BEFORE
    // ensureGeoDb(): that call starts a fresh attempt synchronously, which
    // would always make geoDbInstallInProgress() true and hide the failure.
    if (!geoDbInstallInProgress() && geoDbLastAttemptFailed()) {
      return NextResponse.json({
        ...info, downloading: false, attribution: GEOIP_ATTRIBUTION,
        error: "Auto-install of the DB-IP Lite database failed — check the server's network access and retry.",
      })
    }
    // Kick off the first-run auto-install so the Settings page can tell the
    // user it is downloading without blocking on it.
    ensureGeoDb()
    return NextResponse.json({ ...info, downloading: true, attribution: GEOIP_ATTRIBUTION })
  }
  return NextResponse.json({ ...info, attribution: GEOIP_ATTRIBUTION })
}