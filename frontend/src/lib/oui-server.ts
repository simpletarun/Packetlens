// Server-only: loads the IEEE MA-L OUI table (public/oui.json) via fs and
// enriches devices with vendor names. Never import this from a client module —
// it pulls in node:fs. See src/lib/oui.ts for the pure lookup helpers.

import fs from "node:fs"
import path from "node:path"
import { lookupVendor } from "./oui"
import type { AnalysisDevice } from "./analysis"

let table: Map<string, string> | null = null

function loadOuiTable(): Map<string, string> {
  // Cache only on SUCCESS: a table missing at first load (or regenerated
  // later) must be picked up without a server restart, while a loaded table
  // is reused across requests (QA: every device stayed "unknown" until
  // restart when public/oui.json appeared after the first request).
  if (table) return table
  let fresh = new Map<string, string>()
  try {
    const file = path.join(process.cwd(), "public", "oui.json")
    const entries = JSON.parse(fs.readFileSync(file, "utf8")) as [string, string][]
    fresh = new Map(entries)
    table = fresh
  } catch {
    /* missing/unreadable table — vendors stay empty, retried next call */
  }
  return fresh
}

export function enrichDeviceVendors(devices: AnalysisDevice[]): AnalysisDevice[] {
  const ouiTable = loadOuiTable()
  for (const d of devices) {
    if (d.mac && d.mac !== '\u2014') d.vendor = lookupVendor(d.mac, ouiTable)
  }
  return devices
}
