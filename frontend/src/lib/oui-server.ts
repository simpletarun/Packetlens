// Server-only: loads the IEEE MA-L OUI table (public/oui.json) via fs and
// enriches devices with vendor names. Never import this from a client module —
// it pulls in node:fs. See src/lib/oui.ts for the pure lookup helpers.

import fs from "node:fs"
import path from "node:path"
import { lookupVendor } from "./oui"
import type { AnalysisDevice } from "./analysis"

let table: Map<string, string> | null = null

export function loadOuiTable(): Map<string, string> {
  if (table) return table
  table = new Map()
  try {
    const file = path.join(process.cwd(), "public", "oui.json")
    const entries = JSON.parse(fs.readFileSync(file, "utf8")) as [string, string][]
    table = new Map(entries)
  } catch {
    /* missing/unreadable table — vendors stay empty */
  }
  return table
}

export function enrichDeviceVendors(devices: AnalysisDevice[]): AnalysisDevice[] {
  const ouiTable = loadOuiTable()
  for (const d of devices) {
    if (d.mac && d.mac !== '\u2014') d.vendor = lookupVendor(d.mac, ouiTable)
  }
  return devices
}
