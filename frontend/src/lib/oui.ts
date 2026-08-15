// Pure MAC OUI -> vendor lookup helpers, client-safe. The OUI table itself is
// bundled as public/oui.json (see scripts/gen-oui.mjs) and loaded on the
// server path only (src/lib/oui-server.ts). Locally-administered MACs
// (bit 0x02 of the first octet) have no IEEE assignment — they are labeled.

function normalizeOui(mac: string): string {
  const clean = (mac || "").replace(/[^0-9a-fA-F]/g, "").toUpperCase()
  return clean.length >= 6 ? clean.slice(0, 6) : ""
}

function isLocallyAdministered(mac: string): boolean {
  const oui = normalizeOui(mac)
  if (!oui) return false
  return (parseInt(oui.slice(0, 2), 16) & 0x02) !== 0
}

export function lookupVendor(mac: string, ouiTable: Map<string, string>): string {
  const oui = normalizeOui(mac)
  if (!oui) return ""
  return ouiTable.get(oui) ?? ""
}

// Display-only placeholder for an unresolved MAC: "Locally administered" or
// "Unknown vendor". Callers must never COUNT these as resolved vendors — only
// lookupVendor's real names belong in vendor tallies (QA: "Vendors 1" when
// zero vendors actually resolved, e.g. a missing OUI table).
export function vendorLabel(vendor: string, mac: string): string {
  if (vendor) return vendor
  const oui = normalizeOui(mac)
  if (!oui) return ""
  return isLocallyAdministered(mac) ? "Locally administered" : "Unknown vendor"
}
