// Pure MAC OUI -> vendor lookup helpers, client-safe. The OUI table itself is
// bundled as public/oui.json (see scripts/gen-oui.mjs) and loaded on the
// server path only (src/lib/oui-server.ts). Locally-administered MACs
// (bit 0x02 of the first octet) have no IEEE assignment — they are labeled.

// A MAC is usable as a device identity only when it is a unicast, nonzero
// hardware address. Broadcast (ff:ff:ff:ff:ff:ff), multicast (first-octet
// bit 0x01) and all-zero addresses are frame-addressing artifacts, never an
// endpoint's NIC: ARP requests are addressed TO ff:ff:ff:ff:ff:ff, and the
// request's target IP must never inherit that broadcast MAC as its device
// MAC (QA: device row for an unresolved ARP target showed ff:ff:ff:ff:ff:ff).
export function isUnicastMac(mac: string | undefined): boolean {
  if (!mac) return false
  const clean = mac.replace(/[^0-9a-fA-F]/g, "")
  if (clean.length < 12) return false
  const first = parseInt(clean.slice(0, 2), 16)
  if (!Number.isFinite(first) || (first & 0x01) !== 0) return false
  return !/^0+$/.test(clean)
}

// Display-only MAC: the MAC itself when it is a real unicast address, else
// the em-dash placeholder. Legacy persisted jobs may store a broadcast MAC
// against an unresolved ARP target — it must render as "—", never as the
// device's NIC (QA: endpoint table showed ff:ff:ff:ff:ff:ff).
export function displayMac(mac: string | undefined): string {
  return isUnicastMac(mac) ? (mac as string) : "\u2014"
}

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
