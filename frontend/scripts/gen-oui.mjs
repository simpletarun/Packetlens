// Regenerates public/oui.json from the IEEE MA-L registry (24-bit MAC blocks).
//   node scripts/gen-oui.mjs
// Output: a compact [[oui, vendor], ...] array keyed by 6-hex OUI (upper).
// Source: Wireshark's weekly manuf build at
// https://www.wireshark.org/download/automated/data/manuf (derived from IEEE).
import { writeFileSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

const res = await fetch("https://www.wireshark.org/download/automated/data/manuf")
if (!res.ok) throw new Error(`manuf download failed: ${res.status}`)
const text = await res.text()

const out = []
const seen = new Set()
for (const rawLine of text.split("\n")) {
  const line = rawLine.replace(/\r$/, "")
  if (!line || line.startsWith("#")) continue
  const [blockRaw, short, longName] = line.split("\t")
  const block = (blockRaw || "").trim()
  // 24-bit MA-L block only: exactly XX:XX:XX (range entries have /28 or /36)
  if (!/^([0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}$/.test(block)) continue
  const oui = block.replace(/:/g, "").toUpperCase()
  const vendor = ((longName || short) || "").trim().replace(/\.\.\.$/, "").trim()
  if (vendor && !seen.has(oui)) {
    seen.add(oui)
    out.push([oui, vendor])
  }
}
if (out.length < 10000) throw new Error(`Suspiciously small table: ${out.length} entries`)

writeFileSync(path.join(ROOT, "public", "oui.json"), JSON.stringify(out))
console.log(`wrote ${out.length} OUIs to public/oui.json`)
