// Scans src/** for exported values and reports any whose name appears only at
// its own declaration (count == 1) across the whole frontend (src + tests +
// shared). Type-only exports are skipped (interfaces/types are checked
// separately). Conservative: a name used under any shape (re-export, spread,
// same-name collision elsewhere) counts as used, so this never false-flags
// something that is actually imported.
const fs = require("fs")
const path = require("path")

const ROOT = path.resolve(__dirname, "..")
const SKIP_DIRS = new Set(["node_modules", ".next", "out", "desktop-dist", "src-tauri", "dist"])

function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue
      yield* walk(path.join(dir, e.name))
    } else if (/\.(ts|tsx)$/.test(e.name)) {
      yield path.join(dir, e.name)
    }
  }
}

const files = []
for (const f of walk(path.join(ROOT, "src"))) files.push(f)
const other = []
for (const f of walk(path.join(ROOT, "tests"))) other.push(f)
for (const f of walk(path.join(ROOT, "shared"))) other.push(f)

const allText = files.concat(other).map((f) => ({ f, s: fs.readFileSync(f, "utf8") }))
const repoText = allText.map((x) => x.s).join("\n")

function exportedValues(s) {
  const names = new Set()
  const valueRe = /\bexport\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|export\s+const\s+([A-Za-z_$][\w$]*)|export\s+class\s+([A-Za-z_$][\w$]*)|export\s+\{[^}]+\}/g
  let m
  while ((m = valueRe.exec(s))) {
    for (let i = 1; i <= 3; i++) if (m[i]) names.add(m[i])
  }
  // named export groups: export { a, b as c }
  const groupRe = /export\s*\{([^}]+)\}/g
  while ((m = groupRe.exec(s))) {
    for (const part of m[1].split(",")) {
      const name = part.trim().split(/\s+as\s+/)[0].trim()
      if (name && !name.startsWith("type ")) names.add(name)
    }
  }
  // export default — never "importable by name", skip.
  return names
}

const declByName = new Map() // name -> declaration file
for (const { f, s } of allText) {
  for (const n of exportedValues(s)) declByName.set(n, f)
}

const dead = []
for (const [name, file] of declByName) {
  const count = repoText.split(name).length - 1
  if (count <= 1) dead.push({ name, file: path.relative(ROOT, file), count })
}
dead.sort((a, b) => a.file.localeCompare(b.file))
for (const d of dead) console.log(`${d.count}\t${d.file}\t${d.name}`)
console.log(`\n${dead.length} candidate dead exports`)

// --- module scan: files under src/ never referenced by any import specifier
const SKIP2 = new Set(["node_modules", ".next", "out", "desktop-dist", "src-tauri"])
function walkAll(dir) {
  const out = []
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (SKIP2.has(e.name)) continue
      out.push(...walkAll(path.join(dir, e.name)))
    } else if (/\.(ts|tsx)$/.test(e.name)) out.push(path.join(dir, e.name))
  }
  return out
}
const srcFiles = walkAll(path.join(ROOT, "src"))
const allFiles = srcFiles.concat(walkAll(path.join(ROOT, "tests")), walkAll(path.join(ROOT, "shared")))
const SRC_ROOT = path.join(ROOT, "src")
const norm = (x) => x.split("\\").join("/")
const importSpecs = new Set()
const extCandidates = (base) => [base + ".ts", base + ".tsx", base + "/index.ts", base + "/index.tsx"]
for (const f of allFiles) {
  const s = fs.readFileSync(f, "utf8")
  const dir = path.dirname(f)
  const addResolved = (spec) => {
    if (spec.startsWith("@/")) {
      importSpecs.add(spec.slice(2))
      return
    }
    if (!spec.startsWith(".")) return
    const resolved = path.resolve(dir, spec)
    for (const c of extCandidates(resolved)) {
      if (fs.existsSync(c)) {
        importSpecs.add(norm(path.relative(SRC_ROOT, c)).replace(/\.tsx?$/, ""))
        break
      }
    }
  }
  for (const m of s.matchAll(/from\s+["']([^"']+)["']/g)) addResolved(m[1])
  for (const m of s.matchAll(/(?:import|require)\(["']([^"']+)["']\)/g)) addResolved(m[1])
}
const unimported = []
for (const f of srcFiles) {
  const rel = norm(path.relative(SRC_ROOT, f))
  if (rel.startsWith("app/")) continue // Next entry pages/layouts have no importers
  if (rel.endsWith(".d.ts")) continue // ambient declarations are tsc-included, not imported
  const base = rel.replace(/\.[jt]sx?$/, "")
  if (!importSpecs.has(base)) unimported.push(rel)
}
console.log("\nPOSSIBLY UNIMPORTED MODULES:")
for (const u of unimported.sort()) console.log("  " + u)
console.log(`(${unimported.length})`)
