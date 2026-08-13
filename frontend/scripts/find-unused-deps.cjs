// Reports npm dependencies (dependencies + devDependencies) whose package name
// never appears in any source/config file under src, tests, shared, scripts, or
// root config files. type-imports count too (name appears in text).
// Conservative: checks the bare package name substring.
const fs = require("fs")
const path = require("path")
const ROOT = path.resolve(__dirname, "..")
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"))
const SKIP = new Set(["node_modules", ".next", "out", "target"])
function walk(dir) {
  const out = []
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (SKIP.has(e.name)) continue
      out.push(...walk(path.join(dir, e.name)))
    } else out.push(path.join(dir, e.name))
  }
  return out
}
const textFiles = []
const dirs = [path.join(ROOT, "src"), path.join(ROOT, "tests"), path.join(ROOT, "shared")]
for (const d of dirs) {
  if (!fs.existsSync(d)) continue
  const exts = d.endsWith("src") || d.endsWith("tests") ? ["ts", "tsx"] : ["ts", "json"]
  for (const f of walk(d)) if (exts.some((e) => f.endsWith("." + e))) textFiles.push(f)
}
for (const f of ["next.config.ts", "vitest.config.ts", "eslint.config.mjs", "postcss.config.mjs", "package.json"]) {
  if (fs.existsSync(path.join(ROOT, f))) textFiles.push(path.join(ROOT, f))
}
const text = textFiles.map((f) => fs.readFileSync(f, "utf8")).join("\n")
const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) }
for (const name of Object.keys(deps).sort()) {
  const scoped = name.startsWith("@") ? name.split("/")[1] : name
  const bare = scoped.split(/[.\-+_]/)[0].toLowerCase()
  const used = text.toLowerCase().includes(bare)
  console.log(`${used ? "USED  " : "UNUSED"} ${name}`)
}
