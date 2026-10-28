import { describe, it, expect } from "vitest"
import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { BUILD_STAMP } from "@/lib/build-stamp"

// The build stamp must prove WHICH source revision produced the report: a
// stale hash (two builds, identical fingerprint) means the server never
// picked up the changed analyzer code. Recompute the sha1 the same way
// next.config.ts does and require the embedded hash to match the current
// sources whenever one is actually baked in (the "src" fallback means the
// env was absent — nothing to check, e.g. plain vitest runs).
describe("build stamp freshness", () => {
  const computed = createHash("sha1")
    .update(
      ["src/lib/analysis.ts", "src/lib/report.ts", "src/lib/risk.ts", "src/lib/stats.ts", "src/lib/pcap.ts", "src/lib/geo.ts"]
        .map((f) => {
          try {
            return readFileSync(resolve("src", f), "utf8")
          } catch {
            return ""
          }
        })
        .join("\n")
    )
    .digest("hex")
    .slice(0, 12)

  it("embedded src hash equals the current analyzer/report sources", () => {
    const m = BUILD_STAMP.match(/src:([0-9a-f]{12})/)
    if (!m) return
    expect(m[1]).toBe(computed)
  })

  it("stamp carries the current analyzer version", () => {
    expect(BUILD_STAMP).toContain("v3.4.0")
  })
})
