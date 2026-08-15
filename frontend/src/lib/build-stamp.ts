// Build identity shown on every artifact (PDF cover, appendix, markdown,
// flows CSV). Values are baked at build/server-start by next.config.ts:
//   NEXT_PUBLIC_BUILD_TIME     — when this bundle was compiled
//   NEXT_PUBLIC_BUILD_COMMIT   — the exact `git rev-parse HEAD` of the build
//                                (empty when Git is unavailable)
//   NEXT_PUBLIC_BUILD_SRC_HASH — sha1 of the analysis/report source, kept as a
//                                secondary fingerprint
// HTML, PDF (printed HTML) and the flows CSV all consume this ONE object —
// never recompute the commit per exporter (QA: artifacts once showed only a
// generic source hash that could not be mapped to a commit, so a report could
// not be certified as produced by a specific release).
import { ANALYZER_VERSION } from "@/lib/analysis"

const time = process.env.NEXT_PUBLIC_BUILD_TIME || "development"
const commit = (process.env.NEXT_PUBLIC_BUILD_COMMIT || "").trim()
const srcHash = process.env.NEXT_PUBLIC_BUILD_SRC_HASH || ""

export interface BuildInfo {
  /** Analyzer version (v3.x.y). */
  version: string
  /** Full 40-hex Git commit — empty when the build had no Git. */
  commit: string
  /** Short commit (12 hex) or the source-hash fallback. */
  commitShort: string
  /** ISO timestamp when the bundle was compiled. */
  builtAt: string
  /** sha1 of the analyzer/report sources (secondary fingerprint). */
  sourceHash: string
  /** True when the stamp is a real Git commit (not a hash fallback). */
  isGit: boolean
}

export const BUILD_INFO: BuildInfo = {
  version: ANALYZER_VERSION,
  commit,
  commitShort: (commit && commit.slice(0, 12)) || srcHash,
  builtAt: time,
  sourceHash: srcHash,
  isGit: commit.length > 0,
}

// Inline form: "v3.4.0 · commit:5b4429a · 2026-08-15T11:42:11.814Z"
// (falls back to "src:<hash>" when no Git — the label must never claim a
// commit that is not one).
export const BUILD_STAMP = `v${ANALYZER_VERSION} · ${BUILD_INFO.isGit ? `commit:${BUILD_INFO.commitShort}` : `src:${srcHash || "unknown"}`} · ${time}`