// Build identity shown on every artifact (PDF cover, appendix, markdown,
// flows CSV). Values are baked at build/server-start by next.config.ts:
//   NEXT_PUBLIC_BUILD_TIME     — when this bundle was compiled
//   NEXT_PUBLIC_BUILD_COMMIT   — the exact `git rev-parse HEAD` of the build
//                                (GIT_COMMIT overrides it for CI/packaged
//                                builds without git; empty when neither)
//   NEXT_PUBLIC_BUILD_SRC_HASH — sha1 of the analysis/report source, kept as a
//                                secondary fingerprint
// HTML, PDF (printed HTML) and the flows CSV all consume this ONE object —
// never recompute the commit per exporter (QA: artifacts once showed only a
// generic source hash that could not be mapped to a commit, so a report could
// not be certified as produced by a specific release).
import { ANALYZER_VERSION } from "@/lib/analysis"

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

// NOTE: the env values below are frozen at SERVER START / BUILD time by
// next.config.ts (`git rev-parse HEAD` runs once when the config loads).
// A long-running dev server recompiles changed page modules but does NOT
// re-run next.config.ts, so the stamp can lag the actual HEAD after a new
// commit. Restart the dev server after committing before exporting reports —
// otherwise the artifact's Commit line names an older revision while the
// rendered code is newer (QA: an exported report stamped commit 3a684f3 while
// its content came from commit 1251a5f). Reading the env lazily (below)
// guarantees any server restart or module re-evaluation picks up the current
// values instead of values captured at first import.

function buildInfo(): BuildInfo {
  const time = process.env.NEXT_PUBLIC_BUILD_TIME || "development"
  // GIT_COMMIT is honored directly so CI and packaged builds can inject the
  // commit without a git binary (QA: an artifact once read "no Git in build
  // environment" even though the source hash proved the bundle was fresh).
  const commit = (process.env.GIT_COMMIT || process.env.NEXT_PUBLIC_BUILD_COMMIT || "").trim()
  const srcHash = process.env.NEXT_PUBLIC_BUILD_SRC_HASH || ""
  return {
    version: ANALYZER_VERSION,
    commit,
    commitShort: (commit && commit.slice(0, 12)) || srcHash,
    builtAt: time,
    sourceHash: srcHash,
    isGit: commit.length > 0,
  }
}

export const BUILD_INFO: BuildInfo = buildInfo()

// Inline form: "v3.4.0 · commit:5b4429a · 2026-08-15T11:42:11.814Z" — computed
// lazily so a restarted dev server stamps the real current HEAD (falls back to
// "src:<hash>" when no Git — the label must never claim a commit that is not
// one).
export const BUILD_STAMP = `v${BUILD_INFO.version} · ${BUILD_INFO.isGit ? `commit:${BUILD_INFO.commitShort}` : `src:${BUILD_INFO.sourceHash || "unknown"}`} · ${BUILD_INFO.builtAt}`