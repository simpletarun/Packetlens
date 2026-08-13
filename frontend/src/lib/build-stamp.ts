// Build fingerprint shown on every report (PDF cover, appendix, markdown).
// Values are baked at build/server-start by next.config.ts:
//   NEXT_PUBLIC_BUILD_TIME     — when this bundle was compiled
//   NEXT_PUBLIC_BUILD_SRC_HASH — sha1 of the analysis/report source, so the
//                                fingerprint changes whenever the analyzer
//                                code changes (restart dev / rebuild), instead
//                                of silently claiming a stale build produced
//                                fresh results.
import { ANALYZER_VERSION } from "@/lib/analysis"

const time = process.env.NEXT_PUBLIC_BUILD_TIME || "development"
const hash = process.env.NEXT_PUBLIC_BUILD_SRC_HASH || "src"

export const BUILD_STAMP = `v${ANALYZER_VERSION} · src:${hash} · ${time}`
