import { describe, it, expect } from "vitest"
import fs from "node:fs"
import path from "node:path"
import { computeRisk } from "@/lib/risk"

// Cross-language parity regression (Rust ↔ TypeScript). The expected scores in
// this fixture are computed by the authoritative Rust engine
// (analyzer/tests/risk_parity.rs asserts the same numbers from the Rust side).
// If either engine drifts, this test or the Rust one fails.
const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../shared/risk-parity.json"), "utf-8")
) as {
  cases: {
    name: string
    burst: boolean
    expected: number
    alerts: { ruleId: string; severity: number; confidence: number; srcIp: string; dstIp: string }[]
  }[]
}

describe("cross-language parity — TS computeRisk reproduces Rust scores", () => {
  for (const c of fixture.cases) {
    it(c.name, () => {
      const score = computeRisk(c.alerts, c.burst)
      expect(score).toBe(c.expected)
    })
  }
})
