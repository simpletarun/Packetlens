import { describe, it, expect } from "vitest"
import { computeRisk, riskLevel, computeRiskBreakdown, buildRiskInputs, burstDetected, burstConfidenceBoost } from "@/lib/risk"

function alert(ruleId: string, severity: number, confidence: number, srcIp: string) {
  return { ruleId, severity, confidence, srcIp, dstIp: "10.0.0.9" }
}

describe("computeRisk — canonical scores (mirrors Rust engine)", () => {
  it("empty alerts score zero", () => {
    expect(computeRisk([])).toBe(0)
  })

  it("2 critical + 3 high + 5 medium + 4 low at x1 confidence -> 84", () => {
    const alerts = [
      ...Array.from({ length: 2 }, (_, i) => alert("TEST-000", 5, 70, `1.1.1.${i}`)),
      ...Array.from({ length: 3 }, (_, i) => alert("TEST-000", 4, 70, `1.1.2.${i}`)),
      ...Array.from({ length: 5 }, (_, i) => alert("TEST-000", 3, 70, `1.1.3.${i}`)),
      ...Array.from({ length: 4 }, (_, i) => alert("TEST-000", 2, 70, `1.1.4.${i}`)),
    ]
    expect(computeRisk(alerts)).toBe(84)
  })

  it("deduplicates per (rule, src, dst)", () => {
    const repeated = Array.from({ length: 10 }, () => alert("DNS-TUNNEL-001", 4, 80, "10.0.0.5"))
    expect(computeRisk(repeated)).toBe(computeRisk(repeated.slice(0, 1)))
  })

  it("confidence bands scale contributions", () => {
    expect(computeRisk([alert("TEST-000", 3, 30, "1.1.1.1")])).toBe(5)  // x0.5
    expect(computeRisk([alert("TEST-000", 3, 70, "1.1.1.2")])).toBe(10) // x1
    expect(computeRisk([alert("TEST-000", 3, 85, "1.1.1.3")])).toBe(14) // x1.5
  })

  it("rule weight adds to severity", () => {
    expect(computeRisk([alert("DNS-TUNNEL-001", 4, 80, "10.0.0.5")])).toBe(53)
  })

  it("saturates at 100", () => {
    const many = Array.from({ length: 20 }, (_, i) => alert("MALWARE-DL-001", 5, 95, `9.9.${Math.floor(i / 10)}.${i % 10}`))
    expect(computeRisk(many)).toBe(100)
  })

  it("burst boosts data exfil confidence by 15", () => {
    const base = alert("DATA-EXFIL-001", 5, 70, "10.0.0.5")
    const withoutBurst = computeRisk([base], false)
    const withBurst = computeRisk([base], true)
    expect(withBurst).toBeGreaterThan(withoutBurst)
    expect(withBurst).toBe(68) // 60 raw * 1.5 = 90 -> 100*(1-e^(-90/80)) = 68
  })

  it("burst boosts beacon confidence by 15", () => {
    const base = alert("C2-BEACON-001", 5, 65, "10.0.0.5")
    const withBurst = computeRisk([base], true)
    expect(withBurst).toBe(57) // (25+20)*1.5=67.5 -> 100*(1-e^(-67.5/80)) = 57
  })

  it("burst does not boost DNS tunnel (bonus is 0)", () => {
    const base = alert("DNS-TUNNEL-001", 4, 80, "10.0.0.5")
    const withoutBurst = computeRisk([base], false)
    const withBurst = computeRisk([base], true)
    expect(withBurst).toBe(withoutBurst)
  })
})

describe("burstConfidenceBoost — a DOWNLOAD burst must not boost exfil/beacon confidence", () => {
  const exfil = () => alert("DATA-EXFIL-001", 5, 70, "10.0.0.5")

  it("no burst -> no boost", () => {
    expect(burstConfidenceBoost({ burst: { detected: false } })).toBe(false)
  })

  it("outbound-dominant burst -> boost", () => {
    expect(burstConfidenceBoost({ burst: { detected: true, outboundDominant: true } })).toBe(true)
  })

  it("inbound (download) burst -> NO boost (QA: verylarge.pcapng 86 CRITICAL)", () => {
    expect(burstConfidenceBoost({ burst: { detected: true, outboundDominant: false } })).toBe(false)
    const withBoost = computeRisk([exfil()], true)
    const withoutBoost = computeRisk([exfil()], false)
    expect(withoutBoost).toBeLessThan(withBoost)
  })

  it("missing direction field defaults to boosting (parity fixtures)", () => {
    expect(burstConfidenceBoost({ burst: { detected: true } })).toBe(true)
  })
})

describe("single source of truth — breakdown score equals computeRisk score", () => {
  const srcAlerts = [
    { ruleId: "PORT-SCAN-001", severity: 3, confidence: 70, srcIp: "10.0.0.2", dstIp: "8.8.8.8" },
    { ruleId: "SYN-FLOOD-001", severity: 4, confidence: 75, srcIp: "10.0.0.3", dstIp: "1.1.1.1" },
    { ruleId: "CRED-LEAK-001", severity: 4, confidence: 60, srcIp: "10.0.0.4", dstIp: "93.184.216.34" },
  ]
  const anomalies = { burst: { detected: true } }

  it("matches with burst", () => {
    const inputs = buildRiskInputs(srcAlerts)
    expect(computeRiskBreakdown(inputs, burstDetected(anomalies)).normalizedScore)
      .toBe(computeRisk(inputs, burstDetected(anomalies)))
  })

  it("matches without burst", () => {
    const inputs = buildRiskInputs(srcAlerts)
    expect(computeRiskBreakdown(inputs, false).normalizedScore)
      .toBe(computeRisk(inputs, false))
  })

  it("anomaly flags never inject synthetic inputs (Rust engine owns those rules)", () => {
    const inputs = buildRiskInputs(srcAlerts)
    expect(inputs).toHaveLength(3)
    expect(inputs.some((i) => i.srcIp === "multiple")).toBe(false)
  })
})

describe("calibration intent — combined evidence severity (curve_k 80, C2 weight 20)", () => {
  const beacon = () => alert("C2-BEACON-001", 5, 65, "10.0.0.5")
  const dnsTunnel = () => alert("DNS-TUNNEL-001", 4, 80, "10.0.0.5")
  const exfil = () => alert("DATA-EXFIL-001", 5, 70, "10.0.0.5")

  it("clean LAN traffic (no alerts) -> SAFE", () => {
    expect(computeRisk([])).toBe(0)
    expect(riskLevel(0).label).toBe("SAFE")
  })

  it("single suspicious beacon -> MEDIUM, not HIGH", () => {
    const s = computeRisk([beacon()]) // (25+20) x1.0 = 45 raw -> 43
    expect(s).toBeGreaterThanOrEqual(40)
    expect(s).toBeLessThan(60)
    expect(riskLevel(s).label).toBe("MEDIUM")
  })

  it("beacon + suspicious DNS -> HIGH", () => {
    const s = computeRisk([beacon(), dnsTunnel()]) // 45 + 60 = 105 raw -> 73
    expect(s).toBeGreaterThanOrEqual(60)
    expect(s).toBeLessThan(80)
    expect(riskLevel(s).label).toBe("HIGH")
  })

  it("beacon + exfiltration + C2 channel -> CRITICAL", () => {
    const s = computeRisk([beacon(), exfil(), dnsTunnel()]) // 45 + 60 + 60 = 165 raw -> 87
    expect(s).toBeGreaterThanOrEqual(80)
    expect(riskLevel(s).label).toBe("CRITICAL")
  })
})

describe("riskLevel — 0-19 SAFE .. 80-100 CRITICAL", () => {
  it("maps boundaries", () => {
    expect(riskLevel(0).label).toBe("SAFE")
    expect(riskLevel(19).label).toBe("SAFE")
    expect(riskLevel(20).label).toBe("LOW")
    expect(riskLevel(39).label).toBe("LOW")
    expect(riskLevel(40).label).toBe("MEDIUM")
    expect(riskLevel(59).label).toBe("MEDIUM")
    expect(riskLevel(60).label).toBe("HIGH")
    expect(riskLevel(79).label).toBe("HIGH")
    expect(riskLevel(80).label).toBe("CRITICAL")
    expect(riskLevel(100).label).toBe("CRITICAL")
  })
})
