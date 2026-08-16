import spec from "../../shared/risk-spec.json"

export interface RiskAlertInput {
  ruleId: string
  severity: number
  confidence: number
  srcIp: string
  dstIp: string
}

export interface RiskSourceAlert {
  ruleId: string
  severity: number
  confidence: number
  srcIp: string
  dstIp: string
}

export interface RiskAnomalies {
  dnsTunnelingSuspected?: boolean
  dataExfiltrationSuspected?: boolean
  beaconDetected?: boolean
  ja3Suspicious?: boolean
}

// Single source of truth: risk is a pure function of signature alerts (+burst).
// The Rust engine fires DNS-TUNNEL-001 / DATA-EXFIL-001 / C2-BEACON-001 /
// TLS-SUSPICIOUS-001 as real alerts, so heuristic flags must never inject
// synthetic inputs here — doing so would double-count on the engine path.
export function buildRiskInputs(alerts: RiskSourceAlert[]): RiskAlertInput[] {
  return alerts.map((a) => ({
    ruleId: a.ruleId, severity: a.severity, confidence: a.confidence, srcIp: a.srcIp, dstIp: a.dstIp,
  }))
}

export function burstDetected(anomalies?: RiskAnomalies & { burst?: { detected?: boolean } | null }): boolean {
  return !!(anomalies?.burst?.detected)
}

// Whether the burst may boost alert confidence. A DOWNLOAD spike (inbound)
// is not evidence of data exfiltration, so a burst that is not outbound-
// dominated must not raise the exfil/beacon/DNS-tunnel contributions
// (QA: verylarge.pcapng — 86 CRITICAL driven by an inbound burst boosting
// an upload-style exfil alert to the ×1.5 band). Absent direction data
// (parity fixtures, older captures) the bonus applies as before.
// A null/unevaluable burst reads as false — absence of burst evidence never
// boosts, and never lowers, the score (see the burst math in analysis.ts).
export function burstConfidenceBoost(anomalies?: RiskAnomalies & { burst?: { detected?: boolean; outboundDominant?: boolean } | null }): boolean {
  if (!burstDetected(anomalies)) return false
  return (anomalies?.burst?.outboundDominant ?? true)
}

export interface RiskBreakdownItem {
  ruleId: string
  ruleName: string
  severity: number
  /** Detector confidence the rule was reported at. */
  confidence: number
  /** Detector confidence after the burst bonus (if one applied). The
   *  multiplier is derived from THIS value, so the breakdown table can't
   *  show "×1.5 at 70%" (QA: breakdown showed ×1.5 for a 70%/65% base). */
  effectiveConfidence: number
  confidenceMult: number
  severityWeight: number
  ruleWeight: number
  contribution: number
  category: string
  srcIp: string
  dstIp: string
}

export interface RiskBreakdown {
  rawScore: number
  normalizedScore: number
  items: RiskBreakdownItem[]
  formula: string
}

export interface RiskLevel {
  label: string
  color: string
}

const SEV = spec.severity_weights as Record<string, number>
const RULE = spec.rule_weights as Record<string, number>
const CONF = spec.confidence_multipliers
const BANDS = spec.confidence_bands
const K = spec.normalization.curve_k
const BURST = spec.burst_params as { confidence_bonus: number; data_exfil_bonus: number; beacon_bonus: number; dns_tunnel_bonus: number }

const RULE_NAMES: Record<string, string> = {
  "PORT-SCAN-001": "Port Scan Detection",
  "SYN-FLOOD-001": "SYN Flood Attack",
  "DNS-TUNNEL-001": "DNS Tunneling",
  "CRED-LEAK-001": "Credential Exposure",
  "MALWARE-DL-001": "Malware Download",
  "C2-BEACON-001": "C2 Beaconing",
  "DATA-EXFIL-001": "Data Exfiltration",
  "TLS-SUSPICIOUS-001": "Suspicious TLS",
  "HTTP-CREDS-001": "HTTP Credentials",
}

const RULE_CATEGORIES: Record<string, string> = {
  "PORT-SCAN-001": "Reconnaissance",
  "SYN-FLOOD-001": "Denial of Service",
  "DNS-TUNNEL-001": "C2 Channels",
  "CRED-LEAK-001": "Data Exposure",
  "MALWARE-DL-001": "Malware Activity",
  "C2-BEACON-001": "C2 Channels",
  "DATA-EXFIL-001": "Data Exfiltration",
  "TLS-SUSPICIOUS-001": "C2 Channels",
  "HTTP-CREDS-001": "Plaintext Credential Exposure",
}

export const RISK_PARAMS = spec.rule_params

// Curve constant for the normalization 100 × (1 − exp(−raw / K)). Exported so
// the UI can show the ACTUAL substituted computation (raw 40 → 39.3 → 39),
// instead of a formula template that leaves the raw→normalized jump opaque.
export const RISK_CURVE_K = spec.normalization.curve_k as number

export function computeRisk(alerts: RiskAlertInput[], burstDetected = false): number {
  const seen = new Set<string>()
  let raw = 0
  for (const a of alerts) {
    const key = `${a.ruleId}|${a.srcIp}|${a.dstIp}`
    if (seen.has(key)) continue
    seen.add(key)
    let conf = a.confidence
    if (burstDetected) {
      const bonus = a.ruleId === "DATA-EXFIL-001" ? BURST.data_exfil_bonus
                : a.ruleId === "C2-BEACON-001" ? BURST.beacon_bonus
                : a.ruleId === "DNS-TUNNEL-001" ? BURST.dns_tunnel_bonus
                : 0
      conf = Math.min(100, conf + bonus)
    }
    const mult = conf < BANDS.low_lt ? CONF.low : conf >= BANDS.high_ge ? CONF.high : CONF.medium
    const sev = SEV[String(a.severity)] ?? 0
    const rule = RULE[a.ruleId] ?? 0
    raw += (sev + rule) * mult
  }
  const score = Math.round(100 * (1 - Math.exp(-raw / K)))
  return Math.min(100, Math.max(0, score))
}

export function riskLevel(score: number): RiskLevel {
  let level = spec.levels[0]
  for (const l of spec.levels) {
    if (score >= l.min) level = l
  }
  return level
}

const COLOR_CLASSES: Record<string, string> = {
  green: "text-success",
  lime: "text-lime-500",
  yellow: "text-warning",
  orange: "text-orange-500",
  red: "text-danger",
}

export function riskColorClass(level: RiskLevel): string {
  return COLOR_CLASSES[level.color] ?? "text-muted-foreground"
}

const LEVEL_BY_LABEL = Object.fromEntries(spec.levels.map((l) => [l.label, l]))

// The minimum verdict level dictated by the strongest confirmed finding.
// The pure score band can read LOW (a single HTTP-CREDS-001 → raw 40 → 39/100)
// while a HIGH-severity finding is present; without a floor that capture
// tiers with "nothing found". Maps finding severity to its OWN level, so
// severity is never hidden by the score: Critical(5)→CRITICAL, High(4)→HIGH,
// Medium(3)→MEDIUM, Low(1-2)→LOW. null when there is no finding.
export function severityFloor(highestSeverity: number): RiskLevel | null {
  if (highestSeverity >= 5) return LEVEL_BY_LABEL.CRITICAL ?? null
  if (highestSeverity === 4) return LEVEL_BY_LABEL.HIGH ?? null
  if (highestSeverity === 3) return LEVEL_BY_LABEL.MEDIUM ?? null
  if (highestSeverity >= 1) return LEVEL_BY_LABEL.LOW ?? null
  return null
}

// The verdict level: the score's band, floored by the highest finding's
// severity. The numeric score and the formula are untouched — this only
// decides the LABEL/color a capture is presented with.
export function verdictLevel(scoreLevel: RiskLevel, highestSeverity: number): RiskLevel {
  const floor = severityFloor(highestSeverity)
  if (!floor) return scoreLevel
  const floorMin = LEVEL_BY_LABEL[floor.label]?.min ?? 0
  const scoreMin = LEVEL_BY_LABEL[scoreLevel.label]?.min ?? 0
  return floorMin > scoreMin ? floor : scoreLevel
}

export function computeRiskBreakdown(alerts: RiskAlertInput[], burstDetected = false): RiskBreakdown {
  const seen = new Set<string>()
  const items: RiskBreakdownItem[] = []
  let raw = 0
  const burstBonus: Record<string, number> = {
    "DATA-EXFIL-001": BURST.data_exfil_bonus,
    "C2-BEACON-001": BURST.beacon_bonus,
    "DNS-TUNNEL-001": BURST.dns_tunnel_bonus,
  }
  for (const a of alerts) {
    if (seen.has(`${a.ruleId}|${a.srcIp}|${a.dstIp}`)) continue
    seen.add(`${a.ruleId}|${a.srcIp}|${a.dstIp}`)
    let conf = a.confidence
    if (burstDetected) {
      conf = Math.min(100, conf + (burstBonus[a.ruleId] ?? 0))
    }
    const mult = conf < BANDS.low_lt ? CONF.low : conf >= BANDS.high_ge ? CONF.high : CONF.medium
    const sev = SEV[String(a.severity)] ?? 0
    const rule = RULE[a.ruleId] ?? 0
    const contribution = (sev + rule) * mult
    raw += contribution
    items.push({
      ruleId: a.ruleId,
      ruleName: RULE_NAMES[a.ruleId] || a.ruleId,
      severity: a.severity,
      confidence: a.confidence,
      effectiveConfidence: conf,
      confidenceMult: mult,
      severityWeight: sev,
      ruleWeight: rule,
      contribution,
      category: RULE_CATEGORIES[a.ruleId] || "Unknown",
      srcIp: a.srcIp,
      dstIp: a.dstIp,
    })
  }
  const score = Math.round(100 * (1 - Math.exp(-raw / K)))
  const normalized = Math.min(100, Math.max(0, score))
  return {
    rawScore: raw,
    normalizedScore: normalized,
    items,
    formula: `100 × (1 - exp(-raw / ${K}))`,
  }
}
