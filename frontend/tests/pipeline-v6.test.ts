import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { parsePcap } from "@/lib/pcap"
import { analyzePcap } from "@/lib/analysis"

// Regression fixture: the user's test.pcapng (28-second Windows capture with
// SLAAC IPv6). QA: the host's OWN delegated public v6 (2401:4900:…:275b, same
// /64 as the router's ::1) used to surface as an "External" peer — its /64
// pair with its link-local fe80 was refused by the L2-surface rule, so the
// whole IPv6 side was invisible to direction heuristics (exfil, beacon
// remoteOf, burst, bandwidth). The router's WAN/capture MAC (6e:22) next to
// its LAN MAC (6c:22) also made every forwarded server /64 look two-interface.
const fixture = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "test.pcapng")
const HOST_V6 = "2401:4900:8911:7943:754b:ad97:bd76:275b"
const ROUTER_V6 = "2401:4900:8911:7943:0:0:0:1"

describe("end-to-end pipeline on test.pcapng (SLAAC IPv6 host)", () => {
  it("recognizes the host's delegated IPv6 as local and stays FP-free", async () => {
    const buf = readFileSync(fixture)
    const parsed = await parsePcap(buf)
    const analysis = analyzePcap(parsed)

    // 1. The host's delegated v6 is an alias of its device, never a row or an
    //    external peer; the router's v6 folds into the router device.
    const host = analysis.devices.find((d) => d.ip === HOST_V6 || (d.addresses ?? []).includes(HOST_V6))
    expect(host).toBeDefined()
    const hostAddrs = [host!.ip, ...(host!.addresses ?? [])]
    expect(hostAddrs).toContain(HOST_V6)
    expect(analysis.devices.some((d) => d.ip === HOST_V6)).toBe(false)
    const router = analysis.devices.find((d) => (d.addresses ?? []).includes(ROUTER_V6))
    expect(router).toBeDefined()
    // No forwarded server (Akamai/Cloudflare/Google/…) may claim the router MAC.
    for (const d of analysis.devices) {
      expect((d.addresses ?? []).filter((a) => a.startsWith("2600:") || a.startsWith("2606:") || a.startsWith("2404:") || a.startsWith("2a0"))).toEqual([])
    }
    expect(analysis.job.externalIps).toBe(23)

    // 2. Local device count unchanged (4) while total rows drop from the old
    //    29 to 27 (host v6 + router v6 folded in, both were phantom rows).
    const local = analysis.devices.filter((d) => d.ip.startsWith("192.168.") || d.ip.startsWith("10.") || d.ip.startsWith("fe8"))
    expect(local).toHaveLength(4)
    expect(analysis.devices.length).toBe(27)

    // 3. No false positives: benign browsing stays 0/100 SAFE.
    expect(analysis.threats).toHaveLength(0)
    expect(analysis.job.riskScore).toBe(0)
    expect(analysis.advancedMetrics.dataExfiltrationSuspected).toBe(false)
    expect(analysis.advancedMetrics.beaconDetected).toBe(false)

    // 4. Deterministic across runs.
    const again = analyzePcap(parsed)
    expect(again.threats).toEqual(analysis.threats)
    expect(again.job.externalIps).toBe(analysis.job.externalIps)
    expect(again.devices).toEqual(analysis.devices)
  }, 60000)

  it("counts the host's IPv6 WAN traffic in the direction buckets (bandwidth + throughput)", async () => {
    const buf = readFileSync(fixture)
    const parsed = await parsePcap(buf)
    const analysis = analyzePcap(parsed)

    // The v6 host's 518 outbound / 581 inbound packets are WAN crossing:
    // totalBytesOut must include its uploads, bandwidth must split them out.
    const outSum = analysis.bandwidth.reduce((s, b) => s + b.out, 0)
    const inSum = analysis.bandwidth.reduce((s, b) => s + b.in, 0)
    const v6Out = parsed.packets.filter((p) => p.srcIp === HOST_V6).reduce((s, p) => s + p.length, 0)
    expect(outSum).toBeGreaterThan(v6Out)
    expect(inSum).toBeGreaterThan(0)
    // Pre-fix the whole IPv6 side was counted as IN (isPrivateIp proxy).
    expect(outSum / Math.max(inSum, 1)).toBeGreaterThan(0.6)
    expect(analysis.advancedMetrics.throughputAvg).toBeGreaterThan(10_000)
  }, 60000)
})
