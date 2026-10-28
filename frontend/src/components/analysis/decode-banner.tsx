"use client"

import { useMemo } from "react"
import { useAnalysisStore } from "@/stores/analysis"
import { dltName } from "@/lib/report"
import { AlertTriangle } from "lucide-react"

// Data-quality banner for undecodable captures (unsupported link type): the
// decode gate trips at <5% decoded, and every data page must explain that its
// sections only show decoded traffic instead of silently looking empty
// (QA: large/verylarge — pages must not sit blank without a reason).
export function DecodeBanner({ className }: { className?: string }) {
  const decode = useAnalysisStore((s) => s.decode)
  const packets = useAnalysisStore((s) => s.packets)
  const rate = useMemo(() => {
    if (decode && decode.total > 0) return decode.decoded / decode.total
    if (packets.length === 0) return 1
    return packets.filter((p) => p.srcIp !== "\u2014" || p.dstIp !== "\u2014").length / packets.length
  }, [decode, packets])
  if (rate >= 0.05) return null
  const linkTypes = decode?.linkTypes || []
  return (
    <div className={"border border-danger/30 bg-danger/5 text-danger rounded-md px-3 py-2 text-xs flex items-start gap-2 " + (className || "")}>
      <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
      <span>Only {Math.round(rate * 100)}% of packets decoded — this page shows decoded traffic only. Unsupported encapsulation ({linkTypes.length ? dltName(linkTypes) : "unknown"}); lengths and timestamps parsed, headers not.</span>
    </div>
  )
}
