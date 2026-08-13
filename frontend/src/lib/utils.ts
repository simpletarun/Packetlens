import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatTimestamp(ts: string | number): string {
  const d = new Date(ts)
  return d.toLocaleDateString("en-US", {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  })
}

export function formatTime(ts: string | number): string {
  const d = new Date(ts)
  return d.toLocaleTimeString("en-US", {
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  })
}

// Canonical conversation key for Follow Stream. The two endpoints are kept
// intact ("ip:port") and the pair is joined in lexical order — sorting the
// bare mixed-type tuple (["1.1.1.1", 443, "2.2.2.2", 80]) reordered ports
// away from their IPs lexically and the Stream tab matched nothing.
export function streamConversationKey(p: { srcIp?: string; srcPort?: number; dstIp?: string; dstPort?: number }): string {
  const a = `${p.srcIp ?? ""}:${p.srcPort ?? ""}`
  const b = `${p.dstIp ?? ""}:${p.dstPort ?? ""}`
  return a < b ? `${a}|${b}` : `${b}|${a}`
}


