"use client"

import { useEffect, useState } from "react"
import { useParams } from "next/navigation"
import Link from "next/link"
import { useAnalysisStore } from "@/stores/analysis"
import { resolveGeoBatch, setOnlineGeoAllowed } from "@/lib/geo"
import { Loader2, AlertCircle } from "lucide-react"
import { KeyboardShortcuts } from "@/components/keyboard-shortcuts"

export function AnalysisBoundary({ children }: { children: React.ReactNode }) {
  const params = useParams()
  const jobId = params.jobId as string
  const setAllData = useAnalysisStore((s) => s.setAllData)
  const hasData = useAnalysisStore((s) => s.currentJob?.id === jobId)
  // Error is keyed by the job that produced it: navigating to another job
  // hides the screen without a setState-in-effect clear (the error screen
  // used to stick across navigation, QA).
  const [error, setError] = useState<{ jobId: string; message: string } | null>(null)
  const [pending, setPending] = useState<{ progress: number | null; stage: string | null } | null>(null)

  useEffect(() => {
    if (hasData) return

    if (jobId === "mock-demo") {
      import("@/lib/mock-data").then(m =>
        setAllData({
          job: { ...m.mockJob, id: jobId, isDemo: true },
          packets: m.mockPackets, flows: m.mockFlows,
          sessions: m.mockSessions, dns: m.mockDns,
          http: m.mockHttp, tls: m.mockTls,
          files: m.mockFiles, credentials: m.mockCredentials,
          certificates: m.mockCertificates, devices: m.mockDevices,
          alerts: m.mockThreats, timeline: m.mockTimeline,
          bandwidth: m.mockBandwidth, advancedMetrics: m.mockAdvancedMetrics || null, burst: m.mockAdvancedMetrics?.burst ?? null,
          jobInfo: m.mockJobInfo || { isDemo: true },
        })
      ).catch((err) => setError({ jobId, message: err instanceof Error ? err.message : "Failed to load demo" }))
      return
    }

    // The server analyzes synchronously, so /data answers 200.
    let active = true
    let timer: ReturnType<typeof setTimeout> | undefined
    const deadline = Date.now() + 20 * 60 * 1000
    const load = async () => {
      try {
        const res = await fetch(`/api/v1/jobs/${jobId}/data`)
        if (!active) return
        if (res.status === 202) {
          const p = await res.json().catch(() => ({}))
          if (p.status === "error") {
            setError({ jobId, message: p.error ?? "The server failed to analyze this capture." })
            return
          }
          setPending({ progress: p.progress ?? null, stage: p.stage ?? null })
          if (Date.now() > deadline) {
            setError({ jobId, message: "Analysis is taking too long — check the server and try again." })
            return
          }
          timer = setTimeout(load, 2500)
          return
        }
        if (!res.ok) throw new Error("Job not found")
        const data = await res.json()
        setAllData(data)
      } catch (err) {
        if (active) setError({ jobId, message: err instanceof Error ? err.message : "Failed to load analysis" })
      }
    }
    load()

    return () => { active = false; if (timer) clearTimeout(timer) }
  }, [jobId, hasData, setAllData])

  // Geo resolution for canonical country statistics — module-level cache in
  // lib/geo makes later lookups (map views) instant. Offline MMDB when a
  // database is installed; ipwho.is only when the user opted in (NFR-3).
  // Depends on settings.onlineGeo: toggling it in Settings must re-sync the
  // module flag AND re-run the batch — unknowns are not cached, so they get
  // a fresh online attempt (the toggle used to be a no-op, QA).
  const onlineGeo = useAnalysisStore((s) => s.settings.onlineGeo)
  useEffect(() => {
    const packets = useAnalysisStore.getState().packets
    if (!packets.length) return
    setOnlineGeoAllowed(onlineGeo)
    const ips = new Set<string>()
    for (const p of packets) { if (p.srcIp) ips.add(p.srcIp); if (p.dstIp) ips.add(p.dstIp) }
    resolveGeoBatch([...ips])
      .then((m) => {
        // Guard against a stale resolution from a previous job landing after
        // the new one's setAllData reset the map (job A's countries would
        // briefly paint over job B).
        if (useAnalysisStore.getState().currentJob?.id === jobId) useAnalysisStore.getState().setGeoMap(m)
      })
      .catch(() => {})
  }, [hasData, jobId, onlineGeo])

  if (error && error.jobId === jobId) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="flex flex-col items-center gap-3 text-center max-w-md">
          <AlertCircle className="h-10 w-10 text-destructive" />
          <p className="text-lg font-semibold">Analysis not found</p>
          <p className="text-sm text-muted-foreground">{error.message}</p>
          <Link href="/" className="text-sm text-primary hover:underline mt-2">
            Upload a new file
          </Link>
        </div>
      </div>
    )
  }

  if (!hasData && jobId !== "mock-demo") {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-sm text-muted-foreground">
            {pending
              ? `Analyzing… ${pending.progress != null ? `${Math.round(pending.progress)}%` : ""}${pending.stage ? ` · ${pending.stage}` : ""}`.trim()
              : "Loading analysis..."}
          </p>
        </div>
      </div>
    )
  }

  return (
    <>
      {children}
      <KeyboardShortcuts />
    </>
  )
}