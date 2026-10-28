import { Suspense } from "react"
import { AnalysisBoundary } from "@/components/analysis/analysis-boundary"
import { Loader2 } from "lucide-react"

export const dynamic = "force-dynamic"

function AnalysisLoadingShell() {
  return (
    <div className="flex h-screen items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Loading analysis...</p>
      </div>
    </div>
  )
}

export default function AnalysisLayout({ children }: { children: React.ReactNode }) {
  return (
    <Suspense fallback={<AnalysisLoadingShell />}>
      <AnalysisBoundary>{children}</AnalysisBoundary>
    </Suspense>
  )
}
