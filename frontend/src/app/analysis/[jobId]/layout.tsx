import { AnalysisBoundary } from "@/components/analysis/analysis-boundary"

// Static export (desktop build) needs the dynamic segment to pre-render at
// least one param; every job page loads client-side afterward. The demo job
// is the pre-rendered entry point — arbitrary job ids resolve in the
// browser and never need their own HTML file.
export function generateStaticParams() {
  return [{ jobId: "mock-demo" }]
}

export default function AnalysisLayout({ children }: { children: React.ReactNode }) {
  return <AnalysisBoundary>{children}</AnalysisBoundary>
}