"use client"

// Render-error boundary for the whole app: a crash inside a chart/map/table
// must show a recoverable message instead of blanking the layout. Analysis
// data stays loaded in the store, so "Try again" re-renders the page.
import { useEffect } from "react"

export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error("PacketLens render error:", error)
  }, [error])

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="max-w-md w-full rounded-lg border border-destructive/30 bg-background p-6 text-center space-y-3">
        <h1 className="text-lg font-bold text-destructive">Something went wrong rendering this page</h1>
        <p className="text-xs text-muted-foreground break-all font-mono">{error.message || error.digest || "Unknown render error"}</p>
        <button
          onClick={() => reset()}
          className="rounded-md bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90"
        >
          Try again
        </button>
      </div>
    </div>
  )
}