"use client"

import { useTheme } from "next-themes"
import { Sun, Moon, GraduationCap, Bug, Menu, ArrowLeft } from "lucide-react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { useAnalysisStore } from "@/stores/analysis"
import { useIsClient } from "@/lib/use-client"
import { ANALYZER_VERSION } from "@/lib/analysis"

export function Header() {
  const { theme, setTheme } = useTheme()
  // Selector-only subscriptions: a bare useAnalysisStore() here re-renders
  // the header on every packet/burst of analysis state (QA).
  const beginnerMode = useAnalysisStore((s) => s.beginnerMode)
  const toggleBeginnerMode = useAnalysisStore((s) => s.toggleBeginnerMode)
  const toggleSidebar = useAnalysisStore((s) => s.toggleSidebar)
  const mounted = useIsClient()

  if (!mounted) return <header className="h-14 border-b bg-background" />

  return (
    <header className="h-14 border-b bg-background flex items-center justify-between gap-2 px-2 sm:px-6">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="icon" onClick={toggleSidebar} className="lg:hidden" title="Toggle Sidebar">
          <Menu className="h-5 w-5" />
        </Button>
        <Link href="/" title="Back to upload">
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-5 w-5" />
          </Button>
        </Link>
        <span className="font-mono text-xs">PacketLens</span>
        <span className="text-xs text-muted-foreground hidden sm:inline">v{ANALYZER_VERSION}</span>
      </div>

      <div className="flex items-center gap-1 sm:gap-2">
        <Button variant="ghost" size="sm" onClick={toggleBeginnerMode} title="Toggle Beginner Mode" className="px-2">
          {beginnerMode ? <GraduationCap className="h-4 w-4" /> : <Bug className="h-4 w-4" />}
          <span className="text-xs ml-1 hidden sm:inline">{beginnerMode ? "Beginner" : "Expert"}</span>
        </Button>

        <Button variant="ghost" size="icon" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
      </div>
    </header>
  )
}
