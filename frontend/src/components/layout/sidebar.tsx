"use client"

import Link from "next/link"
import { useParams, usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import {
  LayoutDashboard, Package, GitFork, MessagesSquare, Globe, FileCode,
  Shield, FolderOpen, Key, Verified, Monitor, AlertTriangle, History,
  BarChart3, FileText, Settings, ChevronLeft, X,
} from "lucide-react"
import { useEffect } from "react"
import { useIsClient, useIsMobile } from "@/lib/use-client"

const navGroups = [
  {
    label: "Overview",
    items: [
      { label: "Dashboard", href: "", icon: LayoutDashboard },
      { label: "Visualizations", href: "/visualizations", icon: BarChart3 },
      { label: "Timeline", href: "/timeline", icon: History },
    ],
  },
  {
    label: "Traffic",
    items: [
      { label: "Packets", href: "/packets", icon: Package },
      { label: "Flows", href: "/flows", icon: GitFork },
      { label: "Sessions", href: "/sessions", icon: MessagesSquare },
      { label: "DNS", href: "/dns", icon: Globe },
      { label: "HTTP", href: "/http", icon: FileCode },
      { label: "TLS", href: "/tls", icon: Shield },
    ],
  },
  {
    label: "Forensics",
    items: [
      { label: "Files", href: "/files", icon: FolderOpen },
      { label: "Credentials", href: "/credentials", icon: Key },
      { label: "Certificates", href: "/certificates", icon: Verified },
      { label: "Devices", href: "/devices", icon: Monitor },
      { label: "Threats", href: "/threats", icon: AlertTriangle },
    ],
  },
  {
    label: "System",
    items: [
      { label: "Reports", href: "/reports", icon: FileText },
      { label: "Settings", href: "/settings", icon: Settings },
    ],
  },
]

export function Sidebar({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  const pathname = usePathname()
  const params = useParams()
  const jobId = params?.jobId as string
  const isMobile = useIsMobile()
  const mounted = useIsClient()

  useEffect(() => {
    // Close-on-navigation, never open: with back/forward the pathname changes
    // while the sidebar is already closed, and an unconditional toggle would
    // flip it open over the content on every other navigation (QA).
    if (mounted && isMobile && open) onToggle()
  }, [pathname, isMobile, mounted, onToggle, open])

  return (
    <>
      {open && (
        <div className="fixed inset-0 z-30 bg-black/40 lg:hidden" onClick={onToggle} />
      )}
      <aside
        className={cn(
          "fixed left-0 top-0 z-40 h-full border-r bg-sidebar-background text-sidebar-foreground transition-all duration-300 flex flex-col",
          open ? "w-56" : "w-0 lg:w-16 overflow-hidden lg:overflow-visible"
        )}
      >
        <div className="flex h-14 items-center justify-between px-4 border-b border-sidebar-border shrink-0">
          {open && <span className="font-bold text-sidebar-primary-foreground text-lg whitespace-nowrap">PacketLens</span>}
          <button onClick={onToggle} className="p-1 rounded-md hover:bg-sidebar-accent text-sidebar-foreground">
            {open && mounted && isMobile ? (
              <X className="h-5 w-5" />
            ) : (
              <ChevronLeft className={cn("h-5 w-5 transition-transform", !open && "rotate-180")} />
            )}
          </button>
        </div>

        <div className="flex-1 overflow-y-auto py-2 px-2 space-y-0.5">
          <nav className="space-y-3">
            {navGroups.map((group) => (
              <div key={group.label} className="space-y-0.5">
                {open && (
                  <p className="px-3 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">
                    {group.label}
                  </p>
                )}
                {group.items.map((item) => {
                  const isActive = item.href === ""
                    ? pathname === `/analysis/${jobId}`
                    : pathname === `/analysis/${jobId}${item.href}`

                  return (
                    <Link
                      key={item.href}
                      href={`/analysis/${jobId}${item.href}`}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
                        isActive
                          // Active must read differently from hover: same accent
                          // bg + font-medium was indistinguishable from the hover
                          // state and read as a double-highlight (QA: TLS/Files).
                          ? "bg-sidebar-accent text-sidebar-accent-foreground font-medium ring-1 ring-inset ring-sidebar-accent-foreground/30"
                          : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                        !open && "lg:justify-center lg:px-2"
                      )}
                      title={!open ? item.label : undefined}
                    >
                      <item.icon className="h-5 w-5 shrink-0" />
                      {open && <span className="whitespace-nowrap">{item.label}</span>}
                    </Link>
                  )
                })}
              </div>
            ))}
          </nav>
        </div>
      </aside>
    </>
  )
}
