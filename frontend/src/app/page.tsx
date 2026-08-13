"use client"

import { useEffect, useRef, useState } from "react"
import dynamic from "next/dynamic"
import { UploadZone } from "@/components/upload/upload-zone"
import { Activity, ArrowRight, BarChart3, Bug, Download, Eye, Network, Scan, Shield, Zap, Globe, Lock, Cpu } from "lucide-react"
import Link from "next/link"

const NetworkScene = dynamic(() => import("@/components/landing/network-scene").then((m) => m.NetworkScene), { ssr: false })

const features = [
  { icon: BarChart3, label: "Protocol Analysis", desc: "TCP, UDP, DNS, TLS, HTTP — fully decoded", gradient: "from-chart-1 to-chart-2" },
  { icon: Network, label: "Flow & Sessions", desc: "Conversations, devices, top talkers at a glance", gradient: "from-chart-3 to-chart-2" },
  { icon: Shield, label: "Threat Detection", desc: "Port scans, anomalies, IOCs flagged automatically", gradient: "from-danger to-destructive" },
  { icon: Download, label: "Export Reports", desc: "Download full analysis as a printable PDF", gradient: "from-success to-chart-5" },
]

const stats = [
  { icon: Activity, value: "100%", label: "Free Forever" },
  { icon: Zap, value: "Up to 500 MB", label: "File Size" },
  { icon: Eye, value: "Zero", label: "Sign-ups Needed" },
  { icon: Bug, value: "14+", label: "Analysis Views" },
]

function FadeIn({ children, delay = 0, direction = "up" }: { children: React.ReactNode; delay?: number; direction?: "up" | "down" | "none" }) {
  const [visible, setVisible] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), delay)
    return () => clearTimeout(timer)
  }, [delay])

  const directionMap = {
    up: "translate-y-6",
    down: "translate-y-[-1.5rem]",
    none: "translate-y-0"
  }

  return (
    <div
      ref={ref}
      className={`transition-all duration-700 ease-out ${visible ? "opacity-100 translate-y-0" : `opacity-0 ${directionMap[direction]}`}`}
    >
      {children}
    </div>
  )
}

export default function HomePage() {
  return (
    <div className="min-h-screen flex flex-col relative overflow-hidden">
      <NetworkScene />

      <header className="h-16 border-b flex items-center justify-between px-6 bg-background/70 backdrop-blur-md sticky top-0 z-10 shadow-sm">
        <div className="flex items-center gap-2">
          <div className="h-8 w-8 rounded-xl bg-gradient-to-br from-primary via-chart-2 to-chart-3 flex items-center justify-center shadow-lg shadow-primary/30">
            <Scan className="h-4 w-4 text-white" />
          </div>
          <span className="font-bold text-xl gradient-text">
            PacketLens
          </span>
        </div>
        <nav className="flex items-center gap-4 text-sm">
          <Link href="/privacy" className="text-xs text-muted-foreground hover:text-foreground transition-colors">Privacy</Link>
          <Link
            href="/analysis/mock-demo"
            className="inline-flex items-center gap-1.5 h-9 px-4 rounded-lg bg-primary text-primary-foreground text-xs font-medium hover:bg-primary/90 transition-all duration-300 hover:scale-105 hover:shadow-md hover:shadow-primary/30 group"
          >
            Live Demo <ArrowRight className="h-3 w-3 group-hover:translate-x-0.5 transition-transform" />
          </Link>
        </nav>
      </header>

      <main className="flex-1 relative z-10 flex flex-col items-center px-4">
        <div className="max-w-4xl w-full text-center space-y-8 pt-20 pb-16">
          <FadeIn delay={100} direction="up">
            <div className="space-y-4">
              <div className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full border text-xs text-muted-foreground bg-background/50 backdrop-blur-sm shadow-sm">
                <Zap className="h-3 w-3 text-primary animate-pulse-glow" />
                Free &bull; Privacy-first &bull; No account needed
              </div>
              <h1 className="text-5xl md:text-6xl lg:text-7xl font-extrabold tracking-tight gradient-text leading-tight">
                See Inside Your
                <br />
                Network Traffic
              </h1>
              <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
                Drop a PCAP file and instantly get deep protocol analysis, threat detection,
                flow visualizations, and exportable reports.
              </p>
            </div>
          </FadeIn>

          <FadeIn delay={300} direction="up">
            <div className="max-w-xl mx-auto">
              <UploadZone />
            </div>
          </FadeIn>

          <FadeIn delay={500} direction="up">
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 pt-6">
              {stats.map((s) => (
                <div 
                  key={s.label} 
                  className="flex items-center gap-3 border rounded-xl px-4 py-3 bg-background/40 backdrop-blur-sm hover:bg-background/60 hover:border-primary/40 transition-all duration-300 hover:scale-105"
                >
                  <div className="p-1.5 rounded-md bg-primary/10">
                    <s.icon className="h-5 w-5 text-primary shrink-0" />
                  </div>
                  <div className="text-left">
                    <div className="text-lg font-bold">{s.value}</div>
                    <div className="text-xs text-muted-foreground leading-tight">{s.label}</div>
                  </div>
                </div>
              ))}
            </div>
          </FadeIn>

          <FadeIn delay={700} direction="up">
            <div className="pt-8 border-t">
              <p className="text-xs text-muted-foreground mb-4 uppercase tracking-wider font-medium">What you get</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {features.map((f) => (
                  <div
                    key={f.label}
                    className="border rounded-xl p-5 text-left space-y-3 bg-background/40 backdrop-blur-sm hover:bg-background/60 hover:border-primary/40 transition-all duration-300 group"
                  >
                    <div 
                      className={`h-9 w-9 rounded-xl bg-gradient-to-br ${f.gradient} flex items-center justify-center group-hover:scale-110 transition-transform duration-300`}
                    >
                      <f.icon className="h-4 w-4 text-white" />
                    </div>
                    <div className="text-base font-semibold">{f.label}</div>
                    <div className="text-sm text-muted-foreground leading-tight">{f.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </FadeIn>
        </div>
      </main>

      <footer className="h-14 border-t flex items-center justify-center text-xs text-muted-foreground bg-background/70 backdrop-blur-md">
        <div className="flex items-center gap-2">
          <Globe className="h-3 w-3 text-muted-foreground/50" />
          <span>PacketLens — 100% Free Forever</span>
          <span>&bull;</span>
          <span className="flex items-center gap-1">
            <Lock className="h-3 w-3" />
            Privacy-first
          </span>
          <span>&bull;</span>
          <Link href="/privacy" className="hover:text-foreground transition-colors underline underline-offset-2">
            Privacy Policy
          </Link>
          <span>&bull;</span>
          <span className="flex items-center gap-1">
            <Cpu className="h-3 w-3" />
            Built with Next.js
          </span>
        </div>
      </footer>
    </div>
  )
}
