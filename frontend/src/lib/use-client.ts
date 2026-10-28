import { useSyncExternalStore } from "react"

const emptySubscribe = () => () => {}

// Returns false during SSR/first paint and true after hydration, so
// client-only UI (theme toggles, resize-driven layout) is never server-rendered.
export function useIsClient(): boolean {
  return useSyncExternalStore(emptySubscribe, () => true, () => false)
}

// Live viewport width check — subscribes to resize instead of setState-in-effect.
export function useIsMobile(breakpoint = 1024): boolean {
  const subscribe = (cb: () => void) => {
    window.addEventListener("resize", cb)
    return () => window.removeEventListener("resize", cb)
  }
  const getSnapshot = () => window.innerWidth < breakpoint
  return useSyncExternalStore(subscribe, getSnapshot, () => false)
}