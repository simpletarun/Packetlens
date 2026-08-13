import { type HTMLAttributes, forwardRef } from "react"
import { cn } from "@/lib/utils"

const variants = {
  default: "border-transparent bg-primary text-primary-foreground",
  secondary: "border-transparent bg-secondary text-secondary-foreground",
  destructive: "border-transparent bg-destructive text-destructive-foreground",
  success: "border-transparent bg-success text-black",
  warning: "border-transparent bg-warning text-black",
  info: "border-transparent bg-info text-black",
  outline: "text-foreground",
} as const

export interface BadgeProps extends HTMLAttributes<HTMLDivElement> {
  variant?: keyof typeof variants
}

export const Badge = forwardRef<HTMLDivElement, BadgeProps>(
  ({ className, variant = "default", ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring",
        variants[variant],
        className
      )}
      {...props}
    />
  )
)
Badge.displayName = "Badge"
