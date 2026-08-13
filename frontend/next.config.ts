import type { NextConfig } from "next";
import path from "path"
import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"

// Desktop (Tauri) builds consume a static export — `output: "export"` disallows
// API routes, so the build script masks src/app/api and sets TAURI_BUILD=1.
const isTauri = process.env.TAURI_BUILD === "1"

const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https://*.basemaps.cartocdn.com https://tile.openstreetmap.org https://server.arcgisonline.com",
  "font-src 'self'",
  "connect-src 'self' ws: http://localhost:8080 https://*.basemaps.cartocdn.com https://tile.openstreetmap.org https://server.arcgisonline.com https://ipwho.is geoip://localhost",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "manifest-src 'self'",
  "worker-src 'self' blob:",
  "media-src 'self'",
].join("; ")

const nextConfig: NextConfig = {
  output: isTauri ? "export" : "standalone",
  trailingSlash: isTauri,
  images: isTauri ? { unoptimized: true } : undefined,
  poweredByHeader: false,
  reactStrictMode: true,
  // The dev-tools "N" bubble is position:fixed in dev builds — it repeats
  // once per full-page screenshot band and reads as a duplicated widget.
  devIndicators: false,
  // Baked in at build time so every report can prove which build produced it
  // (PDFs printed from stale servers show the old build timestamp). The src
  // hash covers the analyzer/report sources, so the fingerprint changes when
  // analysis code changes — never two builds claiming the same stamp.
  env: {
    NEXT_PUBLIC_BUILD_TIME: new Date().toISOString(),
    NEXT_PUBLIC_BUILD_SRC_HASH: createHash("sha1")
      .update(
        ["src/lib/analysis.ts", "src/lib/report.ts", "src/lib/risk.ts", "src/lib/stats.ts", "src/lib/pcap.ts", "src/lib/geo.ts"]
          .map((f) => {
            try {
              return readFileSync(path.resolve(__dirname, f), "utf8")
            } catch {
              return ""
            }
          })
          .join("\n")
      )
      .digest("hex")
      .slice(0, 12),
  },
  turbopack: {
    root: path.resolve(__dirname),
  },
  async headers() {
    if (isTauri) return []
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-XSS-Protection", value: "1; mode=block" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
        ],
      },
    ]
  },
};

export default nextConfig;
