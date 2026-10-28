"use client"

import { useState, useRef, type DragEvent } from "react"
import { useRouter } from "next/navigation"
import { Upload, File, Loader2, AlertCircle, Clock, Zap } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { useAnalysisStore } from "@/stores/analysis"

// Link layer override (F-01): captures whose declared link type the analyzer
// can't decode (non-Ethernet raw IP, tcpdump "cooked" frames, loopback) get
// re-parsed with the right encapsulation. Values match libpcap DLT numbers.
const DLT_OPTIONS = [
  { value: "0", label: "NULL / Loopback" },
  { value: "1", label: "Ethernet" },
  { value: "101", label: "Raw IP (IPv4/IPv6)" },
  { value: "113", label: "Linux cooked v1 (SLL)" },
  { value: "276", label: "Linux cooked v2 (SLL2)" },
]

const MAX_SIZE = 500 * 1024 * 1024

const PCAP_MAGICS = [
  new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1]),
  new Uint8Array([0xa1, 0xb2, 0xc3, 0xd4]),
  new Uint8Array([0x4d, 0x3c, 0xb2, 0xa1]),
  new Uint8Array([0xa1, 0xb2, 0x3c, 0x4d]),
]

const PCAPNG_MAGIC = new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a])

async function readMagic(file: File): Promise<Uint8Array> {
  const buf = await file.slice(0, 4).arrayBuffer()
  return new Uint8Array(buf)
}

function isPCAP(magic: Uint8Array): boolean {
  return PCAP_MAGICS.some((m) => m.every((v, i) => v === magic[i]))
}

function isPCAPNG(magic: Uint8Array): boolean {
  return PCAPNG_MAGIC.every((v, i) => v === magic[i])
}

export function UploadZone() {
  const router = useRouter()
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragOver, setDragOver] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const dltOverride = useAnalysisStore((s) => s.dltOverride)
  const setDltOverride = useAnalysisStore((s) => s.setDltOverride)

  const handleDrop = (e: DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    if (uploading) return
    const f = e.dataTransfer.files[0]
    if (f) validateAndSet(f)
  }

  const validateAndSet = async (f: File) => {
    if (uploading) return
    // Server enforces the same cap; checking here avoids the round-trip.
    if (f.size > MAX_SIZE) {
      setError(`File exceeds 500 MB limit (${(f.size / 1024 / 1024).toFixed(1)} MB)`)
      return
    }
    const ext = f.name.split(".").pop()?.toLowerCase()
    if (!ext || !["pcap", "pcapng"].includes(ext)) {
      setError("Only .pcap and .pcapng files are supported")
      return
    }
    const magic = await readMagic(f)
    if (!isPCAP(magic) && !isPCAPNG(magic)) {
      setError("File does not appear to be a valid PCAP/PCAPNG capture")
      return
    }
    setError(null)
    setFile(f)
  }

  const handleUpload = async () => {
    if (!file) return
    setUploading(true)
    setProgress(0)

    const xhr = new XMLHttpRequest()
    xhr.open("POST", "/api/v1/upload")
    // Mirror the proxy route's size-scaled timeout (60 s per 50 MB, min 5 min)
    // or a 250 MB file would time out client-side while the server finishes.
    xhr.timeout = Math.max(300_000, Math.ceil(file.size / (50 << 20)) * 60_000)

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) setProgress(Math.round((e.loaded / e.total) * 100))
    }

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const { jobId } = JSON.parse(xhr.responseText)
          router.push("/analysis/" + jobId)
        } catch {
          setError("Invalid server response")
          setUploading(false)
        }
      } else {
        try {
          const { error } = JSON.parse(xhr.responseText)
          setError(error || "Upload failed")
        } catch { setError("Upload failed") }
        setUploading(false)
      }
    }

    xhr.onerror = () => { setError("Upload failed — could not reach server"); setUploading(false) }
    xhr.ontimeout = () => { setError("Upload timed out"); setUploading(false) }

    const fd = new FormData()
    fd.append("file", file)
    if (dltOverride !== null) fd.append("dltOverride", String(dltOverride))
    xhr.send(fd)
  }

  return (
    <div className="space-y-6 animate-fade-up">
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={cn(
          "border-2 border-dashed rounded-2xl p-12 cursor-pointer transition-all duration-300 relative overflow-hidden",
          dragOver 
            ? "border-primary bg-primary/5 shadow-lg shadow-primary/20 scale-[1.01]" 
            : "border-muted-foreground/25 hover:border-muted-foreground/50 hover:bg-muted/10",
          file && "border-success/50"
        )}
      >
        <div 
          className="absolute inset-0 rounded-2xl bg-gradient-to-r from-primary/5 via-transparent to-chart-2/5 opacity-0 transition-opacity duration-300 pointer-events-none"
          style={{ opacity: dragOver ? 1 : 0 }}
        />

        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          className="hidden"
          onChange={async (e) => { const f = e.target.files?.[0]; if (f) validateAndSet(f) }}
        />

        <div className="flex flex-col items-center gap-4 relative z-10">
          {file ? (
            <div className="flex items-center gap-4 p-4 bg-muted/30 rounded-xl transition-all duration-300">
              <span className="animate-scale-in">
                <File className="h-12 w-12 text-success" />
              </span>
              <div className="text-left">
                <p className="font-medium text-lg">{file.name}</p>
                <p className="text-sm text-muted-foreground">
                  {(file.size / 1024 / 1024).toFixed(1)} MB
                </p>
                <div className="flex items-center gap-2 mt-1">
                  <Clock className="h-3 w-3 text-muted-foreground/50" />
                  <span className="text-xs text-muted-foreground/70">Ready to analyze</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-3">
              <span className={cn(
                "transition-all duration-300",
                dragOver ? "animate-pulse-glow" : ""
              )}>
                <Upload className={cn(
                  "h-12 w-12 transition-all duration-300",
                  dragOver ? "text-primary scale-110" : "text-muted-foreground"
                )} />
              </span>
              <div className="text-center">
                <p className="font-medium text-lg mb-1">Drop your PCAP file here</p>
                <p className="text-sm text-muted-foreground">
                  or click to browse (.pcap, .pcapng)
                </p>
                <p className="text-xs text-muted-foreground/60 mt-2">
                  Maximum file size: 500 MB
                </p>
              </div>
            </div>
          )}
        </div>

        {error && (
          <div className="absolute inset-0 flex items-center justify-center bg-background/80 backdrop-blur-sm">
            <div className="flex items-center gap-3 p-6 bg-destructive/10 border border-destructive/30 rounded-xl max-w-md text-center">
              <AlertCircle className="h-6 w-6 text-destructive flex-shrink-0" />
              <p className="text-sm text-destructive">{error}</p>
            </div>
          </div>
        )}
      </div>

      {file && !uploading && (
        <div className="animate-fade-up space-y-3" style={{ animationDelay: '0.1s' }}>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="dlt-override" className="text-xs text-muted-foreground">
              Link layer (for non-Ethernet captures)
            </label>
            <select
              id="dlt-override"
              className="h-9 w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              value={dltOverride === null ? "" : String(dltOverride)}
              onChange={(e) => setDltOverride(e.target.value === "" ? null : Number(e.target.value))}
            >
              <option value="">Auto (detect from file)</option>
              {DLT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <Button
            onClick={handleUpload}
            className="w-full group relative overflow-hidden transition-all duration-300 hover:scale-[1.02] hover:shadow-lg hover:shadow-primary/30"
            size="lg"
          >
            <Zap className="h-4 w-4 mr-2 group-hover:animate-bounce" />
            Analyze Capture
          </Button>
        </div>
      )}

      {uploading && (
        <div className="space-y-3 animate-fade-up" style={{ animationDelay: '0.1s' }}>
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Analyzing capture... {progress}%
            </div>
            <span className="text-xs text-muted-foreground/70">
              This may take a few moments
            </span>
          </div>
          <div className="h-2 bg-muted/50 rounded-full overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-primary to-chart-2 rounded-full transition-all duration-300"
              style={{ width: progress + "%" }}
            />
          </div>
        </div>
      )}
    </div>
  )
}
