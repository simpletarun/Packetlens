import fs from "node:fs"
import path from "node:path"
import os from "node:os"
import type { AnalysisResult } from './analysis'
import { ANALYZER_VERSION } from './analysis'

interface StoredJob {
  id: string
  filename: string
  data: AnalysisResult
  createdAt: number
  analyzerVersion: string
}

// In ~/.packetlens, not os.tmpdir(): tmp is world-readable on unix and gets
// swept by cleaners; job data contains the full capture analysis.
const STORE_DIR = path.join(os.homedir(), ".packetlens")
const STORE_FILE = path.join(STORE_DIR, "jobs.json")
const MAX_JOBS = 20

const globalForJobs = globalThis as unknown as { __jobStore?: Map<string, StoredJob> }
const jobs = globalForJobs.__jobStore ??= new Map<string, StoredJob>()

function loadFromDisk(): void {
  if (jobs.size > 0) return
  try {
    if (!fs.existsSync(STORE_FILE)) return
    const parsed = JSON.parse(fs.readFileSync(STORE_FILE, "utf8")) as StoredJob[]
    for (const job of parsed) {
      if (!job?.id || !job?.data) continue
      if (job.analyzerVersion !== ANALYZER_VERSION) continue
      jobs.set(job.id, job)
    }
  } catch { /* corrupt file — start empty */ }
}

function saveToDisk(): void {
  try {
    const entries = Array.from(jobs.values())
    if (entries.length > MAX_JOBS) {
      entries.sort((a, b) => b.createdAt - a.createdAt)
      for (const stale of entries.slice(MAX_JOBS)) jobs.delete(stale.id)
    }
    fs.mkdirSync(STORE_DIR, { recursive: true, mode: 0o700 })
    fs.writeFileSync(STORE_FILE, JSON.stringify(Array.from(jobs.values())), { mode: 0o600 })
  } catch { /* disk full/permission — in-memory only */ }
}

loadFromDisk()

export function storeJob(id: string, filename: string, data: AnalysisResult): void {
  jobs.set(id, { id, filename, data, createdAt: Date.now(), analyzerVersion: ANALYZER_VERSION })
  saveToDisk()
}

export function getJob(id: string): StoredJob | undefined {
  return jobs.get(id)
}
