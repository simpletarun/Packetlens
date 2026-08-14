import { create } from "zustand"
import type { BurstInfo } from "@/lib/analysis"
import type { CaptureRates } from "@/lib/metrics"
import type { GeoLocation } from "@/lib/geo"
import { computeStats, AnalysisStats } from "@/lib/stats"

// --- Shared types (mirrors mock-data.ts shapes) ---
export interface JobInfo {
  isDemo?: boolean
  mode?: "local"
  sha256?: string
  sha1?: string
  md5?: string
  analyzerVersion?: string
  ruleVersion?: string
  riskSpecVersion?: string
  geoDbVersion?: string
  ouiVersion?: string
  gitCommit?: string
}

export interface JobSummary {
  id: string; filename: string; fileSize: number
  status: "uploading" | "queued" | "processing" | "done" | "error"
  progress: number; stage: string
  totalPackets: number; totalFlows: number; conversations: number
  devices: number; externalIps: number; countries: number
  domains: number; protocols: string[]; alerts: number
  riskScore: number; captureDuration: number; createdAt: string
  completedAt?: string
  isDemo?: boolean
  sha256?: string
  sha1?: string
  md5?: string
}

export interface Packet {
  num: number; timestamp: string; srcIp: string; dstIp: string
  srcPort: number; dstPort: number; protocol: string
  length: number; flags: string; ttl: number; info: string
  // On-wire frame size (captured length when snaplen truncated the frame).
  origLength?: number
  appProtocol?: string
}

export interface Flow {
  id: string; srcIp: string; dstIp: string
  srcPort: number; dstPort: number; protocol: string
  packets: number; bytesTotal: number; bytesSent: number; bytesRecv: number
  duration: number; startTime: string; endTime: string
  // True when either endpoint is undecodable ("—"): direction unknowable,
  // UI shows "—"/"unknown" instead of fake zero/symmetric bytes.
  directionUnknown?: boolean
  // TCP health metrics (v3.2). Present only when the capture carried enough
  // TCP state to derive them honestly — absent means "not computable".
  retrans?: number
  ooo?: number
  zeroWindow?: number
  rstCount?: number
  rttMs?: number
  lossPct?: number
}

export interface Session {
  id: string; srcIp: string; dstIp: string
  srcPort: number; dstPort: number; protocol: string
  packets: number; bytes: number; state: string
  duration: number; startTime: string
}

export interface DnsEntry {
  id: string; timestamp: string; srcIp: string; dstIp: string
  query: string; type: string; responseCode: string; answer: string
  // null = no answer record (queries and answer-less responses carry no TTL;
  // 0 would fabricate a zero-lease record on the DNS page).
  ttl: number | null
  isResponse?: boolean
}

export interface HttpEntry {
  id: string; timestamp: string; srcIp: string; dstIp: string
  method: string; uri: string; host: string; status: number
  contentType: string; userAgent: string; length: number
  referer?: string; cookies?: string[]
}

export interface TlsEntry {
  id: string; timestamp: string; srcIp: string; dstIp: string
  version: string; sni: string; cipherSuite: string
  ja3: string; issuer: string; validityDays: number
}

interface FileEntry {
  id: string; timestamp: string; srcIp: string; dstIp: string
  filename: string; mimeType: string; size: number
  protocol: string; md5: string
}

interface CredentialEntry {
  id: string; timestamp: string; srcIp: string; dstIp: string
  protocol: string; username: string; password: string; service: string
}

interface CallEntry {
  id: string; callId: string; from: string; to: string
  viaIp: string; startTime: string; endTime: string | null
  durationSec: number | null; userAgent: string; status: string
  rtpPayloadType: number | null; rtpSsrc: number | null
  rtpPackets: number; rtpBytes: number
}

interface CertificateEntry {
  id: string; serial: string; subject: string; issuer: string
  // null = no valid validity time in the capture (a -1 used to render as a
  // fabricated "1969-12-31" date).
  notBefore: string | null; notAfter: string | null; san: string[]
  signatureAlgorithm: string; keySize: number
  fingerprint?: string
}

export interface DeviceEntry {
  id: string; ip: string; mac: string; hostname: string
  vendor: string; os: string; firstSeen: string; lastSeen: string
  packets: number; bytes: number
  // v3.2: every other address this device was seen on (IPv6, additional IPv4)
  // — the UI folds these into one row instead of one row per address.
  addresses?: string[]
  // Where the OS value came from: a User-Agent in this device's own requests,
  // or the TTL heuristic. Absent when no decision was possible.
  osSource?: 'ua' | 'ttl'
}

export interface AlertEntry {
  id: string; timestamp: string; signature: string; category: string
  severity: number; confidence: number; ruleId: string
  srcIp: string; dstIp: string
  srcPort: number; dstPort: number; protocol: string; evidence: string
}

export interface TimelineEntry {
  time: string; packets: number; bytes: number
  tcp: number; udp: number; dns: number; tls: number
}

export interface BandwidthPoint {
  time: string; in: number; out: number
}

export interface AdvancedMetrics {
  /** Canonical rates/duration from the metrics engine; null avg/peak = no
   *  time interval (single packet / zero duration) — render N/A. */
  rates?: CaptureRates
  throughputAvg: number | null
  throughputPeak: number | null
  burst: BurstInfo | null
  beaconDetected: boolean
  dnsTunnelingSuspected: boolean
  dataExfiltrationSuspected: boolean
  torVpnProxyDetected: boolean
  portScanEnhanced: boolean
  ja3Suspicious: boolean
  topTalkers: { ip: string; bytesOut: number; bytesIn: number; packetsOut: number; packetsIn: number }[]
  iocs: { type: string; value: string; description: string; severity: number }[]
  mitreMappings: { technique: string; id: string; description: string; severity: number }[]
}

// User preferences, persisted in localStorage (the privacy policy promises
// this: "Application preferences … stored on your device only"). The in-memory
// copy survives resetAnalysis so a new upload doesn't flip choices back.
export interface AnalysisSettings {
  // v3.2 (NFR-3): online IP lookups (ipwho.is fallback) are OFF by default;
  // enabled explicitly in Settings. Offline MMDB lookups never touch this.
  onlineGeo: boolean
  // v3.2 (F-04 QA): optional MANUAL home location (lat/lon) entered in
  // Settings. When set, the Home card shows these coordinates instead of a
  // (potentially unavailable) online self-lookup — no network required.
  homeLat?: number | null
  homeLon?: number | null
}

const SETTINGS_KEY = "packetlens-settings"

// Read persisted preferences; every field is validated so a hand-edited or
// stale value (wrong type, garbage JSON) can never poison the store.
function loadPersistedPrefs(): { beginnerMode?: boolean; dltOverride?: number | null; settings?: Partial<AnalysisSettings> } {
  if (typeof localStorage === "undefined") return {}
  try {
    const raw = localStorage.getItem(SETTINGS_KEY)
    if (!raw) return {}
    const p = JSON.parse(raw) as Record<string, unknown>
    return {
      beginnerMode: p.beginnerMode === true ? true : undefined,
      dltOverride: typeof p.dltOverride === "number" ? p.dltOverride : undefined,
      settings: {
        onlineGeo: p.onlineGeo === true ? true : undefined,
        homeLat: typeof p.homeLat === "number" ? p.homeLat : undefined,
        homeLon: typeof p.homeLon === "number" ? p.homeLon : undefined,
      },
    }
  } catch {
    return {}
  }
}

interface AnalysisViewData {
  job: JobSummary
  packets: Packet[]
  flows: Flow[]
  sessions: Session[]
  dns: DnsEntry[]
  http: HttpEntry[]
  tls: TlsEntry[]
  files: FileEntry[]
  calls?: CallEntry[]
  credentials: CredentialEntry[]
  certificates: CertificateEntry[]
  devices: DeviceEntry[]
  alerts: AlertEntry[]
  timeline: TimelineEntry[]
  bandwidth: BandwidthPoint[]
  advancedMetrics: AdvancedMetrics | null
  burst: BurstInfo | null
  jobInfo?: JobInfo
  decode?: { decoded: number; total: number; linkTypes: number[] } | null
}

interface AnalysisState {
  currentJob: JobSummary | null
  jobInfo: JobInfo
  packets: Packet[]
  flows: Flow[]
  sessions: Session[]
  dns: DnsEntry[]
  http: HttpEntry[]
  tls: TlsEntry[]
  files: FileEntry[]
  calls: CallEntry[]
  credentials: CredentialEntry[]
  certificates: CertificateEntry[]
  devices: DeviceEntry[]
  alerts: AlertEntry[]
  timeline: TimelineEntry[]
  bandwidth: BandwidthPoint[]
  advancedMetrics: AdvancedMetrics | null
  burst: BurstInfo | null
  decode: { decoded: number; total: number; linkTypes: number[] } | null
  geoMap: Map<string, GeoLocation>
  stats: AnalysisStats
  beginnerMode: boolean
  sidebarOpen: boolean
  // v3.2 (F-01): user-chosen link type override for re-parse; null = auto.
  dltOverride: number | null
  settings: AnalysisSettings
  setCurrentJob: (job: JobSummary | null) => void
  setPackets: (packets: Packet[]) => void
  setFlows: (flows: Flow[]) => void
  setSessions: (s: Session[]) => void
  setDns: (d: DnsEntry[]) => void
  setHttp: (h: HttpEntry[]) => void
  setTls: (t: TlsEntry[]) => void
  setFiles: (f: FileEntry[]) => void
  setCredentials: (c: CredentialEntry[]) => void
  setCertificates: (c: CertificateEntry[]) => void
  setDevices: (d: DeviceEntry[]) => void
  setAlerts: (a: AlertEntry[]) => void
  setTimeline: (t: TimelineEntry[]) => void
  setBandwidth: (b: BandwidthPoint[]) => void
  setAdvancedMetrics: (m: AdvancedMetrics) => void
  setGeoMap: (geo: Map<string, GeoLocation>) => void
  setDltOverride: (dlt: number | null) => void
  setSettings: (patch: Partial<AnalysisSettings>) => void
  setAllData: (data: AnalysisViewData) => void
  toggleBeginnerMode: () => void
  toggleSidebar: () => void
  resetAnalysis: () => void
}

const initialState = {
  currentJob: null,
  jobInfo: {},
  packets: [], flows: [], sessions: [], dns: [], http: [], tls: [],
  files: [], calls: [], credentials: [], certificates: [], devices: [], alerts: [],
  timeline: [], bandwidth: [], advancedMetrics: null, burst: null,
  decode: null,
  geoMap: new Map<string, GeoLocation>(),
  stats: {
    totalPackets: 0, totalFlows: 0, sessions: 0, devices: 0, externalIps: 0,
    countries: 0, domains: 0, protocols: [], alerts: 0, riskScore: 0, captureDuration: 0,
  },
  beginnerMode: false,
  sidebarOpen: true,
  dltOverride: null,
  settings: { onlineGeo: false, homeLat: null, homeLon: null },
}

function recomputeStats(s: {
  job: JobSummary | null
  packets: Packet[]; flows: Flow[]; sessions: Session[]; dns: DnsEntry[]
  devices: DeviceEntry[]; alerts: AlertEntry[]; geo: Map<string, GeoLocation>
}): AnalysisStats {
  return computeStats(s)
}

export const useAnalysisStore = create<AnalysisState>((set, get) => {
  const persisted = loadPersistedPrefs()
  const savePrefs = () => {
    const s = get()
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify({
        onlineGeo: s.settings.onlineGeo,
        homeLat: s.settings.homeLat ?? null,
        homeLon: s.settings.homeLon ?? null,
        beginnerMode: s.beginnerMode,
        dltOverride: s.dltOverride,
      }))
    } catch { /* storage full/blocked: prefs stay session-only */ }
  }
  return {
    ...initialState,
    beginnerMode: persisted.beginnerMode ?? initialState.beginnerMode,
    dltOverride: persisted.dltOverride ?? initialState.dltOverride,
    settings: { ...initialState.settings, ...persisted.settings },
    setCurrentJob: (job) => set({ currentJob: job }),
    setPackets: (packets) => set({ packets }),
    setFlows: (flows) => set({ flows }),
    setSessions: (s) => set({ sessions: s }),
    setDns: (d) => set({ dns: d }),
    setHttp: (h) => set({ http: h }),
    setTls: (t) => set({ tls: t }),
    setFiles: (f) => set({ files: f }),
    setCredentials: (c) => set({ credentials: c }),
    setCertificates: (c) => set({ certificates: c }),
    setDevices: (d) => set({ devices: d }),
    setAlerts: (a) => set({ alerts: a }),
    setTimeline: (t) => set({ timeline: t }),
    setBandwidth: (b) => set({ bandwidth: b }),
    setAdvancedMetrics: (m) => set({ advancedMetrics: m }),
    setAllData: (data) => set((s) => ({
      currentJob: data.job,
      jobInfo: data.jobInfo ?? {},
      packets: data.packets,
      flows: data.flows,
      sessions: data.sessions,
      dns: data.dns,
      http: data.http,
      tls: data.tls,
      files: data.files,
      calls: data.calls ?? [],
      credentials: data.credentials,
      certificates: data.certificates,
      devices: data.devices,
      alerts: data.alerts,
      timeline: data.timeline,
      bandwidth: data.bandwidth,
      advancedMetrics: data.advancedMetrics,
      burst: data.burst ?? null,
      decode: data.decode ?? null,
      // Drop the previous job's geo before the new one's resolution lands — the
      // old countries card would otherwise linger on the new job's stats
      // (geoMap resolves asynchronously after setAllData).
      geoMap: new Map<string, GeoLocation>(),
      stats: recomputeStats({ ...s, job: data.job, geo: new Map<string, GeoLocation>(), packets: data.packets, flows: data.flows, sessions: data.sessions, dns: data.dns, devices: data.devices, alerts: data.alerts }),
    })),
    setGeoMap: (geo) => set((s) => ({ geoMap: geo, stats: recomputeStats({ ...s, job: s.currentJob, geo, packets: s.packets, flows: s.flows, sessions: s.sessions, dns: s.dns, devices: s.devices, alerts: s.alerts }) })),
    setDltOverride: (dlt) => { set({ dltOverride: dlt }); savePrefs() },
    setSettings: (patch) => { set((s) => ({ settings: { ...s.settings, ...patch } })); savePrefs() },
    toggleBeginnerMode: () => { set((s) => ({ beginnerMode: !s.beginnerMode })); savePrefs() },
    toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),
    resetAnalysis: () => set((s) => ({ ...initialState, settings: s.settings })),
  }
})
