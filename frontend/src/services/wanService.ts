import {
  type WanUplink,
  type WanUplinkState,
  type WanStatusEntry,
  type WanStatusResponse,
  type WanMetricPoint,
  type WanFailoverSettings,
  initialWanUplinks,
  initialWanUplinkStates,
  initialWanFailoverSettings,
} from "@/data-mockup/mockData"
import { IS_MOCK_MODE, API_BASE_URL } from "./config"

export type {
  WanUplink,
  WanUplinkState,
  WanStatusEntry,
  WanStatusResponse,
  WanMetricPoint,
  WanFailoverSettings,
}

const UPLINKS_KEY = "pigate_wan_uplinks"
const STATES_KEY = "pigate_wan_uplink_states"
const FAILOVER_SETTINGS_KEY = "pigate_wan_failover_settings"

// windowBucketCount mirrors the backend's statsWindowBuckets map
// (backend/internal/service/traffic_stats.go) so a mock-mode graph has the
// same number of points a real board would return.
const windowBucketCount: Record<string, number> = {
  "15m": 3,
  "30m": 6,
  "1h": 12,
  "3h": 36,
  "6h": 72,
  "12h": 144,
  "24h": 288,
}

function getLocalUplinks(): WanUplink[] {
  const stored = localStorage.getItem(UPLINKS_KEY)
  if (!stored) {
    localStorage.setItem(UPLINKS_KEY, JSON.stringify(initialWanUplinks))
    return initialWanUplinks
  }
  try {
    return JSON.parse(stored)
  } catch (e) {
    console.error("Failed to parse local WAN uplinks, resetting to mock data:", e)
    localStorage.setItem(UPLINKS_KEY, JSON.stringify(initialWanUplinks))
    return initialWanUplinks
  }
}

function saveLocalUplinks(uplinks: WanUplink[]) {
  localStorage.setItem(UPLINKS_KEY, JSON.stringify(uplinks))
}

function getLocalStates(): Record<string, WanUplinkState> {
  const stored = localStorage.getItem(STATES_KEY)
  if (!stored) {
    localStorage.setItem(STATES_KEY, JSON.stringify(initialWanUplinkStates))
    return initialWanUplinkStates
  }
  try {
    return JSON.parse(stored)
  } catch (e) {
    console.error("Failed to parse local WAN uplink states, resetting to mock data:", e)
    localStorage.setItem(STATES_KEY, JSON.stringify(initialWanUplinkStates))
    return initialWanUplinkStates
  }
}

function getLocalFailoverSettings(): WanFailoverSettings {
  const stored = localStorage.getItem(FAILOVER_SETTINGS_KEY)
  if (!stored) {
    localStorage.setItem(FAILOVER_SETTINGS_KEY, JSON.stringify(initialWanFailoverSettings))
    return initialWanFailoverSettings
  }
  try {
    return JSON.parse(stored)
  } catch (e) {
    console.error("Failed to parse local WAN failover settings, resetting to mock data:", e)
    localStorage.setItem(FAILOVER_SETTINGS_KEY, JSON.stringify(initialWanFailoverSettings))
    return initialWanFailoverSettings
  }
}

function saveLocalFailoverSettings(settings: WanFailoverSettings) {
  localStorage.setItem(FAILOVER_SETTINGS_KEY, JSON.stringify(settings))
}

// mockMetricSeries synthesizes a plausible-looking time series around the
// uplink's current mock state (a "down"/"unknown" uplink has no useful
// latency, an "up"/"degraded" one gets gentle random jitter around its
// lastLatencyMs) — good enough to exercise the graph UI, not meant to be
// statistically meaningful.
function mockMetricSeries(uplinkId: string, window: string): WanMetricPoint[] {
  const n = windowBucketCount[window] ?? windowBucketCount["1h"]
  const state = getLocalStates()[uplinkId]
  const points: WanMetricPoint[] = []
  const now = Date.now()
  const spanMs = 5 * 60 * 1000 // 5-minute buckets, mirrors the backend ring

  for (let i = n - 1; i >= 0; i--) {
    const ts = new Date(now - i * spanMs).toISOString()
    if (!state || state.state === "down" || state.state === "unknown") {
      points.push({ timestamp: ts, avgLatencyMs: 0, maxLatencyMs: 0, jitterMs: null, lossPct: state?.state === "down" ? 100 : 0 })
      continue
    }
    const base = state.lastLatencyMs || 10
    const noise = (Math.sin(i * 0.7) + 1) * base * 0.05
    const connectOnly = state.metricQuality === "connect-only"
    points.push({
      timestamp: ts,
      avgLatencyMs: Math.round((base + noise) * 10) / 10,
      maxLatencyMs: Math.round((base + noise * 2) * 10) / 10,
      jitterMs: connectOnly ? null : Math.round((state.jitterMs + noise * 0.3) * 10) / 10,
      lossPct: 0,
    })
  }
  return points
}

export const wanService = {
  // --- Uplink CRUD (GET/POST/PUT/DELETE /api/wan/uplinks) ---------------
  getUplinks: async (): Promise<WanUplink[]> => {
    if (IS_MOCK_MODE) {
      await new Promise((resolve) => setTimeout(resolve, 300))
      return getLocalUplinks()
    }
    const response = await fetch(`${API_BASE_URL}/wan/uplinks`)
    if (!response.ok) {
      throw new Error(`Failed to fetch WAN uplinks: ${response.statusText}`)
    }
    return response.json()
  },

  createUplink: async (input: Omit<WanUplink, "id">): Promise<WanUplink> => {
    if (IS_MOCK_MODE) {
      await new Promise((resolve) => setTimeout(resolve, 350))
      const current = getLocalUplinks()
      const newUplink: WanUplink = { ...input, id: "wan-" + Math.random().toString(36).substring(2, 9) }
      saveLocalUplinks([...current, newUplink])
      return newUplink
    }
    const response = await fetch(`${API_BASE_URL}/wan/uplinks`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    })
    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      throw new Error(body.message || `Failed to create WAN uplink: ${response.statusText}`)
    }
    return response.json()
  },

  updateUplink: async (id: string, input: Omit<WanUplink, "id">): Promise<WanUplink> => {
    if (IS_MOCK_MODE) {
      await new Promise((resolve) => setTimeout(resolve, 350))
      const current = getLocalUplinks()
      const idx = current.findIndex((u) => u.id === id)
      if (idx === -1) throw new Error("WAN uplink not found")
      const updated: WanUplink = { ...input, id }
      current[idx] = updated
      saveLocalUplinks(current)
      return updated
    }
    const response = await fetch(`${API_BASE_URL}/wan/uplinks/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    })
    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      throw new Error(body.message || `Failed to update WAN uplink: ${response.statusText}`)
    }
    return response.json()
  },

  deleteUplink: async (id: string): Promise<void> => {
    if (IS_MOCK_MODE) {
      await new Promise((resolve) => setTimeout(resolve, 200))
      saveLocalUplinks(getLocalUplinks().filter((u) => u.id !== id))
      return
    }
    const response = await fetch(`${API_BASE_URL}/wan/uplinks/${id}`, { method: "DELETE" })
    if (!response.ok) {
      throw new Error(`Failed to delete WAN uplink: ${response.statusText}`)
    }
  },

  // --- Live status/metrics (GET /api/wan/status, /api/wan/metrics) ------
  getStatus: async (): Promise<WanStatusResponse> => {
    if (IS_MOCK_MODE) {
      await new Promise((resolve) => setTimeout(resolve, 300))
      const uplinks = getLocalUplinks()
      const states = getLocalStates()
      return {
        uplinks: uplinks.map((u) => {
          const st = states[u.id] ?? {
            uplinkId: u.id,
            interface: u.interface,
            state: "unknown",
            active: false,
            lastLatencyMs: 0,
            jitterMs: 0,
            lossPct: 0,
            effectiveMethod: "",
            metricQuality: "",
            strikes: 0,
            lastChangeAt: "",
            reason: "",
          }
          return { ...st, name: u.name, priority: u.priority }
        }),
        bypassedByStaticRoute: false,
        activeUplinkId: "",
        lastSwitchAt: "",
        lastSwitchReason: "",
      }
    }
    const response = await fetch(`${API_BASE_URL}/wan/status`)
    if (!response.ok) {
      throw new Error(`Failed to fetch WAN status: ${response.statusText}`)
    }
    return response.json()
  },

  getMetrics: async (uplinkId: string, window: string): Promise<WanMetricPoint[]> => {
    if (IS_MOCK_MODE) {
      await new Promise((resolve) => setTimeout(resolve, 250))
      return mockMetricSeries(uplinkId, window)
    }
    const params = new URLSearchParams({ uplink: uplinkId, window })
    const response = await fetch(`${API_BASE_URL}/wan/metrics?${params.toString()}`)
    if (!response.ok) {
      throw new Error(`Failed to fetch WAN metrics: ${response.statusText}`)
    }
    return response.json()
  },

  // --- Failover settings / kill switch / manual override ----------------
  // Reserved for Phase 2 (docs/ref/todo/multi-wan-failover-plan.md Task
  // 16-18, superAdminRoute) — the backend endpoints do not exist yet, and no
  // Phase 1 UI calls these. Included now so wanService.ts's shape already
  // matches the eventual contract when that phase is approved.
  getFailoverSettings: async (): Promise<WanFailoverSettings> => {
    if (IS_MOCK_MODE) {
      await new Promise((resolve) => setTimeout(resolve, 200))
      return getLocalFailoverSettings()
    }
    const response = await fetch(`${API_BASE_URL}/wan/failover`)
    if (!response.ok) {
      throw new Error(`Failed to fetch WAN failover settings: ${response.statusText}`)
    }
    return response.json()
  },

  updateFailoverSettings: async (settings: WanFailoverSettings): Promise<WanFailoverSettings> => {
    if (IS_MOCK_MODE) {
      await new Promise((resolve) => setTimeout(resolve, 300))
      saveLocalFailoverSettings(settings)
      return settings
    }
    const response = await fetch(`${API_BASE_URL}/wan/failover`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(settings),
    })
    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      throw new Error(body.message || `Failed to update WAN failover settings: ${response.statusText}`)
    }
    return response.json()
  },

  setManualOverride: async (uplinkId: string): Promise<void> => {
    if (IS_MOCK_MODE) {
      await new Promise((resolve) => setTimeout(resolve, 300))
      const settings = getLocalFailoverSettings()
      saveLocalFailoverSettings({ ...settings, mode: "manual", manualUplinkId: uplinkId })
      return
    }
    const response = await fetch(`${API_BASE_URL}/wan/failover/override`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ uplinkId }),
    })
    if (!response.ok) {
      throw new Error(`Failed to set WAN manual override: ${response.statusText}`)
    }
  },
}
