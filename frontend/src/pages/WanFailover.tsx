import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { getErrorMessage } from "@/lib/errors"
import {
  Shuffle,
  Plus,
  Edit,
  Trash2,
  AlertCircle,
  Info,
  Loader2,
  Activity,
  Gauge,
  RefreshCw,
} from "lucide-react"
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
} from "recharts"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Drawer, DrawerContent, DrawerHeader, DrawerTitle } from "@/components/ui/drawer"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert"
import { Switch } from "@/components/ui/switch"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { wanService, type WanUplink, type WanStatusEntry, type WanMetricPoint } from "@/services/wanService"
import { interfaceService } from "@/services/interfaceService"
import { type NetworkInterface } from "@/data-mockup/mockData"
import { useAlert } from "@/hooks/useAlert"
import { useTheme } from "@/hooks/useTheme"
import { cn, isValidIp } from "@/lib/utils"
import { ifaceLabel, formatIfaceLabel } from "@/lib/ifaceLabel"

// /network/wan — Multi-WAN Failover, Phase 1 (docs/ref/todo/
// multi-wan-failover-plan.md Task 11). Read-only health monitoring UI: uplink
// CRUD + live status cards + latency/loss history graph. There is
// deliberately no kill switch / manual override control here yet — that is
// Phase 2 (Task 18), gated on the not-yet-built automatic failover
// controller and superAdminRoute.

const REFRESH_INTERVAL_MS = 5_000

type MetricWindow = "1h" | "24h"

const PROBE_METHOD_LABEL: Record<string, string> = {
  icmp: "ICMP",
  tcp: "TCP",
  auto: "Auto (ICMP → TCP fallback)",
}

const STATE_BADGE_CLASS: Record<string, string> = {
  up: "border-primary/20 bg-primary/10 text-primary",
  degraded: "border-warning/30 bg-warning/10 text-warning",
  down: "border-destructive/20 bg-destructive/10 text-destructive",
  unknown: "border-border bg-muted text-muted-foreground",
}

const STATE_LABEL: Record<string, string> = {
  up: "Up",
  degraded: "Degraded",
  down: "Down",
  unknown: "Unknown",
}

function StateBadge({ state }: { state: string }) {
  return (
    <Badge variant="outline" className={cn("rounded px-2 py-0.5 text-[10px] font-semibold uppercase", STATE_BADGE_CLASS[state] ?? STATE_BADGE_CLASS.unknown)}>
      {STATE_LABEL[state] ?? state}
    </Badge>
  )
}

interface UplinkFormState {
  name: string
  interface: string
  priority: string
  probeTargets: string // comma-separated in the form, split/joined on save
  probeMethod: string
  probeTcpPort: string
  probeIntervalSeconds: string
  probeCount: string
  probeTimeoutMs: string
  lossThresholdPct: string
  latencyThresholdMs: string
  failStrikes: string
  recoverStrikes: string
  status: boolean
  description: string
}

const emptyForm: UplinkFormState = {
  name: "",
  interface: "",
  priority: "1",
  probeTargets: "",
  probeMethod: "auto",
  probeTcpPort: "443",
  probeIntervalSeconds: "5",
  probeCount: "3",
  probeTimeoutMs: "1000",
  lossThresholdPct: "50",
  latencyThresholdMs: "200",
  failStrikes: "3",
  recoverStrikes: "3",
  status: true,
  description: "",
}

function uplinkToForm(u: WanUplink): UplinkFormState {
  return {
    name: u.name,
    interface: u.interface,
    priority: String(u.priority),
    probeTargets: u.probeTargets.join(", "),
    probeMethod: u.probeMethod,
    probeTcpPort: String(u.probeTcpPort || ""),
    probeIntervalSeconds: String(u.probeIntervalSeconds),
    probeCount: String(u.probeCount),
    probeTimeoutMs: String(u.probeTimeoutMs),
    lossThresholdPct: String(u.lossThresholdPct),
    latencyThresholdMs: String(u.latencyThresholdMs),
    failStrikes: String(u.failStrikes),
    recoverStrikes: String(u.recoverStrikes),
    status: u.status,
    description: u.description,
  }
}

function MetricChart({ title, unit, dataKey, data, color, axis, grid, formatTooltip }: {
  title: string
  unit: string
  dataKey: "avgLatencyMs" | "lossPct"
  data: { time: string; avgLatencyMs: number; lossPct: number }[]
  color: string
  axis: string
  grid: string
  formatTooltip: (v: number) => string
}) {
  const hasSignal = data.length > 0
  return (
    <div className="space-y-2">
      <p className="text-xs font-medium text-muted-foreground">{title}</p>
      <div className="h-40 w-full">
        {!hasSignal ? (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
            ยังไม่มีข้อมูล
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={grid} />
              <XAxis dataKey="time" stroke={axis} fontSize={10} tickLine={false} axisLine={false} interval="preserveStartEnd" />
              <YAxis stroke={axis} fontSize={10} tickLine={false} axisLine={false} width={40} tickFormatter={(v) => `${v}${unit}`} />
              <RechartsTooltip
                formatter={(value) => formatTooltip(Number(value))}
                contentStyle={{ fontSize: "11px", borderRadius: "8px" }}
              />
              <Line type="monotone" dataKey={dataKey} stroke={color} strokeWidth={2} dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}

export default function WanFailover() {
  const { alert: showAlert, confirm } = useAlert()
  const { theme } = useTheme()
  const isDark = theme === "dark"
  const grid = isDark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.06)"
  const axis = isDark ? "rgba(255,255,255,0.45)" : "rgba(0,0,0,0.45)"

  const [uplinks, setUplinks] = useState<WanUplink[]>([])
  const [statusById, setStatusById] = useState<Record<string, WanStatusEntry>>({})
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [selectedGraphUplink, setSelectedGraphUplink] = useState<string>("")
  const [metricWindow, setMetricWindow] = useState<MetricWindow>("1h")
  const [metricPoints, setMetricPoints] = useState<WanMetricPoint[]>([])

  const [isDrawerOpen, setIsDrawerOpen] = useState(false)
  const [editingUplink, setEditingUplink] = useState<WanUplink | null>(null)
  const [form, setForm] = useState<UplinkFormState>(emptyForm)
  const [formError, setFormError] = useState("")

  const loadStatus = useCallback(async () => {
    try {
      const status = await wanService.getStatus()
      const byId: Record<string, WanStatusEntry> = {}
      for (const entry of status.uplinks) byId[entry.uplinkId] = entry
      setStatusById(byId)
    } catch {
      // Background poll failures are swallowed — keep showing the last
      // known snapshot rather than flashing an error every 5s.
    }
  }, [])

  const loadAll = useCallback(async (showLoading: boolean) => {
    if (showLoading) setIsLoading(true)
    try {
      const [allUplinks, allIfaces] = await Promise.all([wanService.getUplinks(), interfaceService.getAll()])
      setUplinks(allUplinks)
      setInterfaces(allIfaces)
      setSelectedGraphUplink((prev) => prev || allUplinks[0]?.id || "")
      setError(null)
      await loadStatus()
    } catch (err) {
      if (showLoading) setError(getErrorMessage(err))
    } finally {
      if (showLoading) setIsLoading(false)
    }
  }, [loadStatus])

  // loadAllRef/loadStatusRef indirection mirrors StatisticsTraffic.tsx: the
  // effect below calls the ref rather than the function identifier directly
  // so the initial-load + polling setState isn't flagged as a synchronous
  // setState-in-effect (react-hooks/set-state-in-effect) while still always
  // running the latest closure.
  const loadAllRef = useRef(loadAll)
  useEffect(() => {
    loadAllRef.current = loadAll
  })
  const loadStatusRef = useRef(loadStatus)
  useEffect(() => {
    loadStatusRef.current = loadStatus
  })

  useEffect(() => {
    loadAllRef.current(true)
    const id = setInterval(() => {
      loadStatusRef.current()
    }, REFRESH_INTERVAL_MS)
    return () => clearInterval(id)
  }, [])

  const loadMetrics = useCallback(async (uplinkId: string, win: MetricWindow) => {
    if (!uplinkId) {
      setMetricPoints([])
      return
    }
    try {
      const points = await wanService.getMetrics(uplinkId, win)
      setMetricPoints(points)
    } catch {
      // Graph failures degrade to "no data" silently, same as other
      // statistics pages' background poll errors.
    }
  }, [])

  const loadMetricsRef = useRef(loadMetrics)
  useEffect(() => {
    loadMetricsRef.current = loadMetrics
  })

  useEffect(() => {
    loadMetricsRef.current(selectedGraphUplink, metricWindow)
    const id = setInterval(() => loadMetricsRef.current(selectedGraphUplink, metricWindow), REFRESH_INTERVAL_MS)
    return () => clearInterval(id)
  }, [selectedGraphUplink, metricWindow])

  const chartData = useMemo(
    () =>
      metricPoints.map((p) => {
        const d = new Date(p.timestamp)
        const label = Number.isNaN(d.getTime())
          ? p.timestamp
          : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false })
        return { time: label, avgLatencyMs: p.avgLatencyMs, lossPct: p.lossPct }
      }),
    [metricPoints]
  )

  const resetForm = (uplink?: WanUplink) => {
    setFormError("")
    if (uplink) {
      setEditingUplink(uplink)
      setForm(uplinkToForm(uplink))
    } else {
      setEditingUplink(null)
      setForm({ ...emptyForm, interface: interfaces[0]?.name || "" })
    }
  }

  const handleOpenCreate = () => {
    resetForm()
    setIsDrawerOpen(true)
  }

  const handleOpenEdit = (u: WanUplink) => {
    resetForm(u)
    setIsDrawerOpen(true)
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setFormError("")

    if (!form.name.trim()) {
      setFormError("กรุณากรอกชื่อ Uplink")
      return
    }
    if (!form.interface) {
      setFormError("กรุณาเลือกอินเทอร์เฟซ")
      return
    }
    const targets = form.probeTargets
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)
    if (targets.length === 0) {
      setFormError("กรุณากรอก Probe Target อย่างน้อย 1 รายการ (ไม่มีค่าเริ่มต้นให้โดยตั้งใจ)")
      return
    }
    for (const t of targets) {
      if (!isValidIp(t)) {
        setFormError(`Probe Target "${t}" ต้องเป็น IPv4 address เท่านั้น ห้ามใช้ hostname`)
        return
      }
    }
    const probeTcpPort = parseInt(form.probeTcpPort, 10) || 0
    if (form.probeMethod === "icmp" && probeTcpPort !== 0) {
      setFormError("เมื่อเลือก ICMP เท่านั้น ต้องไม่กำหนด TCP Port")
      return
    }
    if (form.probeMethod !== "icmp" && (probeTcpPort < 1 || probeTcpPort > 65535)) {
      setFormError("TCP Port ต้องอยู่ระหว่าง 1-65535 เมื่อเลือก TCP หรือ Auto")
      return
    }

    const payload = {
      name: form.name.trim(),
      interface: form.interface,
      priority: parseInt(form.priority, 10) || 1,
      probeTargets: targets,
      probeMethod: form.probeMethod,
      probeTcpPort: form.probeMethod === "icmp" ? 0 : probeTcpPort,
      probeIntervalSeconds: parseInt(form.probeIntervalSeconds, 10) || 5,
      probeCount: parseInt(form.probeCount, 10) || 3,
      probeTimeoutMs: parseInt(form.probeTimeoutMs, 10) || 1000,
      lossThresholdPct: parseFloat(form.lossThresholdPct) || 50,
      latencyThresholdMs: parseFloat(form.latencyThresholdMs) || 200,
      failStrikes: parseInt(form.failStrikes, 10) || 3,
      recoverStrikes: parseInt(form.recoverStrikes, 10) || 3,
      status: form.status,
      description: form.description.trim(),
    }

    try {
      setIsSaving(true)
      if (editingUplink) {
        await wanService.updateUplink(editingUplink.id, payload)
      } else {
        await wanService.createUplink(payload)
      }
      setIsDrawerOpen(false)
      await loadAll(false)
    } catch (err) {
      setFormError(getErrorMessage(err) || "บันทึก WAN uplink ไม่สำเร็จ")
    } finally {
      setIsSaving(false)
    }
  }

  const handleDelete = async (u: WanUplink) => {
    const confirmed = await confirm("ลบ WAN Uplink", `คุณแน่ใจหรือไม่ที่จะลบ "${u.name}"? ระบบจะหยุดตรวจสุขภาพเส้นทางนี้ทันที`)
    if (!confirmed) return
    try {
      await wanService.deleteUplink(u.id)
      await loadAll(false)
    } catch (err) {
      showAlert("Error", getErrorMessage(err) || "ลบ WAN uplink ไม่สำเร็จ")
    }
  }

  if (isLoading && uplinks.length === 0) {
    return (
      <div className="flex min-h-[400px] flex-col items-center justify-center space-y-4">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <span className="text-sm font-semibold text-muted-foreground">กำลังโหลดข้อมูล Multi-WAN...</span>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Shuffle className="size-5" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight">Multi-WAN Failover</h1>
            <p className="text-xs text-muted-foreground">
              ตรวจสุขภาพ WAN แต่ละเส้นด้วย ICMP/TCP probe (Phase 1 — แสดงผลอย่างเดียว ยังไม่สลับ route อัตโนมัติ)
            </p>
          </div>
        </div>
        <Button variant="outline" size="sm" className="cursor-pointer gap-2" onClick={() => loadAll(true)}>
          <RefreshCw className={isLoading ? "size-4 animate-spin" : "size-4"} />
          Reload
        </Button>
      </div>

      {/* Permanent IPv4-only notice */}
      <Alert className="border-warning/30 bg-warning/10 px-3 py-2.5 text-warning">
        <AlertCircle className="h-4 w-4 text-warning" />
        <AlertTitle className="text-warning">รองรับเฉพาะ IPv4</AlertTitle>
        <AlertDescription className="text-warning">
          ฟีเจอร์นี้ตรวจสุขภาพและ (ในเฟสถัดไป) สลับเส้นทางสำหรับ IPv4 เท่านั้น — ยังไม่รองรับ IPv6
        </AlertDescription>
      </Alert>

      {error && (
        <Card>
          <CardContent className="py-8 text-center text-sm text-destructive">{error}</CardContent>
        </Card>
      )}

      {/* Uplink status cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {uplinks.map((u) => {
          const st = statusById[u.id]
          const state = st?.state ?? "unknown"
          const connectOnly = st?.metricQuality === "connect-only"
          return (
            <Card key={u.id} size="sm" className="gap-3">
              <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
                <div className="space-y-1">
                  <CardTitle className="flex items-center gap-2 text-sm font-medium">
                    <span className="text-foreground">{u.name}</span>
                    <Badge variant="outline" className="rounded px-1.5 py-0 text-[10px] font-normal text-muted-foreground">
                      Priority {u.priority}
                    </Badge>
                  </CardTitle>
                  <CardDescription className="font-mono text-[11px]">
                    {formatIfaceLabel(u.interface, interfaces)}
                  </CardDescription>
                </div>
                <div className="flex flex-col items-end gap-1">
                  <StateBadge state={state} />
                  {st?.active && (
                    <Badge variant="outline" className="rounded px-1.5 py-0 text-[9px] font-normal text-primary">
                      Active
                    </Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="grid grid-cols-3 gap-2 text-center text-xs">
                  <div className="rounded-lg border border-border bg-muted/50 py-2">
                    <div className="text-[10px] text-muted-foreground">Latency</div>
                    <div className="font-mono font-semibold text-foreground">
                      {st ? `${st.lastLatencyMs.toFixed(1)}ms` : "—"}
                    </div>
                  </div>
                  <div className="rounded-lg border border-border bg-muted/50 py-2">
                    <div className="flex items-center justify-center gap-1 text-[10px] text-muted-foreground">
                      Jitter
                      {connectOnly && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Info className="h-2.5 w-2.5 cursor-help" />
                          </TooltipTrigger>
                          <TooltipContent>
                            ใช้วิธี TCP-connect อยู่ — วัด jitter ไม่ได้ (connect-only)
                          </TooltipContent>
                        </Tooltip>
                      )}
                    </div>
                    <div className={cn("font-mono font-semibold", connectOnly ? "text-muted-foreground/50" : "text-foreground")}>
                      {st && !connectOnly ? `${st.jitterMs.toFixed(1)}ms` : "—"}
                    </div>
                  </div>
                  <div className="rounded-lg border border-border bg-muted/50 py-2">
                    <div className="text-[10px] text-muted-foreground">Loss</div>
                    <div className="font-mono font-semibold text-foreground">{st ? `${st.lossPct.toFixed(0)}%` : "—"}</div>
                  </div>
                </div>
                <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                  <span>
                    Method: <span className="font-medium text-foreground">{PROBE_METHOD_LABEL[st?.effectiveMethod ?? ""] ?? "—"}</span>
                  </span>
                  <span className="truncate">{st?.reason || "ยังไม่เคย probe"}</span>
                </div>
              </CardContent>
            </Card>
          )
        })}
        {uplinks.length === 0 && (
          <Card className="md:col-span-2">
            <CardContent className="py-8 text-center text-sm text-muted-foreground">
              ยังไม่มี WAN uplink ที่ตั้งค่าไว้ — กด "Add Uplink" ด้านล่างเพื่อเริ่มต้น
            </CardContent>
          </Card>
        )}
      </div>

      {/* Latency + loss history */}
      {uplinks.length > 0 && (
        <Card>
          <CardHeader className="flex flex-col gap-3 space-y-0 sm:flex-row sm:items-center sm:justify-between">
            <CardTitle className="flex items-center gap-2 text-base font-semibold">
              <Gauge className="h-4 w-4 text-muted-foreground" />
              ประวัติ Latency / Loss
            </CardTitle>
            <div className="flex flex-wrap items-center gap-2">
              <Select value={selectedGraphUplink} onValueChange={setSelectedGraphUplink}>
                <SelectTrigger className="h-8 w-[180px] text-xs">
                  <SelectValue placeholder="เลือก Uplink" />
                </SelectTrigger>
                <SelectContent>
                  {uplinks.map((u) => (
                    <SelectItem key={u.id} value={u.id}>
                      {u.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <ToggleGroup type="single" variant="outline" size="sm" value={metricWindow} onValueChange={(v) => v && setMetricWindow(v as MetricWindow)}>
                <ToggleGroupItem value="1h" className="px-3 text-[11px]">1h</ToggleGroupItem>
                <ToggleGroupItem value="24h" className="px-3 text-[11px]">24h</ToggleGroupItem>
              </ToggleGroup>
            </div>
          </CardHeader>
          <CardContent className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <MetricChart
              title="Latency (ms)"
              unit="ms"
              dataKey="avgLatencyMs"
              data={chartData}
              color="var(--primary)"
              axis={axis}
              grid={grid}
              formatTooltip={(v) => `${v.toFixed(1)} ms`}
            />
            <MetricChart
              title="Loss (%)"
              unit="%"
              dataKey="lossPct"
              data={chartData}
              color="var(--destructive)"
              axis={axis}
              grid={grid}
              formatTooltip={(v) => `${v.toFixed(0)}%`}
            />
          </CardContent>
        </Card>
      )}

      {/* Uplink configuration table */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base font-semibold">
              <Activity className="h-4 w-4 text-muted-foreground" />
              WAN Uplinks
              <Badge variant="secondary" className="rounded-full px-2 py-0 text-xs font-semibold">
                {uplinks.length}
              </Badge>
            </CardTitle>
            <CardDescription className="text-xs">ตั้งค่าเส้นทาง WAN และพารามิเตอร์การ probe</CardDescription>
          </div>
          <Button size="sm" className="cursor-pointer gap-1.5 font-semibold" onClick={handleOpenCreate}>
            <Plus className="h-4 w-4" />
            Add Uplink
          </Button>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-[80px] text-xs font-medium text-muted-foreground">Status</TableHead>
                <TableHead className="text-xs font-medium text-muted-foreground">Name</TableHead>
                <TableHead className="text-xs font-medium text-muted-foreground">Interface</TableHead>
                <TableHead className="text-xs font-medium text-muted-foreground">Probe Targets</TableHead>
                <TableHead className="text-xs font-medium text-muted-foreground">Method</TableHead>
                <TableHead className="w-[80px] text-center text-xs font-medium text-muted-foreground">Priority</TableHead>
                <TableHead className="w-[110px] text-center text-xs font-medium text-muted-foreground">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {uplinks.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-28 text-center text-muted-foreground">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <AlertCircle className="h-8 w-8 text-muted-foreground/60" />
                      <span className="text-sm font-medium">ยังไม่มี WAN uplink</span>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                uplinks.map((u) => (
                  <TableRow key={u.id} className={cn(!u.status && "opacity-60")}>
                    <TableCell className="py-3">
                      <Switch
                        checked={u.status}
                        onCheckedChange={async () => {
                          try {
                            await wanService.updateUplink(u.id, { ...u, status: !u.status })
                            await loadAll(false)
                          } catch (err) {
                            showAlert("Error", getErrorMessage(err) || "อัปเดตสถานะไม่สำเร็จ")
                          }
                        }}
                      />
                    </TableCell>
                    <TableCell className="py-3 font-medium text-foreground">
                      <div className="flex flex-col">
                        <span>{u.name}</span>
                        {u.description && (
                          <span className="max-w-[200px] truncate text-[11px] font-normal text-muted-foreground">{u.description}</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="py-3">
                      <Badge variant="secondary" className="rounded px-2 py-0.5 font-mono text-xs">
                        {formatIfaceLabel(u.interface, interfaces)}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-3 font-mono text-xs">{u.probeTargets.join(", ")}</TableCell>
                    <TableCell className="py-3 text-xs">{PROBE_METHOD_LABEL[u.probeMethod] ?? u.probeMethod}</TableCell>
                    <TableCell className="py-3 text-center font-mono text-xs text-foreground">{u.priority}</TableCell>
                    <TableCell className="py-3 text-center">
                      <div className="flex items-center justify-center gap-2">
                        <Button
                          variant="outline"
                          size="icon-sm"
                          className="cursor-pointer text-muted-foreground hover:text-foreground"
                          onClick={() => handleOpenEdit(u)}
                          title="แก้ไข WAN uplink"
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="cursor-pointer text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                          onClick={() => handleDelete(u)}
                          title="ลบ WAN uplink"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Create / Edit Drawer */}
      <Drawer direction="right" open={isDrawerOpen} onOpenChange={setIsDrawerOpen}>
        <DrawerContent className="data-[vaul-drawer-direction=right]:sm:max-w-[520px]">
          <DrawerHeader className="border-b border-border/50">
            <DrawerTitle className="text-base font-semibold">
              {editingUplink ? "แก้ไข WAN Uplink" : "เพิ่ม WAN Uplink ใหม่"}
            </DrawerTitle>
          </DrawerHeader>

          <div className="flex-1 overflow-y-auto p-4">
            {formError && (
              <Alert variant="destructive" className="mb-4 px-3 py-2.5">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription className="text-xs">{formError}</AlertDescription>
              </Alert>
            )}

            <form onSubmit={handleSave} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="wan-name" className="block text-xs font-medium text-muted-foreground">
                  ชื่อ Uplink <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="wan-name"
                  placeholder="เช่น Primary Fiber, Backup 4G"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="h-9 text-sm"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="wan-iface" className="block text-xs font-medium text-muted-foreground">
                    อินเทอร์เฟซ <span className="text-destructive">*</span>
                  </Label>
                  <Select value={form.interface} onValueChange={(v) => setForm({ ...form, interface: v })}>
                    <SelectTrigger id="wan-iface" className="h-9 w-full text-sm">
                      <SelectValue placeholder="เลือกอินเทอร์เฟซ" />
                    </SelectTrigger>
                    <SelectContent>
                      {interfaces.map((iface) => (
                        <SelectItem key={iface.id} value={iface.name}>
                          {ifaceLabel(iface)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="wan-priority" className="block text-xs font-medium text-muted-foreground">
                    Priority (1-16, ยิ่งน้อยยิ่งสำคัญ)
                  </Label>
                  <Input
                    id="wan-priority"
                    type="number"
                    min="1"
                    max="16"
                    value={form.priority}
                    onChange={(e) => setForm({ ...form, priority: e.target.value })}
                    className="h-9 font-mono text-sm"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="wan-targets" className="block text-xs font-medium text-muted-foreground">
                  Probe Targets (IPv4, คั่นด้วยจุลภาค) <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="wan-targets"
                  placeholder="เช่น 1.1.1.1, 8.8.8.8"
                  value={form.probeTargets}
                  onChange={(e) => setForm({ ...form, probeTargets: e.target.value })}
                  className="h-9 font-mono text-sm"
                  required
                />
                <p className="text-[10px] text-muted-foreground">
                  ต้องเป็น IPv4 address เท่านั้น ห้ามใช้ hostname — ไม่มีค่าเริ่มต้นให้ ต้องกรอกเอง
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="wan-method" className="block text-xs font-medium text-muted-foreground">
                    Probe Method
                  </Label>
                  <Select value={form.probeMethod} onValueChange={(v) => setForm({ ...form, probeMethod: v })}>
                    <SelectTrigger id="wan-method" className="h-9 w-full text-sm">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="icmp">ICMP</SelectItem>
                      <SelectItem value="tcp">TCP</SelectItem>
                      <SelectItem value="auto">Auto (ICMP → TCP fallback)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="wan-tcp-port" className="block text-xs font-medium text-muted-foreground">
                    TCP Port {form.probeMethod !== "icmp" && <span className="text-destructive">*</span>}
                  </Label>
                  <Input
                    id="wan-tcp-port"
                    type="number"
                    min="1"
                    max="65535"
                    value={form.probeTcpPort}
                    onChange={(e) => setForm({ ...form, probeTcpPort: e.target.value })}
                    className="h-9 font-mono text-sm"
                    disabled={form.probeMethod === "icmp"}
                    placeholder={form.probeMethod === "icmp" ? "ไม่ใช้กับ ICMP" : "443"}
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="wan-interval" className="block text-xs font-medium text-muted-foreground">
                    Interval (วินาที)
                  </Label>
                  <Input
                    id="wan-interval"
                    type="number"
                    min="2"
                    max="300"
                    value={form.probeIntervalSeconds}
                    onChange={(e) => setForm({ ...form, probeIntervalSeconds: e.target.value })}
                    className="h-9 font-mono text-sm"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="wan-count" className="block text-xs font-medium text-muted-foreground">
                    Packet/รอบ
                  </Label>
                  <Input
                    id="wan-count"
                    type="number"
                    min="1"
                    max="10"
                    value={form.probeCount}
                    onChange={(e) => setForm({ ...form, probeCount: e.target.value })}
                    className="h-9 font-mono text-sm"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="wan-timeout" className="block text-xs font-medium text-muted-foreground">
                    Timeout (ms)
                  </Label>
                  <Input
                    id="wan-timeout"
                    type="number"
                    min="100"
                    max="5000"
                    value={form.probeTimeoutMs}
                    onChange={(e) => setForm({ ...form, probeTimeoutMs: e.target.value })}
                    className="h-9 font-mono text-sm"
                  />
                </div>
              </div>

              <div className="space-y-3 rounded-lg border border-border bg-muted/50 p-4">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
                  <Gauge className="h-3.5 w-3.5 text-muted-foreground" /> เกณฑ์ตัดสินสถานะ
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="wan-loss-threshold" className="block text-xs font-medium text-muted-foreground">
                      Loss Threshold (%)
                    </Label>
                    <Input
                      id="wan-loss-threshold"
                      type="number"
                      min="1"
                      max="100"
                      value={form.lossThresholdPct}
                      onChange={(e) => setForm({ ...form, lossThresholdPct: e.target.value })}
                      className="h-9 bg-background font-mono text-sm"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="wan-latency-threshold" className="block text-xs font-medium text-muted-foreground">
                      Latency Threshold (ms)
                    </Label>
                    <Input
                      id="wan-latency-threshold"
                      type="number"
                      min="1"
                      max="10000"
                      value={form.latencyThresholdMs}
                      onChange={(e) => setForm({ ...form, latencyThresholdMs: e.target.value })}
                      className="h-9 bg-background font-mono text-sm"
                    />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="wan-fail-strikes" className="block text-xs font-medium text-muted-foreground">
                      Fail Strikes (รอบก่อนเป็น Down)
                    </Label>
                    <Input
                      id="wan-fail-strikes"
                      type="number"
                      min="1"
                      max="20"
                      value={form.failStrikes}
                      onChange={(e) => setForm({ ...form, failStrikes: e.target.value })}
                      className="h-9 bg-background font-mono text-sm"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="wan-recover-strikes" className="block text-xs font-medium text-muted-foreground">
                      Recover Strikes (รอบก่อนกลับ Up)
                    </Label>
                    <Input
                      id="wan-recover-strikes"
                      type="number"
                      min="1"
                      max="20"
                      value={form.recoverStrikes}
                      onChange={(e) => setForm({ ...form, recoverStrikes: e.target.value })}
                      className="h-9 bg-background font-mono text-sm"
                    />
                  </div>
                </div>
                <p className="flex items-start gap-1.5 text-[11px] leading-relaxed text-muted-foreground">
                  <Info className="mt-0.5 h-3 w-3 shrink-0" />
                  สถานะ "Degraded" (latency เกิน threshold แต่ไม่มี loss) เป็นการแสดงผลเท่านั้น ไม่ทำให้เกิดการสลับ WAN
                </p>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="wan-desc" className="block text-xs font-medium text-muted-foreground">
                  รายละเอียดเพิ่มเติม
                </Label>
                <Input
                  id="wan-desc"
                  placeholder="เช่น เส้นหลักจาก ISP A"
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  className="h-9 text-sm"
                />
              </div>

              <div className="flex items-center justify-between rounded-lg border border-border bg-muted/50 p-3">
                <div className="flex flex-col gap-0.5">
                  <span className="text-xs font-semibold text-foreground">เปิดใช้การตรวจสุขภาพ</span>
                  <span className="text-[10px] text-muted-foreground">เมื่อปิด จะไม่มีการ probe เส้นทางนี้เลย</span>
                </div>
                <Switch checked={form.status} onCheckedChange={(v) => setForm({ ...form, status: v })} />
              </div>

              <div className="flex items-center justify-end gap-3 border-t border-border/50 pt-4">
                <Button type="button" variant="ghost" onClick={() => setIsDrawerOpen(false)} className="cursor-pointer text-muted-foreground">
                  Cancel
                </Button>
                <Button type="submit" className="cursor-pointer px-6 font-semibold" disabled={isSaving}>
                  {isSaving && <Loader2 className="mr-1.5 h-3 w-3 animate-spin" />}
                  {editingUplink ? "Save Changes" : "Create Uplink"}
                </Button>
              </div>
            </form>
          </div>
        </DrawerContent>
      </Drawer>
    </div>
  )
}
