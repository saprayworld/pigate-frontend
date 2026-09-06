package model

// Package-level WAN uplink probe method constants. ProbeMethod on WanUplink
// must be exactly one of these three values (see ValidateWanUplink in
// wan_validate.go). "auto" means: try ICMP first, and if that round gets zero
// replies, immediately fall back to TCP-connect within the SAME probing
// round — never "declare down, then retry" (docs/ref/todo/
// multi-wan-failover-plan.md D-5). This lets an ISP that blocks outbound
// ICMP still be monitored via TCP without a false-positive "down".
const (
	WanProbeMethodICMP = "icmp"
	WanProbeMethodTCP  = "tcp"
	WanProbeMethodAuto = "auto"
)

// WAN uplink health states (WanUplinkState.State). "degraded" is a
// display-only state: it is derived from a latency-threshold breach with no
// packet loss, and — per an explicit product decision (D-7, 2026-09-06) —
// NEVER triggers a failover. Only "down" (loss-threshold breach for
// FailStrikes consecutive rounds) does. There is deliberately no toggle
// anywhere in this package that would let a "degraded" reading drive a
// failover decision.
const (
	WanStateUnknown  = "unknown"
	WanStateUp       = "up"
	WanStateDegraded = "degraded"
	WanStateDown     = "down"
)

// WanMetricQuality describes how much a probe round's numbers can be
// trusted. TCP-connect only ever proves connect-time (a latency proxy) and
// success/failure (a loss proxy) — it cannot produce a meaningful jitter
// figure, so MetricQuality tells the frontend when to gray out/hide jitter
// (D-6) rather than show a number that looks precise but is not.
const (
	WanMetricQualityFull        = "full"
	WanMetricQualityConnectOnly = "connect-only"
)

// WAN failover operating modes (WanFailoverSettings.Mode).
const (
	WanFailoverModeAuto   = "auto"
	WanFailoverModeManual = "manual"
)

// WanUplink is one configured WAN path (e.g. the primary wired uplink or a
// 4G/backup Wi-Fi uplink) that PiGate health-checks via ICMP/TCP probes sent
// out ifaceName with SO_BINDTODEVICE (kernel.PathProbeManager). It is
// persisted config (db.wan_repo.go), not runtime state — see WanUplinkState
// for the live health/metric side.
//
// ProbeTargets are IPv4 literals ONLY, never hostnames — probing a hostname
// would create a DNS-availability dependency loop right when the network is
// in trouble, and would let DNS answers (poisonable from the LAN, see
// tech_stack_design.md §8) influence failover behavior. There is
// intentionally no built-in default target: an operator must type one in
// explicitly (privacy — do not silently probe a third party on their
// behalf).
type WanUplink struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Interface string `json:"interface,omitempty"`
	// Priority orders uplinks for the (future, Phase 2) auto-failover
	// controller: lower value = higher priority = tried first. Not used by
	// anything in Phase 1 (Task 1-13 are read-only with respect to routing).
	Priority int `json:"priority,omitempty"`
	// ProbeTargets is one or more IPv4 literals to probe every round. All
	// configured targets are probed; a round is considered "received" for a
	// target that replies (see WanProbeSample).
	ProbeTargets []string `json:"probeTargets,omitempty"`
	// ProbeMethod is one of WanProbeMethodICMP/TCP/Auto.
	ProbeMethod string `json:"probeMethod,omitempty"`
	// ProbeTCPPort is the destination port for TCP-connect probes. Required
	// (1-65535) when ProbeMethod is "tcp" or "auto"; must be 0 when
	// ProbeMethod is "icmp".
	ProbeTCPPort int `json:"probeTcpPort,omitempty"`
	// ProbeIntervalSeconds is how often a full probe round (ProbeCount
	// packets to every ProbeTargets entry) runs.
	ProbeIntervalSeconds int `json:"probeIntervalSeconds,omitempty"`
	// ProbeCount is how many packets/connections are sent per target per
	// round (used to compute loss% and, for ICMP, jitter).
	ProbeCount int `json:"probeCount,omitempty"`
	// ProbeTimeoutMs bounds how long a single packet/connection may wait for
	// a reply before being counted as lost.
	ProbeTimeoutMs int `json:"probeTimeoutMs,omitempty"`
	// LossThresholdPct is the packet-loss percentage (over one round) at or
	// above which this uplink is considered failing for that round.
	LossThresholdPct float64 `json:"lossThresholdPct,omitempty"`
	// LatencyThresholdMs is the average-latency threshold (over one round)
	// above which this uplink is considered "degraded" for that round — a
	// display-only signal, see WanStateDegraded above.
	LatencyThresholdMs float64 `json:"latencyThresholdMs,omitempty"`
	// FailStrikes is how many consecutive failing rounds are required before
	// the uplink transitions to WanStateDown.
	FailStrikes int `json:"failStrikes,omitempty"`
	// RecoverStrikes is how many consecutive healthy rounds are required
	// before a WanStateDown uplink transitions back to WanStateUp.
	RecoverStrikes int `json:"recoverStrikes,omitempty"`
	// Status enables/disables monitoring for this uplink entirely (a
	// disabled uplink is never probed and never contributes a state).
	Status      bool   `json:"status,omitempty"`
	Description string `json:"description,omitempty"`
}

// WanUplinkInput is the create/update payload for WanUplink (no ID — mirrors
// QosRuleInput/model.QosRule).
type WanUplinkInput struct {
	Name                 string   `json:"name,omitempty"`
	Interface            string   `json:"interface,omitempty"`
	Priority             int      `json:"priority,omitempty"`
	ProbeTargets         []string `json:"probeTargets,omitempty"`
	ProbeMethod          string   `json:"probeMethod,omitempty"`
	ProbeTCPPort         int      `json:"probeTcpPort,omitempty"`
	ProbeIntervalSeconds int      `json:"probeIntervalSeconds,omitempty"`
	ProbeCount           int      `json:"probeCount,omitempty"`
	ProbeTimeoutMs       int      `json:"probeTimeoutMs,omitempty"`
	LossThresholdPct     float64  `json:"lossThresholdPct,omitempty"`
	LatencyThresholdMs   float64  `json:"latencyThresholdMs,omitempty"`
	FailStrikes          int      `json:"failStrikes,omitempty"`
	RecoverStrikes       int      `json:"recoverStrikes,omitempty"`
	Status               bool     `json:"status,omitempty"`
	Description          string   `json:"description,omitempty"`
}

// WanUplinkState is the RAM-only (never persisted — tech_stack_design.md §8)
// live health snapshot of one uplink, built by service.WanMonitor from the
// most recent probe round(s). Served by GET /api/wan/status.
type WanUplinkState struct {
	UplinkID  string `json:"uplinkId,omitempty"`
	Interface string `json:"interface,omitempty"`
	// State is one of WanStateUnknown/Up/Degraded/Down. Unknown means "never
	// successfully probed yet" or "the probe itself errored" (a kernel/socket
	// failure, NOT the same thing as the remote target not answering).
	State string `json:"state,omitempty"`
	// Active reports whether this uplink is the one currently carrying
	// traffic. Always false in Phase 1 (no failover controller exists yet).
	Active        bool    `json:"active,omitempty"`
	LastLatencyMs float64 `json:"lastLatencyMs,omitempty"`
	// JitterMs is only meaningful when MetricQuality == WanMetricQualityFull
	// (D-6) — a connect-only round still fills this with 0, callers MUST
	// check MetricQuality before displaying it.
	JitterMs float64 `json:"jitterMs,omitempty"`
	LossPct  float64 `json:"lossPct,omitempty"`
	// EffectiveMethod is the method actually used on the most recent round
	// ("icmp" or "tcp") — may differ from the configured ProbeMethod when
	// ProbeMethod=="auto" and ICMP has gone sticky-failed (D-5).
	EffectiveMethod string `json:"effectiveMethod,omitempty"`
	MetricQuality   string `json:"metricQuality,omitempty"`
	// Strikes is the current consecutive fail/recover streak count driving
	// the next state transition (see service.decideState).
	Strikes      int    `json:"strikes,omitempty"`
	LastChangeAt string `json:"lastChangeAt,omitempty"` // RFC3339; empty until the first state change
	Reason       string `json:"reason,omitempty"`
}

// WanProbeSample is the raw result of one probe round for one uplink,
// produced by kernel.PathProbeManager and fed into service.WanUplinkMetricsRing
// (RAM-only, D-3). RTTsMs holds only the round-trip times of packets that
// actually got a reply — its length is <= Sent, and Received == len(RTTsMs).
type WanProbeSample struct {
	TimestampUnix int64     `json:"timestampUnix,omitempty"`
	Sent          int       `json:"sent,omitempty"`
	Received      int       `json:"received,omitempty"`
	RTTsMs        []float64 `json:"rttsMs,omitempty"`
	Method        string    `json:"method,omitempty"`
	MetricQuality string    `json:"metricQuality,omitempty"`
}

// WanMetricPoint is one 5-minute bucket of a WAN uplink's latency/loss
// history, as served by GET /api/wan/metrics (service.WanUplinkMetricsRing).
// JitterMs is a pointer so a bucket with no full-quality (ICMP) samples can
// omit it entirely (nil) rather than send a misleading 0 (D-6) — the
// frontend must treat a nil JitterMs as "no data", not "zero jitter".
type WanMetricPoint struct {
	Timestamp    string   `json:"timestamp,omitempty"`
	AvgLatencyMs float64  `json:"avgLatencyMs,omitempty"`
	MaxLatencyMs float64  `json:"maxLatencyMs,omitempty"`
	JitterMs     *float64 `json:"jitterMs,omitempty"`
	LossPct      float64  `json:"lossPct,omitempty"`
}

// WanStatusEntry combines one uplink's static config essentials (name,
// priority) with its live health state, as served by GET /api/wan/status.
// WanUplinkState is embedded so its fields (state, latency, effective
// method, ...) flatten directly into the JSON object rather than nesting
// under a sub-key.
type WanStatusEntry struct {
	WanUplinkState
	Name     string `json:"name,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

// WanStatusResponse is GET /api/wan/status's top-level payload. Uplinks
// always contains one entry per configured uplink (model.WanUplink row),
// even one that has never been probed yet (State==WanStateUnknown in that
// case) — a caller must never need to cross-reference GET /api/wan/uplinks
// separately just to know an uplink exists.
//
// BypassedByStaticRoute/ActiveUplinkID/LastSwitchAt/LastSwitchReason are
// Phase 2 (automatic failover controller, not yet built) fields — Phase 1
// always reports the zero value for all four (no uplink is ever "active" and
// nothing is ever bypassed, since nothing here can change routing yet).
type WanStatusResponse struct {
	Uplinks               []WanStatusEntry `json:"uplinks"`
	BypassedByStaticRoute bool             `json:"bypassedByStaticRoute,omitempty"`
	ActiveUplinkID        string           `json:"activeUplinkId,omitempty"`
	LastSwitchAt          string           `json:"lastSwitchAt,omitempty"`
	LastSwitchReason      string           `json:"lastSwitchReason,omitempty"`
}

// WanFailoverSettings is the single-row (id=1) global failover configuration
// (db.wan_repo.go table wan_failover_settings). Enabled defaults to false
// (kill switch OFF) so installing this feature never changes behavior on an
// existing deployment until an operator opts in.
//
// There is deliberately no field here to make a "degraded" reading drive a
// failover decision (D-7): only "down" ever does. Do not add one back
// without re-reading D-7's rationale in docs/ref/todo/
// multi-wan-failover-plan.md.
type WanFailoverSettings struct {
	Enabled bool `json:"enabled,omitempty"`
	// Mode is one of WanFailoverModeAuto/Manual.
	Mode string `json:"mode,omitempty"`
	// ManualUplinkID is the uplink forced active when Mode=="manual".
	// Required (non-empty) when Mode=="manual".
	ManualUplinkID string `json:"manualUplinkId,omitempty"`
	// MinHoldSeconds is the minimum time between two failovers (anti-flap
	// dampening) — enforced by the Phase 2 controller, not anything in this
	// package.
	MinHoldSeconds int `json:"minHoldSeconds,omitempty"`
	// RevertDelaySeconds is how long the primary uplink must stay healthy
	// before the controller reverts back to it from a backup.
	RevertDelaySeconds int `json:"revertDelaySeconds,omitempty"`
}
