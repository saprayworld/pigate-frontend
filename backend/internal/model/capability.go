package model

// Capability reason codes. These are the only values a kernel prober or the
// SystemCapabilityService may set on CapabilityProbeResult.Reason /
// CapabilityStatus.Reason — keeping them as an exhaustive const set makes the
// service-layer Thai-language mapping (system_capability.go) a total
// function: every reason must have a corresponding human-readable Detail.
const (
	// CapabilityReasonOK means the probe succeeded and the subsystem is fully
	// usable.
	CapabilityReasonOK = "ok"
	// CapabilityReasonMock means the process is running in mock mode
	// (-mock=true or -mock-from-real=true), so no real kernel probe was even
	// attempted — every capability reports available in this mode.
	CapabilityReasonMock = "mock"
	// CapabilityReasonNotSupported means the running kernel/environment lacks
	// the subsystem entirely (e.g. no nf_tables module — common on WSL).
	CapabilityReasonNotSupported = "not_supported"
	// CapabilityReasonPermissionDenied means the subsystem exists but the
	// process lacks the Linux capability/permission needed to use it (e.g.
	// cap_net_admin was not granted via setcap).
	CapabilityReasonPermissionDenied = "permission_denied"
	// CapabilityReasonNoDBus means the process could not reach the D-Bus
	// system bus at all (e.g. no systemd/dbus-daemon present, common on WSL).
	CapabilityReasonNoDBus = "no_dbus"
	// CapabilityReasonServiceMissing means D-Bus answered but the systemd unit
	// in question has never been loaded (its unit file is not installed).
	CapabilityReasonServiceMissing = "service_missing"
	// CapabilityReasonServiceInactive means the unit is loaded but not
	// currently active (a degraded, not fully-unavailable, condition).
	CapabilityReasonServiceInactive = "service_inactive"
	// CapabilityReasonApplyFailed means the read-only probe itself succeeded,
	// but the most recent real attempt to apply this subsystem's
	// database-configured state to the kernel failed — see
	// ApplyHealthReporter. This overrides an otherwise-"ok" probe result with
	// Degraded=true so the UI still surfaces the real failure.
	CapabilityReasonApplyFailed = "apply_failed"
	// CapabilityReasonProbeFailed is the catch-all for any other/unclassified
	// probe error (including a probe that timed out).
	CapabilityReasonProbeFailed = "probe_failed"
	// CapabilityReasonAcctDisabled means the conntrack table itself is
	// reachable (dump succeeded), but every visible flow reports zero bytes —
	// the telltale sign that `net.netfilter.nf_conntrack_acct` is not set to
	// 1, so the kernel isn't counting per-flow bytes at all (see
	// docs/ref/todo/dashboard-traffic-detail-plan.md §5 Caution 1). Reported
	// as Degraded rather than Available=false since the subsystem otherwise
	// works — only the byte counters are silently zero.
	CapabilityReasonAcctDisabled = "acct_disabled"
	// CapabilityReasonEventsUnavailable means the conntrack DESTROY event
	// listener (kernel.TrafficAccountingManager.WatchFlowEnd) could not be
	// subscribed to — e.g. missing CAP_NET_ADMIN or a kernel built without
	// CONFIG_NF_CONNTRACK_EVENTS/net.netfilter.nf_conntrack_events=0 (see
	// docs/ref/todo/traffic-accounting-accuracy-phase2-plan.md T-09). Reported
	// as Degraded rather than Available=false: traffic accounting still works
	// via the existing conntrack poll, it just falls back to "estimated"
	// accuracy instead of "near-exact".
	CapabilityReasonEventsUnavailable = "events_unavailable"
	// CapabilityReasonICMPUnavailable means a raw ICMP socket could not be
	// opened — most commonly a missing cap_net_raw capability on the pigate
	// binary (docs/ref/todo/multi-wan-failover-plan.md Task 13). Reported as
	// Degraded, never Available=false: Multi-WAN Failover's "auto" probe
	// method still falls back to TCP-connect (D-5), and any uplink
	// configured with probeMethod="tcp" is entirely unaffected — this is not
	// a whole-feature outage.
	CapabilityReasonICMPUnavailable = "icmp_unavailable"
)

// CapabilityProbeResult is the raw result of probing one subsystem from the
// kernel layer (kernel.CapabilityProber). It intentionally carries no
// display/localization concerns — that translation into a user-facing
// message happens one layer up, in service.SystemCapabilityService, mirroring
// how kernel.SystemServiceManager stays policy-free and
// service.SystemServiceService owns the catalog/whitelist.
type CapabilityProbeResult struct {
	ID        string `json:"id"`
	Available bool   `json:"available"`
	Degraded  bool   `json:"degraded"`
	Reason    string `json:"reason"`
	Err       string `json:"err"`
}

// CapabilityStatus is the DTO served to the frontend for one subsystem: the
// raw probe result enriched with a display name and a human-readable
// (Thai-language) detail message, plus a timestamp of when it was checked.
type CapabilityStatus struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Degraded  bool   `json:"degraded"`
	Reason    string `json:"reason"`
	Detail    string `json:"detail"`
	CheckedAt string `json:"checkedAt"`
}

// SystemCapabilities is the top-level response of GET /api/system/capabilities.
type SystemCapabilities struct {
	Mock         bool               `json:"mock"`
	CheckedAt    string             `json:"checkedAt"`
	Capabilities []CapabilityStatus `json:"capabilities"`
}
