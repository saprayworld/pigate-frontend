//go:build linux

package kernel

import (
	"errors"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/net/icmp"
	"golang.org/x/sys/unix"

	"pigate/internal/model"
)

// capabilityProbeTimeout bounds the total time ProbeAll() may take, so a
// hung D-Bus/netlink socket never stalls the HTTP handler that calls it
// (docs/ref/todo/kernel-capability-detection-plan.md §5 Caution 7).
const capabilityProbeTimeout = 3 * time.Second

// RealCapabilityProber probes the real kernel/OS for whether the subsystems
// PiGate depends on are actually usable in this environment. Every probe
// here is read-only: it only lists/queries state, it never creates, deletes,
// or otherwise mutates anything (see docs plan §0 "เงื่อนไขทางเทคนิค").
type RealCapabilityProber struct{}

func NewRealCapabilityProber() *RealCapabilityProber {
	return &RealCapabilityProber{}
}

// ProbeAll runs every registered probe and always returns exactly one result
// per registered id (firewall, dbus, dnsmasq, resolved, conntrack,
// conntrack-events), even when a probe fails or times out. The whole batch is
// bounded by capabilityProbeTimeout.
func (p *RealCapabilityProber) ProbeAll() []model.CapabilityProbeResult {
	ids := []string{"firewall", "dbus", "dnsmasq", "resolved", "conntrack", "conntrack-events", "icmp-probe"}

	type resultsMsg struct {
		results []model.CapabilityProbeResult
	}
	done := make(chan resultsMsg, 1)

	go func() {
		dbusResult, dbusOK := probeDBus()
		results := []model.CapabilityProbeResult{
			probeFirewall(),
			dbusResult,
			probeSystemdUnit("dnsmasq", "dnsmasq.service", dbusOK),
			probeSystemdUnit("resolved", "systemd-resolved.service", dbusOK),
			probeConntrack(),
			probeConntrackEvents(),
			probeICMPRaw(),
		}
		done <- resultsMsg{results: results}
	}()

	select {
	case msg := <-done:
		return msg.results
	case <-time.After(capabilityProbeTimeout):
		// The whole batch failed to finish in time — report every registered
		// id as probe_failed rather than leaving some ids missing from the
		// response (T-03 acceptance: ProbeAll must always return all ids).
		out := make([]model.CapabilityProbeResult, 0, len(ids))
		for _, id := range ids {
			out = append(out, model.CapabilityProbeResult{
				ID:     id,
				Reason: model.CapabilityReasonProbeFailed,
				Err:    "probe timed out",
			})
		}
		return out
	}
}

// probeFirewall detects whether nftables/nf_tables is actually usable by
// listing (never creating) the inet-family tables. nftables.New() alone does
// not dial netlink in v0.3.0 unless AsLasting() is used, so it cannot be
// used as a probe on its own (docs plan §5 Caution 2) — ListTablesOfFamily is
// the call that actually round-trips to the kernel.
func probeFirewall() model.CapabilityProbeResult {
	c, err := nftables.New()
	if err != nil {
		return model.CapabilityProbeResult{
			ID:     "firewall",
			Reason: classifyNetlinkErr(err),
			Err:    err.Error(),
		}
	}
	if _, err := c.ListTablesOfFamily(nftables.TableFamilyINet); err != nil {
		return model.CapabilityProbeResult{
			ID:     "firewall",
			Reason: classifyNetlinkErr(err),
			Err:    err.Error(),
		}
	}
	return model.CapabilityProbeResult{ID: "firewall", Available: true, Reason: model.CapabilityReasonOK}
}

// probeDBus detects whether the D-Bus system bus is reachable at all (it is
// entirely absent on plain WSL). The bool return lets probeSystemdUnit skip
// its own redundant dial when the bus is already known to be unreachable.
func probeDBus() (model.CapabilityProbeResult, bool) {
	_, err := dbus.SystemBus()
	if err != nil {
		return model.CapabilityProbeResult{
			ID:     "dbus",
			Reason: model.CapabilityReasonNoDBus,
			Err:    err.Error(),
		}, false
	}
	// Do NOT call conn.Close() here: dbus.SystemBus() (godbus/dbus v5) returns
	// a process-wide shared singleton connection, not a fresh per-call one.
	// Every other caller in this package (dbus_systemd.go, real_hostname.go,
	// dhcp_server.go's WatchLeases) relies on that same connection staying
	// open for the lifetime of the process; closing it here previously tore
	// it out from under WatchLeases's active Signal() subscription and
	// crashed the whole process.
	return model.CapabilityProbeResult{ID: "dbus", Available: true, Reason: model.CapabilityReasonOK}, true
}

// probeSystemdUnit reports whether the given systemd unit is loaded/active
// via the existing GetUnitRuntimeState D-Bus helper (dbus_systemd.go),
// reused as-is rather than re-implemented here.
func probeSystemdUnit(id, unitName string, dbusOK bool) model.CapabilityProbeResult {
	if !dbusOK {
		return model.CapabilityProbeResult{ID: id, Reason: model.CapabilityReasonNoDBus}
	}

	state, err := GetUnitRuntimeState(unitName)
	if err != nil {
		return model.CapabilityProbeResult{ID: id, Reason: model.CapabilityReasonNoDBus, Err: err.Error()}
	}
	if !state.Loaded {
		return model.CapabilityProbeResult{ID: id, Reason: model.CapabilityReasonServiceMissing}
	}
	if state.ActiveState != "active" {
		return model.CapabilityProbeResult{
			ID:        id,
			Available: true,
			Degraded:  true,
			Reason:    model.CapabilityReasonServiceInactive,
			Err:       "ActiveState=" + state.ActiveState,
		}
	}
	return model.CapabilityProbeResult{ID: id, Available: true, Reason: model.CapabilityReasonOK}
}

// probeConntrack detects whether conntrack-based traffic accounting
// (docs/ref/todo/dashboard-traffic-detail-plan.md) is usable: it must be able
// to dump the IPv4 conntrack table at all (permission/support), AND —
// separately — the kernel must actually be counting bytes per flow, which
// requires the operator-set sysctl `net.netfilter.nf_conntrack_acct=1`
// (install.sh sets this, but an upgraded-in-place host may predate that). An
// empty table (nothing connected right now) is inconclusive, not evidence of
// either state, so it is reported as ok rather than degraded — only "every
// visible flow has Bytes==0" is treated as the sysctl being off.
func probeConntrack() model.CapabilityProbeResult {
	flows, err := safeConntrackList(unix.AF_INET)
	if err != nil {
		return model.CapabilityProbeResult{
			ID:     "conntrack",
			Reason: classifyNetlinkErr(err),
			Err:    err.Error(),
		}
	}
	if len(flows) > 0 {
		allZero := true
		for _, f := range flows {
			if f == nil {
				continue
			}
			if f.Forward.Bytes > 0 || f.Reverse.Bytes > 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return model.CapabilityProbeResult{
				ID:        "conntrack",
				Available: true,
				Degraded:  true,
				Reason:    model.CapabilityReasonAcctDisabled,
			}
		}
	}
	return model.CapabilityProbeResult{ID: "conntrack", Available: true, Reason: model.CapabilityReasonOK}
}

// probeConntrackEvents detects whether the conntrack DESTROY event listener
// (kernel.TrafficAccountingManager.WatchFlowEnd, real_conntrack_events.go) can
// be subscribed to at all — i.e. that a NETLINK_NETFILTER socket can bind to
// NFNLGRP_CONNTRACK_DESTROY (requires CAP_NET_ADMIN). This is a bind-only
// probe: it opens and immediately closes the socket, without waiting for or
// asserting that any event actually arrives (that would require exercising
// live traffic and cannot be done in a fixed, read-only probe window) — a
// kernel built without CONFIG_NF_CONNTRACK_EVENTS, or with
// net.netfilter.nf_conntrack_events=0, may still let the socket bind
// successfully; degraded operation in that case is only ever observed at
// runtime once WatchFlowEnd is actually running (StartFlowEndWatcher logs it,
// see service/traffic_stats.go). A failure here is reported as Degraded
// (never Available=false): the "conntrack" capability above still lets the
// existing poll-based accounting work, so the Dashboard cards remain usable —
// this only means their accuracy label stays "estimated" instead of
// "near-exact" (docs/ref/todo/traffic-accounting-accuracy-phase2-plan.md T-09).
func probeConntrackEvents() model.CapabilityProbeResult {
	sock, err := nl.Subscribe(unix.NETLINK_NETFILTER, unix.NFNLGRP_CONNTRACK_DESTROY)
	if err != nil {
		return model.CapabilityProbeResult{
			ID:        "conntrack-events",
			Available: true,
			Degraded:  true,
			Reason:    model.CapabilityReasonEventsUnavailable,
			Err:       err.Error(),
		}
	}
	sock.Close()
	return model.CapabilityProbeResult{ID: "conntrack-events", Available: true, Reason: model.CapabilityReasonOK}
}

// probeICMPRaw detects whether a raw ICMP socket can actually be opened
// (docs/ref/todo/multi-wan-failover-plan.md Task 13) — needed by
// kernel.PathProbeManager.ProbeICMP, which requires cap_net_raw. This is a
// read-only bind-only probe: it opens the socket and immediately closes it
// again WITHOUT sending a single packet (Task 13: "probe ไม่ส่ง packet
// จริง"). A failure here (typically EPERM/EACCES on a binary missing
// cap_net_raw) is always reported as Degraded, never Available=false — the
// Multi-WAN Failover feature keeps working via TCP-connect probing on such a
// host (D-5), it is not a whole-feature outage.
func probeICMPRaw() model.CapabilityProbeResult {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return model.CapabilityProbeResult{
			ID:        "icmp-probe",
			Available: true,
			Degraded:  true,
			Reason:    model.CapabilityReasonICMPUnavailable,
			Err:       err.Error(),
		}
	}
	conn.Close()
	return model.CapabilityProbeResult{ID: "icmp-probe", Available: true, Reason: model.CapabilityReasonOK}
}

// classifyNetlinkErr maps a netlink/nftables error's underlying errno to one
// of the capability reason codes, so the service layer can render the right
// Thai-language explanation instead of a generic failure.
func classifyNetlinkErr(err error) string {
	switch {
	case errors.Is(err, unix.EOPNOTSUPP),
		errors.Is(err, unix.EPROTONOSUPPORT),
		errors.Is(err, unix.EAFNOSUPPORT),
		errors.Is(err, unix.ENOENT):
		return model.CapabilityReasonNotSupported
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return model.CapabilityReasonPermissionDenied
	default:
		return model.CapabilityReasonProbeFailed
	}
}
