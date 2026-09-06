//go:build linux

package kernel

import (
	"testing"

	"pigate/internal/model"
)

// TestProbeICMPRaw_NeverSendsAPacket documents (and, by construction, proves)
// that probeICMPRaw only ever opens then immediately closes a raw socket —
// it never calls WriteTo — regardless of whether cap_net_raw is available in
// the environment running this test (docs/ref/todo/
// multi-wan-failover-plan.md Task 13: "probe ไม่ส่ง packet จริง"). There is
// no observable side channel to assert "no packet was sent" from a unit
// test, so this is a structural guarantee backed by code review of
// probeICMPRaw's body (real_capability.go): it has no WriteTo call at all.
func TestProbeICMPRaw_NeverSendsAPacket(t *testing.T) {
	// Calling it at all, on any machine (with or without cap_net_raw),
	// must never hang, panic, or block waiting on network I/O — a
	// send-nothing bind-only probe returns essentially immediately either
	// way.
	_ = probeICMPRaw()
}

// TestProbeICMPRaw_AlwaysReportsAvailableTrue covers the plan Task 13
// acceptance directly: whether or not this environment actually has
// cap_net_raw, the icmp-probe capability must never come back
// Available=false ("error ทั้งหน้า") — only Degraded=true with a specific
// reason when the raw socket could not be opened. Both outcomes are valid
// here since CI/dev sandboxes typically lack cap_net_raw while a properly
// `setcap`'d production binary would not.
func TestProbeICMPRaw_AlwaysReportsAvailableTrue(t *testing.T) {
	result := probeICMPRaw()

	if result.ID != "icmp-probe" {
		t.Errorf("ID = %q, want icmp-probe", result.ID)
	}
	if !result.Available {
		t.Fatalf("expected Available=true unconditionally (Task 13: never a whole-panel error), got %+v", result)
	}
	if result.Degraded {
		if result.Reason != model.CapabilityReasonICMPUnavailable {
			t.Errorf("expected Reason=%q when Degraded, got %q", model.CapabilityReasonICMPUnavailable, result.Reason)
		}
		if result.Err == "" {
			t.Error("expected a non-empty Err detail when Degraded")
		}
	} else if result.Reason != model.CapabilityReasonOK {
		t.Errorf("expected Reason=ok when not degraded, got %q", result.Reason)
	}
}
