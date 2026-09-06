package service

import (
	"testing"
	"time"

	"pigate/internal/model"
)

// fakeProber is a programmable kernel.CapabilityProber for driving
// SystemCapabilityService deterministically in tests. Each call to ProbeAll
// increments callCount and returns the results currently configured, so
// tests can assert whether a probe actually happened (cache hit vs miss).
type fakeProber struct {
	results   []model.CapabilityProbeResult
	callCount int
}

func (f *fakeProber) ProbeAll() []model.CapabilityProbeResult {
	f.callCount++
	return f.results
}

func okResult(id string) model.CapabilityProbeResult {
	return model.CapabilityProbeResult{ID: id, Available: true, Reason: model.CapabilityReasonOK}
}

func fullResults(firewall model.CapabilityProbeResult) []model.CapabilityProbeResult {
	return []model.CapabilityProbeResult{
		firewall,
		okResult("dbus"),
		okResult("dnsmasq"),
		okResult("resolved"),
	}
}

// fakeApplyHealth is a programmable ApplyHealthReporter.
type fakeApplyHealth struct {
	ok     bool
	detail string
	at     time.Time
}

func (f fakeApplyHealth) ApplyHealth() (bool, string, time.Time) {
	return f.ok, f.detail, f.at
}

func TestSystemCapability_ReasonMapping(t *testing.T) {
	cases := []struct {
		reason string
	}{
		{model.CapabilityReasonOK},
		{model.CapabilityReasonMock},
		{model.CapabilityReasonNotSupported},
		{model.CapabilityReasonPermissionDenied},
		{model.CapabilityReasonNoDBus},
		{model.CapabilityReasonServiceMissing},
		{model.CapabilityReasonServiceInactive},
		{model.CapabilityReasonApplyFailed},
		{model.CapabilityReasonProbeFailed},
	}
	for _, c := range cases {
		detail := detailFor(c.reason, "")
		if detail == "" {
			t.Errorf("detailFor(%q) returned empty string", c.reason)
		}
	}
}

func TestSystemCapability_UnavailableReportedCorrectly(t *testing.T) {
	prober := &fakeProber{results: fullResults(model.CapabilityProbeResult{
		ID:     "firewall",
		Reason: model.CapabilityReasonNotSupported,
		Err:    "netlink: operation not supported",
	})}
	svc := NewSystemCapabilityService(prober, false, nil)

	caps := svc.Get(false)
	if caps.Mock {
		t.Fatal("expected Mock=false")
	}

	var fw *model.CapabilityStatus
	for i := range caps.Capabilities {
		if caps.Capabilities[i].ID == "firewall" {
			fw = &caps.Capabilities[i]
		}
	}
	if fw == nil {
		t.Fatal("expected a firewall entry in capabilities")
	}
	if fw.Available {
		t.Error("expected firewall.Available=false")
	}
	if fw.Reason != model.CapabilityReasonNotSupported {
		t.Errorf("expected reason not_supported, got %q", fw.Reason)
	}
	if fw.Detail == "" {
		t.Error("expected a non-empty Thai detail message")
	}
}

func TestSystemCapability_CacheTTL(t *testing.T) {
	prober := &fakeProber{results: fullResults(okResult("firewall"))}
	svc := NewSystemCapabilityService(prober, false, nil)
	svc.ttl = 50 * time.Millisecond

	svc.Get(false)
	svc.Get(false)
	if prober.callCount != 1 {
		t.Fatalf("expected 1 probe call within TTL, got %d", prober.callCount)
	}

	svc.Get(true)
	if prober.callCount != 2 {
		t.Fatalf("expected force=true to bypass cache, got %d calls", prober.callCount)
	}

	time.Sleep(60 * time.Millisecond)
	svc.Get(false)
	if prober.callCount != 3 {
		t.Fatalf("expected cache to expire after ttl, got %d calls", prober.callCount)
	}
}

func TestSystemCapability_MergeApplyHealth(t *testing.T) {
	prober := &fakeProber{results: fullResults(okResult("firewall"))}
	svc := NewSystemCapabilityService(prober, false, nil)
	svc.RegisterApplyHealth("firewall", fakeApplyHealth{
		ok:     false,
		detail: "failed to apply firewall rules: dial netlink: operation not permitted",
		at:     time.Now(),
	})

	caps := svc.Get(true)
	var fw *model.CapabilityStatus
	for i := range caps.Capabilities {
		if caps.Capabilities[i].ID == "firewall" {
			fw = &caps.Capabilities[i]
		}
	}
	if fw == nil {
		t.Fatal("expected a firewall entry in capabilities")
	}
	if !fw.Available {
		t.Error("expected firewall to remain Available=true (probe passed)")
	}
	if !fw.Degraded {
		t.Error("expected firewall.Degraded=true when apply health failed")
	}
	if fw.Reason != model.CapabilityReasonApplyFailed {
		t.Errorf("expected reason apply_failed, got %q", fw.Reason)
	}
}

func TestSystemCapability_ApplyHealthNeverAppliedIsIgnored(t *testing.T) {
	prober := &fakeProber{results: fullResults(okResult("firewall"))}
	svc := NewSystemCapabilityService(prober, false, nil)
	svc.RegisterApplyHealth("firewall", fakeApplyHealth{ok: true, at: time.Time{}})

	caps := svc.Get(true)
	for _, c := range caps.Capabilities {
		if c.ID == "firewall" && c.Reason != model.CapabilityReasonOK {
			t.Errorf("expected reason ok for a never-applied reporter, got %q", c.Reason)
		}
	}
}

func TestSystemCapability_MockModeAllAvailable(t *testing.T) {
	ids := []string{"firewall", "dbus", "dnsmasq", "resolved", "conntrack", "conntrack-events", "icmp-probe"}
	results := make([]model.CapabilityProbeResult, 0, len(ids))
	for _, id := range ids {
		results = append(results, model.CapabilityProbeResult{ID: id, Available: true, Reason: model.CapabilityReasonMock})
	}
	prober := &fakeProber{results: results}
	svc := NewSystemCapabilityService(prober, true, nil)

	caps := svc.Get(false)
	if !caps.Mock {
		t.Error("expected Mock=true")
	}
	for _, c := range caps.Capabilities {
		if !c.Available {
			t.Errorf("expected %s to be Available in mock mode, got Available=false", c.ID)
		}
		if c.Reason != model.CapabilityReasonMock {
			t.Errorf("expected %s reason=mock, got %q", c.ID, c.Reason)
		}
	}
}

// TestSystemCapability_ICMPProbeDegradedNotError covers docs/ref/todo/
// multi-wan-failover-plan.md Task 13 acceptance: a host missing cap_net_raw
// (icmp-probe comes back Degraded) must surface as Degraded=true with
// Available still true and a detail message that mentions the TCP fallback
// — never as a hard "Available=false" failure for the whole panel.
func TestSystemCapability_ICMPProbeDegradedNotError(t *testing.T) {
	results := append(fullResults(okResult("firewall")),
		okResult("conntrack"),
		okResult("conntrack-events"),
		model.CapabilityProbeResult{
			ID: "icmp-probe", Available: true, Degraded: true,
			Reason: model.CapabilityReasonICMPUnavailable, Err: "listen ip4:icmp 0.0.0.0: socket: operation not permitted",
		},
	)
	prober := &fakeProber{results: results}
	svc := NewSystemCapabilityService(prober, false, nil)

	caps := svc.Get(true)
	var icmpStatus *model.CapabilityStatus
	for i := range caps.Capabilities {
		if caps.Capabilities[i].ID == "icmp-probe" {
			icmpStatus = &caps.Capabilities[i]
		}
	}
	if icmpStatus == nil {
		t.Fatal("expected an icmp-probe entry in the capabilities list")
	}
	if !icmpStatus.Available {
		t.Errorf("expected Available=true even when degraded, got false")
	}
	if !icmpStatus.Degraded {
		t.Errorf("expected Degraded=true when cap_net_raw is missing")
	}
	if icmpStatus.Detail == "" {
		t.Error("expected a non-empty Detail message")
	}
}

// TestSystemCapability_ICMPProbeOK covers the healthy path: a host with
// cap_net_raw reports icmp-probe as fully ok, not degraded.
func TestSystemCapability_ICMPProbeOK(t *testing.T) {
	results := append(fullResults(okResult("firewall")),
		okResult("conntrack"),
		okResult("conntrack-events"),
		okResult("icmp-probe"),
	)
	prober := &fakeProber{results: results}
	svc := NewSystemCapabilityService(prober, false, nil)

	caps := svc.Get(true)
	for _, c := range caps.Capabilities {
		if c.ID == "icmp-probe" {
			if !c.Available || c.Degraded {
				t.Errorf("expected icmp-probe fully ok, got %+v", c)
			}
			return
		}
	}
	t.Fatal("expected an icmp-probe entry in the capabilities list")
}
