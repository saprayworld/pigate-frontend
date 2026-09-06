package model

import (
	"fmt"
	"strings"
	"testing"
)

func validWanUplinkInput() WanUplinkInput {
	return WanUplinkInput{
		Name:                 "Primary",
		Interface:            "eth0",
		Priority:             1,
		ProbeTargets:         []string{"1.1.1.1", "8.8.8.8"},
		ProbeMethod:          WanProbeMethodAuto,
		ProbeTCPPort:         443,
		ProbeIntervalSeconds: 5,
		ProbeCount:           3,
		ProbeTimeoutMs:       1000,
		LossThresholdPct:     50,
		LatencyThresholdMs:   200,
		FailStrikes:          3,
		RecoverStrikes:       3,
		Status:               true,
	}
}

func TestValidateWanUplink_Valid(t *testing.T) {
	if err := ValidateWanUplink(validWanUplinkInput()); err != nil {
		t.Fatalf("expected valid input to pass, got: %v", err)
	}
}

func TestValidateWanUplink_HostnameRejected(t *testing.T) {
	in := validWanUplinkInput()
	in.ProbeTargets = []string{"google.com"}
	if err := ValidateWanUplink(in); err == nil {
		t.Fatal("expected hostname probe target to be rejected")
	}
}

func TestValidateWanUplink_ProbeTargetEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"multicast", "224.0.0.1"},
		{"broadcast", "255.255.255.255"},
		{"loopback", "127.0.0.1"},
		{"unspecified", "0.0.0.0"},
		{"ipv6", "2001:4860:4860::8888"},
		{"empty", ""},
		{"garbage", "not-an-ip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validWanUplinkInput()
			in.ProbeTargets = []string{tt.target}
			if err := ValidateWanUplink(in); err == nil {
				t.Fatalf("expected target %q to be rejected", tt.target)
			}
		})
	}
}

func TestValidateWanUplink_NoProbeTargets(t *testing.T) {
	in := validWanUplinkInput()
	in.ProbeTargets = nil
	if err := ValidateWanUplink(in); err == nil {
		t.Fatal("expected empty probeTargets to be rejected (no default target allowed)")
	}
}

func TestValidateWanUplink_NameInterfaceRequired(t *testing.T) {
	in := validWanUplinkInput()
	in.Name = "   "
	if err := ValidateWanUplink(in); err == nil {
		t.Fatal("expected empty name to be rejected")
	}

	in = validWanUplinkInput()
	in.Interface = ""
	if err := ValidateWanUplink(in); err == nil {
		t.Fatal("expected empty interface to be rejected")
	}
}

func TestValidateWanUplink_ProbeMethodAndPort(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		port    int
		wantErr bool
	}{
		{"icmp with port 0 valid", WanProbeMethodICMP, 0, false},
		{"icmp with nonzero port invalid", WanProbeMethodICMP, 443, true},
		{"tcp with valid port", WanProbeMethodTCP, 443, false},
		{"tcp with port 0 invalid", WanProbeMethodTCP, 0, true},
		{"tcp with port out of range invalid", WanProbeMethodTCP, 70000, true},
		{"auto with valid port", WanProbeMethodAuto, 53, false},
		{"auto with port 0 invalid", WanProbeMethodAuto, 0, true},
		{"unknown method invalid", "ping", 443, true},
		{"empty method invalid", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validWanUplinkInput()
			in.ProbeMethod = tt.method
			in.ProbeTCPPort = tt.port
			err := ValidateWanUplink(in)
			if (err != nil) != tt.wantErr {
				t.Errorf("method=%q port=%d: err=%v, wantErr=%v", tt.method, tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestValidateWanUplink_RangeFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*WanUplinkInput)
	}{
		{"priority too low", func(in *WanUplinkInput) { in.Priority = 0 }},
		{"priority too high", func(in *WanUplinkInput) { in.Priority = 17 }},
		{"interval too low", func(in *WanUplinkInput) { in.ProbeIntervalSeconds = 1 }},
		{"interval too high", func(in *WanUplinkInput) { in.ProbeIntervalSeconds = 301 }},
		{"count too low", func(in *WanUplinkInput) { in.ProbeCount = 0 }},
		{"count too high", func(in *WanUplinkInput) { in.ProbeCount = 11 }},
		{"timeout too low", func(in *WanUplinkInput) { in.ProbeTimeoutMs = 99 }},
		{"timeout too high", func(in *WanUplinkInput) { in.ProbeTimeoutMs = 5001 }},
		{"loss too low", func(in *WanUplinkInput) { in.LossThresholdPct = 0 }},
		{"loss too high", func(in *WanUplinkInput) { in.LossThresholdPct = 101 }},
		{"latency too low", func(in *WanUplinkInput) { in.LatencyThresholdMs = 0 }},
		{"latency too high", func(in *WanUplinkInput) { in.LatencyThresholdMs = 10001 }},
		{"failStrikes too low", func(in *WanUplinkInput) { in.FailStrikes = 0 }},
		{"failStrikes too high", func(in *WanUplinkInput) { in.FailStrikes = 21 }},
		{"recoverStrikes too low", func(in *WanUplinkInput) { in.RecoverStrikes = 0 }},
		{"recoverStrikes too high", func(in *WanUplinkInput) { in.RecoverStrikes = 21 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validWanUplinkInput()
			tt.mutate(&in)
			if err := ValidateWanUplink(in); err == nil {
				t.Errorf("expected %s to be rejected", tt.name)
			}
		})
	}
}

func TestValidateWanUplink_RangeFieldsAtBoundary(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*WanUplinkInput)
	}{
		{"priority min", func(in *WanUplinkInput) { in.Priority = 1 }},
		{"priority max", func(in *WanUplinkInput) { in.Priority = 16 }},
		{"interval min", func(in *WanUplinkInput) { in.ProbeIntervalSeconds = 2 }},
		{"interval max", func(in *WanUplinkInput) { in.ProbeIntervalSeconds = 300 }},
		{"count min", func(in *WanUplinkInput) { in.ProbeCount = 1 }},
		{"count max", func(in *WanUplinkInput) { in.ProbeCount = 10 }},
		{"timeout min", func(in *WanUplinkInput) { in.ProbeTimeoutMs = 100 }},
		{"timeout max", func(in *WanUplinkInput) { in.ProbeTimeoutMs = 5000 }},
		{"loss min", func(in *WanUplinkInput) { in.LossThresholdPct = 1 }},
		{"loss max", func(in *WanUplinkInput) { in.LossThresholdPct = 100 }},
		{"latency min", func(in *WanUplinkInput) { in.LatencyThresholdMs = 1 }},
		{"latency max", func(in *WanUplinkInput) { in.LatencyThresholdMs = 10000 }},
		{"failStrikes min", func(in *WanUplinkInput) { in.FailStrikes = 1 }},
		{"failStrikes max", func(in *WanUplinkInput) { in.FailStrikes = 20 }},
		{"recoverStrikes min", func(in *WanUplinkInput) { in.RecoverStrikes = 1 }},
		{"recoverStrikes max", func(in *WanUplinkInput) { in.RecoverStrikes = 20 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validWanUplinkInput()
			tt.mutate(&in)
			if err := ValidateWanUplink(in); err != nil {
				t.Errorf("expected %s to be accepted, got: %v", tt.name, err)
			}
		})
	}
}

func TestValidateWanFailoverSettings(t *testing.T) {
	tests := []struct {
		name     string
		settings WanFailoverSettings
		wantErr  bool
	}{
		{"valid auto", WanFailoverSettings{Enabled: false, Mode: WanFailoverModeAuto, MinHoldSeconds: 60, RevertDelaySeconds: 120}, false},
		{"valid manual", WanFailoverSettings{Enabled: true, Mode: WanFailoverModeManual, ManualUplinkID: "wan-1", MinHoldSeconds: 60, RevertDelaySeconds: 120}, false},
		{"manual without uplink id", WanFailoverSettings{Mode: WanFailoverModeManual, ManualUplinkID: "  "}, true},
		{"unknown mode", WanFailoverSettings{Mode: "bogus"}, true},
		{"empty mode", WanFailoverSettings{Mode: ""}, true},
		{"minHold too high", WanFailoverSettings{Mode: WanFailoverModeAuto, MinHoldSeconds: 3601}, true},
		{"minHold negative", WanFailoverSettings{Mode: WanFailoverModeAuto, MinHoldSeconds: -1}, true},
		{"revertDelay too high", WanFailoverSettings{Mode: WanFailoverModeAuto, RevertDelaySeconds: 3601}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWanFailoverSettings(tt.settings)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWanFailoverSettings(%+v) err=%v, wantErr=%v", tt.settings, err, tt.wantErr)
			}
		})
	}
}

// TestWanFailoverSettings_NoDegradedField is a lightweight runtime guard for
// D-7 ("degraded never triggers failover" — there must be no field letting a
// degraded reading drive that decision at all): it prints the struct's field
// names via fmt's "%+v" verb and asserts none of them contain "Degraded".
// This is a tripwire, not the primary protection — the real guarantee is
// that this file (and the plan's Final Acceptance grep) never references
// such a field.
func TestWanFailoverSettings_NoDegradedField(t *testing.T) {
	s := WanFailoverSettings{Mode: WanFailoverModeAuto}
	repr := fmt.Sprintf("%+v", s)
	if strings.Contains(repr, "Degraded") {
		t.Fatalf("WanFailoverSettings must not have any field containing \"Degraded\" (D-7), got: %s", repr)
	}
}
