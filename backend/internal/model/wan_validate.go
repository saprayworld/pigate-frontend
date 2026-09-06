package model

import (
	"fmt"
	"net"
	"strings"
)

// validWanProbeMethods mirrors the switch service.selectProbeMethod (and
// kernel.PathProbeManager's two methods) understand.
var validWanProbeMethods = map[string]bool{
	WanProbeMethodICMP: true,
	WanProbeMethodTCP:  true,
	WanProbeMethodAuto: true,
}

// validWanFailoverModes mirrors WanFailoverModeAuto/Manual.
var validWanFailoverModes = map[string]bool{
	WanFailoverModeAuto:   true,
	WanFailoverModeManual: true,
}

// ValidateWanProbeTarget checks a single WAN probe target: it must be an
// IPv4 literal (never a hostname — DNS-dependency-loop and DNS-poisoning
// concerns, see wan_uplink.go doc comment and tech_stack_design.md §8) and
// must not be multicast/broadcast/loopback/unspecified (0.0.0.0), none of
// which is a meaningful "is the internet reachable" target. Exported so the
// api layer can give a field-specific 400 message without re-deriving this
// logic.
func ValidateWanProbeTarget(target string) error {
	ip := net.ParseIP(strings.TrimSpace(target))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("probe target %q must be an IPv4 literal address, not a hostname", target)
	}
	if ip.IsLoopback() {
		return fmt.Errorf("probe target %q is a loopback address and cannot be used to check internet reachability", target)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("probe target %q is unspecified (0.0.0.0) and is not a valid probe target", target)
	}
	if ip.IsMulticast() {
		return fmt.Errorf("probe target %q is a multicast address and is not a valid probe target", target)
	}
	if ip.Equal(net.IPv4bcast) {
		return fmt.Errorf("probe target %q is the broadcast address and is not a valid probe target", target)
	}
	return nil
}

// ValidateWanUplink is a pure function (no DB/kernel access) validating a
// WanUplinkInput before it is persisted, mirroring ValidateWifiPreset's
// shape/reuse pattern (wifi_preset_validate.go): usable both from the
// repository's create/update path and from a future backup-import
// fail-closed validation pass.
func ValidateWanUplink(input WanUplinkInput) error {
	if strings.TrimSpace(input.Name) == "" {
		return fmt.Errorf("name must not be empty")
	}
	if strings.TrimSpace(input.Interface) == "" {
		return fmt.Errorf("interface must not be empty")
	}
	if input.Priority < 1 || input.Priority > 16 {
		return fmt.Errorf("priority must be between 1 and 16")
	}

	if len(input.ProbeTargets) == 0 {
		return fmt.Errorf("probeTargets must not be empty — there is no built-in default target, please provide at least one IPv4 address")
	}
	for _, t := range input.ProbeTargets {
		if err := ValidateWanProbeTarget(t); err != nil {
			return err
		}
	}

	if !validWanProbeMethods[input.ProbeMethod] {
		return fmt.Errorf("probeMethod %q must be one of icmp, tcp, auto", input.ProbeMethod)
	}
	switch input.ProbeMethod {
	case WanProbeMethodICMP:
		if input.ProbeTCPPort != 0 {
			return fmt.Errorf("probeTcpPort must be 0 when probeMethod is icmp")
		}
	case WanProbeMethodTCP, WanProbeMethodAuto:
		if input.ProbeTCPPort < 1 || input.ProbeTCPPort > 65535 {
			return fmt.Errorf("probeTcpPort must be between 1 and 65535 when probeMethod is %q", input.ProbeMethod)
		}
	}

	if input.ProbeIntervalSeconds < 2 || input.ProbeIntervalSeconds > 300 {
		return fmt.Errorf("probeIntervalSeconds must be between 2 and 300")
	}
	if input.ProbeCount < 1 || input.ProbeCount > 10 {
		return fmt.Errorf("probeCount must be between 1 and 10")
	}
	if input.ProbeTimeoutMs < 100 || input.ProbeTimeoutMs > 5000 {
		return fmt.Errorf("probeTimeoutMs must be between 100 and 5000")
	}
	if input.LossThresholdPct < 1 || input.LossThresholdPct > 100 {
		return fmt.Errorf("lossThresholdPct must be between 1 and 100")
	}
	if input.LatencyThresholdMs < 1 || input.LatencyThresholdMs > 10000 {
		return fmt.Errorf("latencyThresholdMs must be between 1 and 10000")
	}
	if input.FailStrikes < 1 || input.FailStrikes > 20 {
		return fmt.Errorf("failStrikes must be between 1 and 20")
	}
	if input.RecoverStrikes < 1 || input.RecoverStrikes > 20 {
		return fmt.Errorf("recoverStrikes must be between 1 and 20")
	}

	return nil
}

// ValidateWanFailoverSettings is a pure function validating the global
// failover kill-switch/mode/dampening settings. Mode=="manual" requires a
// non-empty ManualUplinkID (whether that ID actually refers to an existing
// uplink is a DB-aware check the service/api layer must do separately, since
// this function must stay DB-free to remain unit-testable in isolation).
func ValidateWanFailoverSettings(s WanFailoverSettings) error {
	if !validWanFailoverModes[s.Mode] {
		return fmt.Errorf("mode %q must be one of auto, manual", s.Mode)
	}
	if s.Mode == WanFailoverModeManual && strings.TrimSpace(s.ManualUplinkID) == "" {
		return fmt.Errorf("manualUplinkId must not be empty when mode is manual")
	}
	if s.MinHoldSeconds < 0 || s.MinHoldSeconds > 3600 {
		return fmt.Errorf("minHoldSeconds must be between 0 and 3600")
	}
	if s.RevertDelaySeconds < 0 || s.RevertDelaySeconds > 3600 {
		return fmt.Errorf("revertDelaySeconds must be between 0 and 3600")
	}
	return nil
}
