package service

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"pigate/internal/db"
	"pigate/internal/kernel"
	"pigate/internal/model"
)

// wanMonitorTickInterval is the scheduler "clock" WanMonitor's background
// loop runs on. It is much shorter than any real ProbeIntervalSeconds
// (2-300s, model.ValidateWanUplink) — each tick just checks which enabled
// uplinks are due for a probe round (now - lastProbeAt >= their own
// ProbeIntervalSeconds) and probes only those, so uplinks with different
// intervals are scheduled independently without needing one goroutine/ticker
// per uplink (mirrors dhcp_health_checker.go's single-ticker-over-a-
// collection shape, adapted for a per-item interval instead of one global
// interval).
const wanMonitorTickInterval = 1 * time.Second

// wanStickyICMPFailThreshold is the D-5 "sticky" threshold: once ICMP has
// gotten zero replies (from every configured target) for this many
// consecutive rounds while ProbeMethod=="auto", the monitor stops sending
// ICMP every round (pins to TCP) to avoid redundant probing, and instead
// re-tests ICMP only every wanICMPRetestInterval.
const wanStickyICMPFailThreshold = 3

// wanICMPRetestInterval is how often a sticky-pinned-to-TCP uplink
// re-attempts ICMP to see whether it has recovered (D-5).
const wanICMPRetestInterval = 10 * time.Minute

// wanRuntimeState is the RAM-only (never persisted, tech_stack_design.md §8)
// bookkeeping WanMonitor keeps per uplink between ticks.
type wanRuntimeState struct {
	uplinkID  string
	ifaceName string

	state         string // one of model.WanState*
	failStreak    int    // consecutive failing rounds while not already "down"
	recoverStreak int    // consecutive healthy rounds while already "down"
	reason        string
	lastChangeAt  string // RFC3339; empty until the first state change

	effectiveMethod string // "icmp" or "tcp"; empty until the first successful round
	metricQuality   string
	lastLatencyMs   float64
	jitterMs        float64
	lossPct         float64

	lastProbeAt time.Time

	// icmpFailStreak/lastICMPRetryAt drive the D-5 sticky/re-test decision
	// (selectProbeMethod below) — distinct from failStreak/recoverStreak,
	// which drive the up/degraded/down health state machine (decideState).
	icmpFailStreak  int
	lastICMPRetryAt time.Time
}

// WanMonitor is the Multi-WAN Failover health-check background loop
// (docs/ref/todo/multi-wan-failover-plan.md Task 7). It periodically probes
// every enabled model.WanUplink via kernel.PathProbeManager, maintains a
// RAM-only health state machine per uplink, and records every probe round
// into a WanUplinkMetricsRing for the metrics API/UI.
//
// Phase 1 is entirely read-only with respect to the default-route metric
// (D-1): this file must never mutate any kernel networking state, adjust an
// interface's default-gateway priority, or depend on any lower-level
// packet-forwarding kernel interface — it only observes and records.
// Deciding what to DO about a "down" uplink is Phase 2's job (a not-yet-built
// controller), which is entirely out of scope here.
type WanMonitor struct {
	repo     *db.Repository
	probe    kernel.PathProbeManager
	eventLog *EventLogService
	bus      *NetEventBus
	ring     *WanUplinkMetricsRing

	mu     sync.Mutex
	states map[string]*wanRuntimeState
}

// NewWanMonitor constructs the monitor. Start(ctx) must be called separately
// once startup wiring is complete (mirrors DhcpHealthChecker).
func NewWanMonitor(repo *db.Repository, probe kernel.PathProbeManager, eventLog *EventLogService, bus *NetEventBus, ring *WanUplinkMetricsRing) *WanMonitor {
	return &WanMonitor{
		repo:     repo,
		probe:    probe,
		eventLog: eventLog,
		bus:      bus,
		ring:     ring,
		states:   make(map[string]*wanRuntimeState),
	}
}

// Start launches the periodic background loop. Unlike DhcpHealthChecker,
// this loop deliberately keeps running under -mock=true (via
// kernel.MockPathProbe): the plan requires mock-mode dev runs to see live
// uplink data in the UI (Task 7), so there is no repo.IsMockMode() guard
// here — which kernel implementation is actually behind m.probe is decided
// once, at construction, in cmd/pigate/main.go.
func (m *WanMonitor) Start(ctx context.Context) {
	go m.run(ctx)
}

func (m *WanMonitor) run(ctx context.Context) {
	t := time.NewTicker(wanMonitorTickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			m.tick(now)
		}
	}
}

// tick evaluates every enabled uplink once, probing the ones due for a round
// this pass (see wanMonitorTickInterval's doc comment). Guard order mirrors
// DhcpHealthChecker.tick: bus-pause first (skip the whole tick during a
// backup import so the monitor never races a config restore).
func (m *WanMonitor) tick(now time.Time) {
	if m.bus.IsPaused() {
		return
	}

	uplinks, err := m.repo.GetWanUplinks()
	if err != nil {
		log.Printf("[WanMonitor] failed to read uplinks: %v", err)
		return
	}

	seen := make(map[string]bool, len(uplinks))
	for _, u := range uplinks {
		if !u.Status {
			continue
		}
		seen[u.ID] = true
		m.maybeProbe(u, now)
	}

	// Drop RAM state for uplinks no longer present/enabled, mirroring
	// DhcpHealthChecker.tick's per-tick pruning — state is RAM-only anyway,
	// so this loses nothing that survives a restart regardless.
	m.mu.Lock()
	for id := range m.states {
		if !seen[id] {
			delete(m.states, id)
		}
	}
	m.mu.Unlock()
}

// maybeProbe runs a probe round for u only if its own ProbeIntervalSeconds
// has elapsed since its last round.
func (m *WanMonitor) maybeProbe(u model.WanUplink, now time.Time) {
	m.mu.Lock()
	rt, ok := m.states[u.ID]
	if !ok {
		rt = &wanRuntimeState{uplinkID: u.ID, ifaceName: u.Interface, state: model.WanStateUnknown}
		m.states[u.ID] = rt
	}
	due := rt.lastProbeAt.IsZero() || now.Sub(rt.lastProbeAt) >= time.Duration(u.ProbeIntervalSeconds)*time.Second
	m.mu.Unlock()
	if !due {
		return
	}
	m.probeUplink(u, now)
}

// probeUplink runs one full probe round for u (all configured targets,
// including any D-5 auto-fallback/re-test sub-probes), then folds the
// result into the uplink's health state machine and metrics ring. It reads
// its inputs (previous effective method / sticky counters) under m.mu,
// performs the (possibly multi-second) network I/O WITHOUT holding the
// lock, then re-locks to write the outcome back — the same pattern
// DhcpHealthChecker.tickInterface uses.
func (m *WanMonitor) probeUplink(u model.WanUplink, now time.Time) {
	m.mu.Lock()
	rt, ok := m.states[u.ID]
	if !ok {
		// Defensive: normal operation always reaches probeUplink via
		// maybeProbe, which already creates the entry — but a direct
		// caller (e.g. a future Phase 2 controller, or a test) must not
		// crash the monitor goroutine.
		rt = &wanRuntimeState{uplinkID: u.ID, ifaceName: u.Interface, state: model.WanStateUnknown}
		m.states[u.ID] = rt
	}
	rt.lastProbeAt = now
	prevEffective := rt.effectiveMethod
	icmpFailStreak := rt.icmpFailStreak
	lastICMPRetryAt := rt.lastICMPRetryAt
	prevState := rt.state
	failStreak := rt.failStreak
	recoverStreak := rt.recoverStreak
	m.mu.Unlock()

	timeout := time.Duration(u.ProbeTimeoutMs) * time.Millisecond
	// Outer safety margin: a single "auto" round can make at most two
	// sub-probes (e.g. ICMP then an immediate TCP fallback), each of which
	// PathProbeManager's contract already promises returns within
	// count*timeout on its own.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Duration(u.ProbeCount)*timeout+5*time.Second)
	defer cancel()

	sample, effectiveMethod, newICMPFailStreak, newLastICMPRetryAt, perr := m.runProbeRound(ctx, u, icmpFailStreak, lastICMPRetryAt, now, timeout)

	m.mu.Lock()
	defer m.mu.Unlock()
	rt.icmpFailStreak = newICMPFailStreak
	rt.lastICMPRetryAt = newLastICMPRetryAt

	if perr != nil {
		// A probe-system failure (socket/permission/interface-not-found) is
		// NOT the same as the target being unreachable — report "unknown",
		// never advance the fail/recover strikes, and only log once per
		// transition into this state (never spam every tick).
		if prevState != model.WanStateUnknown {
			m.logStateChange(u, prevState, model.WanStateUnknown, "probe error: "+perr.Error())
			rt.lastChangeAt = now.UTC().Format(time.RFC3339)
		}
		rt.state = model.WanStateUnknown
		rt.reason = "probe error: " + perr.Error()
		return
	}

	decision := decideState(wanDecideInput{
		Sample:             sample,
		LossThresholdPct:   u.LossThresholdPct,
		LatencyThresholdMs: u.LatencyThresholdMs,
		FailStrikes:        u.FailStrikes,
		RecoverStrikes:     u.RecoverStrikes,
		PrevState:          prevState,
		FailStreak:         failStreak,
		RecoverStreak:      recoverStreak,
	})

	if decision.Changed {
		m.logStateChange(u, prevState, decision.State, decision.Reason)
		rt.lastChangeAt = now.UTC().Format(time.RFC3339)
	}
	// Effective-method switch is logged once per switch, independent of
	// whether the health state also changed this round (plan: "ห้าม log ทุก
	// รอบ"). prevEffective == "" means this is the uplink's very first
	// round ever — not a "switch".
	if prevEffective != "" && effectiveMethod != "" && effectiveMethod != prevEffective {
		m.logMethodSwitch(u, prevEffective, effectiveMethod)
	}

	rt.state = decision.State
	rt.failStreak = decision.FailStreak
	rt.recoverStreak = decision.RecoverStreak
	rt.reason = decision.Reason
	rt.effectiveMethod = effectiveMethod
	rt.metricQuality = sample.MetricQuality

	avg, _, jitter, hasJitter := summarizeRTTs(sample.RTTsMs)
	rt.lastLatencyMs = avg
	if hasJitter && sample.MetricQuality == model.WanMetricQualityFull {
		rt.jitterMs = jitter
	} else {
		rt.jitterMs = 0
	}
	if sample.Sent > 0 {
		rt.lossPct = 100 * float64(sample.Sent-sample.Received) / float64(sample.Sent)
	} else {
		rt.lossPct = 0
	}

	m.ring.Add(u.ID, sample)
}

// runProbeRound performs the actual network I/O for one round: it decides
// (via selectProbeMethod) which method(s) to use this round given the
// uplink's configured ProbeMethod and the current sticky state, runs them,
// and returns the round's effective sample plus the updated sticky counters.
// It does not touch m.states — probeUplink writes the results back.
func (m *WanMonitor) runProbeRound(ctx context.Context, u model.WanUplink, icmpFailStreak int, lastICMPRetryAt, now time.Time, timeout time.Duration) (sample model.WanProbeSample, effectiveMethod string, newICMPFailStreak int, newLastICMPRetryAt time.Time, err error) {
	newICMPFailStreak = icmpFailStreak
	newLastICMPRetryAt = lastICMPRetryAt

	if u.ProbeMethod != model.WanProbeMethodAuto {
		// icmp-only / tcp-only: never touches the other method, ever (plan
		// Task 7 acceptance: "method=icmp ล้วน -> ไม่มีการยิง TCP เลยแม้ loss 100%").
		sample, err = m.probeAllTargets(ctx, u.ProbeMethod, u, timeout)
		if err == nil {
			effectiveMethod = u.ProbeMethod
		}
		return
	}

	method, alsoTryICMP := selectProbeMethod(u.ProbeMethod, icmpFailStreak, lastICMPRetryAt, now)

	if method == model.WanProbeMethodICMP {
		sample, err = m.probeAllTargets(ctx, model.WanProbeMethodICMP, u, timeout)
		if err != nil {
			return
		}
		if sample.Received > 0 {
			newICMPFailStreak = 0
			effectiveMethod = model.WanProbeMethodICMP
			return
		}
		// D-5: zero replies from every target this round -> immediately
		// fall back to TCP within the SAME round (never "declare down,
		// then retry later").
		newICMPFailStreak = icmpFailStreak + 1
		tcpSample, tErr := m.probeAllTargets(ctx, model.WanProbeMethodTCP, u, timeout)
		if tErr != nil {
			err = tErr
			return
		}
		sample = tcpSample
		effectiveMethod = model.WanProbeMethodTCP
		return
	}

	// Sticky-pinned to TCP (icmpFailStreak >= wanStickyICMPFailThreshold).
	if alsoTryICMP {
		newLastICMPRetryAt = now
		icmpSample, iErr := m.probeAllTargets(ctx, model.WanProbeMethodICMP, u, timeout)
		if iErr == nil && icmpSample.Received > 0 {
			// ICMP has recovered: un-stick immediately.
			newICMPFailStreak = 0
			sample = icmpSample
			effectiveMethod = model.WanProbeMethodICMP
			return
		}
		// Still dead (or the re-test itself errored) — fall through to the
		// normal TCP probe below so the round still produces a usable
		// sample for the health state machine.
	}
	sample, err = m.probeAllTargets(ctx, model.WanProbeMethodTCP, u, timeout)
	if err == nil {
		effectiveMethod = model.WanProbeMethodTCP
	}
	return
}

// probeAllTargets probes every configured target of u with the given method
// and sums the results into one combined model.WanProbeSample — "every
// target replied with zero packets" (the D-5 fallback trigger) is exactly
// "the combined sample's Received == 0". Returns an error only when the
// underlying kernel.PathProbeManager call itself fails (probe-system
// failure, not target unreachability — see the interface's doc comment).
func (m *WanMonitor) probeAllTargets(ctx context.Context, method string, u model.WanUplink, timeout time.Duration) (model.WanProbeSample, error) {
	combined := model.WanProbeSample{
		TimestampUnix: time.Now().Unix(),
		Method:        method,
	}
	if method == model.WanProbeMethodTCP {
		combined.MetricQuality = model.WanMetricQualityConnectOnly
	} else {
		combined.MetricQuality = model.WanMetricQualityFull
	}

	for _, target := range u.ProbeTargets {
		ip := net.ParseIP(target)
		if ip == nil {
			// Should never happen — targets are validated IPv4 literals
			// before being persisted (model.ValidateWanUplink) — but skip
			// defensively rather than erroring the whole round over a
			// single corrupt entry.
			continue
		}

		var sample model.WanProbeSample
		var err error
		if method == model.WanProbeMethodTCP {
			sample, err = m.probe.ProbeTCP(ctx, u.Interface, ip, u.ProbeTCPPort, u.ProbeCount, timeout)
		} else {
			sample, err = m.probe.ProbeICMP(ctx, u.Interface, ip, u.ProbeCount, timeout)
		}
		if err != nil {
			return combined, fmt.Errorf("probe %s target %s on %s: %w", method, target, u.Interface, err)
		}
		combined.Sent += sample.Sent
		combined.Received += sample.Received
		combined.RTTsMs = append(combined.RTTsMs, sample.RTTsMs...)
	}
	return combined, nil
}

// selectProbeMethod is the pure D-5 decision core: given the uplink's
// configured probeMethod ("icmp" | "tcp" | "auto"), the current ICMP-fail
// streak, when ICMP was last re-tested (zero value = never), and now, it
// returns which method the round should use as its PRIMARY probe this
// round, and whether an additional ICMP re-test should also be attempted
// even though the primary method is "tcp" (only relevant once
// sticky-pinned). It never touches the network — fully unit-testable.
func selectProbeMethod(probeMethod string, icmpFailStreak int, lastICMPRetryAt, now time.Time) (method string, alsoTryICMP bool) {
	switch probeMethod {
	case model.WanProbeMethodICMP:
		return model.WanProbeMethodICMP, false
	case model.WanProbeMethodTCP:
		return model.WanProbeMethodTCP, false
	default: // "auto"
		if icmpFailStreak < wanStickyICMPFailThreshold {
			return model.WanProbeMethodICMP, false
		}
		retest := lastICMPRetryAt.IsZero() || now.Sub(lastICMPRetryAt) >= wanICMPRetestInterval
		return model.WanProbeMethodTCP, retest
	}
}

// wanDecideInput is decideState's pure input: one round's sample plus the
// uplink's configured thresholds/strikes and the state machine's previous
// snapshot. Kept as a struct (rather than a long positional parameter list)
// so call sites and tests stay readable.
type wanDecideInput struct {
	Sample             model.WanProbeSample
	LossThresholdPct   float64
	LatencyThresholdMs float64
	FailStrikes        int
	RecoverStrikes     int
	PrevState          string
	FailStreak         int
	RecoverStreak      int
}

// wanDecideResult is decideState's pure output.
type wanDecideResult struct {
	State         string
	FailStreak    int
	RecoverStreak int
	Reason        string
	Changed       bool
}

// decideState is the pure core of the WAN health state machine (mirrors
// DhcpHealthChecker's decideNextState). D-7 is enforced structurally here:
// "degraded" is only ever derived from a latency-threshold breach with no
// loss-threshold breach, is applied immediately (no strikes needed — it is
// a display-only signal), and never feeds into FailStrikes/RecoverStrikes at
// all. Only a loss-threshold breach ("failing") can ever drive a transition
// to/from "down".
func decideState(in wanDecideInput) wanDecideResult {
	sent := in.Sample.Sent
	received := in.Sample.Received

	lossPct := 100.0
	if sent > 0 {
		lossPct = 100 * float64(sent-received) / float64(sent)
	}
	avgLatency, _, _, _ := summarizeRTTs(in.Sample.RTTsMs)

	failing := lossPct >= in.LossThresholdPct

	out := wanDecideResult{State: in.PrevState, FailStreak: in.FailStreak, RecoverStreak: in.RecoverStreak}

	if failing {
		out.RecoverStreak = 0
		if in.PrevState == model.WanStateDown {
			out.State = model.WanStateDown
			out.Reason = fmt.Sprintf("still failing: loss %.1f%% >= threshold %.1f%%", lossPct, in.LossThresholdPct)
		} else {
			out.FailStreak = in.FailStreak + 1
			if out.FailStreak >= in.FailStrikes {
				out.State = model.WanStateDown
				out.Reason = fmt.Sprintf("loss %.1f%% >= threshold %.1f%% for %d consecutive round(s)", lossPct, in.LossThresholdPct, out.FailStreak)
				out.FailStreak = 0
			} else {
				out.Reason = fmt.Sprintf("loss %.1f%% >= threshold %.1f%% (%d/%d strikes)", lossPct, in.LossThresholdPct, out.FailStreak, in.FailStrikes)
			}
		}
	} else {
		out.FailStreak = 0
		if in.PrevState == model.WanStateDown {
			out.RecoverStreak = in.RecoverStreak + 1
			if out.RecoverStreak >= in.RecoverStrikes {
				out.RecoverStreak = 0
				if avgLatency > in.LatencyThresholdMs {
					out.State = model.WanStateDegraded
					out.Reason = fmt.Sprintf("recovered after %d healthy round(s) but latency %.1fms exceeds threshold %.1fms", in.RecoverStrikes, avgLatency, in.LatencyThresholdMs)
				} else {
					out.State = model.WanStateUp
					out.Reason = fmt.Sprintf("recovered after %d consecutive healthy round(s)", in.RecoverStrikes)
				}
			} else {
				out.State = model.WanStateDown
				out.Reason = fmt.Sprintf("recovering (%d/%d healthy round(s))", out.RecoverStreak, in.RecoverStrikes)
			}
		} else if avgLatency > in.LatencyThresholdMs {
			out.State = model.WanStateDegraded
			out.Reason = fmt.Sprintf("latency %.1fms exceeds threshold %.1fms", avgLatency, in.LatencyThresholdMs)
		} else {
			out.State = model.WanStateUp
			out.Reason = "healthy"
		}
	}

	out.Changed = out.State != in.PrevState
	return out
}

// logStateChange records a health-state transition to the central event
// log. Severity: a transition INTO down/unknown is a warning (something an
// operator should notice); into up/degraded is informational.
func (m *WanMonitor) logStateChange(u model.WanUplink, from, to, reason string) {
	if m.eventLog == nil {
		return
	}
	severity := model.EventSeverityInfo
	if to == model.WanStateDown || to == model.WanStateUnknown {
		severity = model.EventSeverityWarning
	}
	m.eventLog.Log(model.EventCategoryNetwork, "wan-uplink-state", severity,
		model.EventActorSystem, u.Interface,
		fmt.Sprintf("WAN uplink %q (%s) changed state %s -> %s: %s", u.Name, u.Interface, from, to, reason))
}

// logMethodSwitch records an effective-probe-method switch (icmp<->tcp) —
// logged once per switch, never once per round (plan Task 7 acceptance).
func (m *WanMonitor) logMethodSwitch(u model.WanUplink, from, to string) {
	if m.eventLog == nil {
		return
	}
	m.eventLog.Log(model.EventCategoryNetwork, "wan-uplink-method-switch", model.EventSeverityInfo,
		model.EventActorSystem, u.Interface,
		fmt.Sprintf("WAN uplink %q (%s) switched effective probe method %s -> %s", u.Name, u.Interface, from, to))
}

// GetStates returns a snapshot of every uplink's current health state,
// ordered by uplink ID for a stable API response. Active is always false in
// Phase 1 — there is no failover controller yet to ever mark an uplink
// active.
func (m *WanMonitor) GetStates() []model.WanUplinkState {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]model.WanUplinkState, 0, len(m.states))
	for _, rt := range m.states {
		out = append(out, model.WanUplinkState{
			UplinkID:        rt.uplinkID,
			Interface:       rt.ifaceName,
			State:           rt.state,
			Active:          false,
			LastLatencyMs:   rt.lastLatencyMs,
			JitterMs:        rt.jitterMs,
			LossPct:         rt.lossPct,
			EffectiveMethod: rt.effectiveMethod,
			MetricQuality:   rt.metricQuality,
			Strikes:         rt.failStreak,
			LastChangeAt:    rt.lastChangeAt,
			Reason:          rt.reason,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UplinkID < out[j].UplinkID })
	return out
}

// GetMetrics returns the metrics ring's series for one uplink/window,
// exposed for the api layer (GET /api/wan/metrics).
func (m *WanMonitor) GetMetrics(uplinkID, window string) []model.WanMetricPoint {
	return m.ring.Series(uplinkID, window)
}
