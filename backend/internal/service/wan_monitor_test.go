package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"pigate/internal/db"
	"pigate/internal/kernel"
	"pigate/internal/model"
)

// --- decideState (pure) ---------------------------------------------------

func TestDecideState_LossReachesFailStrikesBeforeGoingDown(t *testing.T) {
	in := wanDecideInput{
		Sample:             model.WanProbeSample{Sent: 3, Received: 0},
		LossThresholdPct:   50,
		LatencyThresholdMs: 200,
		FailStrikes:        3,
		RecoverStrikes:     3,
		PrevState:          model.WanStateUp,
	}

	// Round 1: 1st strike, must NOT be down yet.
	d1 := decideState(in)
	if d1.State != model.WanStateUp {
		t.Fatalf("round 1: expected state to stay %q, got %q", model.WanStateUp, d1.State)
	}
	if d1.FailStreak != 1 {
		t.Errorf("round 1: FailStreak = %d, want 1", d1.FailStreak)
	}

	in.PrevState, in.FailStreak = d1.State, d1.FailStreak
	d2 := decideState(in)
	if d2.State != model.WanStateUp {
		t.Fatalf("round 2: expected state to stay %q, got %q", model.WanStateUp, d2.State)
	}

	in.PrevState, in.FailStreak = d2.State, d2.FailStreak
	d3 := decideState(in)
	if d3.State != model.WanStateDown {
		t.Fatalf("round 3: expected state=down after FailStrikes=3, got %q", d3.State)
	}
	if !d3.Changed {
		t.Error("expected Changed=true on the transition to down")
	}
}

func TestDecideState_RecoversAfterRecoverStrikes(t *testing.T) {
	in := wanDecideInput{
		Sample:             model.WanProbeSample{Sent: 3, Received: 3, RTTsMs: []float64{10, 10, 10}},
		LossThresholdPct:   50,
		LatencyThresholdMs: 200,
		FailStrikes:        3,
		RecoverStrikes:     2,
		PrevState:          model.WanStateDown,
	}

	d1 := decideState(in)
	if d1.State != model.WanStateDown {
		t.Fatalf("round 1: expected to stay down (not yet RecoverStrikes), got %q", d1.State)
	}
	if d1.RecoverStreak != 1 {
		t.Errorf("RecoverStreak = %d, want 1", d1.RecoverStreak)
	}

	in.PrevState, in.RecoverStreak = d1.State, d1.RecoverStreak
	d2 := decideState(in)
	if d2.State != model.WanStateUp {
		t.Fatalf("round 2: expected up after RecoverStrikes=2, got %q", d2.State)
	}
	if !d2.Changed {
		t.Error("expected Changed=true on the transition to up")
	}
}

func TestDecideState_HighLatencyNoLossBecomesDegradedImmediately(t *testing.T) {
	in := wanDecideInput{
		Sample:             model.WanProbeSample{Sent: 3, Received: 3, RTTsMs: []float64{500, 500, 500}},
		LossThresholdPct:   50,
		LatencyThresholdMs: 200,
		FailStrikes:        3,
		RecoverStrikes:     3,
		PrevState:          model.WanStateUp,
	}
	d := decideState(in)
	if d.State != model.WanStateDegraded {
		t.Fatalf("expected degraded (latency over threshold, no loss), got %q", d.State)
	}
	if d.FailStreak != 0 {
		t.Errorf("degraded must never advance FailStreak (D-7), got %d", d.FailStreak)
	}
}

func TestDecideState_NoChangeMeansNoChangedFlag(t *testing.T) {
	in := wanDecideInput{
		Sample:             model.WanProbeSample{Sent: 3, Received: 3, RTTsMs: []float64{10, 10, 10}},
		LossThresholdPct:   50,
		LatencyThresholdMs: 200,
		FailStrikes:        3,
		RecoverStrikes:     3,
		PrevState:          model.WanStateUp,
	}
	d := decideState(in)
	if d.State != model.WanStateUp || d.Changed {
		t.Errorf("expected state to stay up with Changed=false, got state=%q changed=%v", d.State, d.Changed)
	}
}

// --- selectProbeMethod (pure) ---------------------------------------------

func TestSelectProbeMethod_NonAutoNeverSwitches(t *testing.T) {
	method, also := selectProbeMethod(model.WanProbeMethodICMP, 99, time.Time{}, time.Now())
	if method != model.WanProbeMethodICMP || also {
		t.Errorf("icmp-only config must always return icmp/false, got %q/%v", method, also)
	}
	method, also = selectProbeMethod(model.WanProbeMethodTCP, 0, time.Time{}, time.Now())
	if method != model.WanProbeMethodTCP || also {
		t.Errorf("tcp-only config must always return tcp/false, got %q/%v", method, also)
	}
}

func TestSelectProbeMethod_AutoBelowStickyThresholdUsesICMP(t *testing.T) {
	method, also := selectProbeMethod(model.WanProbeMethodAuto, wanStickyICMPFailThreshold-1, time.Time{}, time.Now())
	if method != model.WanProbeMethodICMP || also {
		t.Errorf("expected icmp/false below sticky threshold, got %q/%v", method, also)
	}
}

func TestSelectProbeMethod_AutoStickyPinsToTCP(t *testing.T) {
	now := time.Now()
	method, also := selectProbeMethod(model.WanProbeMethodAuto, wanStickyICMPFailThreshold, now, now)
	if method != model.WanProbeMethodTCP {
		t.Fatalf("expected tcp once sticky threshold reached, got %q", method)
	}
	if also {
		t.Error("expected no ICMP re-test immediately after just having probed ICMP")
	}
}

func TestSelectProbeMethod_AutoStickyRetestsAfterInterval(t *testing.T) {
	past := time.Now().Add(-wanICMPRetestInterval - time.Second)
	method, also := selectProbeMethod(model.WanProbeMethodAuto, wanStickyICMPFailThreshold, past, time.Now())
	if method != model.WanProbeMethodTCP || !also {
		t.Errorf("expected tcp/true (re-test due) once past the retest interval, got %q/%v", method, also)
	}
}

func TestSelectProbeMethod_AutoStickyRetestNeverTriedYet(t *testing.T) {
	method, also := selectProbeMethod(model.WanProbeMethodAuto, wanStickyICMPFailThreshold, time.Time{}, time.Now())
	if method != model.WanProbeMethodTCP || !also {
		t.Errorf("expected tcp/true when lastICMPRetryAt is the zero value, got %q/%v", method, also)
	}
}

// --- WanMonitor end-to-end (via MockPathProbe) ----------------------------

func newTestWanMonitor(t *testing.T) (*WanMonitor, *db.Repository, *kernel.MockPathProbe) {
	t.Helper()
	sqlDB, err := db.InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	repo := db.NewRepository(sqlDB)
	probe := kernel.NewMockPathProbe()
	eventLog := NewEventLogService(repo)
	bus := NewNetEventBus()
	ring := NewWanUplinkMetricsRing()

	monitor := NewWanMonitor(repo, probe, eventLog, bus, ring)
	return monitor, repo, probe
}

func createTestUplink(t *testing.T, repo *db.Repository, iface, method string, tcpPort int) model.WanUplink {
	t.Helper()
	u, err := repo.CreateWanUplink(model.WanUplinkInput{
		Name: "Test-" + iface, Interface: iface, Priority: 1,
		ProbeTargets: []string{"1.1.1.1"}, ProbeMethod: method, ProbeTCPPort: tcpPort,
		ProbeIntervalSeconds: 2, ProbeCount: 3, ProbeTimeoutMs: 200,
		LossThresholdPct: 50, LatencyThresholdMs: 200,
		FailStrikes: 3, RecoverStrikes: 3, Status: true,
	})
	if err != nil {
		t.Fatalf("CreateWanUplink failed: %v", err)
	}
	return *u
}

func stateFor(t *testing.T, m *WanMonitor, uplinkID string) model.WanUplinkState {
	t.Helper()
	for _, s := range m.GetStates() {
		if s.UplinkID == uplinkID {
			return s
		}
	}
	t.Fatalf("no state found for uplink %s", uplinkID)
	return model.WanUplinkState{}
}

func TestWanMonitor_BothDeadReachesDownAfterFailStrikes(t *testing.T) {
	monitor, repo, probe := newTestWanMonitor(t)
	u := createTestUplink(t, repo, "eth-both-dead", model.WanProbeMethodICMP, 0)
	probe.SetAllDead(u.Interface, true)

	now := time.Now()
	for i := 0; i < 3; i++ {
		monitor.probeUplink(u, now.Add(time.Duration(i)*3*time.Second))
	}
	st := stateFor(t, monitor, u.ID)
	if st.State != model.WanStateDown {
		t.Fatalf("expected down after 3 failing rounds, got %q (reason=%q)", st.State, st.Reason)
	}
}

func TestWanMonitor_ICMPOnlyNeverCallsTCPEvenOn100PercentLoss(t *testing.T) {
	monitor, repo, probe := newTestWanMonitor(t)
	u := createTestUplink(t, repo, "eth-icmp-only", model.WanProbeMethodICMP, 0)
	probe.SetAllDead(u.Interface, true)

	now := time.Now()
	for i := 0; i < 5; i++ {
		monitor.probeUplink(u, now.Add(time.Duration(i)*3*time.Second))
	}
	if probe.TCPCalls[u.Interface] != 0 {
		t.Errorf("expected ProbeTCP never called for an icmp-only uplink, got %d calls", probe.TCPCalls[u.Interface])
	}
	if probe.ICMPCalls[u.Interface] != 5 {
		t.Errorf("expected 5 ProbeICMP calls, got %d", probe.ICMPCalls[u.Interface])
	}
}

func TestWanMonitor_AutoFallbackToTCPWhenICMPDead(t *testing.T) {
	monitor, repo, probe := newTestWanMonitor(t)
	u := createTestUplink(t, repo, "eth-auto-fallback", model.WanProbeMethodAuto, 443)
	probe.SetICMPDead(u.Interface, true) // ICMP dead, TCP fine

	now := time.Now()
	// Fewer rounds than the sticky threshold: every round independently
	// falls back to TCP within the same round and reports healthy — must
	// NOT be down.
	for i := 0; i < wanStickyICMPFailThreshold; i++ {
		monitor.probeUplink(u, now.Add(time.Duration(i)*3*time.Second))
	}
	st := stateFor(t, monitor, u.ID)
	if st.State != model.WanStateUp {
		t.Fatalf("expected up (TCP fallback succeeds every round), got %q (reason=%q)", st.State, st.Reason)
	}
	if st.EffectiveMethod != model.WanProbeMethodTCP {
		t.Errorf("expected EffectiveMethod=tcp after sticky threshold reached, got %q", st.EffectiveMethod)
	}
}

func TestWanMonitor_ICMPRecoversAfterRetestInterval(t *testing.T) {
	monitor, repo, probe := newTestWanMonitor(t)
	u := createTestUplink(t, repo, "eth-icmp-recovers", model.WanProbeMethodAuto, 443)
	probe.SetICMPDead(u.Interface, true)

	now := time.Now()
	for i := 0; i < wanStickyICMPFailThreshold; i++ {
		monitor.probeUplink(u, now.Add(time.Duration(i)*3*time.Second))
	}
	st := stateFor(t, monitor, u.ID)
	if st.EffectiveMethod != model.WanProbeMethodTCP {
		t.Fatalf("expected sticky-pinned to tcp before recovery, got %q", st.EffectiveMethod)
	}

	// ICMP comes back; advance time past the retest interval so the sticky
	// re-test fires.
	probe.SetICMPDead(u.Interface, false)
	afterRetest := now.Add(wanICMPRetestInterval + time.Minute)
	monitor.probeUplink(u, afterRetest)

	st = stateFor(t, monitor, u.ID)
	if st.EffectiveMethod != model.WanProbeMethodICMP {
		t.Errorf("expected EffectiveMethod back to icmp after recovery+retest, got %q", st.EffectiveMethod)
	}
	if st.MetricQuality != model.WanMetricQualityFull {
		t.Errorf("expected MetricQuality=full after reverting to icmp, got %q", st.MetricQuality)
	}
}

// countStateEvents filters events down to the "wan-uplink-state" action so
// tests can assert on exactly how many health-state transitions were logged,
// ignoring unrelated actions (e.g. "wan-uplink-method-switch") that may share
// model.EventCategoryNetwork.
func countStateEvents(events []model.SystemEvent) int {
	n := 0
	for _, ev := range events {
		if ev.Action == "wan-uplink-state" {
			n++
		}
	}
	return n
}

// queryStateEvents reads the real event log (through the same EventLogService
// the monitor logs into, which merges still-queued/unflushed events —
// EventLogService.Query — so no explicit Flush()/Start() is needed) and
// returns how many "wan-uplink-state" events exist so far.
func queryStateEvents(t *testing.T, m *WanMonitor) int {
	t.Helper()
	events, _, err := m.eventLog.Query(model.EventCategoryNetwork, "", "", 1000, 0)
	if err != nil {
		t.Fatalf("eventLog.Query failed: %v", err)
	}
	return countStateEvents(events)
}

func TestWanMonitor_StateUnchangedDoesNotReLog(t *testing.T) {
	monitor, repo, _ := newTestWanMonitor(t)
	u := createTestUplink(t, repo, "eth-stable", model.WanProbeMethodICMP, 0)

	now := time.Now()
	for i := 0; i < 5; i++ {
		monitor.probeUplink(u, now.Add(time.Duration(i)*3*time.Second))
	}
	st := stateFor(t, monitor, u.ID)
	if st.State != model.WanStateUp {
		t.Fatalf("expected up throughout, got %q", st.State)
	}
	if st.Strikes != 0 {
		t.Errorf("expected FailStreak=0 while consistently healthy, got %d", st.Strikes)
	}

	// D-7 requires "ห้าม log ทุกรอบ" — verify against the real event log
	// (backed by the in-memory DB via EventLogService), not just RAM
	// bookkeeping: exactly one state-change event (unknown->up on round 1)
	// must exist after 5 consistently-healthy rounds.
	got := queryStateEvents(t, monitor)
	if got != 1 {
		t.Fatalf("expected exactly 1 logged state-change event after 5 unchanged rounds, got %d", got)
	}

	// Run several more still-healthy rounds and confirm the log count does
	// NOT grow — this is the actual regression the previous version of this
	// test failed to catch (it only checked FailStreak==0).
	for i := 5; i < 10; i++ {
		monitor.probeUplink(u, now.Add(time.Duration(i)*3*time.Second))
	}
	if got := queryStateEvents(t, monitor); got != 1 {
		t.Errorf("expected still exactly 1 logged state-change event after 5 more unchanged rounds (no re-log), got %d", got)
	}
}

// TestWanMonitor_ProbeErrorProducesUnknownNotDown covers the plan Task 7
// acceptance criterion "probe error (ระบบพัง) != down เป็น unknown+log": when
// the PathProbeManager call itself fails (as opposed to the target simply
// not answering), probeUplink must report "unknown" — never "down" — must
// leave FailStreak/RecoverStreak untouched, and must log the transition only
// once (not every round the error persists).
func TestWanMonitor_ProbeErrorProducesUnknownNotDown(t *testing.T) {
	monitor, repo, probe := newTestWanMonitor(t)
	u := createTestUplink(t, repo, "eth-probe-err", model.WanProbeMethodICMP, 0)

	now := time.Now()
	// Round 1: a normal healthy probe brings the uplink from the initial
	// "unknown" state to "up".
	monitor.probeUplink(u, now)
	st := stateFor(t, monitor, u.ID)
	if st.State != model.WanStateUp {
		t.Fatalf("expected up after a healthy round, got %q (reason=%q)", st.State, st.Reason)
	}
	if got := queryStateEvents(t, monitor); got != 1 {
		t.Fatalf("expected 1 logged state-change event (unknown->up), got %d", got)
	}

	// Round 2: the probe subsystem itself fails (socket/permission/interface
	// error) — must be classified "unknown", NOT "down".
	probe.SetProbeError(u.Interface, errors.New("mock probe system failure"))
	monitor.probeUplink(u, now.Add(3*time.Second))

	st = stateFor(t, monitor, u.ID)
	if st.State != model.WanStateUnknown {
		t.Fatalf("expected unknown on probe error, got %q (reason=%q)", st.State, st.Reason)
	}
	if st.Strikes != 0 {
		t.Errorf("probe error must not advance FailStreak, got %d", st.Strikes)
	}

	monitor.mu.Lock()
	rt := monitor.states[u.ID]
	failStreak, recoverStreak := rt.failStreak, rt.recoverStreak
	monitor.mu.Unlock()
	if failStreak != 0 || recoverStreak != 0 {
		t.Errorf("probe error must not touch FailStreak/RecoverStreak, got fail=%d recover=%d", failStreak, recoverStreak)
	}

	if got := queryStateEvents(t, monitor); got != 2 {
		t.Fatalf("expected 2 logged state-change events after the up->unknown transition, got %d", got)
	}

	// Rounds 3-5: the probe keeps erroring every round — must stay "unknown"
	// and must NOT log again (only once per transition into the state).
	for i := 0; i < 3; i++ {
		monitor.probeUplink(u, now.Add(time.Duration(i+2)*3*time.Second))
	}
	st = stateFor(t, monitor, u.ID)
	if st.State != model.WanStateUnknown {
		t.Fatalf("expected to remain unknown while the probe keeps erroring, got %q", st.State)
	}
	if got := queryStateEvents(t, monitor); got != 2 {
		t.Errorf("expected still exactly 2 logged state-change events (no re-log while stuck unknown), got %d", got)
	}
}

func TestWanMonitor_ProbeIntervalGating(t *testing.T) {
	monitor, repo, probe := newTestWanMonitor(t)
	u := createTestUplink(t, repo, "eth-interval", model.WanProbeMethodICMP, 0)

	now := time.Now()
	monitor.maybeProbe(u, now)
	monitor.maybeProbe(u, now.Add(time.Second)) // 1s < ProbeIntervalSeconds=2, must be skipped
	if probe.ICMPCalls[u.Interface] != 1 {
		t.Fatalf("expected only 1 probe within the interval window, got %d", probe.ICMPCalls[u.Interface])
	}
	monitor.maybeProbe(u, now.Add(3*time.Second)) // past the interval, must probe again
	if probe.ICMPCalls[u.Interface] != 2 {
		t.Errorf("expected a 2nd probe once the interval elapsed, got %d", probe.ICMPCalls[u.Interface])
	}
}

func TestWanMonitor_GetMetricsDelegatesToRing(t *testing.T) {
	monitor, repo, _ := newTestWanMonitor(t)
	u := createTestUplink(t, repo, "eth-metrics", model.WanProbeMethodICMP, 0)
	monitor.probeUplink(u, time.Now())

	points := monitor.GetMetrics(u.ID, "1h")
	if len(points) == 0 {
		t.Fatal("expected at least one metric point")
	}
}

func TestWanMonitor_TickRespectsBusPause(t *testing.T) {
	monitor, repo, probe := newTestWanMonitor(t)
	u := createTestUplink(t, repo, "eth-paused", model.WanProbeMethodICMP, 0)

	monitor.bus.Pause()
	monitor.tick(time.Now())
	if probe.ICMPCalls[u.Interface] != 0 {
		t.Errorf("expected no probes while the bus is paused, got %d calls", probe.ICMPCalls[u.Interface])
	}
	monitor.bus.Resume()
	monitor.tick(time.Now())
	if probe.ICMPCalls[u.Interface] != 1 {
		t.Errorf("expected a probe once resumed, got %d calls", probe.ICMPCalls[u.Interface])
	}
}

func TestWanMonitor_StartStopDoesNotPanic(t *testing.T) {
	monitor, repo, _ := newTestWanMonitor(t)
	createTestUplink(t, repo, "eth-lifecycle", model.WanProbeMethodICMP, 0)

	ctx, cancel := context.WithCancel(context.Background())
	monitor.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)
}
