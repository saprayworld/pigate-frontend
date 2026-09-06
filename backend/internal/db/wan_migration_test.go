package db

import (
	"testing"

	"pigate/internal/model"
)

// TestWanFailoverSettingsSeededOnFreshInstall covers the plan Task 2
// acceptance: a brand-new DB must already have the id=1 row with enabled=0
// (kill switch OFF by default) and the documented defaults for
// probe_method/probe_tcp_port-adjacent settings.
func TestWanFailoverSettingsSeededOnFreshInstall(t *testing.T) {
	rawDB, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer rawDB.Close()

	repo := NewRepository(rawDB)
	settings, err := repo.GetWanFailoverSettings()
	if err != nil {
		t.Fatalf("GetWanFailoverSettings failed: %v", err)
	}
	if settings.Enabled {
		t.Errorf("expected enabled=false (kill switch OFF) on fresh install, got true")
	}
	if settings.Mode != model.WanFailoverModeAuto {
		t.Errorf("Mode = %q, want %q", settings.Mode, model.WanFailoverModeAuto)
	}
	if settings.ManualUplinkID != "" {
		t.Errorf("ManualUplinkID = %q, want empty", settings.ManualUplinkID)
	}
	if settings.MinHoldSeconds != 60 {
		t.Errorf("MinHoldSeconds = %d, want 60", settings.MinHoldSeconds)
	}
	if settings.RevertDelaySeconds != 120 {
		t.Errorf("RevertDelaySeconds = %d, want 120", settings.RevertDelaySeconds)
	}
}

// TestMigrationIsIdempotentForWanTables simulates re-running migrate() on an
// already-migrated DB (every boot does this) — it must not fail or duplicate
// the seeded wan_failover_settings row.
func TestMigrationIsIdempotentForWanTables(t *testing.T) {
	rawDB, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer rawDB.Close()

	if err := migrate(rawDB); err != nil {
		t.Fatalf("second migrate failed (not idempotent): %v", err)
	}

	var count int
	if err := rawDB.QueryRow("SELECT COUNT(*) FROM wan_failover_settings").Scan(&count); err != nil {
		t.Fatalf("failed to count wan_failover_settings: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 wan_failover_settings row after re-migrate, got %d", count)
	}
}

// TestWanUplinkCRUD covers the full create/read/update/delete cycle,
// including that probe_targets round-trips through its comma-separated
// storage column correctly.
func TestWanUplinkCRUD(t *testing.T) {
	rawDB, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer rawDB.Close()

	repo := NewRepository(rawDB)

	input := model.WanUplinkInput{
		Name:                 "Primary",
		Interface:            "eth0",
		Priority:             1,
		ProbeTargets:         []string{"1.1.1.1", "8.8.8.8"},
		ProbeMethod:          model.WanProbeMethodAuto,
		ProbeTCPPort:         443,
		ProbeIntervalSeconds: 5,
		ProbeCount:           3,
		ProbeTimeoutMs:       1000,
		LossThresholdPct:     50,
		LatencyThresholdMs:   200,
		FailStrikes:          3,
		RecoverStrikes:       3,
		Status:               true,
		Description:          "main uplink",
	}

	created, err := repo.CreateWanUplink(input)
	if err != nil {
		t.Fatalf("CreateWanUplink failed: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected a generated ID")
	}
	if len(created.ProbeTargets) != 2 || created.ProbeTargets[0] != "1.1.1.1" || created.ProbeTargets[1] != "8.8.8.8" {
		t.Errorf("ProbeTargets = %v, want [1.1.1.1 8.8.8.8]", created.ProbeTargets)
	}
	if created.ProbeMethod != model.WanProbeMethodAuto || created.ProbeTCPPort != 443 {
		t.Errorf("expected probeMethod=auto probeTcpPort=443, got %q/%d", created.ProbeMethod, created.ProbeTCPPort)
	}

	fetched, err := repo.GetWanUplinkByID(created.ID)
	if err != nil {
		t.Fatalf("GetWanUplinkByID failed: %v", err)
	}
	if fetched == nil {
		t.Fatal("expected uplink to be found")
	}
	if fetched.Name != "Primary" {
		t.Errorf("Name = %q, want Primary", fetched.Name)
	}

	list, err := repo.GetWanUplinks()
	if err != nil {
		t.Fatalf("GetWanUplinks failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 uplink, got %d", len(list))
	}

	input.Name = "Primary Renamed"
	input.ProbeTargets = []string{"9.9.9.9"}
	updated, err := repo.UpdateWanUplink(created.ID, input)
	if err != nil {
		t.Fatalf("UpdateWanUplink failed: %v", err)
	}
	if updated.Name != "Primary Renamed" {
		t.Errorf("Name = %q, want Primary Renamed", updated.Name)
	}
	if len(updated.ProbeTargets) != 1 || updated.ProbeTargets[0] != "9.9.9.9" {
		t.Errorf("ProbeTargets after update = %v, want [9.9.9.9]", updated.ProbeTargets)
	}

	if err := repo.DeleteWanUplink(created.ID); err != nil {
		t.Fatalf("DeleteWanUplink failed: %v", err)
	}
	gone, err := repo.GetWanUplinkByID(created.ID)
	if err != nil {
		t.Fatalf("GetWanUplinkByID after delete failed: %v", err)
	}
	if gone != nil {
		t.Error("expected uplink to be gone after delete")
	}
}

// TestWanUplinkInterfaceUnique covers the UNIQUE(interface) constraint: two
// uplinks pointing at the same interface must not both be creatable.
func TestWanUplinkInterfaceUnique(t *testing.T) {
	rawDB, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer rawDB.Close()

	repo := NewRepository(rawDB)
	input := model.WanUplinkInput{
		Name: "Primary", Interface: "eth0", Priority: 1,
		ProbeTargets: []string{"1.1.1.1"}, ProbeMethod: model.WanProbeMethodICMP,
		ProbeIntervalSeconds: 5, ProbeCount: 3, ProbeTimeoutMs: 1000,
		LossThresholdPct: 50, LatencyThresholdMs: 200, FailStrikes: 3, RecoverStrikes: 3,
	}
	if _, err := repo.CreateWanUplink(input); err != nil {
		t.Fatalf("first CreateWanUplink failed: %v", err)
	}
	input.Name = "Duplicate"
	if _, err := repo.CreateWanUplink(input); err == nil {
		t.Fatal("expected second uplink on the same interface to fail (UNIQUE constraint)")
	}
}

// TestUpdateWanFailoverSettings covers the round-trip of the single-row
// settings table, including that ValidateWanFailoverSettings is enforced on
// write (a manual mode with no ManualUplinkID must be rejected).
func TestUpdateWanFailoverSettings(t *testing.T) {
	rawDB, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer rawDB.Close()

	repo := NewRepository(rawDB)

	valid := model.WanFailoverSettings{
		Enabled: true, Mode: model.WanFailoverModeManual, ManualUplinkID: "wan-1",
		MinHoldSeconds: 30, RevertDelaySeconds: 90,
	}
	if err := repo.UpdateWanFailoverSettings(valid); err != nil {
		t.Fatalf("UpdateWanFailoverSettings failed: %v", err)
	}
	got, err := repo.GetWanFailoverSettings()
	if err != nil {
		t.Fatalf("GetWanFailoverSettings failed: %v", err)
	}
	if !got.Enabled || got.Mode != model.WanFailoverModeManual || got.ManualUplinkID != "wan-1" {
		t.Errorf("unexpected settings after update: %+v", got)
	}

	invalid := model.WanFailoverSettings{Mode: model.WanFailoverModeManual, ManualUplinkID: ""}
	if err := repo.UpdateWanFailoverSettings(invalid); err == nil {
		t.Fatal("expected manual mode with empty ManualUplinkID to be rejected")
	}
}
