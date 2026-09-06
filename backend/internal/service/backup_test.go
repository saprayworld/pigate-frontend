package service

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pigate/internal/db"
	"pigate/internal/kernel"
	"pigate/internal/model"
)

// newBackupTestEnv spins up a temp-file, mock-seeded DB and a BackupService with
// no downstream services except interfaceService (re-apply for everything else
// becomes a no-op, monitor is nil), which is all the export/import DB logic
// needs. interfaceService must be real (backed by the mock kernel) because
// resolveInterfaces uses it to resolve which backup interfaces are present on
// this device (issue #89). A real file (not ":memory:") is used so pooled
// connections share one database and the pre-import snapshot path is exercised
// for real.
func newBackupTestEnv(t *testing.T) (*BackupService, *db.Repository) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "pigate-test.db")
	sqlDB, err := db.InitDB(dbPath, true)
	if err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	repo := db.NewRepository(sqlDB)
	repo.SetMockMode(true, false)
	interfaceService := NewInterfaceService(repo, kernel.NewMockNetwork())
	bs := NewBackupService(repo, dbPath, "test",
		interfaceService, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	return bs, repo
}

// newBackupTestEnvWithBlocklists is newBackupTestEnv plus a DNSBlocklistService
// wired via SetBlocklistService (docs/ref/todo/dns-blocklist-import-plan.md
// §2.4/T-09), backed by a MockDNSServerManager so nothing touches the real
// filesystem.
func newBackupTestEnvWithBlocklists(t *testing.T) (*BackupService, *db.Repository, *DNSBlocklistService, *kernel.MockDNSServerManager) {
	t.Helper()
	bs, repo := newBackupTestEnv(t)
	mgr := kernel.NewMockDNSServerManager()
	blSvc := NewDNSBlocklistService(repo, mgr)
	if err := blSvc.Load(); err != nil {
		t.Fatalf("blocklist service Load(): %v", err)
	}
	bs.SetBlocklistService(blSvc)
	return bs, repo, blSvc, mgr
}

// seedCustomConfig adds one custom object of each restorable kind on top of the
// mock seed so a backup exercises every section.
func seedCustomConfig(t *testing.T, repo *db.Repository) {
	t.Helper()
	if err := repo.CreateAddress(model.AddressObject{ID: "addr-c1", Name: "LabNet", Type: "subnet", Value: "10.10.0.0/24"}); err != nil {
		t.Fatalf("create address: %v", err)
	}
	if err := repo.CreateService(model.ServiceObject{ID: "svc-c1", Name: "Custom8080", Protocol: "TCP", Port: "8080", Type: "custom"}); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if err := repo.CreatePolicy(model.PolicyRule{
		ID: "pol-1", Name: "AllowLab", InInterface: "eth0", OutInterface: "any",
		Source: []string{"LabNet"}, Destination: []string{"ALL"}, Service: []string{"Custom8080"},
		Action: "ACCEPT", Log: true, Status: true,
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	// Gateway "default" must survive a round-trip verbatim (not resolved to an IP).
	if err := repo.CreateRoute(model.StaticRoute{
		ID: "rt-1", Destination: "10.20.0.0/24", Gateway: "default", Interface: "eth0",
		Metric: 100, Type: "customgateway", Status: true, Scope: "global", Proto: "static",
	}); err != nil {
		t.Fatalf("create route: %v", err)
	}
	if err := repo.CreateDHCPConfig(model.DhcpConfig{
		Interface: "wlan0", Enabled: true, StartIP: "192.168.5.100", EndIP: "192.168.5.200",
		Gateway: "192.168.5.1", Netmask: "255.255.255.0", DNS1: "8.8.8.8", DNS2: "1.1.1.1", LeaseTime: 3600,
		Domain: "lab.local",
	}); err != nil {
		t.Fatalf("create dhcp config: %v", err)
	}
	if err := repo.CreateDNSZone(model.DNSZone{ID: "zone-1", ZoneName: "lab.local", IsAuthoritative: true, Enabled: true}); err != nil {
		t.Fatalf("create dns zone: %v", err)
	}
	if err := repo.CreateDNSRecord(model.DNSRecord{ID: "rec-1", ZoneID: "zone-1", Name: "server", Type: "A", Value: "10.10.0.5", TTL: 300}); err != nil {
		t.Fatalf("create dns record: %v", err)
	}
	if _, err := repo.CreateQosRule(model.QosRuleInput{Name: "CapLab", Interface: "eth0", EgressRateMbps: 50, EgressCeilMbps: 100, Priority: 10, Status: true}); err != nil {
		t.Fatalf("create qos rule: %v", err)
	}
	if err := repo.CreateWifiPreset(model.WifiPreset{ID: "preset-1", Name: "HomeWifi", SSID: "MyHomeSSID", Security: "WPA2", Password: "supersecret1", MacMode: "randomized"}); err != nil {
		t.Fatalf("create wifi preset: %v", err)
	}
	if _, err := repo.CreateWanUplink(model.WanUplinkInput{
		Name: "Primary", Interface: "eth0", Priority: 1,
		ProbeTargets: []string{"1.1.1.1", "8.8.8.8"}, ProbeMethod: model.WanProbeMethodAuto, ProbeTCPPort: 443,
		ProbeIntervalSeconds: 5, ProbeCount: 3, ProbeTimeoutMs: 1000,
		LossThresholdPct: 50, LatencyThresholdMs: 200, FailStrikes: 3, RecoverStrikes: 3, Status: true,
	}); err != nil {
		t.Fatalf("create wan uplink: %v", err)
	}
}

func TestExportIncludesAllSections(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	if !strings.HasPrefix(file.Meta.Checksum, "sha256:") {
		t.Errorf("checksum missing/malformed: %q", file.Meta.Checksum)
	}
	if file.Meta.SchemaVersion != model.CurrentBackupSchemaVersion {
		t.Errorf("schemaVersion = %d, want %d", file.Meta.SchemaVersion, model.CurrentBackupSchemaVersion)
	}

	c := file.Config
	if len(c.Policies) != 1 {
		t.Errorf("policies = %d, want 1", len(c.Policies))
	}
	if len(c.QosRules) != 1 {
		t.Errorf("qosRules = %d, want 1", len(c.QosRules))
	}
	if len(c.DnsZones) != 1 || len(c.DnsZones[0].Records) != 1 {
		t.Errorf("dns zones/records not exported correctly: %+v", c.DnsZones)
	}
	// wlan0 custom config + seeded eth0 default => at least 2 DHCP configs.
	if len(c.DhcpConfigs) < 2 {
		t.Errorf("dhcpConfigs = %d, want >=2 (multi-config)", len(c.DhcpConfigs))
	}
	// Raw route must keep the "default" gateway sentinel.
	var found bool
	for _, r := range c.StaticRoutes {
		if r.ID == "rt-1" {
			found = true
			if r.Gateway != "default" {
				t.Errorf("route gateway = %q, want raw \"default\"", r.Gateway)
			}
		}
	}
	if !found {
		t.Errorf("custom route rt-1 not exported")
	}
	if len(c.Users) != 0 {
		t.Errorf("users must be excluded when includeUsers=false, got %d", len(c.Users))
	}
	if len(c.Presets) != 1 || c.Presets[0].Password != "supersecret1" {
		t.Errorf("wifi presets not exported with plaintext password: %+v", c.Presets)
	}

	withUsers, err := bs.Export(true, "", false)
	if err != nil {
		t.Fatalf("export with users: %v", err)
	}
	if len(withUsers.Config.Users) == 0 {
		t.Errorf("expected users when includeUsers=true")
	}
	if withUsers.Config.Users[0].PasswordHash == "" {
		t.Errorf("exported user must carry password hash for restore")
	}
}

func TestImportRoundTrip(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, _ := json.Marshal(file)

	// Mutate DB to prove import replaces state, not merges: drop the custom
	// policy and address ref, add a stray address that should be gone after.
	_ = repo.DeletePolicy("pol-1")
	_ = repo.CreateAddress(model.AddressObject{ID: "addr-stray", Name: "StrayNet", Type: "subnet", Value: "172.31.0.0/24"})

	res, err := bs.Import(raw, model.ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Counts["policies"] != 1 {
		t.Errorf("imported policies count = %d, want 1", res.Counts["policies"])
	}

	// Round-trip fidelity: re-export and compare canonical checksums.
	file2, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("re-export: %v", err)
	}
	sum1, _ := configChecksum(*file.Config)
	sum2, _ := configChecksum(*file2.Config)
	if sum1 != sum2 {
		t.Errorf("round-trip changed config:\n before=%s\n after =%s", sum1, sum2)
	}

	// Replace semantics: the stray address must be gone.
	addrs, _ := repo.GetAddresses()
	for _, a := range addrs {
		if a.Name == "StrayNet" {
			t.Errorf("StrayNet survived import — replace semantics violated")
		}
	}

	// Wi-Fi preset round-trip: name/ssid/security/macMode/password all restored
	// verbatim, including the plaintext password (needed so a later /apply still
	// works against the restored preset).
	presets, err := repo.GetWifiPresets()
	if err != nil {
		t.Fatalf("get wifi presets: %v", err)
	}
	if len(presets) != 1 {
		t.Fatalf("wifi presets after import = %d, want 1", len(presets))
	}
	p := presets[0]
	if p.Name != "HomeWifi" || p.SSID != "MyHomeSSID" || p.Security != "WPA2" || p.MacMode != "randomized" {
		t.Errorf("wifi preset fields not restored correctly: %+v", p)
	}
	if p.Password != "supersecret1" {
		t.Errorf("wifi preset password not restored: got %q", p.Password)
	}
	if !p.HasPassword {
		t.Errorf("wifi preset HasPassword should be true after restore")
	}
}

// TestImportRejectsInvalidWifiPreset ensures a backup carrying one broken preset
// (SSID with an embedded newline — a wpa_supplicant config-injection vector) is
// rejected in full, fail-closed: no partial write, existing presets untouched.
// Mirrors TestImportRejectsDnsmasqInjection/TestImportRejectsDhcpConfigInjection.
func TestImportRejectsInvalidWifiPreset(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	file.Config.Presets = append(file.Config.Presets, model.WifiPreset{
		ID: "preset-evil", Name: "Evil", SSID: "bad\nssid", Security: "WPA2",
	})
	sum, _ := configChecksum(*file.Config)
	file.Meta.Checksum = sum
	raw, _ := json.Marshal(file)

	beforePresets, _ := repo.GetWifiPresets()

	if _, err := bs.Import(raw, model.ImportOptions{}); err == nil {
		t.Fatalf("expected import to be rejected on invalid wifi preset")
	}

	afterPresets, _ := repo.GetWifiPresets()
	if len(afterPresets) != len(beforePresets) {
		t.Errorf("DB changed despite rejected import: presets before=%d after=%d", len(beforePresets), len(afterPresets))
	}
	for _, p := range afterPresets {
		if p.ID == "preset-evil" {
			t.Errorf("invalid preset leaked into DB")
		}
	}
}

// TestImportLegacyBackupWithoutPresets ensures a v2 backup produced before this
// feature existed (no "presets" key at all) still imports cleanly — Presets must
// stay nil/omitempty-safe and the import must not crash or reject.
func TestImportLegacyBackupWithoutPresets(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Simulate an older exporter: drop presets entirely before marshalling, as
	// if the field never existed. omitempty means Presets == nil already
	// produces no "presets" key, but clear it explicitly for clarity.
	file.Config.Presets = nil
	sum, _ := configChecksum(*file.Config)
	file.Meta.Checksum = sum
	raw, _ := json.Marshal(file)
	if strings.Contains(string(raw), `"presets"`) {
		t.Fatalf("test setup invalid: raw backup still contains a presets key: %s", raw)
	}

	res, err := bs.Import(raw, model.ImportOptions{})
	if err != nil {
		t.Fatalf("import of legacy backup without presets must succeed, got: %v", err)
	}
	if res.Counts["wifiPresets"] != 0 {
		t.Errorf("wifiPresets count = %d, want 0", res.Counts["wifiPresets"])
	}

	presets, err := repo.GetWifiPresets()
	if err != nil {
		t.Fatalf("get wifi presets: %v", err)
	}
	if len(presets) != 0 {
		t.Errorf("expected no presets after importing a legacy backup, got %d", len(presets))
	}
}

// TestImportRoundTripPreservesChain verifies chain survives an export/import
// cycle for all three chains, and that reordering after import stays scoped
// per chain (docs/ref/todo/input-output-chain-firewall-plan.md T-15).
func TestImportRoundTripPreservesChain(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo) // seeds one forward-chain policy "pol-1"

	if err := repo.CreatePolicy(model.PolicyRule{
		ID: "pol-in", Name: "AllowSSH", Chain: model.PolicyChainInput,
		Source: []string{"LabNet"}, Destination: []string{"ALL"}, Service: []string{"Custom8080"},
		Action: "ACCEPT", Status: true,
	}); err != nil {
		t.Fatalf("create input policy: %v", err)
	}
	if err := repo.CreatePolicy(model.PolicyRule{
		ID: "pol-out", Name: "BlockOut", Chain: model.PolicyChainOutput,
		Source: []string{"LabNet"}, Destination: []string{"ALL"}, Service: []string{"Custom8080"},
		Action: "DROP", Status: true,
	}); err != nil {
		t.Fatalf("create output policy: %v", err)
	}

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, _ := json.Marshal(file)

	if _, err := bs.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}

	chainByID := map[string]string{}
	all, err := repo.GetPolicies()
	if err != nil {
		t.Fatalf("get policies after import: %v", err)
	}
	for _, p := range all {
		chainByID[p.ID] = p.Chain
	}
	want := map[string]string{
		"pol-1":   model.PolicyChainForward,
		"pol-in":  model.PolicyChainInput,
		"pol-out": model.PolicyChainOutput,
	}
	for id, exp := range want {
		if chainByID[id] != exp {
			t.Errorf("policy %s: chain = %q after import, want %q", id, chainByID[id], exp)
		}
	}
}

// TestImportLegacyBackupWithoutChainNormalizesToForward simulates restoring a
// backup file exported before the input/output chain feature existed (no
// `chain` value on any policy). It must import successfully as "forward" for
// every policy, not fail the whole restore on the chain CHECK constraint
// (Caution 12).
func TestImportLegacyBackupWithoutChainNormalizesToForward(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo) // seeds policy "pol-1"

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(file.Config.Policies) != 1 {
		t.Fatalf("expected 1 seeded policy, got %d", len(file.Config.Policies))
	}
	// Simulate a pre-feature exporter: clear chain as if the field never
	// existed on this policy.
	for i := range file.Config.Policies {
		file.Config.Policies[i].Chain = ""
	}
	sum, _ := configChecksum(*file.Config)
	file.Meta.Checksum = sum
	raw, _ := json.Marshal(file)

	if _, err := bs.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import of legacy backup without chain must succeed, got: %v", err)
	}

	restored, err := repo.GetPolicyByID("pol-1")
	if err != nil || restored == nil {
		t.Fatalf("get restored policy: %v", err)
	}
	if restored.Chain != model.PolicyChainForward {
		t.Errorf("restored policy chain = %q, want %q (Caution 12 normalization)", restored.Chain, model.PolicyChainForward)
	}
}

// TestImportLegacyBackupWithoutEntriesKeyChecksumRegression is a regression
// test for T-09/T-08 (docs/ref/todo/multi-value-address-service-objects-plan.md
// Caution 1): AddressObject.Entries/ServiceObject.Entries MUST stay
// `json:"entries,omitempty"` so that a pre-multi-value (v2.x) backup file —
// which never had an "entries" key at all — still marshals to byte-identical
// JSON and its stored checksum still verifies. If anyone removes omitempty,
// a freshly-exported cfg with Entries populated would marshal differently
// than the legacy fixture below, and this test fails immediately.
func TestImportLegacyBackupWithoutEntriesKeyChecksumRegression(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Simulate a pre-multi-value exporter: clear Entries on every address and
	// service object, as if the field never existed (legacy Type/Value only).
	for i := range file.Config.Addresses {
		file.Config.Addresses[i].Entries = nil
	}
	for i := range file.Config.ServiceObjects {
		file.Config.ServiceObjects[i].Entries = nil
	}
	sum, err := configChecksum(*file.Config)
	if err != nil {
		t.Fatalf("configChecksum: %v", err)
	}
	file.Meta.Checksum = sum
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Load-bearing assertion: the "entries" key must be entirely absent from
	// the marshalled legacy fixture — this is what breaks if omitempty is
	// ever removed from AddressEntry/ServiceEntry's Entries field.
	if strings.Contains(string(raw), `"entries"`) {
		t.Fatalf("test setup invalid (or omitempty was removed from Entries): raw backup still contains an entries key: %s", raw)
	}

	res, err := bs.Import(raw, model.ImportOptions{})
	if err != nil {
		t.Fatalf("import of legacy backup without an entries key must succeed (checksum must still verify), got: %v", err)
	}
	if res.Counts["addresses"] == 0 {
		t.Errorf("expected addresses to be imported, got count 0")
	}

	// After import, every address/service must have been backfilled to
	// exactly one entry mirroring its legacy Type/Value or Protocol/Port.
	addr, err := repo.GetAddressByID("addr-c1")
	if err != nil || addr == nil {
		t.Fatalf("get imported address: %v", err)
	}
	if len(addr.Entries) != 1 || addr.Entries[0].Type != "subnet" || addr.Entries[0].Value != "10.10.0.0/24" {
		t.Errorf("expected addr-c1 backfilled to a single subnet entry, got %+v", addr.Entries)
	}

	svc, err := repo.GetServiceByID("svc-c1")
	if err != nil || svc == nil {
		t.Fatalf("get imported service: %v", err)
	}
	if len(svc.Entries) != 1 || svc.Entries[0].Protocol != "TCP" || svc.Entries[0].Port != "8080" {
		t.Errorf("expected svc-c1 backfilled to a single TCP/8080 entry, got %+v", svc.Entries)
	}
}

// TestImportRoundTripMultiEntryObjects covers the multi-value round-trip
// case: an object with several entries must export/import with every entry
// intact, in order, and the checksum must still verify since Entries IS
// populated on this file (mirrors TestImportRoundTrip's pattern).
func TestImportRoundTripMultiEntryObjects(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	if err := repo.CreateAddress(model.AddressObject{
		ID:   "addr-multi",
		Name: "MultiBranch",
		Entries: []model.AddressEntry{
			{Type: "subnet", Value: "10.30.0.0/24"},
			{Type: "subnet", Value: "10.30.1.0/24"},
			{Type: "range", Value: "10.30.2.1-10.30.2.20"},
		},
	}); err != nil {
		t.Fatalf("create multi-entry address: %v", err)
	}
	if err := repo.CreateService(model.ServiceObject{
		ID:   "svc-multi",
		Name: "MultiWeb",
		Type: "custom",
		Entries: []model.ServiceEntry{
			{Protocol: "TCP", Port: "80"},
			{Protocol: "TCP", Port: "443"},
		},
	}); err != nil {
		t.Fatalf("create multi-entry service: %v", err)
	}

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"entries"`) {
		t.Fatalf("test setup invalid: expected an entries key for the multi-entry objects in %s", raw)
	}

	// Wipe and re-import into a fresh DB to prove entries round-trip.
	bs2, repo2 := newBackupTestEnv(t)
	if _, err := bs2.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import of multi-entry objects failed: %v", err)
	}

	addr, err := repo2.GetAddressByID("addr-multi")
	if err != nil || addr == nil {
		t.Fatalf("get imported multi-entry address: %v", err)
	}
	wantAddrValues := []string{"10.30.0.0/24", "10.30.1.0/24", "10.30.2.1-10.30.2.20"}
	if len(addr.Entries) != len(wantAddrValues) {
		t.Fatalf("expected %d entries, got %d: %+v", len(wantAddrValues), len(addr.Entries), addr.Entries)
	}
	for i, want := range wantAddrValues {
		if addr.Entries[i].Value != want {
			t.Errorf("entry[%d]: expected %q, got %q", i, want, addr.Entries[i].Value)
		}
	}

	svc, err := repo2.GetServiceByID("svc-multi")
	if err != nil || svc == nil {
		t.Fatalf("get imported multi-entry service: %v", err)
	}
	if len(svc.Entries) != 2 || svc.Entries[0].Port != "80" || svc.Entries[1].Port != "443" {
		t.Fatalf("expected 2 entries (80, 443) in order, got %+v", svc.Entries)
	}
}

func TestImportChecksumMismatchRejected(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	file.Meta.Checksum = "sha256:deadbeef"
	raw, _ := json.Marshal(file)

	before, _ := repo.GetAddresses()

	if _, err := bs.Import(raw, model.ImportOptions{}); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("expected checksum error, got %v", err)
	}

	after, _ := repo.GetAddresses()
	if len(after) != len(before) {
		t.Errorf("DB changed on a rejected import: before=%d after=%d", len(before), len(after))
	}
}

func TestImportConstraintViolationRollsBack(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Inject a value that passes structural validation but violates the SQLite
	// CHECK on address type, so the failure happens mid-transaction.
	file.Config.Addresses = append(file.Config.Addresses, model.AddressObject{
		ID: "addr-bad", Name: "BadType", Type: "bogus", Value: "x",
	})
	sum, _ := configChecksum(*file.Config)
	file.Meta.Checksum = sum
	raw, _ := json.Marshal(file)

	beforePolicies, _ := repo.GetPolicies()

	if _, err := bs.Import(raw, model.ImportOptions{}); err == nil {
		t.Fatalf("expected restore to fail on bad address type")
	}

	// Transaction must have rolled back: original policy still intact, bad
	// address absent.
	afterPolicies, _ := repo.GetPolicies()
	if len(afterPolicies) != len(beforePolicies) {
		t.Errorf("rollback failed: policies before=%d after=%d", len(beforePolicies), len(afterPolicies))
	}
	addrs, _ := repo.GetAddresses()
	for _, a := range addrs {
		if a.Name == "BadType" {
			t.Errorf("bad address leaked despite rollback")
		}
	}
}

// TestImportRejectsDnsmasqInjection ensures a crafted backup carrying a DNS
// record value with an embedded newline (a dnsmasq directive injection) is
// rejected before any DB mutation — the import path bypasses the create/update
// handlers, so validation must also live in the import flow.
func TestImportRejectsDnsmasqInjection(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	file.Config.DnsZones = append(file.Config.DnsZones, model.DNSZone{
		ID: "zone-evil", ZoneName: "evil.local", IsAuthoritative: true, Enabled: true,
		Records: []model.DNSRecord{
			{ID: "rec-evil", ZoneID: "zone-evil", Name: "www", Type: "A",
				Value: "1.2.3.4\naddress=/evil/6.6.6.6"},
		},
	})
	sum, _ := configChecksum(*file.Config)
	file.Meta.Checksum = sum
	raw, _ := json.Marshal(file)

	beforeZones, _ := repo.GetDNSZones()

	if _, err := bs.Import(raw, model.ImportOptions{}); err == nil {
		t.Fatalf("expected import to be rejected on injected DNS record")
	}

	afterZones, _ := repo.GetDNSZones()
	if len(afterZones) != len(beforeZones) {
		t.Errorf("DB changed despite rejected import: zones before=%d after=%d", len(beforeZones), len(afterZones))
	}
	for _, z := range afterZones {
		if z.ID == "zone-evil" {
			t.Errorf("injected zone leaked into DB")
		}
	}
}

// TestImportRejectsDhcpConfigInjection ensures a crafted backup carrying a DHCP
// scope with an embedded newline in an IP field (a dnsmasq directive injection)
// is rejected before any DB mutation — mirroring the DNS-record guard above but
// for the DhcpConfig path, which previously had no import-time validation.
func TestImportRejectsDhcpConfigInjection(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	file.Config.DhcpConfigs = append(file.Config.DhcpConfigs, model.DhcpConfig{
		ID: "dhcp-evil", Enabled: true, Interface: "eth0",
		StartIP: "192.168.1.10\naddress=/evil/6.6.6.6", EndIP: "192.168.1.200",
	})
	sum, _ := configChecksum(*file.Config)
	file.Meta.Checksum = sum
	raw, _ := json.Marshal(file)

	beforeCfgs, _ := repo.GetDHCPConfigs()

	if _, err := bs.Import(raw, model.ImportOptions{}); err == nil {
		t.Fatalf("expected import to be rejected on injected DHCP config")
	}

	afterCfgs, _ := repo.GetDHCPConfigs()
	if len(afterCfgs) != len(beforeCfgs) {
		t.Errorf("DB changed despite rejected import: dhcp configs before=%d after=%d", len(beforeCfgs), len(afterCfgs))
	}
	for _, c := range afterCfgs {
		if c.ID == "dhcp-evil" {
			t.Errorf("injected DHCP config leaked into DB")
		}
	}
}

// TestImportRejectsPolicyInterfacesOverCap ensures a crafted (or foreign,
// higher-cap) backup carrying a policy rule whose InInterfaces/OutInterfaces
// exceed max-policy-interfaces-per-direction is rejected before any DB
// mutation — RestoreConfig writes policy_interfaces directly, bypassing
// CreatePolicy/UpdatePolicy's cap enforcement entirely, so the cap must also
// be enforced inside RestoreConfig itself (docs/ref/todo/
// multi-interface-firewall-rule-plan.md §2.2, Caution 7). Without this check,
// an unbounded interface count expands into an unbounded in x out cartesian
// product in kernel/real_firewall.go's buildRuleExpressions before the
// max-expanded-rules-per-policy cap is even checked — a memory/CPU DoS at
// apply time (QA finding, Critical).
func TestImportRejectsPolicyInterfacesOverCap(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// Default cap is model.DefaultMaxPolicyInterfacesPerDirection (8) — this
	// test env never calls repo.SetPolicyInterfaceLimit, so 8 applies. Seed
	// 20 distinct in-interfaces, well over the cap.
	overCapIfaces := make([]string, 20)
	for i := range overCapIfaces {
		overCapIfaces[i] = fmt.Sprintf("eth%d", i)
	}
	file.Config.Policies = append(file.Config.Policies, model.PolicyRule{
		ID: "pol-overcap", Name: "OverCapIfaces", Chain: "forward",
		InInterfaces: overCapIfaces, OutInterfaces: []string{"ALL"},
		Source: []string{"ALL"}, Destination: []string{"ALL"}, Service: []string{"ALL"},
		Action: "ACCEPT", Status: true,
	})
	sum, _ := configChecksum(*file.Config)
	file.Meta.Checksum = sum
	raw, _ := json.Marshal(file)

	beforePolicies, _ := repo.GetPolicies()

	if _, err := bs.Import(raw, model.ImportOptions{}); err == nil {
		t.Fatalf("expected import to be rejected: policy interfaces exceed the configured cap")
	}

	// Transaction must have rolled back entirely: no new policy, and no
	// policy_interfaces rows for the rejected policy.
	afterPolicies, _ := repo.GetPolicies()
	if len(afterPolicies) != len(beforePolicies) {
		t.Errorf("rollback failed: policies before=%d after=%d", len(beforePolicies), len(afterPolicies))
	}
	for _, p := range afterPolicies {
		if p.ID == "pol-overcap" {
			t.Errorf("over-cap policy leaked into DB despite rejected import")
		}
	}
}

func TestImportLegacyV1(t *testing.T) {
	bs, repo := newBackupTestEnv(t)

	v1 := `{
		"device": "PiGate Firewall Gateway",
		"version": "v1.0.0-Release",
		"exportedAt": "2026-01-01T00:00:00Z",
		"systemSettings": {"timezone": "Asia/Bangkok (GMT+7:00)", "ntpSync": true, "ntpServer": "pool.ntp.org"},
		"hostnameSettings": {"hostname": "old-box", "shareWithDhcp": false},
		"config": {
			"addresses": [{"id":"addr-v1","name":"V1Net","type":"subnet","value":"10.99.0.0/24","system":false}],
			"serviceObjects": [],
			"policies": [],
			"routes": [
				{"id":"route-sys-ghost","destination":"0.0.0.0/0","gateway":"192.168.1.1","interface":"eth0","type":"system","status":true},
				{"id":"rt-v1","destination":"10.50.0.0/24","gateway":"default","interface":"eth0","type":"customgateway","status":true}
			],
			"interfaces": [],
			"dhcp": {"config": {"interface":"eth0","enabled":true,"startIp":"192.168.9.10","endIp":"192.168.9.99","gateway":"192.168.9.1","netmask":"255.255.255.0","dns1":"8.8.8.8","dns2":"1.1.1.1","leaseTime":3600}, "reservations": []}
		}
	}`

	res, err := bs.Import([]byte(v1), model.ImportOptions{})
	if err != nil {
		t.Fatalf("import v1: %v", err)
	}
	if res.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", res.SchemaVersion)
	}

	addrs, _ := repo.GetAddresses()
	var haveV1 bool
	for _, a := range addrs {
		if a.Name == "V1Net" {
			haveV1 = true
		}
	}
	if !haveV1 {
		t.Errorf("v1 custom address not restored")
	}

	// Ghost system route must have been dropped by the mapper.
	routes, _ := repo.GetRawStaticRoutes()
	for _, r := range routes {
		if r.ID == "route-sys-ghost" {
			t.Errorf("v1 ghost/system route should not be restored")
		}
	}

	// Legacy display timezone must be normalized to a bare IANA name.
	tz, _ := repo.GetSystemTimeSettings()
	if tz.Timezone != "Asia/Bangkok" {
		t.Errorf("timezone = %q, want normalized Asia/Bangkok", tz.Timezone)
	}
}

func TestExportImportEncryptedRoundTrip(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	const pass = "correct horse battery staple"
	file, err := bs.Export(false, pass, false)
	if err != nil {
		t.Fatalf("encrypted export: %v", err)
	}
	if !file.Meta.Encrypted || file.EncryptedConfig == "" || file.Config != nil {
		t.Fatalf("expected encrypted file with no plaintext config: encrypted=%v cfgNil=%v", file.Meta.Encrypted, file.Config == nil)
	}
	if file.Meta.Encryption == nil || file.Meta.Encryption.Algorithm != "AES-256-GCM" {
		t.Fatalf("missing/incorrect encryption params: %+v", file.Meta.Encryption)
	}
	raw, _ := json.Marshal(file)

	// The ciphertext must not leak a known plaintext token.
	if strings.Contains(string(raw), "LabNet") {
		t.Errorf("plaintext object name leaked into encrypted file")
	}

	// No passphrase → specific ErrPassphraseRequired.
	if _, err := bs.Import(raw, model.ImportOptions{}); err == nil {
		t.Errorf("expected error importing encrypted file without passphrase")
	}

	// Wrong passphrase → generic failure, DB untouched.
	before, _ := repo.GetAddresses()
	if _, err := bs.Import(raw, model.ImportOptions{Passphrase: "wrong"}); err == nil {
		t.Errorf("expected error with wrong passphrase")
	}
	after, _ := repo.GetAddresses()
	if len(after) != len(before) {
		t.Errorf("DB changed on failed decrypt")
	}

	// Correct passphrase → restores successfully.
	res, err := bs.Import(raw, model.ImportOptions{Passphrase: pass})
	if err != nil {
		t.Fatalf("import with correct passphrase: %v", err)
	}
	if res.Counts["policies"] != 1 {
		t.Errorf("policies restored = %d, want 1", res.Counts["policies"])
	}
}

func TestImportUsersActorGuardAndSessionPurge(t *testing.T) {
	bs, repo := newBackupTestEnv(t)

	// A user that exists now but won't be in the backup — must be reported for
	// session purge after the wipe+restore.
	if err := repo.CreateUser(model.User{ID: "u-ghost", Username: "ghost", PasswordHash: "x", Role: "admin_readonly", Status: "active"}); err != nil {
		t.Fatalf("create ghost: %v", err)
	}

	file, err := bs.Export(true, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// Simulate a hostile/careless backup: drop ghost and disable the actor.
	kept := file.Config.Users[:0]
	for _, u := range file.Config.Users {
		if u.Username == "ghost" {
			continue
		}
		if u.Username == "pigate" {
			u.Status = "disabled" // would lock the operator out
		}
		kept = append(kept, u)
	}
	file.Config.Users = kept
	sum, _ := configChecksum(*file.Config)
	file.Meta.Checksum = sum
	raw, _ := json.Marshal(file)

	res, err := bs.Import(raw, model.ImportOptions{IncludeUsers: true, ActorUsername: "pigate", ActorUserID: "user-pigate"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !res.UsersImported {
		t.Errorf("UsersImported should be true")
	}

	// Actor must remain an active super_admin despite the backup disabling them.
	actor, _ := repo.GetUserByUsername("pigate")
	if actor == nil || actor.Status != "active" || actor.Role != "super_admin" {
		t.Errorf("actor not preserved as active super_admin: %+v", actor)
	}

	// ghost was removed by the import → flagged for session purge.
	var ghostPurged bool
	for _, u := range res.RemovedUsernames {
		if u == "ghost" {
			ghostPurged = true
		}
	}
	if !ghostPurged {
		t.Errorf("removed user 'ghost' not reported for session purge: %v", res.RemovedUsernames)
	}
}

func TestImportSkipsUnknownInterface(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Rename one interface to a name that doesn't exist on this device.
	for i := range file.Config.Interfaces {
		if file.Config.Interfaces[i].Name == "eth0" {
			file.Config.Interfaces[i].Name = "eth99"
		}
	}
	sum, _ := configChecksum(*file.Config)
	file.Meta.Checksum = sum
	raw, _ := json.Marshal(file)

	res, err := bs.Import(raw, model.ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	var warned bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "eth99") && strings.Contains(w, "skipped") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected skip warning for eth99, got warnings: %v", res.Warnings)
	}
	// eth99 must not have been created.
	ifaces, _ := repo.GetInterfaces()
	for _, i := range ifaces {
		if i.Name == "eth99" {
			t.Errorf("phantom interface eth99 was created")
		}
	}
}

// A VLAN row in a backup must survive import even though the VLAN link is not
// present on the device (it only comes back when re-created at reapply). Its parent
// must exist; an orphan VLAN (missing parent) is skipped with a warning. (issue #20)
func TestImportKeepsVlanRow(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	parent := "eth0" // present in the mock-seeded DB
	vid := 100
	orphanParent := "ethX" // not present
	ovid := 200
	file.Config.Interfaces = append(file.Config.Interfaces,
		model.NetworkInterface{
			ID: "iface-eth0.100", Name: "eth0.100", Alias: "vlan100", Role: "LAN",
			Type: "ethernet", Subtype: "vlan", AddressingMode: "dhcp", IP: "0.0.0.0",
			Netmask: "24", Gateway: "", MacAddress: "aa:bb:cc:dd:ee:ff", Status: "up",
			Speed: "1000 Mbps", AdminAccess: []string{"PING"}, VlanParent: &parent, VlanID: &vid,
		},
		model.NetworkInterface{
			ID: "iface-ethX.200", Name: "ethX.200", Alias: "vlanOrphan", Role: "LAN",
			Type: "ethernet", Subtype: "vlan", AddressingMode: "dhcp", IP: "0.0.0.0",
			Netmask: "24", Gateway: "", MacAddress: "aa:bb:cc:dd:ee:00", Status: "up",
			Speed: "1000 Mbps", AdminAccess: []string{"PING"}, VlanParent: &orphanParent, VlanID: &ovid,
		},
	)
	sum, _ := configChecksum(*file.Config)
	file.Meta.Checksum = sum
	raw, _ := json.Marshal(file)

	res, err := bs.Import(raw, model.ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	ifaces, _ := repo.GetInterfaces()
	byName := map[string]model.NetworkInterface{}
	for _, i := range ifaces {
		byName[i.Name] = i
	}
	kept, ok := byName["eth0.100"]
	if !ok {
		t.Fatalf("VLAN eth0.100 was dropped during import")
	}
	if kept.VlanParent == nil || *kept.VlanParent != "eth0" || kept.VlanID == nil || *kept.VlanID != 100 {
		t.Errorf("VLAN metadata not preserved: %+v", kept)
	}
	if _, present := byName["ethX.200"]; present {
		t.Errorf("orphan VLAN ethX.200 (missing parent) should not have been restored")
	}
	var warned bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "ethX.200") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected a skip warning for orphan VLAN ethX.200, got: %v", res.Warnings)
	}
}

// TestRestoreConfigRecreatesDeletedInterfaceRow covers issue #89: eth1 is
// hardcoded as physically present in the mock kernel (see GetKernelInterfaces)
// but, unlike eth0/wlan0, has no seeded DB row — exactly the "unmanaged
// interface" shape the bug report described. This seeds a DB row for it with
// a distinct config, backs it up, deletes the row to simulate the
// unmanaged/DB-lost state, then restores from that same backup and asserts
// the row is recreated with the backup's values on the very first import
// (T-02/T-03), not skipped as "not present on this device".
func TestRestoreConfigRecreatesDeletedInterfaceRow(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	const ifaceID = "iface-eth1"
	if err := repo.CreateInterfaceForTest(model.NetworkInterface{
		ID: ifaceID, Name: "eth1", Alias: "eth1_custom", Role: "LAN",
		Type: "ethernet", Subtype: "device", AddressingMode: "static",
		IP: "10.9.9.9", Netmask: "24", Gateway: "10.9.9.1",
		MacAddress: "DC:A6:32:AA:BB:C3", AdminAccess: []string{"PING"},
		Status: "up", Speed: "100 Mbps",
	}); err != nil {
		t.Fatalf("seed eth1: %v", err)
	}

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, _ := json.Marshal(file)

	// Simulate the "unmanaged" state: DB row gone, device still present
	// (the mock kernel's eth1 entry is hardcoded, independent of the DB).
	if err := repo.DeleteInterface(ifaceID); err != nil {
		t.Fatalf("delete eth1 row: %v", err)
	}

	res, err := bs.Import(raw, model.ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	restored, err := repo.GetInterfaceByID(ifaceID)
	if err != nil {
		t.Fatalf("get interface by id: %v", err)
	}
	if restored == nil {
		t.Fatalf("eth1 row was not recreated on restore")
	}
	if restored.Alias != "eth1_custom" || restored.AddressingMode != "static" || restored.IP != "10.9.9.9" {
		t.Errorf("restored eth1 does not match backup values: %+v", restored)
	}

	for _, w := range res.Warnings {
		if strings.Contains(w, "eth1") {
			t.Errorf("eth1 unexpectedly reported in warnings: %q", w)
		}
	}
}

// A backup carrying duplicate (or name-colliding) aliases must not abort the
// restore: the unique alias index would fail the single restore transaction, so
// resolveInterfaces de-duplicates them up front with a warning. (issue #25)
func TestImportDedupsConflictingAliases(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Corrupt the backup: give both interfaces the same alias (different case).
	for i := range file.Config.Interfaces {
		switch file.Config.Interfaces[i].Name {
		case "eth0":
			file.Config.Interfaces[i].Alias = "Shared_Label"
		case "wlan0":
			file.Config.Interfaces[i].Alias = "shared_label"
		}
	}
	sum, _ := configChecksum(*file.Config)
	file.Meta.Checksum = sum
	raw, _ := json.Marshal(file)

	res, err := bs.Import(raw, model.ImportOptions{})
	if err != nil {
		t.Fatalf("import with duplicate aliases must not fail, got: %v", err)
	}

	var warned bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "alias") && strings.Contains(w, "shared_label") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected an alias-dedup warning, got warnings: %v", res.Warnings)
	}

	ifaces, err := repo.GetInterfaces()
	if err != nil {
		t.Fatalf("get interfaces: %v", err)
	}
	seen := map[string]string{}
	for _, i := range ifaces {
		lower := strings.ToLower(i.Alias)
		if prev, dup := seen[lower]; dup {
			t.Errorf("aliases still duplicated after import: %s and %s share %q", prev, i.Name, i.Alias)
		}
		seen[lower] = i.Name
	}
}

// TestImportLegacyDNSServerSettingsBackupUsesDefaultCacheLimits is
// docs/ref/todo/statistics-dns-top-domain-plan.md T-11 item 13: a backup
// file predating the DNS Statistics fields (TTL/cap unmarshal to their Go
// zero value, 0) must restore to the package defaults (60/4096), never 0
// (0 would silently disable the reverse cache).
func TestImportLegacyDNSServerSettingsBackupUsesDefaultCacheLimits(t *testing.T) {
	bs, repo := newBackupTestEnv(t)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Simulate a pre-feature backup file: TTL/cap fields never existed, so
	// they unmarshal as the Go zero value (0), not the seeded defaults.
	file.Config.DnsServerSettings.DNSCacheTTLMinutes = 0
	file.Config.DnsServerSettings.DNSCacheMaxEntries = 0
	file.Config.DnsServerSettings.QueryLogging = false
	file.Config.DnsServerSettings.Interfaces = []string{"eth0"}
	sum, err := configChecksum(*file.Config)
	if err != nil {
		t.Fatalf("checksum: %v", err)
	}
	file.Meta.Checksum = sum
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := bs.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}

	settings, err := repo.GetDNSServerSettings()
	if err != nil {
		t.Fatalf("GetDNSServerSettings: %v", err)
	}
	if settings.DNSCacheTTLMinutes != model.DNSCacheTTLDefault {
		t.Errorf("DNSCacheTTLMinutes = %d, want default %d (not 0)", settings.DNSCacheTTLMinutes, model.DNSCacheTTLDefault)
	}
	if settings.DNSCacheMaxEntries != model.DNSCacheEntriesDefault {
		t.Errorf("DNSCacheMaxEntries = %d, want default %d (not 0)", settings.DNSCacheMaxEntries, model.DNSCacheEntriesDefault)
	}
	if len(settings.Interfaces) != 1 || settings.Interfaces[0] != "eth0" {
		t.Errorf("Interfaces = %v, want [eth0]", settings.Interfaces)
	}
}

// TestImportPreservesCustomDNSCacheLimits round-trips a non-default TTL/cap
// through export -> import and confirms the custom values survive (plan
// Final Acceptance "Backup -> Restore ไฟล์ที่มีค่า custom").
func TestImportPreservesCustomDNSCacheLimits(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	if err := repo.SetDNSServerSettings(true, 30, 8192, model.DNSUpstreamModeSystem, nil); err != nil {
		t.Fatalf("seed custom dns server settings: %v", err)
	}

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if file.Config.DnsServerSettings.DNSCacheTTLMinutes != 30 || file.Config.DnsServerSettings.DNSCacheMaxEntries != 8192 || !file.Config.DnsServerSettings.QueryLogging {
		t.Fatalf("export did not capture custom dns server settings: %+v", file.Config.DnsServerSettings)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Change the live DB away from the custom values before import, so the
	// assertion below actually proves import restored them (rather than
	// them having never changed).
	if err := repo.SetDNSServerSettings(false, 60, 4096, model.DNSUpstreamModeSystem, nil); err != nil {
		t.Fatalf("reset dns server settings: %v", err)
	}

	if _, err := bs.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}

	settings, err := repo.GetDNSServerSettings()
	if err != nil {
		t.Fatalf("GetDNSServerSettings: %v", err)
	}
	if settings.DNSCacheTTLMinutes != 30 {
		t.Errorf("DNSCacheTTLMinutes = %d, want 30", settings.DNSCacheTTLMinutes)
	}
	if settings.DNSCacheMaxEntries != 8192 {
		t.Errorf("DNSCacheMaxEntries = %d, want 8192", settings.DNSCacheMaxEntries)
	}
	if !settings.QueryLogging {
		t.Errorf("QueryLogging = false, want true")
	}
}

// TestImportPreservesCustomUpstreamSettings is T-08 item 6(a) (docs/ref/todo/
// dns-server-settings-tab-and-upstream-plan.md): a backup file carrying a
// "custom" upstream mode with 2 IPs must round-trip through export -> import
// with both the mode and the exact IP list intact.
func TestImportPreservesCustomUpstreamSettings(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	if err := repo.SetDNSServerSettings(false, model.DNSCacheTTLDefault, model.DNSCacheEntriesDefault, model.DNSUpstreamModeCustom, []string{"1.1.1.1", "9.9.9.9"}); err != nil {
		t.Fatalf("seed custom upstream settings: %v", err)
	}

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if file.Config.DnsServerSettings.UpstreamMode != model.DNSUpstreamModeCustom {
		t.Fatalf("export did not capture upstream mode: %+v", file.Config.DnsServerSettings)
	}
	if len(file.Config.DnsServerSettings.UpstreamServers) != 2 {
		t.Fatalf("export did not capture upstream servers: %+v", file.Config.DnsServerSettings)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Change the live DB away from the custom values before import, so the
	// assertion below actually proves import restored them.
	if err := repo.SetDNSServerSettings(false, model.DNSCacheTTLDefault, model.DNSCacheEntriesDefault, model.DNSUpstreamModeSystem, nil); err != nil {
		t.Fatalf("reset dns server settings: %v", err)
	}

	if _, err := bs.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}

	settings, err := repo.GetDNSServerSettings()
	if err != nil {
		t.Fatalf("GetDNSServerSettings: %v", err)
	}
	if settings.UpstreamMode != model.DNSUpstreamModeCustom {
		t.Errorf("UpstreamMode = %q, want %q", settings.UpstreamMode, model.DNSUpstreamModeCustom)
	}
	if len(settings.UpstreamServers) != 2 || settings.UpstreamServers[0] != "1.1.1.1" || settings.UpstreamServers[1] != "9.9.9.9" {
		t.Errorf("UpstreamServers = %v, want [1.1.1.1 9.9.9.9]", settings.UpstreamServers)
	}
}

// TestImportLegacyDNSServerSettingsBackupDefaultsUpstreamToSystem is T-08
// item 6(b): a backup file predating upstreamMode/upstreamServers (they
// unmarshal to their Go zero values — "" and nil) must restore to
// UpstreamMode="system" and an empty UpstreamServers list, without erroring
// or panicking (plan §5 item 8: "" must never be treated as a recognized
// mode).
func TestImportLegacyDNSServerSettingsBackupDefaultsUpstreamToSystem(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	// Start from a non-default upstream so the assertions below actually
	// prove the import reset it, rather than it having never changed.
	if err := repo.SetDNSServerSettings(false, model.DNSCacheTTLDefault, model.DNSCacheEntriesDefault, model.DNSUpstreamModeCustom, []string{"1.1.1.1"}); err != nil {
		t.Fatalf("seed pre-import upstream settings: %v", err)
	}

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Simulate a pre-feature backup file: upstreamMode/upstreamServers never
	// existed, so they unmarshal as the Go zero value ("" and nil).
	file.Config.DnsServerSettings.UpstreamMode = ""
	file.Config.DnsServerSettings.UpstreamServers = nil
	file.Config.DnsServerSettings.Interfaces = []string{"eth0"}
	sum, err := configChecksum(*file.Config)
	if err != nil {
		t.Fatalf("checksum: %v", err)
	}
	file.Meta.Checksum = sum
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := bs.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}

	settings, err := repo.GetDNSServerSettings()
	if err != nil {
		t.Fatalf("GetDNSServerSettings: %v", err)
	}
	if settings.UpstreamMode != model.DNSUpstreamModeSystem {
		t.Errorf("UpstreamMode = %q, want %q (not empty)", settings.UpstreamMode, model.DNSUpstreamModeSystem)
	}
	if len(settings.UpstreamServers) != 0 {
		t.Errorf("UpstreamServers = %v, want empty", settings.UpstreamServers)
	}
}

// TestExportImportRoundTripsMonitoredField covers T-12 (docs/ref/todo/
// fqdn-retry-and-monitored-counters-plan.md, issue #141): exporting a
// monitored policy must carry the flag, and importing it must restore
// monitored=true (round-trip, not just marshal-level).
func TestExportImportRoundTripsMonitoredField(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)
	if err := repo.SetPolicyMonitored("pol-1", true); err != nil {
		t.Fatalf("SetPolicyMonitored: %v", err)
	}

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var found bool
	for _, p := range file.Config.Policies {
		if p.ID == "pol-1" {
			found = true
			if !p.Monitored {
				t.Fatalf("expected exported pol-1 to have monitored=true")
			}
		}
	}
	if !found {
		t.Fatalf("pol-1 not found in export")
	}

	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := bs.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}

	imported, err := repo.GetPolicyByID("pol-1")
	if err != nil || imported == nil {
		t.Fatalf("get imported policy: %v", err)
	}
	if !imported.Monitored {
		t.Fatalf("expected imported pol-1 to have monitored=true")
	}

	monitoredIDs, err := repo.GetMonitoredPolicyIDs()
	if err != nil {
		t.Fatalf("GetMonitoredPolicyIDs: %v", err)
	}
	if !monitoredIDs["pol-1"] {
		t.Fatalf("expected pol-1 to be in GetMonitoredPolicyIDs after import")
	}
	counters, err := repo.GetPolicyRuleCounters()
	if err != nil {
		t.Fatalf("GetPolicyRuleCounters: %v", err)
	}
	var hasRow bool
	for _, c := range counters {
		if c.RuleID == "pol-1" {
			hasRow = true
		}
	}
	if !hasRow {
		t.Fatalf("expected a fresh policy_rule_counters row for pol-1 after import, got %+v", counters)
	}
}

// TestImportLegacyBackupWithoutMonitoredKeyChecksumRegression mirrors
// TestImportLegacyBackupWithoutEntriesKeyChecksumRegression: a backup file
// that predates the `monitored` field (issue #141) must still import
// successfully (checksum must still verify) and every policy must decode as
// monitored=false.
func TestImportLegacyBackupWithoutMonitoredKeyChecksumRegression(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	sum, err := configChecksum(*file.Config)
	if err != nil {
		t.Fatalf("configChecksum: %v", err)
	}
	file.Meta.Checksum = sum
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Load-bearing assertion: a policy with monitored=false (every policy in
	// this fixture, since none were toggled) must marshal WITHOUT a
	// "monitored" key at all — this is what breaks if omitempty is ever
	// removed from PolicyRule.Monitored.
	if strings.Contains(string(raw), `"monitored"`) {
		t.Fatalf("test setup invalid (or omitempty was removed from PolicyRule.Monitored): raw backup still contains a monitored key: %s", raw)
	}

	res, err := bs.Import(raw, model.ImportOptions{})
	if err != nil {
		t.Fatalf("import of legacy backup without a monitored key must succeed (checksum must still verify), got: %v", err)
	}
	if res.Counts["policies"] == 0 {
		t.Errorf("expected policies to be imported, got count 0")
	}

	imported, err := repo.GetPolicyByID("pol-1")
	if err != nil || imported == nil {
		t.Fatalf("get imported policy: %v", err)
	}
	if imported.Monitored {
		t.Errorf("expected legacy-imported pol-1 to default monitored=false")
	}
	monitoredIDs, err := repo.GetMonitoredPolicyIDs()
	if err != nil {
		t.Fatalf("GetMonitoredPolicyIDs: %v", err)
	}
	if len(monitoredIDs) != 0 {
		t.Fatalf("expected no monitored policies after a legacy import, got %v", monitoredIDs)
	}
}

// TestImportDoesNotExportCounterTable asserts policy_rule_counters itself is
// never part of the exported/imported config shape (Caution 7) — this is a
// compile-time-adjacent check: model.BackupConfig has no field for it, so
// this test just documents/locks in the invariant by asserting the export
// JSON never contains the table's column names as a top-level backup key.
func TestImportDoesNotExportCounterTable(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)
	if err := repo.SetPolicyMonitored("pol-1", true); err != nil {
		t.Fatalf("SetPolicyMonitored: %v", err)
	}
	if err := repo.AddPolicyRuleCounterDeltas(map[string]model.RuleCounter{"pol-1": {Bytes: 12345, Packets: 10}}); err != nil {
		t.Fatalf("AddPolicyRuleCounterDeltas: %v", err)
	}

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "12345") {
		t.Fatalf("expected the runtime counter value to NEVER appear in the exported backup, got: %s", raw)
	}
}

// TestBackupService_SetCounterStoreReloadsAfterImport asserts Import calls
// PolicyCounterStore.Reload() after a successful restore, so the RAM cache
// reflects the DB's post-import state instead of stale pre-import values.
func TestBackupService_SetCounterStoreReloadsAfterImport(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)
	if err := repo.SetPolicyMonitored("pol-1", true); err != nil {
		t.Fatalf("SetPolicyMonitored: %v", err)
	}
	if err := repo.AddPolicyRuleCounterDeltas(map[string]model.RuleCounter{"pol-1": {Bytes: 500, Packets: 5}}); err != nil {
		t.Fatalf("AddPolicyRuleCounterDeltas: %v", err)
	}

	acct := &fakeTrafficAccounting{}
	ts := NewTrafficStatsService(acct, repo, &fakeDhcpForTraffic{}, kernel.NewMockSystemStats(), 0, 0, 0)
	store := NewPolicyCounterStore(repo, ts, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if store.Totals()["pol-1"].Bytes != 500 {
		t.Fatalf("expected pre-import cache to hold 500, got %+v", store.Totals()["pol-1"])
	}
	bs.SetCounterStore(store)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Mutate the DB counter value directly (simulating time passing between
	// export and import) so we can distinguish "reloaded from DB" from
	// "stale cache untouched".
	if err := repo.ResetPolicyRuleCounter("pol-1"); err != nil {
		t.Fatalf("ResetPolicyRuleCounter: %v", err)
	}
	if err := repo.AddPolicyRuleCounterDeltas(map[string]model.RuleCounter{"pol-1": {Bytes: 999, Packets: 9}}); err != nil {
		t.Fatalf("AddPolicyRuleCounterDeltas: %v", err)
	}

	if _, err := bs.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Import restores policy_rule_counters to a fresh zeroed row (D-6 —
	// backup never carries the runtime counter value itself, Caution 7), so
	// after Reload the cache must reflect that fresh DB state (0), not the
	// pre-import 500 nor the 999 written directly above (which RestoreConfig
	// overwrote).
	got := store.Totals()["pol-1"]
	if got.Bytes != 0 {
		t.Fatalf("expected cache reloaded to the post-import DB value (0), got %+v", got)
	}
}

// TestImportDoesNotExportEndpointsTable is E-09 of docs/ref/todo/
// persisted-rule-endpoints-plan.md (issue #141 follow-up), mirroring
// TestImportDoesNotExportCounterTable above: policy_rule_endpoints is
// runtime data and model.BackupConfig has no field for it, so a distinctive
// endpoint key/IP value seeded into that table must never appear in the
// exported backup JSON.
func TestImportDoesNotExportEndpointsTable(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)
	if err := repo.SetPolicyMonitored("pol-1", true); err != nil {
		t.Fatalf("SetPolicyMonitored: %v", err)
	}
	const distinctiveIP = "203.0.113.77"
	if _, err := repo.AddPolicyEndpointDeltas([]model.PersistedEndpoint{
		{RuleID: "pol-1", Direction: model.EndpointDirectionSrc, Key: distinctiveIP, Count: 3, FirstSeenAt: "2026-01-01T00:00:00Z", LastSeenAt: "2026-01-01T00:00:00Z"},
	}, 1000); err != nil {
		t.Fatalf("AddPolicyEndpointDeltas: %v", err)
	}

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), distinctiveIP) {
		t.Fatalf("expected the runtime endpoint IP to NEVER appear in the exported backup, got: %s", raw)
	}
}

// TestBackupService_SetCounterStoreReloadsRecorderAfterImport is E-09: Import
// must clear the RAM endpoint recorder's pending data and resync its
// monitored-rule set to the post-import DB, via the same
// PolicyCounterStore.Reload() call E-06 already extended for this — a stray
// pending delta from a rule that existed only in the pre-import DB must
// never reach the DB on the next flush after import.
func TestBackupService_SetCounterStoreReloadsRecorderAfterImport(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)
	if err := repo.SetPolicyMonitored("pol-1", true); err != nil {
		t.Fatalf("SetPolicyMonitored: %v", err)
	}

	acct := &fakeTrafficAccounting{}
	ts := NewTrafficStatsService(acct, repo, &fakeDhcpForTraffic{}, kernel.NewMockSystemStats(), 0, 0, 0)
	store := NewPolicyCounterStore(repo, ts, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	recorder := NewPolicyEndpointRecorder(true, 1000)
	store.SetEndpointRecorder(recorder, 1000)
	recorder.SetMonitoredRules(map[string]bool{"pol-1": true})
	bs.SetCounterStore(store)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Pending data accumulates in RAM right before import (simulating traffic
	// that arrived in the window between export and import completing).
	recorder.Record(model.FirewallLog{RuleID: "pol-1", Src: "198.51.100.5", Time: "2026-01-01T00:00:00Z"})

	if _, err := bs.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}

	// The pending delta captured before import must have been discarded by
	// Reload() — draining now must be empty, and nothing must have been
	// written to policy_rule_endpoints for that stray key.
	if got := recorder.Drain(); len(got) != 0 {
		t.Fatalf("expected Reload (via Import) to have cleared pending recorder data, got %+v", got)
	}
	rows, err := repo.GetTopPolicyEndpoints("pol-1", model.EndpointDirectionSrc, 10)
	if err != nil {
		t.Fatalf("GetTopPolicyEndpoints: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected no endpoint rows written for the pre-import stray pending delta, got %+v", rows)
	}

	// The recorder's monitored set must still reflect the post-import DB
	// state (pol-1 is still monitored=true in this fixture), so a fresh
	// Record must be accepted.
	recorder.Record(model.FirewallLog{RuleID: "pol-1", Src: "198.51.100.6", Time: "2026-01-01T00:01:00Z"})
	if got := recorder.Drain(); len(got) != 1 {
		t.Fatalf("expected recorder's monitored set to be resynced after import, got %+v", got)
	}
}

// =============================================================================
// DNS blocklist import feature (docs/ref/todo/dns-blocklist-import-plan.md
// §2.4/T-09) — backup export/import
// =============================================================================

const backupTestHostsBody = "" +
	"# sample blocklist\n" +
	"0.0.0.0 ads.example.com\n" +
	"0.0.0.0 tracker.example.net\n"

// TestBackupBlocklistRoundTrip_Upload covers plan §3 T-09 item 5: an
// upload-sourced list's .hosts file must round-trip through export/import
// (byte-identical content, matching sha256) even though ?includeBlocklistFiles
// was never passed — upload-sourced lists are always carried.
func TestBackupBlocklistRoundTrip_Upload(t *testing.T) {
	bs, _, blSvc, mgr := newBackupTestEnvWithBlocklists(t)

	entry, err := blSvc.CreateFromUpload("Uploaded List", []byte(backupTestHostsBody), model.DNSBlockModeSinkhole, true)
	if err != nil {
		t.Fatalf("CreateFromUpload: %v", err)
	}
	origContent, ok := mgr.BlocklistFileInfo(entry.ID)
	if !ok || origContent == 0 {
		t.Fatalf("expected .hosts to exist before export")
	}

	// includeBlocklistFiles=false: an upload-sourced list must still be
	// carried regardless.
	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(file.Config.Blocklists) != 1 {
		t.Fatalf("expected 1 blocklist in export, got %d", len(file.Config.Blocklists))
	}
	if len(file.Config.BlocklistFiles) != 1 {
		t.Fatalf("expected 1 blocklist file payload in export (upload-sourced must always be carried), got %d", len(file.Config.BlocklistFiles))
	}
	payload := file.Config.BlocklistFiles[0]
	if payload.ID != entry.ID {
		t.Fatalf("payload ID = %q, want %q", payload.ID, entry.ID)
	}
	if payload.Sha256 != entry.Sha256 {
		t.Errorf("payload.Sha256 = %q, want %q (must match the manifest's own sha256 of the same .hosts content)", payload.Sha256, entry.Sha256)
	}

	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Simulate a fresh device: wipe the blocklist store/files before import.
	bs2, _, blSvc2, mgr2 := newBackupTestEnvWithBlocklists(t)
	if _, err := bs2.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}

	restored := blSvc2.List()
	if len(restored) != 1 {
		t.Fatalf("expected 1 restored blocklist, got %d", len(restored))
	}
	if restored[0].ID != entry.ID {
		t.Fatalf("restored blocklist ID = %q, want %q", restored[0].ID, entry.ID)
	}
	if restored[0].DomainCount != entry.DomainCount {
		t.Errorf("restored DomainCount = %d, want %d (not needing a refresh)", restored[0].DomainCount, entry.DomainCount)
	}
	if restored[0].LastError != "" {
		t.Errorf("restored LastError = %q, want empty (file payload was present and verified)", restored[0].LastError)
	}
	content2, exists2 := mgr2.BlocklistFileInfo(entry.ID)
	if !exists2 || content2 == 0 {
		t.Fatalf("expected imported .hosts file to exist on the destination device")
	}
	if content2 != origContent {
		t.Errorf("imported .hosts size = %d, want %d (byte-identical round trip)", content2, origContent)
	}
	if _, existsConf := mgr2.BlocklistConfFileInfo(entry.ID); existsConf {
		t.Errorf("sinkhole-mode list must not gain a .conf file on import")
	}
}

// TestBackupBlocklistRoundTrip_NXDomain covers plan §3 T-09 item 5: a
// nxdomain-mode list's <id>.conf must be regenerated on import purely from
// the imported .hosts content, even though the backup itself never carried
// any .conf payload (only DNSBlocklistFilePayload for .hosts exists).
func TestBackupBlocklistRoundTrip_NXDomain(t *testing.T) {
	bs, _, blSvc, _ := newBackupTestEnvWithBlocklists(t)

	entry, err := blSvc.CreateFromUpload("NX Uploaded List", []byte(backupTestHostsBody), model.DNSBlockModeNXDomain, true)
	if err != nil {
		t.Fatalf("CreateFromUpload: %v", err)
	}

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Load-bearing: the backup must never carry the derived .conf artifact —
	// only the canonical .hosts payload (plan §2.1.1/§2.4).
	if strings.Contains(string(raw), "address=/ads.example.com/") {
		t.Fatalf("backup must not embed rendered .conf content, but raw payload contains it: %s", raw)
	}

	bs2, _, blSvc2, mgr2 := newBackupTestEnvWithBlocklists(t)
	if _, err := bs2.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}

	restored := blSvc2.List()
	if len(restored) != 1 || restored[0].BlockMode != model.DNSBlockModeNXDomain {
		t.Fatalf("expected 1 restored nxdomain-mode blocklist, got %+v", restored)
	}
	confBytes, exists := mgr2.BlocklistConfContent(entry.ID)
	if !exists {
		t.Fatalf("expected .conf to be regenerated on import for a nxdomain-mode list")
	}
	for _, domain := range []string{"ads.example.com", "tracker.example.net"} {
		want := "address=/" + domain + "/"
		if !strings.Contains(string(confBytes), want) {
			t.Errorf(".conf missing %q, got:\n%s", want, confBytes)
		}
	}
}

// unsupportedNXDomainBackupManager makes SupportsBulkNXDomain() report false,
// used to test the automatic sinkhole downgrade on import (plan §3 T-09 item
// 3).
type unsupportedNXDomainBackupManager struct {
	*kernel.MockDNSServerManager
}

func (m *unsupportedNXDomainBackupManager) SupportsBulkNXDomain() bool { return false }

// TestBackupBlocklistImportDowngradesNXDomainWhenUnsupported covers plan §3
// T-09 item 3: importing a nxdomain-mode list onto a system whose dnsmasq
// doesn't support it must downgrade to sinkhole (not fail the whole import),
// and record why in LastError.
func TestBackupBlocklistImportDowngradesNXDomainWhenUnsupported(t *testing.T) {
	bs, _, blSvc, _ := newBackupTestEnvWithBlocklists(t)
	entry, err := blSvc.CreateFromUpload("NX List", []byte(backupTestHostsBody), model.DNSBlockModeNXDomain, true)
	if err != nil {
		t.Fatalf("CreateFromUpload: %v", err)
	}
	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	bs2, repo2 := newBackupTestEnv(t)
	mgr2 := &unsupportedNXDomainBackupManager{kernel.NewMockDNSServerManager()}
	blSvc2 := NewDNSBlocklistService(repo2, mgr2)
	if err := blSvc2.Load(); err != nil {
		t.Fatalf("blocklist service Load(): %v", err)
	}
	bs2.SetBlocklistService(blSvc2)

	res, err := bs2.Import(raw, model.ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	restored := blSvc2.List()
	if len(restored) != 1 {
		t.Fatalf("expected 1 restored blocklist, got %d", len(restored))
	}
	if restored[0].BlockMode != model.DNSBlockModeSinkhole {
		t.Errorf("BlockMode = %q, want %q (downgraded)", restored[0].BlockMode, model.DNSBlockModeSinkhole)
	}
	if restored[0].LastError == "" {
		t.Errorf("expected LastError to explain the downgrade, got empty")
	}
	if _, exists := mgr2.BlocklistConfFileInfo(entry.ID); exists {
		t.Errorf("a downgraded-to-sinkhole list must not have a .conf file")
	}
	if len(res.Warnings) == 0 {
		t.Logf("no warnings recorded for the downgrade (acceptable: downgrade is recorded per-list via LastError, not necessarily a top-level warning)")
	}
}

// TestBackupBlocklistExportOmitsUrlSourcedFilesByDefault covers plan §2.4:
// url-sourced lists are only carried when includeBlocklistFiles is requested;
// by default only the metadata (manifest entry) travels, and the list needs
// a Refresh after import.
func TestBackupBlocklistExportOmitsUrlSourcedFilesByDefault(t *testing.T) {
	bs, _, blSvc, _ := newBackupTestEnvWithBlocklists(t)
	srv := blocklistTestServer(t, backupTestHostsBody)
	blSvc.fetcher = newLoopbackFetcher(srv)

	entry, err := blSvc.CreateFromURL(context.Background(), "URL List", testBlocklistBaseURL+"/hosts", model.DNSBlockModeSinkhole, true)
	if err != nil {
		t.Fatalf("CreateFromURL: %v", err)
	}

	fileDefault, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export (default): %v", err)
	}
	if len(fileDefault.Config.Blocklists) != 1 {
		t.Fatalf("expected the url-sourced list's metadata to still be exported")
	}
	if len(fileDefault.Config.BlocklistFiles) != 0 {
		t.Fatalf("expected NO file payload by default for a url-sourced list, got %d", len(fileDefault.Config.BlocklistFiles))
	}

	fileIncluded, err := bs.Export(false, "", true)
	if err != nil {
		t.Fatalf("export (includeBlocklistFiles=true): %v", err)
	}
	if len(fileIncluded.Config.BlocklistFiles) != 1 || fileIncluded.Config.BlocklistFiles[0].ID != entry.ID {
		t.Fatalf("expected the url-sourced list's file payload to be included with includeBlocklistFiles=true, got %+v", fileIncluded.Config.BlocklistFiles)
	}

	// Importing the default (no-file-payload) export must not fail — the
	// list is kept but flagged as needing a refresh.
	raw, err := json.Marshal(fileDefault)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	bs2, _, blSvc2, _ := newBackupTestEnvWithBlocklists(t)
	if _, err := bs2.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import: %v", err)
	}
	restored := blSvc2.List()
	if len(restored) != 1 {
		t.Fatalf("expected 1 restored blocklist, got %d", len(restored))
	}
	if restored[0].DomainCount != 0 {
		t.Errorf("DomainCount = %d, want 0 (no file payload was carried)", restored[0].DomainCount)
	}
	if restored[0].LastError != "needs refresh after import" {
		t.Errorf("LastError = %q, want %q", restored[0].LastError, "needs refresh after import")
	}
}

// TestImportOldBackupWithoutBlocklistsKeyChecksumRegression is the most
// important regression test in this file (plan §3 T-09 acceptance): a
// backup exported by a build that predates the DNS blocklist import feature
// entirely lacks the "blocklists"/"blocklistFiles" keys, and MUST still
// import successfully — the checksum, computed by re-marshalling the decoded
// BackupConfig, must be unaffected by the two new omitempty fields added to
// BackupConfig in this change.
func TestImportOldBackupWithoutBlocklistsKeyChecksumRegression(t *testing.T) {
	bs, repo := newBackupTestEnv(t) // no SetBlocklistService — mirrors a pre-feature binary
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Load-bearing: this exporter (blocklistService unset) must never emit
	// these keys — omitempty must actually be doing its job.
	if strings.Contains(string(raw), `"blocklists"`) || strings.Contains(string(raw), `"blocklistFiles"`) {
		t.Fatalf("expected no blocklists/blocklistFiles keys when blocklistService is unset, got: %s", raw)
	}

	if _, err := bs.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import of a backup without blocklists/blocklistFiles keys must succeed (checksum must still verify), got: %v", err)
	}
}

// TestBackupWanUplinksRoundTrip covers docs/ref/todo/
// multi-wan-failover-plan.md Task 12 acceptance: exporting then importing a
// backup carries WAN uplinks and the global failover settings through
// completely (probeTargets, thresholds, strikes, and the manual-mode
// failover settings all survive the round trip).
func TestBackupWanUplinksRoundTrip(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo) // seeds one WAN uplink "Primary"

	if err := repo.UpdateWanFailoverSettings(model.WanFailoverSettings{
		Enabled: true, Mode: model.WanFailoverModeManual, ManualUplinkID: "wan-manual-target",
		MinHoldSeconds: 45, RevertDelaySeconds: 90,
	}); err != nil {
		t.Fatalf("update wan failover settings: %v", err)
	}

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(file.Config.WanUplinks) != 1 {
		t.Fatalf("expected 1 wan uplink in export, got %d", len(file.Config.WanUplinks))
	}
	if file.Config.WanFailoverSettings == nil || !file.Config.WanFailoverSettings.Enabled {
		t.Fatalf("expected wan failover settings to be exported with enabled=true, got %+v", file.Config.WanFailoverSettings)
	}

	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	res, err := bs.Import(raw, model.ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Counts["wanUplinks"] != 1 {
		t.Errorf("imported wanUplinks count = %d, want 1", res.Counts["wanUplinks"])
	}

	uplinks, err := repo.GetWanUplinks()
	if err != nil {
		t.Fatalf("get wan uplinks after import: %v", err)
	}
	if len(uplinks) != 1 {
		t.Fatalf("expected 1 wan uplink after import, got %d", len(uplinks))
	}
	u := uplinks[0]
	if u.Name != "Primary" || u.Interface != "eth0" {
		t.Errorf("unexpected restored uplink: %+v", u)
	}
	if len(u.ProbeTargets) != 2 || u.ProbeTargets[0] != "1.1.1.1" || u.ProbeTargets[1] != "8.8.8.8" {
		t.Errorf("ProbeTargets not restored correctly: %v", u.ProbeTargets)
	}
	if u.ProbeMethod != model.WanProbeMethodAuto || u.ProbeTCPPort != 443 {
		t.Errorf("probe method/port not restored correctly: %q/%d", u.ProbeMethod, u.ProbeTCPPort)
	}

	settings, err := repo.GetWanFailoverSettings()
	if err != nil {
		t.Fatalf("get wan failover settings after import: %v", err)
	}
	if !settings.Enabled || settings.Mode != model.WanFailoverModeManual || settings.ManualUplinkID != "wan-manual-target" {
		t.Errorf("wan failover settings not restored correctly: %+v", settings)
	}
	if settings.MinHoldSeconds != 45 || settings.RevertDelaySeconds != 90 {
		t.Errorf("wan failover dampening settings not restored correctly: %+v", settings)
	}
}

// TestImportOldBackupWithoutWanKeysChecksumRegression mirrors
// TestImportOldBackupWithoutBlocklistsKeyChecksumRegression: a backup file
// that predates the Multi-WAN Failover feature entirely lacks the
// "wanUplinks"/"wanFailoverSettings" keys, and MUST still import
// successfully — the checksum (computed by re-marshalling the decoded
// BackupConfig) must be unaffected by these two new omitempty fields.
func TestImportOldBackupWithoutWanKeysChecksumRegression(t *testing.T) {
	bs, repo := newBackupTestEnv(t)
	seedCustomConfig(t, repo)

	file, err := bs.Export(false, "", false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Simulate an exporter that predates this feature entirely: drop both
	// keys before marshalling, then recompute the checksum the way an old
	// binary would have (over a BackupConfig that never had these fields).
	file.Config.WanUplinks = nil
	file.Config.WanFailoverSettings = nil
	sum, err := configChecksum(*file.Config)
	if err != nil {
		t.Fatalf("recompute checksum: %v", err)
	}
	file.Meta.Checksum = sum

	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), `"wanUplinks"`) || strings.Contains(string(raw), `"wanFailoverSettings"`) {
		t.Fatalf("test setup invalid: raw backup still contains a wanUplinks/wanFailoverSettings key: %s", raw)
	}

	if _, err := bs.Import(raw, model.ImportOptions{}); err != nil {
		t.Fatalf("import of a backup without wanUplinks/wanFailoverSettings keys must succeed (checksum must still verify), got: %v", err)
	}

	// A pre-existing wan_failover_settings row (seeded at DB init, enabled=0)
	// must be left untouched by an import that carries no wanFailoverSettings
	// at all — never wiped/zeroed just because the key was absent.
	settings, err := repo.GetWanFailoverSettings()
	if err != nil {
		t.Fatalf("get wan failover settings after import: %v", err)
	}
	if settings.Enabled {
		t.Errorf("expected wan_failover_settings to be left at its default (enabled=false) when the backup carried no wanFailoverSettings key, got enabled=true")
	}
}
