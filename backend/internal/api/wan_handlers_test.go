package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pigate/internal/db"
	"pigate/internal/kernel"
	"pigate/internal/model"
	"pigate/internal/service"
)

// setupWanTestServer builds a test Server (mock kernels + in-memory DB, like
// buildTestServer) plus a WanMonitor wired via the additive SetWanMonitor
// setter, and returns the mock probe so tests can drive
// SetICMPDead/SetAllDead scenarios.
func setupWanTestServer(t *testing.T) (http.Handler, *db.Repository, *kernel.MockPathProbe, *service.WanMonitor) {
	server, repo := buildTestServer(t, false)
	probe := kernel.NewMockPathProbe()
	monitor := service.NewWanMonitor(repo, probe, service.NewEventLogService(repo), service.NewNetEventBus(), service.NewWanUplinkMetricsRing())
	server.SetWanMonitor(monitor)

	handler := RegisterRoutes(server)
	AddSession("mock_session_id_test_token", "pigate")
	return handler, repo, probe, monitor
}

const wanTestAuthToken = "mock_session_id_test_token"

func validWanUplinkInputJSON() model.WanUplinkInput {
	return model.WanUplinkInput{
		Name: "Primary", Interface: "eth0", Priority: 1,
		ProbeTargets: []string{"1.1.1.1"}, ProbeMethod: model.WanProbeMethodAuto, ProbeTCPPort: 443,
		ProbeIntervalSeconds: 5, ProbeCount: 3, ProbeTimeoutMs: 1000,
		LossThresholdPct: 50, LatencyThresholdMs: 200,
		FailStrikes: 3, RecoverStrikes: 3, Status: true, Description: "main uplink",
	}
}

func TestWanUplinksCRUD(t *testing.T) {
	handler, repo, _, _ := setupWanTestServer(t)

	// 1. GET (empty)
	req := httptest.NewRequest("GET", "/api/wan/uplinks", nil)
	addSessionCookie(req, wanTestAuthToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var list []model.WanUplink
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected 0 uplinks initially, got %d", len(list))
	}

	// 2. POST (create)
	body, _ := json.Marshal(validWanUplinkInputJSON())
	req = httptest.NewRequest("POST", "/api/wan/uplinks", bytes.NewBuffer(body))
	addSessionCookie(req, wanTestAuthToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created model.WanUplink
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if created.ID == "" || created.Name != "Primary" {
		t.Fatalf("unexpected created uplink: %+v", created)
	}

	dbUplink, err := repo.GetWanUplinkByID(created.ID)
	if err != nil || dbUplink == nil {
		t.Fatalf("expected uplink persisted, err=%v uplink=%v", err, dbUplink)
	}

	// 3. PUT (update)
	updateInput := validWanUplinkInputJSON()
	updateInput.Name = "Primary Renamed"
	body, _ = json.Marshal(updateInput)
	req = httptest.NewRequest("PUT", "/api/wan/uplinks/"+created.ID, bytes.NewBuffer(body))
	addSessionCookie(req, wanTestAuthToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var updated model.WanUplink
	json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.Name != "Primary Renamed" {
		t.Errorf("expected renamed, got %q", updated.Name)
	}

	// 4. PUT unknown id -> 404
	req = httptest.NewRequest("PUT", "/api/wan/uplinks/does-not-exist", bytes.NewBuffer(body))
	addSessionCookie(req, wanTestAuthToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown id, got %d", rec.Code)
	}

	// 5. DELETE
	req = httptest.NewRequest("DELETE", "/api/wan/uplinks/"+created.ID, nil)
	addSessionCookie(req, wanTestAuthToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	gone, _ := repo.GetWanUplinkByID(created.ID)
	if gone != nil {
		t.Error("expected uplink deleted")
	}

	// 6. DELETE unknown id -> 404
	req = httptest.NewRequest("DELETE", "/api/wan/uplinks/does-not-exist", nil)
	addSessionCookie(req, wanTestAuthToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown id, got %d", rec.Code)
	}
}

func TestWanUplinkCreate_HostnameTargetRejected(t *testing.T) {
	handler, _, _, _ := setupWanTestServer(t)

	input := validWanUplinkInputJSON()
	input.ProbeTargets = []string{"google.com"}
	body, _ := json.Marshal(input)
	req := httptest.NewRequest("POST", "/api/wan/uplinks", bytes.NewBuffer(body))
	addSessionCookie(req, wanTestAuthToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a hostname probe target, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["message"] == "" {
		t.Error("expected a non-empty error message naming the field")
	}
}

func TestWanUplinkCreate_DuplicateInterfaceRejected(t *testing.T) {
	handler, _, _, _ := setupWanTestServer(t)

	body, _ := json.Marshal(validWanUplinkInputJSON())
	req := httptest.NewRequest("POST", "/api/wan/uplinks", bytes.NewBuffer(body))
	addSessionCookie(req, wanTestAuthToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected first create to succeed, got %d: %s", rec.Code, rec.Body.String())
	}

	second := validWanUplinkInputJSON()
	second.Name = "Duplicate"
	body, _ = json.Marshal(second)
	req = httptest.NewRequest("POST", "/api/wan/uplinks", bytes.NewBuffer(body))
	addSessionCookie(req, wanTestAuthToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for a duplicate interface, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestWanStatus_ReportsUnknownForNeverProbedUplink(t *testing.T) {
	handler, repo, _, _ := setupWanTestServer(t)

	created, err := repo.CreateWanUplink(validWanUplinkInputJSON())
	if err != nil {
		t.Fatalf("CreateWanUplink failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/wan/status", nil)
	addSessionCookie(req, wanTestAuthToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp model.WanStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(resp.Uplinks) != 1 {
		t.Fatalf("expected exactly 1 uplink in status, got %d", len(resp.Uplinks))
	}
	entry := resp.Uplinks[0]
	if entry.UplinkID != created.ID {
		t.Errorf("UplinkID = %q, want %q", entry.UplinkID, created.ID)
	}
	if entry.State != model.WanStateUnknown {
		t.Errorf("expected state=unknown for a never-probed uplink, got %q", entry.State)
	}
	if entry.Name != "Primary" {
		t.Errorf("expected Name to be carried through from config, got %q", entry.Name)
	}
}

func TestWanStatus_ReflectsMonitorState(t *testing.T) {
	handler, repo, probe, monitor := setupWanTestServer(t)
	created, err := repo.CreateWanUplink(validWanUplinkInputJSON())
	if err != nil {
		t.Fatalf("CreateWanUplink failed: %v", err)
	}
	_ = probe

	// Drive a real probe round through the monitor's own background loop
	// (its only entry point — probeUplink/tick are package-private by
	// design) and poll briefly until GetStates() reflects it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	monitor.Start(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(monitor.GetStates()) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	req := httptest.NewRequest("GET", "/api/wan/status", nil)
	addSessionCookie(req, wanTestAuthToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var resp model.WanStatusResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Uplinks) != 1 {
		t.Fatalf("expected 1 uplink, got %d", len(resp.Uplinks))
	}
	if resp.Uplinks[0].UplinkID != created.ID {
		t.Errorf("UplinkID mismatch: %q vs %q", resp.Uplinks[0].UplinkID, created.ID)
	}
	if resp.Uplinks[0].State == "" {
		t.Error("expected a non-empty state after a probe round")
	}
}

func TestWanMetrics_RequiresUplinkParam(t *testing.T) {
	handler, _, _, _ := setupWanTestServer(t)
	req := httptest.NewRequest("GET", "/api/wan/metrics?window=1h", nil)
	addSessionCookie(req, wanTestAuthToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when uplink param is missing, got %d", rec.Code)
	}
}

func TestWanMetrics_UnknownUplinkReturnsEmptySeriesNotError(t *testing.T) {
	handler, _, _, _ := setupWanTestServer(t)
	req := httptest.NewRequest("GET", "/api/wan/metrics?uplink=does-not-exist&window=1h", nil)
	addSessionCookie(req, wanTestAuthToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with an empty/zero series, got %d: %s", rec.Code, rec.Body.String())
	}
	var points []model.WanMetricPoint
	if err := json.Unmarshal(rec.Body.Bytes(), &points); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(points) == 0 {
		t.Error("expected a full zero-valued window, not an empty array")
	}
}

func TestWanUplinksRequireAuth(t *testing.T) {
	handler, _, _, _ := setupWanTestServer(t)
	req := httptest.NewRequest("GET", "/api/wan/uplinks", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without a session, got %d", rec.Code)
	}
}
