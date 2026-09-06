package api

import (
	"encoding/json"
	"net/http"

	"pigate/internal/model"
)

// =========================================================================
// Multi-WAN Failover Handlers (docs/ref/todo/multi-wan-failover-plan.md)
//
// Phase 1 only (Task 9): uplink CRUD + read-only status/metrics. All
// endpoints here are authRoute (same sensitivity as Static Routes/QoS) —
// the superAdminRoute-gated kill switch/manual override endpoints
// (PUT /api/wan/failover, POST /api/wan/failover/override) are Phase 2
// (Task 16) and do not exist yet.
// =========================================================================

// HandleGetWanUplinks returns every configured WAN uplink.
func (s *Server) HandleGetWanUplinks(w http.ResponseWriter, r *http.Request) {
	uplinks, err := s.repo.GetWanUplinks()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to retrieve WAN uplinks")
		return
	}
	s.writeJSON(w, http.StatusOK, uplinks)
}

// HandleCreateWanUplink validates then creates a new WAN uplink.
// model.ValidateWanUplink is called explicitly (not just relied on inside
// the repository) so a validation failure is always distinguishable from a
// database-layer failure, and always maps to 400.
func (s *Server) HandleCreateWanUplink(w http.ResponseWriter, r *http.Request) {
	var input model.WanUplinkInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := model.ValidateWanUplink(input); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	uplink, err := s.repo.CreateWanUplink(input)
	if err != nil {
		// Anything past our own explicit validation above is still a
		// request-data problem in practice (e.g. the UNIQUE(interface)
		// constraint rejecting a second uplink on the same interface), so it
		// is reported as 400 rather than 500.
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryNetwork, "wan.uplink_created", model.EventSeverityInfo,
		uplink.Name, "WAN uplink \""+uplink.Name+"\" created on "+uplink.Interface)
	s.writeJSON(w, http.StatusCreated, uplink)
}

// HandleUpdateWanUplink validates then updates an existing WAN uplink.
func (s *Server) HandleUpdateWanUplink(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.repo.GetWanUplinkByID(id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to look up WAN uplink")
		return
	}
	if existing == nil {
		s.writeError(w, http.StatusNotFound, "WAN uplink not found")
		return
	}

	var input model.WanUplinkInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := model.ValidateWanUplink(input); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := s.repo.UpdateWanUplink(id, input)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryNetwork, "wan.uplink_updated", model.EventSeverityInfo,
		updated.Name, "WAN uplink \""+updated.Name+"\" updated")
	s.writeJSON(w, http.StatusOK, updated)
}

// HandleDeleteWanUplink removes a WAN uplink.
func (s *Server) HandleDeleteWanUplink(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.repo.GetWanUplinkByID(id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to look up WAN uplink")
		return
	}
	if existing == nil {
		s.writeError(w, http.StatusNotFound, "WAN uplink not found")
		return
	}

	if err := s.repo.DeleteWanUplink(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to delete WAN uplink")
		return
	}
	s.logEvent(r, model.EventCategoryNetwork, "wan.uplink_deleted", model.EventSeverityWarning,
		existing.Name, "WAN uplink \""+existing.Name+"\" deleted")
	s.writeJSON(w, http.StatusOK, map[string]string{"message": "WAN uplink deleted"})
}

// HandleGetWanStatus returns the live status of every configured uplink,
// merging repo-configured uplinks (always present) with the monitor's
// RAM-only health state (present only once an uplink has been probed at
// least once). An uplink with no matching state yet is reported as
// state=unknown rather than being omitted — a caller must never need to
// cross-reference GET /api/wan/uplinks separately just to know an uplink
// exists (plan Task 9 acceptance).
func (s *Server) HandleGetWanStatus(w http.ResponseWriter, r *http.Request) {
	uplinks, err := s.repo.GetWanUplinks()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to retrieve WAN uplinks")
		return
	}

	statesByID := make(map[string]model.WanUplinkState, len(uplinks))
	if s.wanMonitor != nil {
		for _, st := range s.wanMonitor.GetStates() {
			statesByID[st.UplinkID] = st
		}
	}

	entries := make([]model.WanStatusEntry, 0, len(uplinks))
	for _, u := range uplinks {
		st, ok := statesByID[u.ID]
		if !ok {
			st = model.WanUplinkState{UplinkID: u.ID, Interface: u.Interface, State: model.WanStateUnknown}
		}
		entries = append(entries, model.WanStatusEntry{WanUplinkState: st, Name: u.Name, Priority: u.Priority})
	}

	// Phase 2 fields (BypassedByStaticRoute/ActiveUplinkID/LastSwitchAt/
	// LastSwitchReason) intentionally stay at their zero value — there is no
	// failover controller yet to ever populate them (see
	// model.WanStatusResponse's doc comment).
	s.writeJSON(w, http.StatusOK, model.WanStatusResponse{Uplinks: entries})
}

// HandleGetWanMetrics returns the metrics-ring time series for one uplink
// (?uplink=<id>&window=<1h|24h|...>). An unknown/never-probed uplink id
// simply reads back an all-zero series (service.WanUplinkMetricsRing.Series
// never errors on a missing key) rather than 404 — the graph just renders
// empty, which is the correct degrade for "not probed yet" too.
func (s *Server) HandleGetWanMetrics(w http.ResponseWriter, r *http.Request) {
	uplinkID := r.URL.Query().Get("uplink")
	if uplinkID == "" {
		s.writeError(w, http.StatusBadRequest, "uplink query parameter is required")
		return
	}
	window := r.URL.Query().Get("window")

	if s.wanMonitor == nil {
		s.writeJSON(w, http.StatusOK, []model.WanMetricPoint{})
		return
	}
	s.writeJSON(w, http.StatusOK, s.wanMonitor.GetMetrics(uplinkID, window))
}
