package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"pigate/internal/model"

	"github.com/google/uuid"
)

// wanUplinkColumns is the column list shared by every SELECT below, kept as
// one constant so Get/GetByID never drift from each other (mirrors the
// qos_rules repo pattern in db/qos.go).
const wanUplinkColumns = `id, name, interface, priority, probe_targets, probe_method, probe_tcp_port,
	probe_interval_seconds, probe_count, probe_timeout_ms, loss_threshold_pct, latency_threshold_ms,
	fail_strikes, recover_strikes, status, description`

// scanWanUplink reads one wan_uplinks row (column order matching
// wanUplinkColumns) into a model.WanUplink, splitting the comma-separated
// probe_targets column back into a slice.
func scanWanUplink(scan func(dest ...any) error) (model.WanUplink, error) {
	var u model.WanUplink
	var probeTargets string
	var statusInt int
	err := scan(
		&u.ID, &u.Name, &u.Interface, &u.Priority, &probeTargets, &u.ProbeMethod, &u.ProbeTCPPort,
		&u.ProbeIntervalSeconds, &u.ProbeCount, &u.ProbeTimeoutMs, &u.LossThresholdPct, &u.LatencyThresholdMs,
		&u.FailStrikes, &u.RecoverStrikes, &statusInt, &u.Description,
	)
	if err != nil {
		return model.WanUplink{}, err
	}
	u.Status = statusInt == 1
	if probeTargets != "" {
		u.ProbeTargets = strings.Split(probeTargets, ",")
	} else {
		u.ProbeTargets = []string{}
	}
	return u, nil
}

// GetWanUplinks returns every configured WAN uplink, ordered by priority
// ascending (lower priority value = tried first, same convention as
// qos_rules).
func (r *Repository) GetWanUplinks() ([]model.WanUplink, error) {
	rows, err := r.db.Query(`SELECT ` + wanUplinkColumns + ` FROM wan_uplinks ORDER BY priority ASC, name COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("query wan_uplinks: %w", err)
	}
	defer rows.Close()

	uplinks := []model.WanUplink{}
	for rows.Next() {
		u, err := scanWanUplink(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan wan_uplink: %w", err)
		}
		uplinks = append(uplinks, u)
	}
	return uplinks, rows.Err()
}

// GetWanUplinkByID returns a single uplink, or nil (no error) if id doesn't
// match any row — mirrors GetAddressByID's not-found convention.
func (r *Repository) GetWanUplinkByID(id string) (*model.WanUplink, error) {
	row := r.db.QueryRow(`SELECT `+wanUplinkColumns+` FROM wan_uplinks WHERE id = ?`, id)
	u, err := scanWanUplink(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get wan_uplink %q: %w", id, err)
	}
	return &u, nil
}

// CreateWanUplink validates then inserts a new uplink, returning the created
// record. interface uniqueness is enforced by the UNIQUE constraint on
// wan_uplinks.interface — a duplicate is returned as a plain wrapped sqlite
// error, which the api layer maps to 400 like any other validation failure.
func (r *Repository) CreateWanUplink(input model.WanUplinkInput) (*model.WanUplink, error) {
	if err := model.ValidateWanUplink(input); err != nil {
		return nil, err
	}

	id := "wan-" + uuid.New().String()
	statusInt := 0
	if input.Status {
		statusInt = 1
	}

	_, err := r.db.Exec(`INSERT INTO wan_uplinks (
			id, name, interface, priority, probe_targets, probe_method, probe_tcp_port,
			probe_interval_seconds, probe_count, probe_timeout_ms, loss_threshold_pct, latency_threshold_ms,
			fail_strikes, recover_strikes, status, description
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, input.Name, input.Interface, input.Priority, strings.Join(input.ProbeTargets, ","), input.ProbeMethod, input.ProbeTCPPort,
		input.ProbeIntervalSeconds, input.ProbeCount, input.ProbeTimeoutMs, input.LossThresholdPct, input.LatencyThresholdMs,
		input.FailStrikes, input.RecoverStrikes, statusInt, input.Description,
	)
	if err != nil {
		return nil, fmt.Errorf("insert wan_uplink: %w", err)
	}
	return r.GetWanUplinkByID(id)
}

// UpdateWanUplink validates then updates an existing uplink, returning the
// updated record.
func (r *Repository) UpdateWanUplink(id string, input model.WanUplinkInput) (*model.WanUplink, error) {
	if err := model.ValidateWanUplink(input); err != nil {
		return nil, err
	}

	statusInt := 0
	if input.Status {
		statusInt = 1
	}

	res, err := r.db.Exec(`UPDATE wan_uplinks SET
			name = ?, interface = ?, priority = ?, probe_targets = ?, probe_method = ?, probe_tcp_port = ?,
			probe_interval_seconds = ?, probe_count = ?, probe_timeout_ms = ?, loss_threshold_pct = ?, latency_threshold_ms = ?,
			fail_strikes = ?, recover_strikes = ?, status = ?, description = ?
		WHERE id = ?`,
		input.Name, input.Interface, input.Priority, strings.Join(input.ProbeTargets, ","), input.ProbeMethod, input.ProbeTCPPort,
		input.ProbeIntervalSeconds, input.ProbeCount, input.ProbeTimeoutMs, input.LossThresholdPct, input.LatencyThresholdMs,
		input.FailStrikes, input.RecoverStrikes, statusInt, input.Description,
		id,
	)
	if err != nil {
		return nil, fmt.Errorf("update wan_uplink %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("wan uplink %q not found", id)
	}
	return r.GetWanUplinkByID(id)
}

// DeleteWanUplink removes an uplink by ID.
func (r *Repository) DeleteWanUplink(id string) error {
	res, err := r.db.Exec(`DELETE FROM wan_uplinks WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete wan_uplink %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("wan uplink %q not found", id)
	}
	return nil
}

// GetWanFailoverSettings returns the single-row global failover settings
// (id=1), mirroring GetDhcpHealthSettings's shape.
func (r *Repository) GetWanFailoverSettings() (*model.WanFailoverSettings, error) {
	row := r.db.QueryRow(`SELECT enabled, mode, manual_uplink_id, min_hold_seconds, revert_delay_seconds FROM wan_failover_settings WHERE id = 1`)
	var s model.WanFailoverSettings
	var enabledInt int
	if err := row.Scan(&enabledInt, &s.Mode, &s.ManualUplinkID, &s.MinHoldSeconds, &s.RevertDelaySeconds); err != nil {
		return nil, err
	}
	s.Enabled = enabledInt == 1
	return &s, nil
}

// UpdateWanFailoverSettings validates then persists the global failover
// settings. Validation happens here (not only at the api layer) so any
// future direct caller (e.g. backup import) gets the same fail-closed
// guarantee as WifiPreset/QoS updates.
func (r *Repository) UpdateWanFailoverSettings(s model.WanFailoverSettings) error {
	if err := model.ValidateWanFailoverSettings(s); err != nil {
		return err
	}
	enabledInt := 0
	if s.Enabled {
		enabledInt = 1
	}
	_, err := r.db.Exec(`UPDATE wan_failover_settings SET enabled = ?, mode = ?, manual_uplink_id = ?, min_hold_seconds = ?, revert_delay_seconds = ? WHERE id = 1`,
		enabledInt, s.Mode, s.ManualUplinkID, s.MinHoldSeconds, s.RevertDelaySeconds)
	return err
}
