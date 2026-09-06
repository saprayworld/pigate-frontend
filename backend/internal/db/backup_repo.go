package db

import (
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"pigate/internal/model"
)

// GetRawStaticRoutes returns static routes exactly as stored in the DB, without
// merging live kernel routes (GetRoutes) or resolving the "default" gateway
// sentinel to a concrete IP (GetDatabaseRoutes). This raw form is what a backup
// must capture so a restore on another machine/network keeps "default" and the
// original type classification intact.
func (r *Repository) GetRawStaticRoutes() ([]model.StaticRoute, error) {
	rows, err := r.db.Query("SELECT id, destination, gateway, interface, metric, description, status, type, scope, src, proto FROM static_routes")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []model.StaticRoute{}
	for rows.Next() {
		var rt model.StaticRoute
		var statInt int
		if err := rows.Scan(&rt.ID, &rt.Destination, &rt.Gateway, &rt.Interface, &rt.Metric, &rt.Description, &statInt, &rt.Type, &rt.Scope, &rt.Src, &rt.Proto); err != nil {
			return nil, err
		}
		rt.Status = statInt == 1
		list = append(list, rt)
	}
	return list, rows.Err()
}

// GetBackupUsers returns all users including their bcrypt password hash for
// inclusion in a backup. Unlike GetUsers (whose model.User hides the hash from
// JSON) this returns the credential material explicitly.
func (r *Repository) GetBackupUsers() ([]model.BackupUser, error) {
	users, err := r.GetUsers()
	if err != nil {
		return nil, err
	}
	out := make([]model.BackupUser, 0, len(users))
	for _, u := range users {
		out = append(out, model.BackupUser{
			ID:           u.ID,
			Username:     u.Username,
			PasswordHash: u.PasswordHash,
			IsInitial:    u.IsInitial,
			Role:         u.Role,
			Status:       u.Status,
			CreatedAt:    u.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	return out, nil
}

// MaxObjectEntries returns the per-object entries cap currently enforced by
// this repository (either the config-supplied max-object-entries value set via
// SetObjectLimits at startup, or model.DefaultMaxObjectEntries if that was
// never called). BackupService.Import uses this so backup entry validation
// enforces the exact same cap as CreateAddress/CreateService, instead of a
// second hardcoded number (plan Caution 5 — validation must live in one
// place; this just exposes the limit that already lives there).
func (r *Repository) MaxObjectEntries() int {
	return r.maxObjectEntries
}

// Checkpoint flushes the WAL into the main database file. Call this before
// SnapshotDatabase so a file-copy snapshot doesn't miss recently written pages
// that still live only in the -wal file. No-op errors are ignored by callers in
// mock/:memory: mode where WAL isn't enabled.
func (r *Repository) Checkpoint() error {
	_, err := r.db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
	return err
}

// RestoreConfig replaces all user-editable configuration with the contents of
// cfg inside a single transaction (wipe & restore semantics). System-seeded rows
// are preserved: system address/service objects, and system/defaultgateway
// static routes are never deleted or re-inserted. Interfaces are matched by id
// and updated in place — callers must pre-resolve cfg.Interfaces to rows that
// already exist on this device (see BackupService.Import). Users are only
// touched when includeUsers is true.
//
// Any error rolls the whole transaction back, leaving the original DB untouched.
func (r *Repository) RestoreConfig(cfg model.BackupConfig, includeUsers bool) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// --- 1. Wipe in FK-safe order (children before parents) --------------
	// Junction tables reference firewall_policies (CASCADE) and address/service
	// objects (RESTRICT), so they must go before the objects they point at.
	// address_object_values / service_object_ports (T-02) reference their
	// parent address_objects/service_objects row with ON DELETE CASCADE, so
	// deleting only the non-system parent rows below also removes exactly
	// their own child rows automatically — system objects (and therefore their
	// child rows too, since their parent is never deleted here) are left
	// untouched, same as before this table existed (Caution 7).
	wipes := []string{
		"DELETE FROM policy_services",
		"DELETE FROM policy_addresses",
		// policy_interfaces (docs/ref/todo/multi-interface-firewall-rule-plan.md
		// §2.3, T-05) has ON DELETE CASCADE from firewall_policies, but is
		// listed explicitly for the same reason policy_services/
		// policy_addresses are: match the existing wipe pattern's clarity over
		// implicit cascade behavior.
		"DELETE FROM policy_interfaces",
		"DELETE FROM firewall_policies",
		"DELETE FROM port_forwards",
		"DELETE FROM address_objects WHERE system = 0",
		"DELETE FROM service_objects WHERE type = 'custom'",
		"DELETE FROM static_routes WHERE type NOT IN ('system', 'defaultgateway')",
		"DELETE FROM qos_rules",
		// wan_uplinks (docs/ref/todo/multi-wan-failover-plan.md Task 12) — a
		// full list, same wipe-and-reinsert treatment as qos_rules just above.
		// wan_failover_settings is a single-row table restored via UPDATE
		// further down (same pattern as dhcp_health_settings), never wiped.
		"DELETE FROM wan_uplinks",
		"DELETE FROM dhcp_reservations",
		"DELETE FROM dhcp_configs",
		"DELETE FROM dns_records",
		"DELETE FROM dns_zones",
		"DELETE FROM dns_blocked_domains",
		"DELETE FROM wifi_presets",
	}
	for _, q := range wipes {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("wipe failed (%s): %w", q, err)
		}
	}

	// --- 2. Address objects (skip system; those were preserved) ----------
	for _, a := range cfg.Addresses {
		if a.System {
			continue
		}
		// Defense-in-depth only: BackupService.Import already normalized
		// legacy Type/Value into Entries (and validated every entry) before
		// this transaction started, fail-closed. NormalizeAddressObject is
		// idempotent and nil-safe, so calling it again here is a no-op for an
		// already-normalized object and only matters if RestoreConfig is ever
		// called directly with a pre-normalization cfg. The master row is
		// always written as a mirror of entry 1 (plan T-07 item 1).
		obj := a
		model.NormalizeAddressObject(&obj)
		if _, err := tx.Exec(
			"INSERT INTO address_objects (id, name, type, value, system) VALUES (?, ?, ?, ?, 0)",
			obj.ID, obj.Name, obj.Type, obj.Value,
		); err != nil {
			return fmt.Errorf("restore address %q: %w", obj.Name, err)
		}
		if err := replaceAddressEntries(tx, obj.ID, obj.Entries); err != nil {
			return fmt.Errorf("restore address %q entries: %w", obj.Name, err)
		}
	}

	// --- 3. Service objects (skip system) --------------------------------
	for _, s := range cfg.ServiceObjects {
		if s.Type == "system" {
			continue
		}
		// See the address-object loop above for why Normalize is called here
		// too (defense-in-depth; BackupService.Import already did this).
		obj := s
		model.NormalizeServiceObject(&obj)
		if _, err := tx.Exec(
			"INSERT INTO service_objects (id, name, protocol, port, type) VALUES (?, ?, ?, ?, 'custom')",
			obj.ID, obj.Name, obj.Protocol, obj.Port,
		); err != nil {
			return fmt.Errorf("restore service %q: %w", obj.Name, err)
		}
		if err := replaceServiceEntries(tx, obj.ID, obj.Entries); err != nil {
			return fmt.Errorf("restore service %q entries: %w", obj.Name, err)
		}
	}

	// --- 4. Firewall policies + junction relations -----------------------
	// Preserve the backup's ordering as priority (GetPolicies exported them
	// ordered by chain ASC, priority ASC). Priority is scoped per chain
	// (Caution 3), so each chain gets its own 1..N sequence rather than one
	// running counter across all three chains. Old backups that predate the
	// `chain` field have an empty Chain here — normalize to "forward" so the
	// CHECK constraint on the column does not fail the whole restore
	// (Caution 12/9).
	chainPriority := map[string]int{}
	for _, p := range cfg.Policies {
		chain := model.NormalizePolicyChain(p.Chain)
		chainPriority[chain]++
		// InInterfaces/OutInterfaces (docs/ref/todo/
		// multi-interface-firewall-rule-plan.md §2.3, T-05): normalize here,
		// AFTER the checksum verification that already ran earlier in
		// BackupService.Import (see decodeBackup Caution 1) — never move this
		// normalization before the checksum check. Old backups that predate
		// these fields have empty InInterfaces/OutInterfaces here; Normalize
		// seeds them from the legacy scalar InInterface/OutInterface (or
		// "ALL" if that is empty too), giving byte-identical behavior to
		// pre-feature backups.
		p.Chain = chain
		model.NormalizePolicyRuleInterfaces(&p)
		// Enforce the same per-direction interfaces cap the normal
		// CreatePolicy/UpdatePolicy path enforces (docs/ref/todo/
		// multi-interface-firewall-rule-plan.md §2.2, Caution 7: "เพดานต้อง
		// มาจาก config จุดเดียว — บังคับที่ repository เท่านั้น"). RestoreConfig
		// writes policy_interfaces directly via replacePolicyInterfaces below,
		// bypassing CreatePolicy/UpdatePolicy entirely, so without this check
		// here a crafted/foreign backup file could persist a policy with an
		// unbounded number of interfaces per direction — buildRuleExpressions'
		// in x out cartesian expansion (kernel/real_firewall.go) only enforces
		// max-expanded-rules-per-policy AFTER building the full expansion in
		// memory, so an unbounded interface count is a real memory/CPU DoS at
		// apply time, not just a bloated ruleset. Reject and roll back the
		// whole import (fail-closed) rather than silently truncating.
		if err := model.ValidatePolicyInterfaces(p.InInterfaces, r.maxPolicyInterfacesPerDirection); err != nil {
			return fmt.Errorf("restore policy %q inInterfaces: %w", p.Name, err)
		}
		if err := model.ValidatePolicyInterfaces(p.OutInterfaces, r.maxPolicyInterfacesPerDirection); err != nil {
			return fmt.Errorf("restore policy %q outInterfaces: %w", p.Name, err)
		}
		logVal, natVal, statVal := boolToInt(p.Log), boolToInt(p.Nat), boolToInt(p.Status)
		// monitored (docs/ref/todo/fqdn-retry-and-monitored-counters-plan.md
		// T-12, issue #141) round-trips through backup export/import like
		// every other policy flag — a backup file that predates this field
		// simply decodes p.Monitored as the Go zero value (false), which is
		// exactly the desired backward-compatible behavior (Caution 7: the
		// policy_rule_counters table itself is runtime data and is never
		// exported/imported — only the flag is).
		monVal := boolToInt(p.Monitored)
		if _, err := tx.Exec(
			"INSERT INTO firewall_policies (id, name, chain, in_interface, out_interface, action, log, nat, status, priority, monitored) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			p.ID, p.Name, chain, p.InInterface, p.OutInterface, p.Action, logVal, natVal, statVal, chainPriority[chain], monVal,
		); err != nil {
			return fmt.Errorf("restore policy %q: %w", p.Name, err)
		}
		if p.Monitored {
			now := time.Now().UTC().Format(time.RFC3339)
			if _, err := tx.Exec(
				"INSERT OR IGNORE INTO policy_rule_counters (policy_id, bytes, packets, started_at, updated_at) VALUES (?, 0, 0, ?, ?)",
				p.ID, now, now,
			); err != nil {
				return fmt.Errorf("restore policy %q counter row: %w", p.Name, err)
			}
		}
		if err := restorePolicyRelations(tx, p); err != nil {
			return err
		}
		if err := replacePolicyInterfaces(tx, p.ID, "in", p.InInterfaces); err != nil {
			return fmt.Errorf("restore policy %q interfaces (in): %w", p.Name, err)
		}
		if err := replacePolicyInterfaces(tx, p.ID, "out", p.OutInterfaces); err != nil {
			return fmt.Errorf("restore policy %q interfaces (out): %w", p.Name, err)
		}
	}

	// --- 4.1 Port forwards (DNAT) ----------------------------------------
	for _, pf := range cfg.PortForwards {
		if _, err := tx.Exec(
			"INSERT INTO port_forwards (id, name, in_interface, external_port, protocol, internal_ip, internal_port, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			pf.ID, pf.Name, pf.InInterface, pf.ExternalPort, strings.ToLower(pf.Protocol), pf.InternalIP, pf.InternalPort, boolToInt(pf.Status),
		); err != nil {
			return fmt.Errorf("restore port forward %q: %w", pf.Name, err)
		}
	}

	// --- 5. Static routes (skip system/defaultgateway) -------------------
	for _, rt := range cfg.StaticRoutes {
		if rt.Type == "system" || rt.Type == "defaultgateway" {
			continue
		}
		scope := rt.Scope
		if scope == "" {
			scope = "global"
		}
		proto := rt.Proto
		if proto == "" {
			proto = "static"
		}
		if _, err := tx.Exec(
			"INSERT INTO static_routes (id, destination, gateway, interface, metric, description, status, type, scope, src, proto) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			rt.ID, rt.Destination, rt.Gateway, rt.Interface, rt.Metric, rt.Description, boolToInt(rt.Status), rt.Type, scope, rt.Src, proto,
		); err != nil {
			return fmt.Errorf("restore route %q: %w", rt.Destination, err)
		}
	}

	// --- 6. QoS rules ----------------------------------------------------
	for _, q := range cfg.QosRules {
		if _, err := tx.Exec(
			`INSERT INTO qos_rules (id, name, interface, match_src_ip, match_dst_ip, egress_rate_mbps, egress_ceil_mbps, ingress_rate_mbps, ingress_ceil_mbps, priority, status, description)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			q.ID, q.Name, q.Interface, q.MatchSrcIP, q.MatchDstIP, q.EgressRateMbps, q.EgressCeilMbps, q.IngressRateMbps, q.IngressCeilMbps, q.Priority, boolToInt(q.Status), q.Description,
		); err != nil {
			return fmt.Errorf("restore qos rule %q: %w", q.Name, err)
		}
	}

	// --- 6b. Multi-WAN Failover uplinks (docs/ref/todo/
	// multi-wan-failover-plan.md Task 12) — probe_targets round-trips through
	// its comma-separated storage column, same convention as CreateWanUplink/
	// UpdateWanUplink in wan_repo.go.
	for _, u := range cfg.WanUplinks {
		if _, err := tx.Exec(
			`INSERT INTO wan_uplinks (
				id, name, interface, priority, probe_targets, probe_method, probe_tcp_port,
				probe_interval_seconds, probe_count, probe_timeout_ms, loss_threshold_pct, latency_threshold_ms,
				fail_strikes, recover_strikes, status, description
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			u.ID, u.Name, u.Interface, u.Priority, strings.Join(u.ProbeTargets, ","), u.ProbeMethod, u.ProbeTCPPort,
			u.ProbeIntervalSeconds, u.ProbeCount, u.ProbeTimeoutMs, u.LossThresholdPct, u.LatencyThresholdMs,
			u.FailStrikes, u.RecoverStrikes, boolToInt(u.Status), u.Description,
		); err != nil {
			return fmt.Errorf("restore wan uplink %q: %w", u.Name, err)
		}
	}

	// --- 7. DHCP configs + reservations ----------------------------------
	for _, d := range cfg.DhcpConfigs {
		id := d.ID
		if id == "" {
			id = fmt.Sprintf("dhcp-cfg-%s", d.Interface)
		}
		if _, err := tx.Exec(
			"INSERT INTO dhcp_configs (id, interface, enabled, start_ip, end_ip, gateway, netmask, dns1, dns2, lease_time, domain) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			id, d.Interface, boolToInt(d.Enabled), d.StartIP, d.EndIP, d.Gateway, d.Netmask, d.DNS1, d.DNS2, d.LeaseTime, d.Domain,
		); err != nil {
			return fmt.Errorf("restore dhcp config for %q: %w", d.Interface, err)
		}
	}
	for _, res := range cfg.DhcpReservations {
		if _, err := tx.Exec(
			"INSERT INTO dhcp_reservations (id, device_name, mac_address, ip_address) VALUES (?, ?, ?, ?)",
			res.ID, res.DeviceName, res.MacAddress, res.IPAddress,
		); err != nil {
			return fmt.Errorf("restore dhcp reservation %q: %w", res.MacAddress, err)
		}
	}

	// --- 8. DNS zones + records ------------------------------------------
	for _, z := range cfg.DnsZones {
		if _, err := tx.Exec(
			"INSERT INTO dns_zones (id, zone_name, forward_to, allowed_ips, is_authoritative, enabled) VALUES (?, ?, ?, ?, ?, ?)",
			z.ID, z.ZoneName, z.ForwardTo, z.AllowedIPs, boolToInt(z.IsAuthoritative), boolToInt(z.Enabled),
		); err != nil {
			return fmt.Errorf("restore dns zone %q: %w", z.ZoneName, err)
		}
		for _, rec := range z.Records {
			ttl := rec.TTL
			if ttl == 0 {
				ttl = 300
			}
			if _, err := tx.Exec(
				"INSERT INTO dns_records (id, zone_id, name, type, value, ttl, glue_ips, delegation_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
				rec.ID, z.ID, rec.Name, rec.Type, rec.Value, ttl, joinGlueIPs(rec.GlueIPs), rec.DelegationMode,
			); err != nil {
				return fmt.Errorf("restore dns record %q: %w", rec.Name, err)
			}
		}
	}

	// --- 8.0.1 DNS Server — blocked domains (deny-list) -------------------
	// A mode value that no longer matches the CHECK constraint (e.g. hand-edited
	// or from a future schema) is clamped to the default "nxdomain" rather than
	// failing the whole import — validateConfig already fail-closed rejected
	// anything ValidateBlockedDomain considers invalid, so a bad mode here can
	// only come from a value the CHECK constraint itself would reject.
	for _, b := range cfg.BlockedDomains {
		mode := b.Mode
		if mode != model.DNSBlockModeNXDomain && mode != model.DNSBlockModeSinkhole {
			mode = model.DNSBlockModeNXDomain
		}
		if _, err := tx.Exec(
			"INSERT INTO dns_blocked_domains (id, domain, mode, enabled, comment) VALUES (?, ?, ?, ?, ?)",
			b.ID, b.Domain, mode, boolToInt(b.Enabled), b.Comment,
		); err != nil {
			return fmt.Errorf("restore blocked domain %q: %w", b.Domain, err)
		}
	}

	// --- 8.1 Wi-Fi presets (plaintext password, restore-only path) -------
	for _, p := range cfg.Presets {
		if _, err := tx.Exec(
			"INSERT INTO wifi_presets (id, name, ssid, security, password, mac_mode) VALUES (?, ?, ?, ?, ?, ?)",
			p.ID, p.Name, p.SSID, p.Security, p.Password, p.MacMode,
		); err != nil {
			return fmt.Errorf("restore wifi preset %q: %w", p.Name, err)
		}
	}

	// --- 9. Single-row system settings -----------------------------------
	// These rows always exist (seeded); a backup that omits a section (e.g. a
	// legacy v1 file has no systemDns/dnsServerSettings) leaves the existing row
	// untouched rather than writing an invalid empty value.
	if cfg.DnsServerSettings.Interfaces != nil {
		// A backup file from before this feature existed (or a hand-edited one)
		// carries TTL/cap as 0 (missing JSON field) — clamp to the package
		// default rather than writing 0, which would mean "cache disabled"
		// (docs/ref/todo/statistics-dns-top-domain-plan.md T-02/T-11 item 13).
		ttl := cfg.DnsServerSettings.DNSCacheTTLMinutes
		if ttl < model.DNSCacheTTLMin || ttl > model.DNSCacheTTLMax {
			ttl = model.DNSCacheTTLDefault
		}
		maxEntries := cfg.DnsServerSettings.DNSCacheMaxEntries
		if maxEntries < model.DNSCacheEntriesMin || maxEntries > model.DNSCacheEntriesMax {
			maxEntries = model.DNSCacheEntriesDefault
		}
		// upstream_mode/upstream_servers (docs/ref/todo/
		// dns-server-settings-tab-and-upstream-plan.md T-07): a backup file
		// from before this feature existed carries an empty/unrecognized mode
		// — clamp to "system" rather than writing "" (an unrecognized mode).
		// upstream_servers values come from an external file, so filter with
		// net.ParseIP before writing, same discipline as the handler/kernel
		// layers (plan §5 item 1: 3 layers of defense).
		upstreamMode := cfg.DnsServerSettings.UpstreamMode
		if upstreamMode != model.DNSUpstreamModeSystem && upstreamMode != model.DNSUpstreamModeCustom {
			upstreamMode = model.DNSUpstreamModeSystem
		}
		validUpstreams := make([]string, 0, len(cfg.DnsServerSettings.UpstreamServers))
		for _, ip := range cfg.DnsServerSettings.UpstreamServers {
			if net.ParseIP(ip) == nil {
				continue
			}
			validUpstreams = append(validUpstreams, ip)
		}
		if _, err := tx.Exec(
			"UPDATE dns_server_settings SET interfaces = ?, query_logging = ?, dns_cache_ttl_minutes = ?, dns_cache_max_entries = ?, upstream_mode = ?, upstream_servers = ? WHERE id = 1",
			strings.Join(cfg.DnsServerSettings.Interfaces, ","), boolToInt(cfg.DnsServerSettings.QueryLogging), ttl, maxEntries, upstreamMode, strings.Join(validUpstreams, ","),
		); err != nil {
			return fmt.Errorf("restore dns server settings: %w", err)
		}
	}
	// System DNS (mode is CHECK-constrained to wan/static).
	if cfg.SystemDns.Mode != "" {
		if _, err := tx.Exec(
			"UPDATE system_dns_settings SET mode = ?, primary_dns = ?, secondary_dns = ?, local_domain = ? WHERE id = 1",
			cfg.SystemDns.Mode, cfg.SystemDns.PrimaryDNS, cfg.SystemDns.SecondaryDNS, cfg.SystemDns.LocalDomain,
		); err != nil {
			return fmt.Errorf("restore system dns: %w", err)
		}
	}
	// System time (Status is live-only and excluded from backup).
	if cfg.SystemTime.Timezone != "" {
		if _, err := tx.Exec(
			"UPDATE system_time_settings SET timezone = ?, ntp_sync = ?, ntp_server = ? WHERE id = 1",
			cfg.SystemTime.Timezone, boolToInt(cfg.SystemTime.NTPSync), cfg.SystemTime.NTPServer,
		); err != nil {
			return fmt.Errorf("restore system time: %w", err)
		}
	}
	// Hostname.
	if cfg.SystemHostname.Hostname != "" {
		if _, err := tx.Exec(
			"UPDATE system_hostname_settings SET hostname = ?, share_with_dhcp = ? WHERE id = 1",
			cfg.SystemHostname.Hostname, boolToInt(cfg.SystemHostname.ShareWithDhcp),
		); err != nil {
			return fmt.Errorf("restore hostname: %w", err)
		}
	}
	// DHCP health-checker settings (issue #78) — omitted (nil) in backups
	// taken before this field existed, so only restore when present.
	if cfg.DhcpHealthSettings != nil {
		if _, err := tx.Exec(
			`UPDATE dhcp_health_settings SET enabled = ?, check_interval_seconds = ?,
			consecutive_strikes = ?, min_running_seconds = ?, restart_backoff_seconds = ?,
			max_restarts_before_pause = ? WHERE id = 1`,
			boolToInt(cfg.DhcpHealthSettings.Enabled), cfg.DhcpHealthSettings.CheckIntervalSeconds,
			cfg.DhcpHealthSettings.ConsecutiveStrikes, cfg.DhcpHealthSettings.MinRunningSeconds,
			cfg.DhcpHealthSettings.RestartBackoffSeconds, cfg.DhcpHealthSettings.MaxRestartsBeforePause,
		); err != nil {
			return fmt.Errorf("restore dhcp health settings: %w", err)
		}
	}
	// Multi-WAN Failover settings (docs/ref/todo/multi-wan-failover-plan.md
	// Task 12) — same nil-check pattern as DhcpHealthSettings just above:
	// omitted in any backup taken before this feature existed.
	if cfg.WanFailoverSettings != nil {
		if _, err := tx.Exec(
			`UPDATE wan_failover_settings SET enabled = ?, mode = ?, manual_uplink_id = ?, min_hold_seconds = ?, revert_delay_seconds = ? WHERE id = 1`,
			boolToInt(cfg.WanFailoverSettings.Enabled), cfg.WanFailoverSettings.Mode,
			cfg.WanFailoverSettings.ManualUplinkID, cfg.WanFailoverSettings.MinHoldSeconds, cfg.WanFailoverSettings.RevertDelaySeconds,
		); err != nil {
			return fmt.Errorf("restore wan failover settings: %w", err)
		}
	}

	// --- 10. Interfaces (update-in-place; matched to existing rows) -------
	for _, iface := range cfg.Interfaces {
		if err := restoreInterface(tx, iface); err != nil {
			return err
		}
	}

	// --- 11. Users (optional) --------------------------------------------
	if includeUsers {
		if _, err := tx.Exec("DELETE FROM users"); err != nil {
			return fmt.Errorf("wipe users: %w", err)
		}
		for _, u := range cfg.Users {
			if _, err := tx.Exec(
				"INSERT INTO users (id, username, password_hash, is_initial, role, status) VALUES (?, ?, ?, ?, ?, ?)",
				u.ID, u.Username, u.PasswordHash, boolToInt(u.IsInitial), u.Role, u.Status,
			); err != nil {
				return fmt.Errorf("restore user %q: %w", u.Username, err)
			}
		}
	}

	return tx.Commit()
}

// restorePolicyRelations reinserts a policy's source/destination/service links,
// resolving object names to ids within the same transaction. Address/service
// objects (system + freshly restored custom) must already be inserted.
func restorePolicyRelations(tx *sql.Tx, p model.PolicyRule) error {
	link := func(names []string, assoc string) error {
		for _, name := range names {
			var addrID string
			if err := tx.QueryRow("SELECT id FROM address_objects WHERE name = ?", name).Scan(&addrID); err != nil {
				return fmt.Errorf("policy %q references missing address object %q", p.Name, name)
			}
			if _, err := tx.Exec("INSERT INTO policy_addresses (policy_id, address_id, association_type) VALUES (?, ?, ?)", p.ID, addrID, assoc); err != nil {
				return err
			}
		}
		return nil
	}
	if err := link(p.Source, "SOURCE"); err != nil {
		return err
	}
	if err := link(p.Destination, "DESTINATION"); err != nil {
		return err
	}
	for _, name := range p.Service {
		var svcID string
		if err := tx.QueryRow("SELECT id FROM service_objects WHERE name = ?", name).Scan(&svcID); err != nil {
			return fmt.Errorf("policy %q references missing service object %q", p.Name, name)
		}
		if _, err := tx.Exec("INSERT INTO policy_services (policy_id, service_id) VALUES (?, ?)", p.ID, svcID); err != nil {
			return err
		}
	}
	return nil
}

// restoreInterface updates the config fields of an existing interface row,
// matched by id. Hardware/runtime identity columns (name, type, mac_address,
// status, speed) are intentionally not written by the UPDATE — the caller
// (BackupService.Import) has already merged the backup's config fields onto the
// live device row, so those columns already hold the device's own values.
//
// If the UPDATE matches no row, the interface's DB row is missing entirely —
// either because it's a VLAN sub-interface that hasn't been re-created on the
// target board yet (issue #20), or because a physical interface's row was
// deleted while the device itself still exists ("unmanaged" state, issue #89).
// In both cases we INSERT the full row (identity fields included) so the
// interface is recreated rather than silently left absent. VLAN-only columns
// (vlan_parent, vlan_id) are only populated when the interface is actually a
// VLAN, to avoid stamping bogus VLAN linkage onto a physical interface.
func restoreInterface(tx *sql.Tx, iface model.NetworkInterface) error {
	adminAccess := strings.Join(iface.AdminAccess, ",")
	recon := 0
	if iface.RandomizeOnReconnect != nil && *iface.RandomizeOnReconnect {
		recon = 1
	}
	fo := 0
	if iface.FailoverEnabled != nil && *iface.FailoverEnabled {
		fo = 1
	}
	prefer5GHz := 0
	if iface.Prefer5GHz != nil && *iface.Prefer5GHz {
		prefer5GHz = 1
	}
	res, err := tx.Exec(`UPDATE network_interfaces SET
		alias = ?, role = ?, addressing_mode = ?, ip = ?, netmask = ?, gateway = ?, metric = ?, admin_access = ?,
		mac_mode = ?, randomized_mac = ?, laa_mac_address = ?, randomize_on_reconnect = ?,
		connected_ssid = ?, wifi_password = ?, wifi_security = ?, failover_enabled = ?, backup_ssid = ?, backup_wifi_password = ?, backup_wifi_security = ?,
		ip_check_timeout = ?, primary_max_retries = ?, failover_cooldown = ?, prefer_5ghz = ?
		WHERE id = ?`,
		iface.Alias, iface.Role, iface.AddressingMode, iface.IP, iface.Netmask, iface.Gateway, iface.Metric, adminAccess,
		iface.MacMode, iface.RandomizedMac, iface.LaaMacAddress, recon,
		iface.WifiSSID, iface.WifiPassword, iface.WifiSecurity, fo, iface.BackupSSID, iface.BackupWifiPassword, iface.BackupWifiSecurity,
		iface.IPCheckTimeout, iface.PrimaryMaxRetries, iface.FailoverCooldown, prefer5GHz, iface.ID)
	if err != nil {
		return fmt.Errorf("restore interface %q: %w", iface.Name, err)
	}

	// When the UPDATE matched no row, the interface's DB row is missing
	// entirely (VLAN not yet re-created on this board, or a physical
	// interface's row was deleted while the device still exists — see
	// issue #89). INSERT the full row, including identity fields, regardless
	// of subtype so the interface is recreated on restore.
	if n, _ := res.RowsAffected(); n == 0 {
		var vlanParent *string
		var vlanID *int
		if iface.Subtype == "vlan" {
			vlanParent = iface.VlanParent
			vlanID = iface.VlanID
		}
		if _, err := tx.Exec(`INSERT INTO network_interfaces (
			id, name, alias, role, type, subtype, addressing_mode, ip, netmask, gateway, metric, mac_address, admin_access, status, speed,
			mac_mode, randomized_mac, laa_mac_address, randomize_on_reconnect,
			connected_ssid, wifi_password, wifi_security, failover_enabled, backup_ssid, backup_wifi_password, backup_wifi_security,
			ip_check_timeout, primary_max_retries, failover_cooldown, vlan_parent, vlan_id, prefer_5ghz
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			iface.ID, iface.Name, iface.Alias, iface.Role, iface.Type, iface.Subtype, iface.AddressingMode, iface.IP, iface.Netmask, iface.Gateway, iface.Metric, iface.MacAddress, adminAccess, iface.Status, iface.Speed,
			iface.MacMode, iface.RandomizedMac, iface.LaaMacAddress, recon,
			iface.WifiSSID, iface.WifiPassword, iface.WifiSecurity, fo, iface.BackupSSID, iface.BackupWifiPassword, iface.BackupWifiSecurity,
			iface.IPCheckTimeout, iface.PrimaryMaxRetries, iface.FailoverCooldown, vlanParent, vlanID, prefer5GHz); err != nil {
			return fmt.Errorf("restore interface %q: %w", iface.Name, err)
		}
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
