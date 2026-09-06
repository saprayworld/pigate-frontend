package db

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// InitDB initializes SQLite connection, runs table migrations, and seeds initial data.
func InitDB(dsn string, isMock ...bool) (*sql.DB, error) {
	mockMode := true
	if len(isMock) > 0 {
		mockMode = isMock[0]
	}

	// If it is a file-based DB, ensure the parent directory exists
	if dsn != ":memory:" {
		dir := filepath.Dir(dsn)
		if dir != "." && dir != "/" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create db directory: %w", err)
			}
		}
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Enable WAL mode and foreign keys for better concurrency and integrity
	if dsn != ":memory:" {
		if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
			return nil, fmt.Errorf("failed to set WAL mode: %w", err)
		}
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON;"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	if err := backupDatabase(dsn); err != nil {
		log.Printf("[Warning] Failed to backup database: %v", err)
	}

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("database migration failed: %w", err)
	}

	if err := seed(db, dsn, mockMode); err != nil {
		return nil, fmt.Errorf("database seeding failed: %w", err)
	}

	return db, nil
}

func migrate(db *sql.DB) error {
	// Rebuild static_routes table if existing schema doesn't support defaultgateway type in CHECK constraint or advanced fields
	var sqlCreate string
	err := db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='static_routes'").Scan(&sqlCreate)
	if err == nil {
		if !strings.Contains(sqlCreate, "'customgateway'") || !strings.Contains(sqlCreate, "scope") {
			migrationQueries := []string{
				"PRAGMA foreign_keys=OFF;",
				`CREATE TABLE static_routes_new (
					id TEXT PRIMARY KEY,
					destination TEXT NOT NULL,
					gateway TEXT NOT NULL,
					interface TEXT NOT NULL,
					metric INTEGER DEFAULT 0,
					description TEXT,
					status INTEGER DEFAULT 1 CHECK(status IN (0, 1)),
					type TEXT NOT NULL CHECK(type IN ('system', 'custom', 'defaultgateway', 'customgateway')),
					scope TEXT DEFAULT 'global',
					src TEXT DEFAULT '',
					proto TEXT DEFAULT 'static'
				);`,
				"INSERT INTO static_routes_new (id, destination, gateway, interface, metric, description, status, type, scope, src, proto) SELECT id, destination, gateway, interface, metric, description, status, type, 'global', '', 'static' FROM static_routes;",
				"DROP TABLE static_routes;",
				"ALTER TABLE static_routes_new RENAME TO static_routes;",
				"PRAGMA foreign_keys=ON;",
			}
			for _, q := range migrationQueries {
				if _, err := db.Exec(q); err != nil {
					return fmt.Errorf("failed to migrate static_routes table: %w (query: %s)", err, q)
				}
			}
		}
	}

	// Rebuild network_interfaces table if existing schema doesn't support 'offline' status in CHECK constraint
	var sqlCreateIface string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='network_interfaces'").Scan(&sqlCreateIface)
	if err == nil {
		if !strings.Contains(sqlCreateIface, "'offline'") {
			migrationQueries := []string{
				"PRAGMA foreign_keys=OFF;",
				`CREATE TABLE network_interfaces_new (
					id TEXT PRIMARY KEY,
					name TEXT UNIQUE NOT NULL,
					alias TEXT NOT NULL,
					role TEXT NOT NULL CHECK(role IN ('LAN', 'WAN')),
					type TEXT NOT NULL CHECK(type IN ('ethernet', 'wireless')),
					addressing_mode TEXT NOT NULL CHECK(addressing_mode IN ('dhcp', 'static')),
					ip TEXT NOT NULL,
					netmask TEXT NOT NULL,
					gateway TEXT NOT NULL,
					mac_address TEXT NOT NULL,
					admin_access TEXT NOT NULL,
					status TEXT NOT NULL CHECK(status IN ('up', 'down', 'offline')),
					speed TEXT NOT NULL,
					connected_ssid TEXT,
					wifi_password TEXT,
					wifi_security TEXT,
					mac_mode TEXT CHECK(mac_mode IN ('hardware', 'randomized', 'laa')),
					real_mac_address TEXT,
					randomized_mac TEXT,
					laa_mac_address TEXT,
					randomize_on_reconnect INTEGER DEFAULT 0,
					failover_enabled INTEGER DEFAULT 0,
					backup_ssid TEXT,
					backup_wifi_password TEXT,
					backup_wifi_security TEXT DEFAULT 'WPA2',
					ip_check_timeout INTEGER,
					primary_max_retries INTEGER,
					failover_cooldown INTEGER
				);`,
				`INSERT INTO network_interfaces_new (
					id, name, alias, role, type, addressing_mode, ip, netmask, gateway, mac_address, admin_access, status, speed,
					connected_ssid, wifi_password, wifi_security, mac_mode, real_mac_address, randomized_mac, laa_mac_address, 
					randomize_on_reconnect, failover_enabled, backup_ssid, backup_wifi_password, backup_wifi_security, ip_check_timeout, primary_max_retries, failover_cooldown
				) SELECT 
					id, name, alias, role, type, addressing_mode, ip, netmask, gateway, mac_address, admin_access, status, speed,
					connected_ssid, wifi_password, wifi_security, mac_mode, real_mac_address, randomized_mac, laa_mac_address, 
					randomize_on_reconnect, failover_enabled, backup_ssid, backup_wifi_password, 'WPA2', ip_check_timeout, primary_max_retries, failover_cooldown 
				FROM network_interfaces;`,
				"DROP TABLE network_interfaces;",
				"ALTER TABLE network_interfaces_new RENAME TO network_interfaces;",
				"PRAGMA foreign_keys=ON;",
			}
			for _, q := range migrationQueries {
				if _, err := db.Exec(q); err != nil {
					return fmt.Errorf("failed to migrate network_interfaces table: %w (query: %s)", err, q)
				}
			}
		}
	}

	// Rebuild dns_records table if the existing CHECK constraint on `type` doesn't
	// yet include 'NS' (docs/ref/todo/dns-ns-record-support-plan.md). SQLite can't
	// ALTER a CHECK constraint in place, so rebuild the table the same way as
	// static_routes/network_interfaces above: create a new table with the wider
	// constraint, copy all existing rows, drop the old table, rename. Detected via
	// the CHECK constraint token "'NS'" so this only runs once, on upgrade.
	var sqlCreateDNSRecords string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='dns_records'").Scan(&sqlCreateDNSRecords)
	if err == nil {
		if !strings.Contains(sqlCreateDNSRecords, "'NS'") {
			migrationQueries := []string{
				"PRAGMA foreign_keys=OFF;",
				`CREATE TABLE dns_records_new (
					id         TEXT PRIMARY KEY,
					zone_id    TEXT NOT NULL,
					name       TEXT NOT NULL,
					type       TEXT NOT NULL CHECK(type IN ('A','AAAA','CNAME','MX','TXT','PTR','NS')),
					value      TEXT NOT NULL,
					ttl        INTEGER DEFAULT 300,
					created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
					FOREIGN KEY (zone_id) REFERENCES dns_zones(id) ON DELETE CASCADE
				);`,
				"INSERT INTO dns_records_new (id, zone_id, name, type, value, ttl, created_at) SELECT id, zone_id, name, type, value, ttl, created_at FROM dns_records;",
				"DROP TABLE dns_records;",
				"ALTER TABLE dns_records_new RENAME TO dns_records;",
				"PRAGMA foreign_keys=ON;",
			}
			for _, q := range migrationQueries {
				if _, err := db.Exec(q); err != nil {
					return fmt.Errorf("failed to migrate dns_records table: %w (query: %s)", err, q)
				}
			}
			log.Println("[Migration] Rebuilt dns_records table to allow 'NS' in the type CHECK constraint")
		}
	}

	// Add glue_ips column to dns_records if it doesn't exist
	// (docs/ref/todo/dns-ns-delegation-plan.md T-03). Additive only — no
	// CHECK constraint changes, so a plain ALTER is enough (unlike the
	// 'NS' rebuild above). NOT NULL DEFAULT '' means every pre-existing
	// row reads back as "no glue" = the previous publish-only behaviour.
	// Must run after the 'NS' rebuild above: an old DB that still needs
	// that rebuild has a dns_records table (created via
	// CREATE TABLE dns_records_new above) that does not have glue_ips yet,
	// so this block re-queries sqlite_master fresh rather than reusing
	// sqlCreateDNSRecords (which reflects the pre-rebuild schema).
	var sqlCreateDNSRecordsGlue string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='dns_records'").Scan(&sqlCreateDNSRecordsGlue)
	if err == nil {
		if !strings.Contains(sqlCreateDNSRecordsGlue, "glue_ips") {
			_, err = db.Exec("ALTER TABLE dns_records ADD COLUMN glue_ips TEXT NOT NULL DEFAULT ''")
			if err != nil {
				return fmt.Errorf("failed to add glue_ips column: %w", err)
			}
			log.Println("[Migration] Added glue_ips column to dns_records table")
		}
	}

	// Add delegation_mode column to dns_records if it doesn't exist
	// (docs/ref/todo/dns-ns-delegation-cname-fix-plan.md T-03). Additive only,
	// same pattern as glue_ips above. NOT NULL DEFAULT '' means every
	// pre-existing row reads back as "" -> model.EffectiveNSDelegationMode
	// normalizes that to "glue" = the previous forwarding behaviour, byte for
	// byte. Must run after the glue_ips block above (and re-query
	// sqlite_master fresh into its own variable — reusing
	// sqlCreateDNSRecordsGlue would read the pre-ALTER schema).
	var sqlCreateDNSRecordsDelegationMode string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='dns_records'").Scan(&sqlCreateDNSRecordsDelegationMode)
	if err == nil {
		if !strings.Contains(sqlCreateDNSRecordsDelegationMode, "delegation_mode") {
			_, err = db.Exec("ALTER TABLE dns_records ADD COLUMN delegation_mode TEXT NOT NULL DEFAULT ''")
			if err != nil {
				return fmt.Errorf("failed to add delegation_mode column: %w", err)
			}
			log.Println("[Migration] Added delegation_mode column to dns_records table")
		}
	}

	// Add subtype column to network_interfaces if it doesn't exist
	var sqlCreateIfaceSubtype string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='network_interfaces'").Scan(&sqlCreateIfaceSubtype)
	if err == nil {
		if !strings.Contains(sqlCreateIfaceSubtype, "subtype") {
			_, err = db.Exec("ALTER TABLE network_interfaces ADD COLUMN subtype TEXT DEFAULT ''")
			if err != nil {
				return fmt.Errorf("failed to add subtype column: %w", err)
			}
		}
	}

	// Add backup_wifi_security column to network_interfaces if it doesn't exist
	var sqlCreateIfaceBackupSecurity string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='network_interfaces'").Scan(&sqlCreateIfaceBackupSecurity)
	if err == nil {
		if !strings.Contains(sqlCreateIfaceBackupSecurity, "backup_wifi_security") {
			_, err = db.Exec("ALTER TABLE network_interfaces ADD COLUMN backup_wifi_security TEXT DEFAULT 'WPA2'")
			if err != nil {
				return fmt.Errorf("failed to add backup_wifi_security column: %w", err)
			}
		}
	}

	// Add metric column to network_interfaces if it doesn't exist.
	// Nullable (no NOT NULL/DEFAULT) so "unset" (NULL) stays distinct from metric 0.
	var sqlCreateIfaceMetric string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='network_interfaces'").Scan(&sqlCreateIfaceMetric)
	if err == nil {
		if !strings.Contains(sqlCreateIfaceMetric, "metric") {
			_, err = db.Exec("ALTER TABLE network_interfaces ADD COLUMN metric INTEGER")
			if err != nil {
				return fmt.Errorf("failed to add metric column: %w", err)
			}
		}
	}

	// Add vlan_parent/vlan_id columns to network_interfaces if they don't exist.
	// Both nullable — only populated for rows with subtype='vlan', immutable after
	// creation (change VLAN ID/parent = delete + recreate). These let VLAN links be
	// re-created from the DB on boot (InitApplyConfigurationAtStartup).
	var sqlCreateIfaceVlan string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='network_interfaces'").Scan(&sqlCreateIfaceVlan)
	if err == nil {
		if !strings.Contains(sqlCreateIfaceVlan, "vlan_parent") {
			_, err = db.Exec("ALTER TABLE network_interfaces ADD COLUMN vlan_parent TEXT")
			if err != nil {
				return fmt.Errorf("failed to add vlan_parent column: %w", err)
			}
		}
		if !strings.Contains(sqlCreateIfaceVlan, "vlan_id") {
			_, err = db.Exec("ALTER TABLE network_interfaces ADD COLUMN vlan_id INTEGER")
			if err != nil {
				return fmt.Errorf("failed to add vlan_id column: %w", err)
			}
		}
	}

	// Add prefer_5ghz column to network_interfaces if it doesn't exist.
	// Radio-level toggle to restrict the Wi-Fi client to 5GHz channels (freq_list in
	// wpa_supplicant config, generated by a later task); defaults to 0 (disabled).
	var sqlCreateIfacePrefer5GHz string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='network_interfaces'").Scan(&sqlCreateIfacePrefer5GHz)
	if err == nil {
		if !strings.Contains(sqlCreateIfacePrefer5GHz, "prefer_5ghz") {
			_, err = db.Exec("ALTER TABLE network_interfaces ADD COLUMN prefer_5ghz INTEGER DEFAULT 0")
			if err != nil {
				return fmt.Errorf("failed to add prefer_5ghz column: %w", err)
			}
		}
	}

	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			is_initial INTEGER DEFAULT 0,
			role TEXT NOT NULL DEFAULT 'super_admin' CHECK(role IN ('super_admin', 'admin_readonly')),
			status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'disabled')),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS address_objects (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			type TEXT NOT NULL CHECK(type IN ('subnet', 'range', 'fqdn')),
			value TEXT NOT NULL,
			system INTEGER DEFAULT 0 CHECK(system IN (0, 1)),
			comment TEXT
		);`,

		`CREATE TABLE IF NOT EXISTS service_objects (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			protocol TEXT NOT NULL CHECK(protocol IN ('TCP', 'UDP', 'TCP/UDP', 'ICMP')),
			port TEXT NOT NULL,
			type TEXT NOT NULL CHECK(type IN ('system', 'custom')),
			comment TEXT
		);`,

		// address_object_values / service_object_ports (docs/ref/todo/
		// multi-value-address-service-objects-plan.md §3 items 1/2, D-4): child
		// tables are the source of truth for the (possibly many) match entries of
		// an Address/Service object. The parent tables' type/value and
		// protocol/port columns above are now a TEMPORARY compat mirror of the
		// first entry (seq=1) only — kept solely because (a) they are NOT NULL
		// with a CHECK constraint and older SQLite has no DROP COLUMN, and (b)
		// they let a downgraded binary keep working during the transition. They
		// are written on every create/update for backward compatibility but must
		// NEVER be read again to generate firewall rules; new code must read the
		// entries from these child tables instead. Planned removal in the next
		// major version.
		`CREATE TABLE IF NOT EXISTS address_object_values (
			address_id TEXT NOT NULL,
			seq        INTEGER NOT NULL,
			type       TEXT NOT NULL CHECK(type IN ('subnet', 'range', 'fqdn')),
			value      TEXT NOT NULL,
			PRIMARY KEY (address_id, seq),
			FOREIGN KEY (address_id) REFERENCES address_objects(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS service_object_ports (
			service_id TEXT NOT NULL,
			seq        INTEGER NOT NULL,
			protocol   TEXT NOT NULL CHECK(protocol IN ('TCP', 'UDP', 'TCP/UDP', 'ICMP')),
			port       TEXT NOT NULL,
			PRIMARY KEY (service_id, seq),
			FOREIGN KEY (service_id) REFERENCES service_objects(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS firewall_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			chain TEXT NOT NULL DEFAULT 'forward' CHECK(chain IN ('forward', 'input', 'output')),
			in_interface TEXT NOT NULL,
			out_interface TEXT NOT NULL,
			action TEXT NOT NULL CHECK(action IN ('ACCEPT', 'DROP')),
			log INTEGER DEFAULT 0 CHECK(log IN (0, 1)),
			status INTEGER DEFAULT 1 CHECK(status IN (0, 1)),
			priority INTEGER NOT NULL,
			monitored INTEGER NOT NULL DEFAULT 0 CHECK(monitored IN (0, 1))
		);`,

		`CREATE TABLE IF NOT EXISTS policy_addresses (
			policy_id TEXT NOT NULL,
			address_id TEXT NOT NULL,
			association_type TEXT NOT NULL CHECK(association_type IN ('SOURCE', 'DESTINATION')),
			PRIMARY KEY (policy_id, address_id, association_type),
			FOREIGN KEY (policy_id) REFERENCES firewall_policies(id) ON DELETE CASCADE,
			FOREIGN KEY (address_id) REFERENCES address_objects(id) ON DELETE RESTRICT
		);`,

		`CREATE TABLE IF NOT EXISTS policy_services (
			policy_id TEXT NOT NULL,
			service_id TEXT NOT NULL,
			PRIMARY KEY (policy_id, service_id),
			FOREIGN KEY (policy_id) REFERENCES firewall_policies(id) ON DELETE CASCADE,
			FOREIGN KEY (service_id) REFERENCES service_objects(id) ON DELETE RESTRICT
		);`,

		// policy_interfaces (docs/ref/todo/multi-interface-firewall-rule-plan.md
		// §2.3, D-1/D-3): child table is the source of truth for the (possibly
		// many) in/out interface names of a PolicyRule. The parent table's
		// in_interface/out_interface columns above are now a TEMPORARY compat
		// mirror of the first entry (seq=1) per direction only — kept solely
		// because they are NOT NULL and let a downgraded binary keep working
		// during the transition. They are written on every create/update for
		// backward compatibility but must NEVER be read again to generate
		// firewall rules; new code must read the interfaces from this child
		// table instead. Planned removal in the next major version.
		`CREATE TABLE IF NOT EXISTS policy_interfaces (
			policy_id TEXT NOT NULL,
			direction TEXT NOT NULL CHECK(direction IN ('in', 'out')),
			seq       INTEGER NOT NULL,
			name      TEXT NOT NULL,
			PRIMARY KEY (policy_id, direction, seq),
			FOREIGN KEY (policy_id) REFERENCES firewall_policies(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS policy_rule_counters (
			policy_id TEXT PRIMARY KEY,
			bytes INTEGER NOT NULL DEFAULT 0,
			packets INTEGER NOT NULL DEFAULT 0,
			started_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			endpoints_evicted INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (policy_id) REFERENCES firewall_policies(id) ON DELETE CASCADE
		);`,

		// Persisted rule endpoints (docs/ref/todo/persisted-rule-endpoints-plan.md
		// E-D3, issue #141 follow-up). One row per unique (policy, direction,
		// endpoint_key) seen while the policy has Monitor enabled and Log
		// enabled. `direction` is 'src'/'dst'/'svc'; `endpoint_key` is an IP
		// literal for src/dst or "PROTO/PORT" for svc.
		`CREATE TABLE IF NOT EXISTS policy_rule_endpoints (
			policy_id TEXT NOT NULL,
			direction TEXT NOT NULL CHECK(direction IN ('src', 'dst', 'svc')),
			endpoint_key TEXT NOT NULL,
			count INTEGER NOT NULL DEFAULT 0,
			first_seen_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL,
			PRIMARY KEY (policy_id, direction, endpoint_key),
			FOREIGN KEY (policy_id) REFERENCES firewall_policies(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_policy_rule_endpoints_lru ON policy_rule_endpoints(policy_id, direction, last_seen_at);`,

		`CREATE TABLE IF NOT EXISTS port_forwards (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			in_interface TEXT NOT NULL,
			external_port TEXT NOT NULL,
			protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
			internal_ip TEXT NOT NULL,
			internal_port TEXT NOT NULL DEFAULT '',
			status INTEGER DEFAULT 1 CHECK(status IN (0, 1))
		);`,

		`CREATE TABLE IF NOT EXISTS static_routes (
			id TEXT PRIMARY KEY,
			destination TEXT NOT NULL,
			gateway TEXT NOT NULL,
			interface TEXT NOT NULL,
			metric INTEGER DEFAULT 0,
			description TEXT,
			status INTEGER DEFAULT 1 CHECK(status IN (0, 1)),
			type TEXT NOT NULL CHECK(type IN ('system', 'custom', 'defaultgateway', 'customgateway')),
			scope TEXT DEFAULT 'global',
			src TEXT DEFAULT '',
			proto TEXT DEFAULT 'static'
		);`,

		`CREATE TABLE IF NOT EXISTS dhcp_configs (
			id          TEXT PRIMARY KEY,
			interface   TEXT NOT NULL UNIQUE,
			enabled     INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
			start_ip    TEXT NOT NULL,
			end_ip      TEXT NOT NULL,
			gateway     TEXT NOT NULL,
			netmask     TEXT NOT NULL,
			dns1        TEXT NOT NULL DEFAULT '8.8.8.8',
			dns2        TEXT NOT NULL DEFAULT '1.1.1.1',
			lease_time  INTEGER NOT NULL DEFAULT 86400,
			domain      TEXT NOT NULL DEFAULT '',
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS dhcp_leases (
			mac_address TEXT NOT NULL PRIMARY KEY,
			ip_address  TEXT NOT NULL,
			hostname    TEXT,
			interface   TEXT,
			expires_at  DATETIME
		);`,

		`CREATE TABLE IF NOT EXISTS dns_zones (
			id               TEXT PRIMARY KEY,
			zone_name        TEXT NOT NULL UNIQUE,
			forward_to       TEXT,
			allowed_ips      TEXT,
			is_authoritative INTEGER DEFAULT 1 CHECK(is_authoritative IN (0, 1)),
			enabled          INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
			created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS dns_records (
			id         TEXT PRIMARY KEY,
			zone_id    TEXT NOT NULL,
			name       TEXT NOT NULL,
			type       TEXT NOT NULL CHECK(type IN ('A','AAAA','CNAME','MX','TXT','PTR','NS')),
			value      TEXT NOT NULL,
			ttl        INTEGER DEFAULT 300,
			glue_ips   TEXT NOT NULL DEFAULT '',
			delegation_mode TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (zone_id) REFERENCES dns_zones(id) ON DELETE CASCADE
		);`,

		// Deny-list of blocked domains for the DNS Server (docs/ref/todo/
		// dns-blocked-domains-plan.md). A new, standalone table — additive to
		// dns_zones/dns_records, so no ALTER migration is needed here.
		`CREATE TABLE IF NOT EXISTS dns_blocked_domains (
			id         TEXT PRIMARY KEY,
			domain     TEXT NOT NULL UNIQUE COLLATE NOCASE,
			mode       TEXT NOT NULL DEFAULT 'nxdomain' CHECK(mode IN ('nxdomain','sinkhole')),
			enabled    INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
			comment    TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,

		// Listen interfaces for the DNS Server (auth-server binding). Kept independent
		// from dhcp_configs so DNS Server interface selection doesn't depend on DHCP Server state.
		`CREATE TABLE IF NOT EXISTS dns_server_settings (
			id         INTEGER PRIMARY KEY CHECK(id = 1),
			interfaces TEXT NOT NULL DEFAULT ''
		);`,

		`CREATE TABLE IF NOT EXISTS dhcp_reservations (
			id TEXT PRIMARY KEY,
			device_name TEXT NOT NULL,
			mac_address TEXT UNIQUE NOT NULL,
			ip_address TEXT NOT NULL
		);`,

		`CREATE TABLE IF NOT EXISTS system_time_settings (
			id INTEGER PRIMARY KEY CHECK(id = 1),
			timezone TEXT NOT NULL,
			ntp_sync INTEGER DEFAULT 1 CHECK(ntp_sync IN (0, 1)),
			ntp_server TEXT NOT NULL
		);`,

		`CREATE TABLE IF NOT EXISTS system_hostname_settings (
			id INTEGER PRIMARY KEY CHECK(id = 1),
			hostname TEXT NOT NULL,
			share_with_dhcp INTEGER DEFAULT 0 CHECK(share_with_dhcp IN (0,1))
		);`,

		// dhcp_health_settings: tunable thresholds for the DHCP link-local
		// (169.254.x.x APIPA) fallback health-checker (issue #78). Single-row
		// table mirroring system_hostname_settings/system_time_settings.
		`CREATE TABLE IF NOT EXISTS dhcp_health_settings (
			id INTEGER PRIMARY KEY CHECK(id = 1),
			enabled INTEGER DEFAULT 1 CHECK(enabled IN (0,1)),
			check_interval_seconds INTEGER NOT NULL DEFAULT 60,
			consecutive_strikes INTEGER NOT NULL DEFAULT 3,
			min_running_seconds INTEGER NOT NULL DEFAULT 30,
			restart_backoff_seconds INTEGER NOT NULL DEFAULT 300,
			max_restarts_before_pause INTEGER NOT NULL DEFAULT 3
		);`,

		// wan_uplinks / wan_failover_settings: configured WAN paths + the
		// global failover kill switch (docs/ref/todo/multi-wan-failover-plan.md
		// Task 2). probe_targets is a comma-separated list of IPv4 literals
		// (mirrors dns_server_settings.upstream_servers's storage convention,
		// see db/repository.go GetDNSServerSettings) — validated as IPv4-only,
		// non-hostname entries by model.ValidateWanUplink before being
		// persisted, so no injection concern from the comma-join/split. Phase 1
		// (this migration) is entirely read-only with respect to
		// routing/nftables (D-1) — these tables only ever feed the read-only
		// health monitor; nothing here is consulted by any kernel-mutating
		// code path yet. wan_failover_settings.enabled defaults to 0 (kill
		// switch OFF) so installing this feature changes nothing on an
		// existing deployment until an operator opts in (plan Caution 9).
		// There is intentionally no failover_on_degraded column (D-7).
		`CREATE TABLE IF NOT EXISTS wan_uplinks (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			interface TEXT UNIQUE NOT NULL,
			priority INTEGER NOT NULL DEFAULT 1,
			probe_targets TEXT NOT NULL DEFAULT '',
			probe_method TEXT NOT NULL DEFAULT 'auto' CHECK(probe_method IN ('icmp', 'tcp', 'auto')),
			probe_tcp_port INTEGER NOT NULL DEFAULT 0,
			probe_interval_seconds INTEGER NOT NULL DEFAULT 5,
			probe_count INTEGER NOT NULL DEFAULT 3,
			probe_timeout_ms INTEGER NOT NULL DEFAULT 1000,
			loss_threshold_pct REAL NOT NULL DEFAULT 50,
			latency_threshold_ms REAL NOT NULL DEFAULT 200,
			fail_strikes INTEGER NOT NULL DEFAULT 3,
			recover_strikes INTEGER NOT NULL DEFAULT 3,
			status INTEGER NOT NULL DEFAULT 1 CHECK(status IN (0,1)),
			description TEXT NOT NULL DEFAULT ''
		);`,

		`CREATE TABLE IF NOT EXISTS wan_failover_settings (
			id INTEGER PRIMARY KEY CHECK(id = 1),
			enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
			mode TEXT NOT NULL DEFAULT 'auto' CHECK(mode IN ('auto', 'manual')),
			manual_uplink_id TEXT NOT NULL DEFAULT '',
			min_hold_seconds INTEGER NOT NULL DEFAULT 60,
			revert_delay_seconds INTEGER NOT NULL DEFAULT 120
		);`,

		`CREATE TABLE IF NOT EXISTS network_interfaces (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			alias TEXT NOT NULL,
			role TEXT NOT NULL CHECK(role IN ('LAN', 'WAN')),
			type TEXT NOT NULL CHECK(type IN ('ethernet', 'wireless')),
			subtype TEXT DEFAULT '',
			addressing_mode TEXT NOT NULL CHECK(addressing_mode IN ('dhcp', 'static')),
			ip TEXT NOT NULL,
			netmask TEXT NOT NULL,
			gateway TEXT NOT NULL,
			metric INTEGER,
			mac_address TEXT NOT NULL,
			admin_access TEXT NOT NULL, -- comma separated values like "PING,HTTP,SSH"
			status TEXT NOT NULL CHECK(status IN ('up', 'down', 'offline')),
			speed TEXT NOT NULL,
			-- Wireless specific optional fields
			connected_ssid TEXT,
			wifi_password TEXT,
			wifi_security TEXT,
			mac_mode TEXT CHECK(mac_mode IN ('hardware', 'randomized', 'laa')),
			real_mac_address TEXT,
			randomized_mac TEXT,
			laa_mac_address TEXT,
			randomize_on_reconnect INTEGER DEFAULT 0,
			failover_enabled INTEGER DEFAULT 0,
			backup_ssid TEXT,
			backup_wifi_password TEXT,
			backup_wifi_security TEXT DEFAULT 'WPA2',
			ip_check_timeout INTEGER,
			primary_max_retries INTEGER,
			failover_cooldown INTEGER,
			-- VLAN (802.1Q) sub-interface fields (populated only when subtype='vlan')
			vlan_parent TEXT,
			vlan_id INTEGER,
			prefer_5ghz INTEGER DEFAULT 0
		);`,

		`CREATE TABLE IF NOT EXISTS system_dns_settings (
			id INTEGER PRIMARY KEY CHECK(id = 1),
			mode TEXT NOT NULL CHECK(mode IN ('wan', 'static')),
			primary_dns TEXT NOT NULL,
			secondary_dns TEXT NOT NULL,
			local_domain TEXT NOT NULL DEFAULT 'pigate.local'
		);`,

		`CREATE TABLE IF NOT EXISTS qos_rules (
			id                TEXT PRIMARY KEY,
			name              TEXT NOT NULL,
			interface         TEXT NOT NULL,
			match_src_ip      TEXT NOT NULL DEFAULT '',
			match_dst_ip      TEXT NOT NULL DEFAULT '',
			egress_rate_mbps  INTEGER NOT NULL DEFAULT 0,
			egress_ceil_mbps  INTEGER NOT NULL DEFAULT 0,
			ingress_rate_mbps INTEGER NOT NULL DEFAULT 0,
			ingress_ceil_mbps INTEGER NOT NULL DEFAULT 0,
			priority          INTEGER NOT NULL DEFAULT 10,
			status            INTEGER NOT NULL DEFAULT 1 CHECK(status IN (0, 1)),
			description       TEXT NOT NULL DEFAULT '',
			created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,

		// Central audit/event log. Rows are inserted in async batches by
		// EventLogService and pruned to a fixed cap — deliberately excluded from
		// config backup/restore (history, not configuration).
		`CREATE TABLE IF NOT EXISTS system_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL,
			category TEXT NOT NULL,
			action TEXT NOT NULL,
			severity TEXT NOT NULL,
			actor TEXT,
			target TEXT,
			message TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_system_events_category ON system_events(category);`,
		`CREATE INDEX IF NOT EXISTS idx_system_events_severity ON system_events(severity);`,

		// Saved Wi-Fi networks ("known networks" library, issue #66). A preset is
		// just a template: applying it copies its fields into the target
		// interface's primary/backup Wi-Fi slot (network_interfaces) — it is not a
		// live link, so editing a preset afterwards does not touch interfaces that
		// already applied it. Password is plaintext (matches
		// network_interfaces.wifi_password) but write-only from the API's
		// perspective — see model.WifiPreset.
		`CREATE TABLE IF NOT EXISTS wifi_presets (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			ssid TEXT NOT NULL,
			security TEXT NOT NULL DEFAULT 'WPA2',
			password TEXT DEFAULT '',
			mac_mode TEXT DEFAULT '' CHECK(mac_mode IN ('', 'hardware', 'randomized', 'laa')),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}

	// Add domain column to dhcp_configs if it doesn't exist (DHCP option 15 support).
	var sqlDhcpDomain string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='dhcp_configs'").Scan(&sqlDhcpDomain)
	if err == nil && !strings.Contains(sqlDhcpDomain, "domain") {
		if _, err = db.Exec("ALTER TABLE dhcp_configs ADD COLUMN domain TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("failed to add domain column: %w", err)
		}
	}

	// Add query_logging/dns_cache_ttl_minutes/dns_cache_max_entries columns to
	// dns_server_settings if they don't exist (docs/ref/todo/
	// statistics-dns-top-domain-plan.md T-02) — an already-installed DB must
	// upgrade in place, not require a restore. Defaults match model.DNSCacheTTLDefault/
	// DNSCacheEntriesDefault (60/4096) so an upgraded row reads sane values
	// immediately, not 0 (which would mean "cache disabled").
	var sqlCreateDNSServerSettings string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='dns_server_settings'").Scan(&sqlCreateDNSServerSettings)
	if err == nil {
		if !strings.Contains(sqlCreateDNSServerSettings, "query_logging") {
			if _, err = db.Exec("ALTER TABLE dns_server_settings ADD COLUMN query_logging INTEGER NOT NULL DEFAULT 0"); err != nil {
				return fmt.Errorf("failed to add query_logging column: %w", err)
			}
		}
		if !strings.Contains(sqlCreateDNSServerSettings, "dns_cache_ttl_minutes") {
			if _, err = db.Exec("ALTER TABLE dns_server_settings ADD COLUMN dns_cache_ttl_minutes INTEGER NOT NULL DEFAULT 60"); err != nil {
				return fmt.Errorf("failed to add dns_cache_ttl_minutes column: %w", err)
			}
		}
		if !strings.Contains(sqlCreateDNSServerSettings, "dns_cache_max_entries") {
			if _, err = db.Exec("ALTER TABLE dns_server_settings ADD COLUMN dns_cache_max_entries INTEGER NOT NULL DEFAULT 4096"); err != nil {
				return fmt.Errorf("failed to add dns_cache_max_entries column: %w", err)
			}
		}
		// Add upstream_mode/upstream_servers columns (docs/ref/todo/
		// dns-server-settings-tab-and-upstream-plan.md T-02). DEFAULT 'system'
		// preserves byte-for-byte identical generated pigate-dns.conf output for
		// already-installed DBs (the DNS Server keeps reading System DNS at
		// generate-time, same as before this feature existed).
		if !strings.Contains(sqlCreateDNSServerSettings, "upstream_mode") {
			if _, err = db.Exec("ALTER TABLE dns_server_settings ADD COLUMN upstream_mode TEXT NOT NULL DEFAULT 'system'"); err != nil {
				return fmt.Errorf("failed to add upstream_mode column: %w", err)
			}
		}
		if !strings.Contains(sqlCreateDNSServerSettings, "upstream_servers") {
			if _, err = db.Exec("ALTER TABLE dns_server_settings ADD COLUMN upstream_servers TEXT NOT NULL DEFAULT ''"); err != nil {
				return fmt.Errorf("failed to add upstream_servers column: %w", err)
			}
		}
	}

	// Migrate data from old dhcp_config (if it exists) to new dhcp_configs
	var sqlCreateOldDhcpConfig string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='dhcp_config'").Scan(&sqlCreateOldDhcpConfig)
	if err == nil {
		// Old table exists, check if new table has any records. If new table is empty, migrate the old record.
		var newCount int
		err = db.QueryRow("SELECT COUNT(*) FROM dhcp_configs").Scan(&newCount)
		if err == nil && newCount == 0 {
			row := db.QueryRow("SELECT enabled, interface, start_ip, end_ip, gateway, netmask, dns1, dns2, lease_time FROM dhcp_config WHERE id = 1")
			var enabled, leaseTime int
			var iface, startIP, endIP, gateway, netmask, dns1, dns2 string
			errScan := row.Scan(&enabled, &iface, &startIP, &endIP, &gateway, &netmask, &dns1, &dns2, &leaseTime)
			if errScan == nil {
				_, errInsert := db.Exec(`INSERT INTO dhcp_configs 
					(id, interface, enabled, start_ip, end_ip, gateway, netmask, dns1, dns2, lease_time) 
					VALUES ('dhcp-cfg-default', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					iface, enabled, startIP, endIP, gateway, netmask, dns1, dns2, leaseTime)
				if errInsert != nil {
					return fmt.Errorf("failed to migrate data from dhcp_config to dhcp_configs: %w", errInsert)
				}
				log.Println("[Migration] Successfully migrated old DHCP config to dhcp_configs table")
			}
		}
		// Drop old table
		_, errDrop := db.Exec("DROP TABLE dhcp_config;")
		if errDrop != nil {
			return fmt.Errorf("failed to drop old dhcp_config table: %w", errDrop)
		}
		log.Println("[Migration] Successfully dropped old dhcp_config table")
	}

	// Add is_initial column to users table if it doesn't exist
	var sqlCreateUsers string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").Scan(&sqlCreateUsers)
	if err == nil {
		if !strings.Contains(sqlCreateUsers, "is_initial") {
			_, err = db.Exec("ALTER TABLE users ADD COLUMN is_initial INTEGER DEFAULT 0")
			if err != nil {
				return fmt.Errorf("failed to add is_initial column to users table: %w", err)
			}
		}

		// Add role/status columns for the multi-user system. Detect via the
		// unique CHECK-constraint tokens ('admin_readonly' / 'disabled') rather
		// than the bare column names, which could collide with other substrings.
		// Existing rows (e.g. the legacy "pigate" account) inherit the column
		// DEFAULT of super_admin/active, so an upgraded box never locks out.
		if !strings.Contains(sqlCreateUsers, "admin_readonly") {
			_, err = db.Exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'super_admin' CHECK(role IN ('super_admin', 'admin_readonly'))")
			if err != nil {
				return fmt.Errorf("failed to add role column to users table: %w", err)
			}
		}
		if !strings.Contains(sqlCreateUsers, "'disabled'") {
			_, err = db.Exec("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'disabled'))")
			if err != nil {
				return fmt.Errorf("failed to add status column to users table: %w", err)
			}
		}
	}

	// Policy-based source NAT (issue #43). Add a per-policy `nat` toggle to
	// firewall_policies. NAT used to be automatic on every interface with
	// Role=WAN; it now comes solely from the policy's NAT flag. To preserve
	// behaviour across the upgrade we do a one-shot data migration inside the
	// same guard branch as the ADD COLUMN (so it runs exactly once, when the
	// column is first added — running it every boot would flip nat=0 that an
	// admin later set back to 1). We backfill nat=1 on every ACCEPT policy that
	// egresses a WAN interface, or that leaves the egress unrestricted ('' or
	// 'ALL'), matching the old "masquerade everything leaving WAN" behaviour.
	// This runs after all CREATE TABLE statements above, so network_interfaces
	// is readable; on a brand-new DB both tables are empty and the UPDATE is a
	// no-op.
	var sqlCreatePolicies string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='firewall_policies'").Scan(&sqlCreatePolicies)
	if err == nil {
		if !strings.Contains(sqlCreatePolicies, "nat") {
			if _, err = db.Exec("ALTER TABLE firewall_policies ADD COLUMN nat INTEGER DEFAULT 0 CHECK(nat IN (0, 1))"); err != nil {
				return fmt.Errorf("failed to add nat column to firewall_policies table: %w", err)
			}
			res, errUpd := db.Exec(`UPDATE firewall_policies SET nat = 1 WHERE action = 'ACCEPT' AND (
				out_interface IN (SELECT name FROM network_interfaces WHERE UPPER(role) = 'WAN')
				OR out_interface IN ('', 'ALL'))`)
			if errUpd != nil {
				return fmt.Errorf("failed to backfill nat on firewall_policies: %w", errUpd)
			}
			if n, _ := res.RowsAffected(); n > 0 {
				log.Printf("[Migration] Policy-based source NAT: enabled nat on %d existing ACCEPT policy(ies) egressing WAN/ALL to preserve behaviour. Review your firewall policies — policies with out_interface 'ALL' now masquerade LAN-bound traffic too.", n)
			}
		}
	}

	// Input/Output chain firewall policies (docs/ref/todo/input-output-chain-firewall-plan.md).
	// Add a `chain` column so a PolicyRule can target the input/output nftables
	// base chains in addition to forward. Detect via the CHECK constraint token
	// "'output'" rather than the word "chain" (which could appear elsewhere in
	// the CREATE statement in the future) — existing rows get 'forward' via the
	// column DEFAULT, preserving current behaviour exactly.
	var sqlCreatePoliciesChain string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='firewall_policies'").Scan(&sqlCreatePoliciesChain)
	if err == nil {
		if !strings.Contains(sqlCreatePoliciesChain, "'output'") {
			if _, err = db.Exec("ALTER TABLE firewall_policies ADD COLUMN chain TEXT NOT NULL DEFAULT 'forward' CHECK(chain IN ('forward', 'input', 'output'))"); err != nil {
				return fmt.Errorf("failed to add chain column to firewall_policies table: %w", err)
			}
		}
	}

	// Persisted "Monitor" opt-in counters (docs/ref/todo/
	// fqdn-retry-and-monitored-counters-plan.md T-05, issue #141). Add a
	// per-policy `monitored` flag to firewall_policies. Detect via the
	// column name "monitored" (unambiguous — no other column/constraint in
	// this table's CREATE statement contains that substring). No backfill
	// beyond the column DEFAULT of 0 — a fresh upgrade never auto-enables
	// monitoring on any existing rule.
	var sqlCreatePoliciesMonitored string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='firewall_policies'").Scan(&sqlCreatePoliciesMonitored)
	if err == nil {
		if !strings.Contains(sqlCreatePoliciesMonitored, "monitored") {
			if _, err = db.Exec("ALTER TABLE firewall_policies ADD COLUMN monitored INTEGER NOT NULL DEFAULT 0 CHECK(monitored IN (0, 1))"); err != nil {
				return fmt.Errorf("failed to add monitored column to firewall_policies table: %w", err)
			}
		}
	}

	// Persisted rule endpoints (docs/ref/todo/persisted-rule-endpoints-plan.md
	// E-D3, issue #141 follow-up). Add `endpoints_evicted` to
	// policy_rule_counters (a dev machine may already have this table from
	// before this migration, created without the column). Detect via the
	// column name "endpoints_evicted" (unambiguous). No backfill beyond the
	// column DEFAULT of 0.
	var sqlCreateRuleCountersEvicted string
	err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='policy_rule_counters'").Scan(&sqlCreateRuleCountersEvicted)
	if err == nil {
		if !strings.Contains(sqlCreateRuleCountersEvicted, "endpoints_evicted") {
			if _, err = db.Exec("ALTER TABLE policy_rule_counters ADD COLUMN endpoints_evicted INTEGER NOT NULL DEFAULT 0"); err != nil {
				return fmt.Errorf("failed to add endpoints_evicted column to policy_rule_counters table: %w", err)
			}
		}
	}

	// Normalize legacy timezone values. Older seeds stored the display string
	// "Asia/Bangkok (GMT+7:00)" instead of a bare IANA name, which both
	// time.LoadLocation and systemd-timedated reject. Strip anything from the
	// first " (" onwards. Idempotent: values without the suffix are untouched.
	if err := normalizeTimezoneSetting(db); err != nil {
		return fmt.Errorf("failed to normalize legacy timezone value: %w", err)
	}

	// Interface aliases are displayed as the primary interface label (issue #25), so
	// they must be unique. Existing databases may hold empty or duplicate aliases
	// (an old PUT could persist ""), which would make CREATE UNIQUE INDEX fail and
	// abort boot — normalize and de-duplicate before creating the index.
	if err := ensureUniqueAliasIndex(db); err != nil {
		return fmt.Errorf("failed to enforce unique interface aliases: %w", err)
	}

	// HTTPS (443) becomes the primary admin channel (issue #27). On an upgraded box
	// the firewall now drops non-HTTPS/whitelisted traffic and HTTP 308-redirects to
	// HTTPS, so any interface whose admin_access already allows the web UI over HTTP
	// but not HTTPS would lock the admin out of 443. Backfill HTTPS on exactly those
	// rows before the listener starts serving.
	if err := ensureHTTPSAdminAccess(db); err != nil {
		return fmt.Errorf("failed to backfill HTTPS admin access: %w", err)
	}

	return nil
}

// ensureHTTPSAdminAccess adds "HTTPS" to the comma-separated admin_access of every
// interface that already allows "HTTP" but not "HTTPS". Rows that do not expose the
// web UI over HTTP (e.g. a WAN interface with just "PING") are intentionally left
// untouched — the presence of HTTP is the signal that admin web access is desired.
// Idempotent: a second run finds no HTTP-without-HTTPS rows and changes nothing.
func ensureHTTPSAdminAccess(db *sql.DB) error {
	rows, err := db.Query("SELECT id, admin_access FROM network_interfaces")
	if err != nil {
		return err
	}
	type ifaceRow struct{ id, adminAccess string }
	var toUpdate []ifaceRow
	for rows.Next() {
		var r ifaceRow
		if err := rows.Scan(&r.id, &r.adminAccess); err != nil {
			rows.Close()
			return err
		}
		tokens := strings.Split(r.adminAccess, ",")
		hasHTTP, hasHTTPS := false, false
		for _, t := range tokens {
			switch strings.ToUpper(strings.TrimSpace(t)) {
			case "HTTP":
				hasHTTP = true
			case "HTTPS":
				hasHTTPS = true
			}
		}
		if hasHTTP && !hasHTTPS {
			toUpdate = append(toUpdate, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, r := range toUpdate {
		// Insert HTTPS immediately after HTTP so the stored order reads
		// "...,HTTP,HTTPS,...", matching the seed/default ordering.
		tokens := strings.Split(r.adminAccess, ",")
		out := make([]string, 0, len(tokens)+1)
		for _, t := range tokens {
			out = append(out, t)
			if strings.EqualFold(strings.TrimSpace(t), "HTTP") {
				out = append(out, "HTTPS")
			}
		}
		updated := strings.Join(out, ",")
		if _, err := db.Exec("UPDATE network_interfaces SET admin_access = ? WHERE id = ?", updated, r.id); err != nil {
			return fmt.Errorf("failed to backfill HTTPS admin_access for interface %s: %w", r.id, err)
		}
		log.Printf("[Migration] Added HTTPS admin access to interface %s (admin_access %q -> %q)", r.id, r.adminAccess, updated)
	}
	return nil
}

// ensureUniqueAliasIndex normalizes interface aliases (empty -> the interface's own
// name, duplicates -> own name plus a numeric suffix when even that is taken) and
// then creates the case-insensitive unique index that enforces uniqueness from then
// on. Runs after the CREATE TABLE queries so it works on both fresh and existing
// databases; safe to run repeatedly.
func ensureUniqueAliasIndex(db *sql.DB) error {
	if _, err := db.Exec("UPDATE network_interfaces SET alias = name WHERE TRIM(alias) = ''"); err != nil {
		return fmt.Errorf("failed to normalize empty aliases: %w", err)
	}

	rows, err := db.Query("SELECT id, name, alias FROM network_interfaces ORDER BY rowid")
	if err != nil {
		return err
	}
	type ifaceRow struct{ id, name, alias string }
	var all []ifaceRow
	for rows.Next() {
		var r ifaceRow
		if err := rows.Scan(&r.id, &r.name, &r.alias); err != nil {
			rows.Close()
			return err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	taken := make(map[string]bool, len(all))
	for _, r := range all {
		key := strings.ToLower(r.alias)
		if !taken[key] {
			taken[key] = true
			continue
		}
		// Duplicate (case-insensitive): fall back to the row's own name, which is
		// UNIQUE — unless another row happens to use that name as its alias, then
		// append a numeric suffix until free.
		candidate := r.name
		for i := 2; taken[strings.ToLower(candidate)]; i++ {
			candidate = fmt.Sprintf("%s_%d", r.name, i)
		}
		if _, err := db.Exec("UPDATE network_interfaces SET alias = ? WHERE id = ?", candidate, r.id); err != nil {
			return fmt.Errorf("failed to de-duplicate alias for interface %s: %w", r.name, err)
		}
		log.Printf("[Migration] Warning: interface %s had duplicate alias %q, renamed to %q", r.name, r.alias, candidate)
		taken[strings.ToLower(candidate)] = true
	}

	if _, err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_network_interfaces_alias ON network_interfaces(alias COLLATE NOCASE)"); err != nil {
		return fmt.Errorf("failed to create unique alias index: %w", err)
	}
	return nil
}

// normalizeTimezoneSetting rewrites a legacy timezone value like
// "Asia/Bangkok (GMT+7:00)" to the bare IANA form "Asia/Bangkok". Safe to run
// repeatedly. If the row is missing it is a no-op.
func normalizeTimezoneSetting(db *sql.DB) error {
	var tz string
	err := db.QueryRow("SELECT timezone FROM system_time_settings WHERE id = 1").Scan(&tz)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}

	normalized := NormalizeTimezone(tz)
	if normalized == tz {
		return nil
	}

	_, err = db.Exec("UPDATE system_time_settings SET timezone = ? WHERE id = 1", normalized)
	if err != nil {
		return err
	}
	log.Printf("[Migration] Normalized legacy timezone %q -> %q", tz, normalized)
	return nil
}

// NormalizeTimezone strips a trailing " (GMT...)"-style suffix from a timezone
// string, returning the bare IANA name. Exported so the config-import path can
// reuse it on old backup files. It does not validate the result — callers that
// need validation must do it separately.
func NormalizeTimezone(tz string) string {
	tz = strings.TrimSpace(tz)
	if idx := strings.Index(tz, " ("); idx >= 0 {
		tz = strings.TrimSpace(tz[:idx])
	}
	return tz
}

func generateRandomPassword(length int) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		result[i] = chars[num.Int64()]
	}
	return string(result), nil
}

func seed(db *sql.DB, dsn string, mockMode bool) error {
	// 1. Seed Default Admin User if empty
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		var password string
		var hash []byte
		var err error

		if dsn == ":memory:" {
			// For automated testing in memory, use static password "pigate"
			password = "pigate"
			hash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("failed to hash default test password: %w", err)
			}
		} else {
			// For real execution, generate a secure random password
			password, err = generateRandomPassword(16)
			if err != nil {
				return fmt.Errorf("failed to generate random password: %w", err)
			}
			hash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("failed to hash random password: %w", err)
			}
		}

		isInitialVal := 1
		if dsn == ":memory:" {
			isInitialVal = 0
		}
		_, err = db.Exec(`INSERT INTO users (id, username, password_hash, is_initial, role, status) VALUES (
			'user-pigate', 'pigate', ?, ?, 'super_admin', 'active'
		)`, string(hash), isInitialVal)
		if err != nil {
			return err
		}

		if dsn != ":memory:" {
			log.Printf("==================================================================")
			log.Printf("  PiGate First Run initialization")
			log.Printf("  Generated random password for user 'pigate': %s", password)
			log.Printf("==================================================================")
		}
	}

	// 2. Seed Default Predefined Address Objects
	var addrCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM address_objects").Scan(&addrCount); err != nil {
		return err
	}
	if addrCount == 0 {
		_, err := db.Exec(`INSERT INTO address_objects (id, name, type, value, system, comment) VALUES 
			('addr-1', 'ALL', 'subnet', '0.0.0.0/0', 1, 'Default fallback subnet object')`)
		if err != nil {
			return err
		}
	}

	// 3. Seed Default Predefined Service Objects
	var svcCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM service_objects").Scan(&svcCount); err != nil {
		return err
	}
	if svcCount == 0 {
		_, err := db.Exec(`INSERT INTO service_objects (id, name, protocol, port, type, comment) VALUES 
			('svc-1', 'ALL', 'TCP/UDP', '1-65535', 'system', 'All services and ports wildcard'),
			('svc-2', 'HTTP', 'TCP', '80', 'system', 'Web plain HTTP service'),
			('svc-3', 'HTTPS', 'TCP', '443', 'system', 'Web secure HTTPS service'),
			('svc-4', 'SSH', 'TCP', '22', 'system', 'Remote Secure Shell service'),
			('svc-5', 'DNS', 'UDP', '53', 'system', 'Domain Name System service'),
			('svc-6', 'ICMP', 'ICMP', '-', 'system', 'Internet Control Message Protocol')`)
		if err != nil {
			return err
		}
	}

	// 3.1 Backfill address_object_values / service_object_ports (docs/ref/todo/
	// multi-value-address-service-objects-plan.md §3 item 3, D-2). Must run
	// AFTER the default object seeds above so freshly-seeded rows (addr-1,
	// svc-1..svc-6) get a seq=1 child row too, in addition to any pre-existing
	// user objects from before this migration. The `WHERE NOT EXISTS` guard
	// makes this safe to run on every InitDB call (idempotent) and safe across
	// a downgrade-then-upgrade cycle, without ever touching/duplicating a row
	// that already has children — no user data is ever lost or overwritten here.
	if res, err := db.Exec(`
		INSERT INTO address_object_values (address_id, seq, type, value)
		SELECT a.id, 1, a.type, a.value
		FROM address_objects a
		WHERE NOT EXISTS (SELECT 1 FROM address_object_values v WHERE v.address_id = a.id)
	`); err != nil {
		return fmt.Errorf("failed to backfill address_object_values: %w", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[Migration] Backfilled %d row(s) into address_object_values", n)
	}

	if res, err := db.Exec(`
		INSERT INTO service_object_ports (service_id, seq, protocol, port)
		SELECT s.id, 1, s.protocol, s.port
		FROM service_objects s
		WHERE NOT EXISTS (SELECT 1 FROM service_object_ports p WHERE p.service_id = s.id)
	`); err != nil {
		return fmt.Errorf("failed to backfill service_object_ports: %w", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[Migration] Backfilled %d row(s) into service_object_ports", n)
	}

	// 3.2 Backfill policy_interfaces (docs/ref/todo/
	// multi-interface-firewall-rule-plan.md §2.3, T-03). Same idempotent
	// `WHERE NOT EXISTS` pattern as the address/service backfills above:
	// safe to run on every InitDB call, and safe across a
	// downgrade-then-upgrade cycle. Empty/whitespace-only legacy values are
	// treated as "ALL" (matches model.NormalizePolicyRuleInterfaces).
	if res, err := db.Exec(`
		INSERT INTO policy_interfaces (policy_id, direction, seq, name)
		SELECT p.id, 'in', 1, CASE WHEN TRIM(p.in_interface) = '' THEN 'ALL' ELSE p.in_interface END
		FROM firewall_policies p
		WHERE NOT EXISTS (SELECT 1 FROM policy_interfaces i WHERE i.policy_id = p.id AND i.direction = 'in')
	`); err != nil {
		return fmt.Errorf("failed to backfill policy_interfaces (in): %w", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[Migration] Backfilled %d row(s) into policy_interfaces (direction=in)", n)
	}

	if res, err := db.Exec(`
		INSERT INTO policy_interfaces (policy_id, direction, seq, name)
		SELECT p.id, 'out', 1, CASE WHEN TRIM(p.out_interface) = '' THEN 'ALL' ELSE p.out_interface END
		FROM firewall_policies p
		WHERE NOT EXISTS (SELECT 1 FROM policy_interfaces i WHERE i.policy_id = p.id AND i.direction = 'out')
	`); err != nil {
		return fmt.Errorf("failed to backfill policy_interfaces (out): %w", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[Migration] Backfilled %d row(s) into policy_interfaces (direction=out)", n)
	}

	// 4. Seed Default DHCP Configuration
	var dhcpCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM dhcp_configs").Scan(&dhcpCount); err != nil {
		return err
	}
	if dhcpCount == 0 {
		_, err := db.Exec(`INSERT INTO dhcp_configs (id, enabled, interface, start_ip, end_ip, gateway, netmask, dns1, dns2, lease_time) VALUES 
			('dhcp-cfg-default', 0, 'eth0', '192.168.1.100', '192.168.1.200', '192.168.1.1', '255.255.255.0', '8.8.8.8', '1.1.1.1', 86400)`)
		if err != nil {
			return err
		}
	}

	// 5. Seed Default System Time Settings
	var timeCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM system_time_settings").Scan(&timeCount); err != nil {
		return err
	}
	if timeCount == 0 {
		_, err := db.Exec(`INSERT INTO system_time_settings (id, timezone, ntp_sync, ntp_server) VALUES
			(1, 'Asia/Bangkok', 1, 'pool.ntp.org')`)
		if err != nil {
			return err
		}
	}

	// 5.1 Seed Default System Hostname Settings (from actual OS hostname, never hardcoded)
	var hostnameCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM system_hostname_settings").Scan(&hostnameCount); err != nil {
		return err
	}
	if hostnameCount == 0 {
		defaultHostname, err := os.Hostname()
		if err != nil || defaultHostname == "" {
			defaultHostname = "pigate"
		}
		_, err = db.Exec(`INSERT INTO system_hostname_settings (id, hostname, share_with_dhcp) VALUES (1, ?, 0)`, defaultHostname)
		if err != nil {
			return err
		}
	}

	// 5.2 Seed Default DHCP Health-Checker Settings (issue #78)
	var dhcpHealthCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM dhcp_health_settings").Scan(&dhcpHealthCount); err != nil {
		return err
	}
	if dhcpHealthCount == 0 {
		_, err := db.Exec(`INSERT INTO dhcp_health_settings (id, enabled, check_interval_seconds, consecutive_strikes, min_running_seconds, restart_backoff_seconds, max_restarts_before_pause) VALUES
			(1, 1, 60, 3, 30, 300, 3)`)
		if err != nil {
			return err
		}
	}

	// 5.3 Seed Default WAN Failover Settings (docs/ref/todo/
	// multi-wan-failover-plan.md Task 2) — enabled=0 (kill switch OFF) so a
	// fresh install/upgrade never changes routing behavior until an operator
	// opts in (plan Caution 9).
	var wanFailoverCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM wan_failover_settings").Scan(&wanFailoverCount); err != nil {
		return err
	}
	if wanFailoverCount == 0 {
		_, err := db.Exec(`INSERT OR IGNORE INTO wan_failover_settings (id, enabled, mode, manual_uplink_id, min_hold_seconds, revert_delay_seconds) VALUES
			(1, 0, 'auto', '', 60, 120)`)
		if err != nil {
			return err
		}
	}

	// 6. Seed Default System Interfaces for mock purposes
	if mockMode {
		var ifaceCount int
		if err := db.QueryRow("SELECT COUNT(*) FROM network_interfaces").Scan(&ifaceCount); err != nil {
			return err
		}
		if ifaceCount == 0 {
			_, err := db.Exec(`INSERT INTO network_interfaces (
				id, name, alias, role, type, subtype, addressing_mode, ip, netmask, gateway, mac_address, admin_access, status, speed,
				mac_mode, real_mac_address, randomized_mac, laa_mac_address, randomize_on_reconnect,
				connected_ssid, wifi_security, failover_enabled, backup_ssid, backup_wifi_password, backup_wifi_security, ip_check_timeout, primary_max_retries, failover_cooldown
			) VALUES 
			(
				'iface-1', 'eth0', 'LAN_Internal', 'LAN', 'ethernet', 'device', 'static', '192.168.1.1', '24', '', 'DC:A6:32:AA:BB:C1', 'PING,HTTP,HTTPS,SSH', 'up', '1000 Mbps',
				'hardware', 'DC:A6:32:AA:BB:C1', NULL, NULL, 0, NULL, NULL, 0, NULL, NULL, 'WPA2', NULL, NULL, NULL
			),
			(
				'iface-2', 'wlan0', 'WAN_WiFi', 'WAN', 'wireless', 'device', 'dhcp', '10.0.0.45', '24', '10.0.0.1', '4E:88:2F:BC:A1:90', 'PING', 'up', '72 Mbps',
				'randomized', 'DC:A6:32:AA:BB:C2', '4E:88:2F:BC:A1:90', '9A:11:22:33:44:55', 1,
				'MyHome_5G', 'WPA2-PSK', 0, 'MyHome_2G', 'backupPassword123', 'WPA2', 15, 3, 60
			)`)
			if err != nil {
				return err
			}
		}
	}

	// 7. Seed Default Static Routes (Only custom or customgateway)
	if mockMode {
		var routeCount int
		if err := db.QueryRow("SELECT COUNT(*) FROM static_routes").Scan(&routeCount); err != nil {
			return err
		}
		if routeCount == 0 {
			_, err := db.Exec(`INSERT INTO static_routes (id, destination, gateway, interface, metric, description, status, type, scope, src, proto) VALUES 
				('route-custom-seed', '8.8.8.8/32', '10.0.0.1', 'wlan0', 100, 'Google DNS Route', 1, 'customgateway', 'global', '', 'static')`)
			if err != nil {
				return err
			}
		}
	}

	// 8. Seed Default System DNS settings
	var dnsCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM system_dns_settings").Scan(&dnsCount); err != nil {
		return err
	}
	if dnsCount == 0 {
		_, err := db.Exec(`INSERT INTO system_dns_settings (id, mode, primary_dns, secondary_dns, local_domain)
			VALUES (1, 'static', '1.1.1.1', '8.8.8.8', 'pigate.local')`)
		if err != nil {
			return err
		}
	}

	// 9. Seed Default DNS Server settings (no interfaces selected until user configures)
	var dnsServerSettingsCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM dns_server_settings").Scan(&dnsServerSettingsCount); err != nil {
		return err
	}
	if dnsServerSettingsCount == 0 {
		if _, err := db.Exec(`INSERT INTO dns_server_settings (id, interfaces) VALUES (1, '')`); err != nil {
			return err
		}
	}

	return nil
}

func backupDatabase(dbPath string) error {
	_, err := SnapshotDatabase(dbPath, "backup")
	return err
}

// SnapshotDatabase copies the SQLite database file to a timestamped sibling file
// named "<dbPath>.<suffix>-<timestamp>". It returns the path of the snapshot it
// wrote (empty when there was nothing to copy, e.g. an in-memory DB or a
// not-yet-created file). Used both for the startup safety backup ("backup") and
// the pre-import snapshot ("backup-preimport"). Callers that need the WAL flushed
// into the main file first should Checkpoint() before calling this.
func SnapshotDatabase(dbPath, suffix string) (string, error) {
	if dbPath == ":memory:" || dbPath == "" {
		return "", nil
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// Database doesn't exist yet, nothing to snapshot.
		return "", nil
	}

	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.%s-%s", dbPath, suffix, timestamp)

	input, err := os.ReadFile(dbPath)
	if err != nil {
		return "", fmt.Errorf("failed to read database file for backup: %w", err)
	}

	if err := os.WriteFile(backupPath, input, 0644); err != nil {
		return "", fmt.Errorf("failed to write database backup file: %w", err)
	}

	log.Printf("[Backup] Database snapshot written to %s", backupPath)
	return backupPath, nil
}
