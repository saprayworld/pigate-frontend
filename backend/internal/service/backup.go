package service

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"pigate/internal/db"
	"pigate/internal/model"
)

// dnsBlocklistBackupCapBytes bounds the total size (post-gzip, post-base64)
// of every DNSBlocklistFilePayload carried in one export (docs/ref/todo/
// dns-blocklist-import-plan.md §2.4) — a 93k-domain list gzips down to
// roughly ~500 KB (~700 KB base64), so 8 MiB comfortably covers several large
// lists while still keeping a backup file well under the 10 MB body cap
// HandleImportConfig enforces on the way back in (handlers.go). Lists beyond
// the cap are simply omitted from the export (a warning is logged, not
// returned — BackupFile carries no warnings field) rather than growing the
// backup unboundedly.
const dnsBlocklistBackupCapBytes = 8 << 20

// BackupService owns configuration export/import. Export only needs the
// repository; import additionally drives every subsystem service so restored DB
// state is re-applied to the kernel in the same order as startup.
type BackupService struct {
	repo       *db.Repository
	dbPath     string
	appVersion string

	interfaceService  *InterfaceService
	routingService    *RoutingService
	firewallService   *FirewallService
	dnsService        *DNSService
	dnsServerService  *DNSServerService
	qosService        *QosService
	dhcpServerService *DhcpServerService
	dhcpcdService     *DhcpcdService
	hostnameService   *HostnameService
	timeService       *TimeService
	monitor           *NetlinkMonitor

	// counterStore is the optional PolicyCounterStore (docs/ref/todo/
	// fqdn-retry-and-monitored-counters-plan.md T-12, issue #141), wired
	// post-construction via SetCounterStore (additive-setter pattern,
	// consistent with e.g. PolicyStatsService.SetDomainLookup) so
	// NewBackupService's already-long parameter list never changes. When
	// set, Import calls Reload() after a successful restore so the RAM
	// cache reflects the DB's post-import policy_rule_counters state
	// instead of stale pre-import values.
	counterStore *PolicyCounterStore

	// blocklistService is the optional DNSBlocklistService (docs/ref/todo/
	// dns-blocklist-import-plan.md §2.4/T-09), wired post-construction via
	// SetBlocklistService for the same reason as counterStore above —
	// NewBackupService's parameter list stays unchanged. When set, Export
	// includes the manifest's lists (+ selected .hosts file payloads) and
	// Import restores them. The DNS blocklist feature intentionally never
	// uses SQLite (plan §2.3/R1), so it cannot be folded into
	// repo.RestoreConfig's transaction the way every other table is — it is
	// handled as its own step, both here in Export/Import.
	blocklistService *DNSBlocklistService
}

// SetCounterStore wires the optional PolicyCounterStore — see the
// counterStore field doc comment above.
func (s *BackupService) SetCounterStore(store *PolicyCounterStore) {
	s.counterStore = store
}

// SetBlocklistService wires the optional DNSBlocklistService — see the
// blocklistService field doc comment above.
func (s *BackupService) SetBlocklistService(svc *DNSBlocklistService) {
	s.blocklistService = svc
}

func NewBackupService(
	repo *db.Repository,
	dbPath, appVersion string,
	interfaceService *InterfaceService,
	routingService *RoutingService,
	firewallService *FirewallService,
	dnsService *DNSService,
	dnsServerService *DNSServerService,
	qosService *QosService,
	dhcpServerService *DhcpServerService,
	dhcpcdService *DhcpcdService,
	hostnameService *HostnameService,
	timeService *TimeService,
	monitor *NetlinkMonitor,
) *BackupService {
	return &BackupService{
		repo:              repo,
		dbPath:            dbPath,
		appVersion:        appVersion,
		interfaceService:  interfaceService,
		routingService:    routingService,
		firewallService:   firewallService,
		dnsService:        dnsService,
		dnsServerService:  dnsServerService,
		qosService:        qosService,
		dhcpServerService: dhcpServerService,
		dhcpcdService:     dhcpcdService,
		hostnameService:   hostnameService,
		timeService:       timeService,
		monitor:           monitor,
	}
}

// =============================================================================
// EXPORT
// =============================================================================

// Export reads every configuration table into a typed BackupFile. Errors from
// any table abort the export (a silent partial backup is worse than none). When
// includeUsers is true the users table — including bcrypt hashes — is included.
// When passphrase is non-empty the config section is AES-256-GCM encrypted with
// an Argon2id-derived key; the returned file then carries EncryptedConfig
// instead of Config. includeBlocklistFiles additionally carries subscribe-URL
// blocklists' .hosts file content (upload-sourced lists are always carried
// regardless of this flag — plan §2.4).
func (s *BackupService) Export(includeUsers bool, passphrase string, includeBlocklistFiles bool) (*model.BackupFile, error) {
	cfg := model.BackupConfig{}
	var err error

	if cfg.Interfaces, err = s.repo.GetInterfaces(); err != nil {
		return nil, fmt.Errorf("read interfaces: %w", err)
	}
	// Raw static routes only — never the kernel-merged or gateway-resolved view.
	if cfg.StaticRoutes, err = s.repo.GetRawStaticRoutes(); err != nil {
		return nil, fmt.Errorf("read static routes: %w", err)
	}
	if cfg.Addresses, err = s.repo.GetAddresses(); err != nil {
		return nil, fmt.Errorf("read address objects: %w", err)
	}
	if cfg.ServiceObjects, err = s.repo.GetServices(); err != nil {
		return nil, fmt.Errorf("read service objects: %w", err)
	}
	if cfg.Policies, err = s.repo.GetPolicies(); err != nil {
		return nil, fmt.Errorf("read policies: %w", err)
	}
	if cfg.PortForwards, err = s.repo.GetPortForwards(); err != nil {
		return nil, fmt.Errorf("read port forwards: %w", err)
	}
	if cfg.DhcpConfigs, err = s.repo.GetDHCPConfigs(); err != nil {
		return nil, fmt.Errorf("read dhcp configs: %w", err)
	}
	if cfg.DhcpReservations, err = s.repo.GetDHCPReservations(); err != nil {
		return nil, fmt.Errorf("read dhcp reservations: %w", err)
	}
	if cfg.DnsZones, err = s.repo.GetDNSZones(); err != nil {
		return nil, fmt.Errorf("read dns zones: %w", err)
	}
	if cfg.BlockedDomains, err = s.repo.GetBlockedDomains(); err != nil {
		return nil, fmt.Errorf("read dns blocked domains: %w", err)
	}

	// DNS blocklist import feature (plan §2.4/T-09) — never touches SQLite,
	// so it is not part of any repo.Get* call above; blocklistService is
	// nil-safe (optional dependency, unset in some tests).
	if s.blocklistService != nil {
		cfg.Blocklists = s.blocklistService.List()
		payloads, perr := s.buildBlocklistFilePayloads(cfg.Blocklists, includeBlocklistFiles)
		if perr != nil {
			return nil, fmt.Errorf("build blocklist file payloads: %w", perr)
		}
		cfg.BlocklistFiles = payloads
	}

	dnsServerSettings, err := s.repo.GetDNSServerSettings()
	if err != nil {
		return nil, fmt.Errorf("read dns server settings: %w", err)
	}
	cfg.DnsServerSettings = dnsServerSettings

	dnsCfg, err := s.repo.GetDNSConfig()
	if err != nil {
		return nil, fmt.Errorf("read system dns: %w", err)
	}
	cfg.SystemDns = model.DNSConfigInput{
		Mode:         dnsCfg.Mode,
		PrimaryDNS:   dnsCfg.PrimaryDNS,
		SecondaryDNS: dnsCfg.SecondaryDNS,
		LocalDomain:  dnsCfg.LocalDomain,
	}

	if cfg.QosRules, err = s.repo.GetQosRules(); err != nil {
		return nil, fmt.Errorf("read qos rules: %w", err)
	}

	// Presets carry their plaintext password into the backup — same treatment
	// as network_interfaces' wifi_password fields above (interfaces).
	if cfg.Presets, err = s.repo.GetWifiPresets(); err != nil {
		return nil, fmt.Errorf("read wifi presets: %w", err)
	}

	sysTime, err := s.repo.GetSystemTimeSettings()
	if err != nil {
		return nil, fmt.Errorf("read system time: %w", err)
	}
	sysTime.Status = nil // live-only, never persisted in a backup
	cfg.SystemTime = *sysTime

	sysHostname, err := s.repo.GetHostnameSettings()
	if err != nil {
		return nil, fmt.Errorf("read hostname settings: %w", err)
	}
	cfg.SystemHostname = *sysHostname

	dhcpHealth, err := s.repo.GetDhcpHealthSettings()
	if err != nil {
		return nil, fmt.Errorf("read dhcp health settings: %w", err)
	}
	cfg.DhcpHealthSettings = dhcpHealth

	// Multi-WAN Failover (docs/ref/todo/multi-wan-failover-plan.md Task 12) —
	// same pointer/omitempty treatment as DhcpHealthSettings above.
	if cfg.WanUplinks, err = s.repo.GetWanUplinks(); err != nil {
		return nil, fmt.Errorf("read wan uplinks: %w", err)
	}
	wanFailover, err := s.repo.GetWanFailoverSettings()
	if err != nil {
		return nil, fmt.Errorf("read wan failover settings: %w", err)
	}
	cfg.WanFailoverSettings = wanFailover

	if includeUsers {
		if cfg.Users, err = s.repo.GetBackupUsers(); err != nil {
			return nil, fmt.Errorf("read users: %w", err)
		}
	}

	checksum, err := configChecksum(cfg)
	if err != nil {
		return nil, fmt.Errorf("compute checksum: %w", err)
	}

	file := &model.BackupFile{
		Meta: model.BackupMeta{
			Device:        "PiGate Firewall Gateway",
			Hostname:      sysHostname.Hostname,
			AppVersion:    s.appVersion,
			SchemaVersion: model.CurrentBackupSchemaVersion,
			ExportedAt:    time.Now().Format(time.RFC3339),
			Checksum:      checksum,
			IncludeUsers:  includeUsers,
		},
	}

	if passphrase == "" {
		file.Config = &cfg
		return file, nil
	}

	enc, encParams, err := encryptConfig(cfg, passphrase)
	if err != nil {
		return nil, fmt.Errorf("encrypt config: %w", err)
	}
	file.Meta.Encrypted = true
	file.Meta.Encryption = encParams
	file.EncryptedConfig = enc
	return file, nil
}

// buildBlocklistFilePayloads selects which of lists' <id>.hosts files to
// carry into the backup and gzip+base64-encodes their content (plan §2.4):
// sourceType==upload is always included (an upload can never be re-fetched);
// sourceType==url is included only when includeBlocklistFiles was requested.
// The running total is capped at dnsBlocklistBackupCapBytes — once reached,
// remaining eligible lists are omitted (logged, not returned as an error: an
// export must still succeed, just smaller than it could have been).
func (s *BackupService) buildBlocklistFilePayloads(lists []model.DNSBlocklist, includeBlocklistFiles bool) ([]model.DNSBlocklistFilePayload, error) {
	if s.blocklistService == nil {
		return nil, nil
	}

	var payloads []model.DNSBlocklistFilePayload
	total := 0
	for _, l := range lists {
		eligible := l.SourceType == model.DNSBlocklistSourceUpload ||
			(l.SourceType == model.DNSBlocklistSourceURL && includeBlocklistFiles)
		if !eligible {
			continue
		}

		raw, err := s.readBlocklistHostsFile(l.ID)
		if err != nil {
			log.Printf("[Export] blocklist %q: failed to read .hosts file, omitting from backup: %v", l.ID, err)
			continue
		}
		if raw == nil {
			// Never written yet (e.g. a list that failed its very first
			// ingest) — nothing to carry.
			continue
		}

		gz, err := gzipBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("compress blocklist %q: %w", l.ID, err)
		}
		b64 := base64.StdEncoding.EncodeToString(gz)
		if total+len(b64) > dnsBlocklistBackupCapBytes {
			log.Printf("[Export] blocklist backup payload cap (%d bytes) reached; omitting %q and any remaining blocklist files", dnsBlocklistBackupCapBytes, l.ID)
			break
		}
		total += len(b64)

		sum := sha256.Sum256(raw)
		payloads = append(payloads, model.DNSBlocklistFilePayload{
			ID:         l.ID,
			Sha256:     hex.EncodeToString(sum[:]),
			GzipBase64: b64,
		})
	}
	return payloads, nil
}

// readBlocklistHostsFile reconstructs the exact bytes of <id>.hosts by
// streaming it back line-by-line via the kernel layer (there is no raw-bytes
// read method on kernel.DNSServerManager by design — StreamBlocklistFile is
// the only read path, plan §2.1.1/T-02) and rejoining with "\n". This is
// lossless because every line RenderHostsFile writes ends in "\n" and the
// file has no trailing partial line, so bufio.Scanner's line-split-then-
// rejoin round-trips byte-for-byte — which is what lets the payload's sha256
// end up equal to the sha256 the manifest already recorded for this content.
// Returns (nil, nil) if the file has never been written (empty/missing).
func (s *BackupService) readBlocklistHostsFile(id string) ([]byte, error) {
	var lines []string
	err := s.blocklistService.manager.StreamBlocklistFile(id, func(line string) error {
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

// gzipBytes compresses raw with the standard gzip writer.
func gzipBytes(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(raw); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// gunzipBytes decompresses gz produced by gzipBytes.
func gunzipBytes(gz []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// =============================================================================
// IMPORT
// =============================================================================

// Import validates, snapshots, restores, and re-applies a backup file. It never
// leaves the DB partially written: validation and checksum run before any DB
// mutation, the restore itself is a single transaction, and a file-copy snapshot
// is taken beforehand so a catastrophic failure is recoverable. Kernel re-apply
// failures are non-fatal (collected as warnings) because the DB is the source of
// truth and a reboot re-applies it anyway.
func (s *BackupService) Import(raw []byte, opts model.ImportOptions) (*model.ImportResult, error) {
	cfg, schemaVersion, err := decodeBackup(raw, opts.Passphrase)
	if err != nil {
		return nil, err
	}

	// Legacy Type/Value (address) and Protocol/Port (service) fields are
	// normalized into Entries — and every entry validated — only now, strictly
	// after decodeBackup's checksum check has already run. See Caution 1 at
	// decodeBackup's checksum comparison for why this ordering is load-bearing.
	if err := s.normalizeAndValidateObjectEntries(&cfg); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	result := &model.ImportResult{
		SchemaVersion: schemaVersion,
		Counts:        map[string]int{},
		Warnings:      []string{},
	}

	// Normalise legacy timezone display strings so both old and new backups
	// produce a bare IANA name that systemd-timedated accepts.
	cfg.SystemTime.Timezone = db.NormalizeTimezone(cfg.SystemTime.Timezone)
	cfg.SystemTime.Status = nil

	// Resolve backup interfaces against the device: match by name, merge config
	// fields onto the live row, skip (with a warning) any interface absent here.
	mergedIfaces, ifaceWarnings, ifacesChanged, err := s.resolveInterfaces(cfg.Interfaces)
	if err != nil {
		return nil, fmt.Errorf("resolve interfaces: %w", err)
	}
	cfg.Interfaces = mergedIfaces
	result.Warnings = append(result.Warnings, ifaceWarnings...)
	result.InterfacesChanged = ifacesChanged

	// Snapshot the pre-import user set so we can (a) purge sessions of users that
	// disappear and (b) reinstate the actor if the backup would lock them out.
	var preUsers []model.User
	if opts.IncludeUsers {
		if preUsers, err = s.repo.GetUsers(); err != nil {
			return nil, fmt.Errorf("read existing users: %w", err)
		}
	}

	// Bracket the whole mutation with a monitor pause so kernel reconciliation
	// doesn't race the replacement of routes/interfaces.
	if s.monitor != nil {
		s.monitor.Pause()
		defer s.monitor.Resume()
	}

	// Pre-import snapshot (best-effort; checkpoint first so WAL pages are flushed).
	_ = s.repo.Checkpoint()
	if snapPath, snapErr := db.SnapshotDatabase(s.dbPath, "backup-preimport"); snapErr != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("pre-import snapshot failed: %v", snapErr))
	} else if snapPath != "" {
		log.Printf("[Import] Pre-import snapshot: %s", snapPath)
	}

	// Atomic restore. On any error the original DB is untouched.
	if err := s.repo.RestoreConfig(cfg, opts.IncludeUsers); err != nil {
		return nil, fmt.Errorf("restore failed (no changes applied): %w", err)
	}

	// The RAM cache PolicyCounterStore keeps must reflect the DB's
	// post-import policy_rule_counters state (RestoreConfig above just
	// replaced firewall_policies/policy_rule_counters wholesale) — never the
	// pre-import numbers (docs/ref/todo/
	// fqdn-retry-and-monitored-counters-plan.md T-12). Best-effort: a reload
	// failure is a warning, not a fatal import error, since the DB itself
	// (source of truth) already restored correctly.
	if s.counterStore != nil {
		if err := s.counterStore.Reload(); err != nil {
			log.Printf("[Import] failed to reload Monitor counter cache after import: %v", err)
		}
	}

	// Guard against the actor locking themselves out, and figure out whose
	// sessions to purge.
	if opts.IncludeUsers {
		result.UsersImported = true
		if warn := s.guardActor(opts, preUsers); warn != "" {
			result.Warnings = append(result.Warnings, warn)
		}
		result.RemovedUsernames = s.removedUsernames(preUsers, opts.ActorUsername)
	}

	result.Counts = configCounts(cfg)

	// DNS blocklist import feature (plan §2.4/T-09) — never in SQLite, so it
	// is restored as its own step rather than through repo.RestoreConfig
	// above. Failures are warnings, same policy as reapply() below: the
	// manifest/files this writes are this feature's only state, so a partial
	// failure here does not roll back anything else already restored.
	result.Warnings = append(result.Warnings, s.importBlocklists(cfg.Blocklists, cfg.BlocklistFiles)...)

	// Re-apply DB config to the kernel in startup order. Failures are warnings.
	result.Warnings = append(result.Warnings, s.reapply()...)

	return result, nil
}

// resolveInterfaces matches each backup interface to a live device interface by
// name, merging the backup's config fields onto the device row while keeping the
// device's hardware/runtime identity (id, name, type, mac addresses, status,
// speed). "Existing" here is the merged data-layer view (live kernel links plus
// DB rows, including DB-only "offline" rows) rather than the raw DB table, so a
// physically-present interface whose DB row was deleted (e.g. wlan0 still
// running via wpa_supplicant after its config row was removed — "unmanaged"
// state, issue #89) is still recognised as present on this device and gets its
// DB row recreated from the backup, instead of being skipped. Interfaces in the
// backup that don't exist on this device are skipped with a warning (§3.5).
// Returns the merged rows to restore, warnings, and whether any interface config
// changed (used to warn the admin about possible disconnection).
func (s *BackupService) resolveInterfaces(backup []model.NetworkInterface) ([]model.NetworkInterface, []string, bool, error) {
	existing, err := s.interfaceService.GetDataLayerInterfaceIncludingOffline()
	if err != nil {
		return nil, nil, false, err
	}
	byName := make(map[string]model.NetworkInterface, len(existing))
	for _, e := range existing {
		byName[e.Name] = e
	}

	var merged []model.NetworkInterface
	var warnings []string
	changed := false
	for _, b := range backup {
		dev, ok := byName[b.Name]
		if !ok {
			// VLAN sub-interfaces are not present in the kernel until they are
			// re-created at reapply time (InitApplyConfigurationAtStartup), so a VLAN
			// row absent from the device must NOT be dropped — keep it verbatim as long
			// as its parent interface exists here. Without this, restoring onto a fresh
			// board would silently lose every VLAN.
			if b.Subtype == "vlan" {
				parentName := ""
				if b.VlanParent != nil {
					parentName = *b.VlanParent
				}
				if _, parentOK := byName[parentName]; parentName == "" || !parentOK {
					warnings = append(warnings, fmt.Sprintf("VLAN %q from backup skipped: parent %q is not present on this device", b.Name, parentName))
					continue
				}
				changed = true
				merged = append(merged, b)
				continue
			}
			warnings = append(warnings, fmt.Sprintf("interface %q from backup is not present on this device — skipped", b.Name))
			continue
		}
		if interfaceConfigDiffers(dev, b) {
			changed = true
		}
		// Start from the live device row (keeps id/name/type/mac/status/speed)
		// then overlay the backup's config-only fields.
		m := dev
		m.Alias = b.Alias
		m.Role = b.Role
		m.AddressingMode = b.AddressingMode
		m.IP = b.IP
		m.Netmask = b.Netmask
		m.Gateway = b.Gateway
		m.Metric = b.Metric
		m.AdminAccess = b.AdminAccess
		m.MacMode = b.MacMode
		m.RandomizedMac = b.RandomizedMac
		m.LaaMacAddress = b.LaaMacAddress
		m.RandomizeOnReconnect = b.RandomizeOnReconnect
		m.WifiSSID = b.WifiSSID
		m.WifiPassword = b.WifiPassword
		m.WifiSecurity = b.WifiSecurity
		m.FailoverEnabled = b.FailoverEnabled
		m.BackupSSID = b.BackupSSID
		m.BackupWifiPassword = b.BackupWifiPassword
		m.BackupWifiSecurity = b.BackupWifiSecurity
		m.IPCheckTimeout = b.IPCheckTimeout
		m.PrimaryMaxRetries = b.PrimaryMaxRetries
		m.FailoverCooldown = b.FailoverCooldown
		merged = append(merged, m)
	}

	// Alias uniqueness guard (issue #25): network_interfaces has a case-insensitive
	// unique index on alias, and RestoreConfig runs in a single transaction — one
	// bad alias in the backup would roll back the whole restore. Normalize (empty ->
	// own name) and de-duplicate against both the other merged rows and the device
	// rows this restore does not touch (restore updates by id, it does not replace
	// the table).
	mergedIDs := make(map[string]bool, len(merged))
	for _, m := range merged {
		mergedIDs[m.ID] = true
	}
	taken := make(map[string]bool)
	names := make(map[string]bool)
	for _, e := range existing {
		names[strings.ToLower(e.Name)] = true
		if !mergedIDs[e.ID] {
			taken[strings.ToLower(e.Alias)] = true
		}
	}
	for _, m := range merged {
		names[strings.ToLower(m.Name)] = true // VLAN rows may be new to this device
	}
	conflicts := func(alias, ownName string) bool {
		lower := strings.ToLower(alias)
		return taken[lower] || (names[lower] && !strings.EqualFold(alias, ownName))
	}
	for i := range merged {
		m := &merged[i]
		alias := strings.TrimSpace(m.Alias)
		if alias == "" {
			alias = m.Name
		}
		if conflicts(alias, m.Name) {
			orig := alias
			alias = m.Name
			for n := 2; conflicts(alias, m.Name); n++ {
				alias = fmt.Sprintf("%s_%d", m.Name, n)
			}
			warnings = append(warnings, fmt.Sprintf("interface %q: alias %q already in use — replaced with %q", m.Name, orig, alias))
		}
		m.Alias = alias
		taken[strings.ToLower(alias)] = true
	}

	return merged, warnings, changed, nil
}

// guardActor ensures the account performing the import is still an active
// super_admin after users were restored. If the backup omitted or demoted/
// disabled them, the actor is reinstated from the pre-import snapshot so an
// import can never lock the operator out. Returns a warning string if it acted.
func (s *BackupService) guardActor(opts model.ImportOptions, preUsers []model.User) string {
	if opts.ActorUsername == "" {
		return ""
	}
	actor, err := s.repo.GetUserByUsername(opts.ActorUsername)
	if err != nil {
		return fmt.Sprintf("could not verify actor account %q after import: %v", opts.ActorUsername, err)
	}
	if actor != nil && actor.Role == "super_admin" && actor.Status == "active" {
		return "" // still fine
	}

	// Reinstate from the pre-import record.
	var pre *model.User
	for i := range preUsers {
		if preUsers[i].Username == opts.ActorUsername {
			pre = &preUsers[i]
			break
		}
	}

	if actor == nil {
		if pre == nil {
			return fmt.Sprintf("actor %q not found before or after import; could not guarantee access", opts.ActorUsername)
		}
		reinstated := *pre
		reinstated.Role = "super_admin"
		reinstated.Status = "active"
		if err := s.repo.CreateUser(reinstated); err != nil {
			return fmt.Sprintf("failed to reinstate actor %q: %v", opts.ActorUsername, err)
		}
		return fmt.Sprintf("imported backup omitted your account %q — it was preserved as an active super_admin to prevent lock-out", opts.ActorUsername)
	}

	// Exists but demoted/disabled → restore role+status.
	_ = s.repo.UpdateUserRole(actor.ID, "super_admin")
	_ = s.repo.SetUserStatus(actor.ID, "active")
	return fmt.Sprintf("imported backup demoted/disabled your account %q — it was kept as an active super_admin to prevent lock-out", opts.ActorUsername)
}

// removedUsernames returns usernames that existed before the import but are gone
// or disabled afterwards, excluding the actor. The API layer purges their
// sessions.
func (s *BackupService) removedUsernames(preUsers []model.User, actor string) []string {
	post, err := s.repo.GetUsers()
	if err != nil {
		return nil
	}
	activeNow := make(map[string]bool, len(post))
	for _, u := range post {
		if u.Status == "active" {
			activeNow[u.Username] = true
		}
	}
	var removed []string
	for _, u := range preUsers {
		if u.Username == actor {
			continue
		}
		if !activeNow[u.Username] {
			removed = append(removed, u.Username)
		}
	}
	return removed
}

// importBlocklists restores the DNS blocklist import feature's manifest
// entries and file payloads (plan §2.4/T-09). It is a no-op if
// blocklistService was never wired (SetBlocklistService) or the backup
// carries no blocklists at all — e.g. every backup taken before this feature
// existed. Never fatal: any per-list problem downgrades that single list
// (domainCount=0, lastError set) rather than aborting the whole import, since
// by the time this runs the DB restore has already committed.
//
// For each list:
//  1. blockMode is normalized (garbage/legacy "" -> the blocklist default).
//  2. If no matching DNSBlocklistFilePayload was carried (a url-sourced list
//     exported without ?includeBlocklistFiles=1), the list is kept in the
//     manifest but with domainCount=0 and lastError="needs refresh after
//     import" — ApplyZones skips a list whose <id>.hosts file does not exist
//     (kernel os.Stat check), so this never renders a stale/empty directive.
//  3. Otherwise the payload is base64-decoded, gunzipped, and its sha256
//     verified against DNSBlocklistFilePayload.Sha256 BEFORE anything is
//     written to disk (this content is later loaded straight into dnsmasq).
//     A verified file is written via kernel.WriteBlocklistFile.
//  4. blockMode's derived artifact (<id>.conf, only for
//     DNSBlockModeNXDomain) is (re)rendered from the just-written .hosts
//     content via the SAME renderArtifacts path CreateFromURL/UpdateInfo use
//     (T-05) — never a second writer. If this system's dnsmasq does not
//     support nxdomain mode (SupportsBulkNXDomain()==false), the list is
//     silently downgraded to sinkhole (not an error — plan §3 T-09 item 3)
//     with lastError explaining why.
//
// The whole restored set replaces the manifest wholesale via
// blocklistStore.ReplaceAll — a backup import is a full restore, not a merge.
func (s *BackupService) importBlocklists(lists []model.DNSBlocklist, files []model.DNSBlocklistFilePayload) []string {
	if s.blocklistService == nil || len(lists) == 0 {
		return nil
	}

	payloadByID := make(map[string]model.DNSBlocklistFilePayload, len(files))
	for _, f := range files {
		payloadByID[f.ID] = f
	}

	var warnings []string
	restored := make([]model.DNSBlocklist, 0, len(lists))
	for _, l := range lists {
		mode, err := model.NormalizeBlocklistBlockMode(l.BlockMode)
		if err != nil {
			mode = model.DNSBlocklistDefaultBlockMode
		}
		l.BlockMode = mode

		payload, ok := payloadByID[l.ID]
		if !ok {
			l.DomainCount = 0
			l.LastError = "needs refresh after import"
			restored = append(restored, l)
			continue
		}

		gz, err := base64.StdEncoding.DecodeString(payload.GzipBase64)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("blocklist %q: invalid backup file payload, skipping file restore: %v", l.ID, err))
			l.DomainCount = 0
			l.LastError = "needs refresh after import"
			restored = append(restored, l)
			continue
		}
		content, err := gunzipBytes(gz)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("blocklist %q: failed to decompress backup file payload, skipping file restore: %v", l.ID, err))
			l.DomainCount = 0
			l.LastError = "needs refresh after import"
			restored = append(restored, l)
			continue
		}
		if len(content) > model.DNSBlocklistMaxFileBytes {
			warnings = append(warnings, fmt.Sprintf("blocklist %q: backup file payload exceeds maximum size, skipping file restore", l.ID))
			l.DomainCount = 0
			l.LastError = "needs refresh after import"
			restored = append(restored, l)
			continue
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != payload.Sha256 {
			warnings = append(warnings, fmt.Sprintf("blocklist %q: backup file payload checksum mismatch, skipping file restore", l.ID))
			l.DomainCount = 0
			l.LastError = "needs refresh after import"
			restored = append(restored, l)
			continue
		}

		if err := s.blocklistService.manager.WriteBlocklistFile(l.ID, content); err != nil {
			warnings = append(warnings, fmt.Sprintf("blocklist %q: failed to write hosts file: %v", l.ID, err))
			l.DomainCount = 0
			l.LastError = "needs refresh after import"
			restored = append(restored, l)
			continue
		}

		if mode == model.DNSBlockModeNXDomain && !s.blocklistService.manager.SupportsBulkNXDomain() {
			mode = model.DNSBlockModeSinkhole
			l.BlockMode = mode
			l.LastError = "blockMode downgraded to sinkhole on import: this system's dnsmasq does not support nxdomain mode (requires dnsmasq >= 2.86)"
		}
		if err := s.blocklistService.renderArtifacts(l.ID, mode); err != nil {
			warnings = append(warnings, fmt.Sprintf("blocklist %q: failed to render blockMode %q artifacts: %v", l.ID, mode, err))
		}

		restored = append(restored, l)
	}

	if err := s.blocklistService.store.ReplaceAll(restored); err != nil {
		warnings = append(warnings, fmt.Sprintf("failed to persist restored blocklist manifest: %v", err))
	}
	return warnings
}

// reapply pushes the freshly restored DB state to the kernel, in the same order
// as the startup sequence in cmd/pigate/main.go. Each failure is collected as a
// warning rather than aborting — the DB is authoritative and a reboot re-applies
// everything regardless.
func (s *BackupService) reapply() []string {
	var warnings []string
	step := func(name string, fn func() error) {
		if fn == nil {
			return
		}
		if err := fn(); err != nil {
			warnings = append(warnings, fmt.Sprintf("re-apply %s failed: %v", name, err))
		}
	}

	if s.timeService != nil {
		step("time", s.timeService.InitApplyConfig)
	}
	if s.interfaceService != nil {
		step("interfaces", s.interfaceService.InitApplyConfigurationAtStartup)
	}
	if s.routingService != nil {
		step("routes", s.routingService.InitApplyConfig)
	}
	if s.hostnameService != nil {
		step("hostname", s.hostnameService.InitApplyConfig)
	}
	if s.dhcpcdService != nil {
		s.dhcpcdService.SyncActiveInterfaces()
	}
	if s.dhcpServerService != nil {
		step("dhcp", s.dhcpServerService.InitApplyConfig)
	}
	if s.dnsServerService != nil {
		step("dns-server", s.dnsServerService.InitApplyConfig)
	}
	if s.dnsService != nil {
		step("dns", s.dnsService.ApplyDNSConfig)
	}
	if s.firewallService != nil {
		step("firewall", s.firewallService.InitApplyConfig)
	}
	if s.qosService != nil {
		step("qos", s.qosService.InitApplyConfig)
	}
	return warnings
}

// =============================================================================
// Decoding / validation helpers
// =============================================================================

// decodeBackup parses a backup file, transparently accepting the v2 typed
// format (plaintext or passphrase-encrypted) and the legacy v1 layout, and
// verifies the checksum when present. Returns the config plus the detected
// schema version.
func decodeBackup(raw []byte, passphrase string) (model.BackupConfig, int, error) {
	// Probe for a v2 meta block.
	var probe struct {
		Meta *struct {
			SchemaVersion int `json:"schemaVersion"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return model.BackupConfig{}, 0, fmt.Errorf("invalid JSON: %w", err)
	}

	if probe.Meta == nil {
		cfg, err := mapLegacyV1(raw)
		return cfg, 1, err
	}

	var file model.BackupFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return model.BackupConfig{}, 0, fmt.Errorf("invalid backup structure: %w", err)
	}
	if file.Meta.SchemaVersion > model.CurrentBackupSchemaVersion {
		return model.BackupConfig{}, 0, fmt.Errorf("backup schema version %d is newer than supported version %d", file.Meta.SchemaVersion, model.CurrentBackupSchemaVersion)
	}

	var cfg model.BackupConfig
	if file.Meta.Encrypted {
		if passphrase == "" {
			return model.BackupConfig{}, 0, ErrPassphraseRequired
		}
		plaintext, err := decryptConfig(file.EncryptedConfig, passphrase, file.Meta.Encryption)
		if err != nil {
			return model.BackupConfig{}, 0, err
		}
		if err := json.Unmarshal(plaintext, &cfg); err != nil {
			return model.BackupConfig{}, 0, fmt.Errorf("decrypted config is not valid JSON: %w", err)
		}
	} else {
		if file.Config == nil {
			return model.BackupConfig{}, 0, fmt.Errorf("backup file has no config section")
		}
		cfg = *file.Config
	}

	// CAUTION 1 (docs/ref/todo/multi-value-address-service-objects-plan.md §4):
	// cfg must be compared against the checksum EXACTLY as decoded above — do
	// NOT normalize (legacy Type/Value -> Entries) or otherwise mutate cfg
	// before this point. AddressObject.Entries/ServiceObject.Entries are
	// `omitempty`, so a pre-v2.x/legacy backup file marshals with no "entries"
	// key at all; configChecksum() must reproduce those exact bytes or every
	// legacy backup would fail verification here. Normalization happens later,
	// in BackupService.Import (normalizeAndValidateObjectEntries), strictly
	// after this checksum check has already passed.
	if file.Meta.Checksum != "" {
		want := strings.TrimPrefix(file.Meta.Checksum, "sha256:")
		got, err := configChecksum(cfg)
		if err != nil {
			return model.BackupConfig{}, 0, fmt.Errorf("recompute checksum: %w", err)
		}
		if strings.TrimPrefix(got, "sha256:") != want {
			return model.BackupConfig{}, 0, fmt.Errorf("checksum mismatch: backup file is corrupted or was modified")
		}
	}
	return cfg, file.Meta.SchemaVersion, nil
}

// mapLegacyV1 maps the pre-v2 export shape into a v2 BackupConfig. The old
// format nested settings under systemSettings/hostnameSettings and DHCP under
// config.dhcp.config, and exported the kernel-merged route view — ghost
// "route-sys-*" rows and system/defaultgateway routes are dropped here.
func mapLegacyV1(raw []byte) (model.BackupConfig, error) {
	var v1 struct {
		SystemSettings   *model.SystemTimeSettings     `json:"systemSettings"`
		HostnameSettings *model.SystemHostnameSettings `json:"hostnameSettings"`
		Config           struct {
			Addresses      []model.AddressObject    `json:"addresses"`
			ServiceObjects []model.ServiceObject    `json:"serviceObjects"`
			Policies       []model.PolicyRule       `json:"policies"`
			Routes         []model.StaticRoute      `json:"routes"`
			Interfaces     []model.NetworkInterface `json:"interfaces"`
			DHCP           *struct {
				Config       *model.DhcpConfig       `json:"config"`
				Reservations []model.DhcpReservation `json:"reservations"`
			} `json:"dhcp"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &v1); err != nil {
		return model.BackupConfig{}, fmt.Errorf("invalid v1 backup structure: %w", err)
	}

	cfg := model.BackupConfig{
		Addresses:      v1.Config.Addresses,
		ServiceObjects: v1.Config.ServiceObjects,
		Policies:       v1.Config.Policies,
		Interfaces:     v1.Config.Interfaces,
	}
	for _, rt := range v1.Config.Routes {
		if rt.Type == "system" || rt.Type == "defaultgateway" || strings.HasPrefix(rt.ID, "route-sys-") {
			continue
		}
		cfg.StaticRoutes = append(cfg.StaticRoutes, rt)
	}
	if v1.Config.DHCP != nil {
		if v1.Config.DHCP.Config != nil {
			cfg.DhcpConfigs = []model.DhcpConfig{*v1.Config.DHCP.Config}
		}
		cfg.DhcpReservations = v1.Config.DHCP.Reservations
	}
	if v1.SystemSettings != nil {
		cfg.SystemTime = *v1.SystemSettings
	}
	if v1.HostnameSettings != nil {
		cfg.SystemHostname = *v1.HostnameSettings
	}
	return cfg, nil
}

// normalizeAndValidateObjectEntries backfills Entries from the legacy
// Type/Value (address) / Protocol/Port (service) fields for backup files that
// predate the multi-value feature — i.e. files with no "entries" key at all —
// then validates every resulting entry through the single canonical validator
// (model.ValidateAddressEntries/ValidateServiceEntries, plan Caution 5),
// using the same per-object cap the live repository enforces
// (s.repo.MaxObjectEntries(): either the config-supplied max-object-entries
// value, or model.DefaultMaxObjectEntries if that was never set). This is
// fail-closed: any single invalid/duplicate/over-cap entry rejects the whole
// file — nothing is written to the DB — before RestoreConfig ever runs (plan
// T-07 acceptance: "ไฟล์ที่มี entry เพี้ยนถูก reject ก่อนเขียน DB").
//
// Must only be called after decodeBackup's checksum check (see Caution 1
// comment there) — never before.
func (s *BackupService) normalizeAndValidateObjectEntries(cfg *model.BackupConfig) error {
	maxEntries := s.repo.MaxObjectEntries()
	for i := range cfg.Addresses {
		model.NormalizeAddressObject(&cfg.Addresses[i])
		if err := model.ValidateAddressEntries(cfg.Addresses[i].Entries, maxEntries); err != nil {
			return fmt.Errorf("address object %q: %w", cfg.Addresses[i].Name, err)
		}
	}
	for i := range cfg.ServiceObjects {
		model.NormalizeServiceObject(&cfg.ServiceObjects[i])
		if err := model.ValidateServiceEntries(cfg.ServiceObjects[i].Entries, maxEntries); err != nil {
			return fmt.Errorf("service object %q: %w", cfg.ServiceObjects[i].Name, err)
		}
	}
	return nil
}

// validateConfig runs cheap, structural validation before any DB write:
// referential integrity of policies against the objects in the same file, plus
// a few enum sanity checks. Deep value checks are left to SQLite CHECK
// constraints, which roll the restore transaction back if violated.
func validateConfig(cfg model.BackupConfig) error {
	addrNames := make(map[string]bool, len(cfg.Addresses))
	for _, a := range cfg.Addresses {
		addrNames[a.Name] = true
	}
	svcNames := make(map[string]bool, len(cfg.ServiceObjects))
	for _, s := range cfg.ServiceObjects {
		svcNames[s.Name] = true
	}

	for _, p := range cfg.Policies {
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("policy has empty name")
		}
		if p.Action != "ACCEPT" && p.Action != "DROP" {
			return fmt.Errorf("policy %q has invalid action %q", p.Name, p.Action)
		}
		if len(p.Source) == 0 || len(p.Destination) == 0 || len(p.Service) == 0 {
			return fmt.Errorf("policy %q must reference at least one source, destination, and service", p.Name)
		}
		// Old backups predate the `chain` field (Caution 12) — normalize the
		// local copy before validating so those files still import cleanly as
		// "forward", matching what backup_repo.go actually writes to the DB.
		p.Chain = model.NormalizePolicyChain(p.Chain)
		if err := model.ValidatePolicyRule(p); err != nil {
			return fmt.Errorf("policy %q: %w", p.Name, err)
		}
		for _, n := range append(append([]string{}, p.Source...), p.Destination...) {
			if !addrNames[n] {
				return fmt.Errorf("policy %q references unknown address object %q", p.Name, n)
			}
		}
		for _, n := range p.Service {
			if !svcNames[n] {
				return fmt.Errorf("policy %q references unknown service object %q", p.Name, n)
			}
		}
	}

	for _, pf := range cfg.PortForwards {
		if err := model.ValidatePortForward(pf); err != nil {
			return fmt.Errorf("port forward %q: %w", pf.Name, err)
		}
	}

	if cfg.SystemDns.Mode != "" && cfg.SystemDns.Mode != "wan" && cfg.SystemDns.Mode != "static" {
		return fmt.Errorf("invalid system DNS mode %q", cfg.SystemDns.Mode)
	}

	// The import path writes DNS zones/records and DHCP reservations straight to
	// the DB, bypassing the create/update handlers. Enforce the same whitelist
	// here so a crafted backup can't inject a dnsmasq directive. Fail-closed:
	// one bad entry rejects the whole import (which is atomic) before any write.
	for _, z := range cfg.DnsZones {
		if err := model.ValidateDNSZone(z); err != nil {
			return fmt.Errorf("dns zone %q: %w", z.ZoneName, err)
		}
		for _, rec := range z.Records {
			if err := model.ValidateDNSRecord(rec); err != nil {
				return fmt.Errorf("dns record in zone %q: %w", z.ZoneName, err)
			}
		}
	}
	// Same fail-closed treatment for the deny-list (docs/ref/todo/
	// dns-blocked-domains-plan.md §5 Caution 1): backup import is a write path
	// that bypasses HandleCreateBlockedDomain/HandleUpdateBlockedDomain, so it
	// must run through the same validator or a crafted backup could inject a
	// dnsmasq directive via an embedded newline.
	for _, b := range cfg.BlockedDomains {
		if err := model.ValidateBlockedDomain(b); err != nil {
			return fmt.Errorf("blocked domain %q: %w", b.Domain, err)
		}
	}
	// Same fail-closed treatment for the DNS blocklist import feature (plan
	// §2.4/T-09): its manifest entries bypass HandleCreateDNSBlocklist/
	// HandleUpdateDNSBlocklist on import, so a crafted backup must not be able
	// to smuggle an invalid id (used directly to build a filesystem path,
	// plan §2.1) or blockMode.
	for _, bl := range cfg.Blocklists {
		if err := model.ValidateDNSBlocklistID(bl.ID); err != nil {
			return fmt.Errorf("blocklist %q: %w", bl.Name, err)
		}
		if err := model.ValidateDNSBlocklistName(bl.Name); err != nil {
			return fmt.Errorf("blocklist %q: %w", bl.ID, err)
		}
		if bl.SourceType != model.DNSBlocklistSourceURL && bl.SourceType != model.DNSBlocklistSourceUpload {
			return fmt.Errorf("blocklist %q: invalid sourceType %q", bl.ID, bl.SourceType)
		}
		if bl.SourceType == model.DNSBlocklistSourceURL {
			if err := model.ValidateDNSBlocklistURL(bl.URL); err != nil {
				return fmt.Errorf("blocklist %q: %w", bl.ID, err)
			}
		}
		if _, err := model.NormalizeBlocklistBlockMode(bl.BlockMode); err != nil {
			return fmt.Errorf("blocklist %q: %w", bl.ID, err)
		}
	}
	for _, res := range cfg.DhcpReservations {
		if err := model.ValidateReservation(res); err != nil {
			return fmt.Errorf("dhcp reservation %q: %w", res.DeviceName, err)
		}
	}
	for _, c := range cfg.DhcpConfigs {
		if err := model.ValidateDhcpConfig(c); err != nil {
			return fmt.Errorf("dhcp config %q: %w", c.Interface, err)
		}
	}
	// Wi-Fi presets carry a plaintext password that later feeds
	// GenerateWpaConfig (kernel/wpa.go) via /apply — validate the same way as
	// DhcpConfigs/DnsZones above: one bad preset rejects the whole import
	// before any write (fail-closed).
	for _, p := range cfg.Presets {
		if err := model.ValidateWifiPreset(p); err != nil {
			return fmt.Errorf("wifi preset %q: %w", p.Name, err)
		}
	}
	return nil
}

func configCounts(cfg model.BackupConfig) map[string]int {
	records := 0
	for _, z := range cfg.DnsZones {
		records += len(z.Records)
	}
	return map[string]int{
		"interfaces":       len(cfg.Interfaces),
		"staticRoutes":     len(cfg.StaticRoutes),
		"addresses":        len(cfg.Addresses),
		"serviceObjects":   len(cfg.ServiceObjects),
		"policies":         len(cfg.Policies),
		"portForwards":     len(cfg.PortForwards),
		"dhcpConfigs":      len(cfg.DhcpConfigs),
		"dhcpReservations": len(cfg.DhcpReservations),
		"dnsZones":         len(cfg.DnsZones),
		"dnsRecords":       records,
		"blockedDomains":   len(cfg.BlockedDomains),
		"qosRules":         len(cfg.QosRules),
		"users":            len(cfg.Users),
		"wifiPresets":      len(cfg.Presets),
		"blocklists":       len(cfg.Blocklists),
		"wanUplinks":       len(cfg.WanUplinks),
	}
}

// configChecksum returns "sha256:<hex>" over the canonical JSON marshalling of a
// BackupConfig. Because Go marshals struct fields in declaration order, the same
// config always produces the same bytes, so a reformatted (pretty-printed) file
// re-normalises through the typed struct and still verifies.
func configChecksum(cfg model.BackupConfig) (string, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// interfaceConfigDiffers reports whether the backup's config-only fields differ
// from the device row, used to flag a possible admin disconnection.
func interfaceConfigDiffers(dev, b model.NetworkInterface) bool {
	return dev.IP != b.IP ||
		dev.Netmask != b.Netmask ||
		dev.Gateway != b.Gateway ||
		dev.AddressingMode != b.AddressingMode ||
		dev.Role != b.Role ||
		strings.Join(dev.AdminAccess, ",") != strings.Join(b.AdminAccess, ",")
}
