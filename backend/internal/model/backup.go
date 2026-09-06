package model

// CurrentBackupSchemaVersion is the schema version emitted by the current
// exporter. v1 is the legacy format produced before the typed BackupService
// (fields nested under systemSettings/hostnameSettings/config.dhcp.config). The
// importer still accepts v1 by mapping it into the v2 BackupConfig.
const CurrentBackupSchemaVersion = 2

// BackupFile is the top-level structure of an exported configuration backup.
// The checksum in Meta is computed over the canonical JSON marshalling of the
// (plaintext) Config, so the importer can re-normalise a reformatted
// (pretty-printed) file through the typed struct and still verify integrity.
//
// A backup is either plaintext (Config set, EncryptedConfig empty) or encrypted
// (Config nil, EncryptedConfig holds base64 AES-256-GCM ciphertext of the
// marshalled Config, and Meta.Encryption describes how to derive the key).
type BackupFile struct {
	Meta            BackupMeta    `json:"meta"`
	Config          *BackupConfig `json:"config,omitempty"`
	EncryptedConfig string        `json:"encryptedConfig,omitempty"`
}

// BackupMeta carries provenance and integrity metadata for a backup file.
type BackupMeta struct {
	Device        string `json:"device"`
	Hostname      string `json:"hostname"`
	AppVersion    string `json:"appVersion"`
	SchemaVersion int    `json:"schemaVersion"`
	ExportedAt    string `json:"exportedAt"`
	Checksum      string `json:"checksum"`     // "sha256:<hex>" over marshalled plaintext Config
	IncludeUsers  bool   `json:"includeUsers"` // whether Config.Users is populated

	// Encryption metadata — present only when the config is passphrase-encrypted.
	Encrypted  bool              `json:"encrypted,omitempty"`
	Encryption *EncryptionParams `json:"encryption,omitempty"`
}

// EncryptionParams records the algorithm and KDF parameters needed to re-derive
// the AES key from the user's passphrase and decrypt EncryptedConfig. It carries
// no secret — the passphrase is never stored.
type EncryptionParams struct {
	Algorithm string `json:"algorithm"` // "AES-256-GCM"
	KDF       string `json:"kdf"`       // "argon2id"
	Salt      string `json:"salt"`      // base64, KDF salt
	Nonce     string `json:"nonce"`     // base64, GCM nonce
	Time      uint32 `json:"time"`      // argon2 iterations
	Memory    uint32 `json:"memory"`    // argon2 memory (KiB)
	Threads   uint8  `json:"threads"`   // argon2 parallelism
}

// BackupConfig is the full, typed set of configuration tables captured in a
// backup. Every field maps to a persisted configuration table; runtime/live
// state (DHCP leases, live time status, firewall counters) is deliberately
// excluded.
type BackupConfig struct {
	Interfaces        []NetworkInterface     `json:"interfaces"`
	StaticRoutes      []StaticRoute          `json:"staticRoutes"`
	Addresses         []AddressObject        `json:"addresses"`
	ServiceObjects    []ServiceObject        `json:"serviceObjects"`
	Policies          []PolicyRule           `json:"policies"`
	DhcpConfigs       []DhcpConfig           `json:"dhcpConfigs"`
	DhcpReservations  []DhcpReservation      `json:"dhcpReservations"`
	DnsZones          []DNSZone              `json:"dnsZones"`
	DnsServerSettings DNSServerSettings      `json:"dnsServerSettings"`
	SystemDns         DNSConfigInput         `json:"systemDns"`
	QosRules          []QosRule              `json:"qosRules"`
	SystemTime        SystemTimeSettings     `json:"systemTime"`
	SystemHostname    SystemHostnameSettings `json:"systemHostname"`
	Users             []BackupUser           `json:"users,omitempty"`
	// PortForwards MUST stay omitempty: the importer verifies a backup's checksum
	// by re-marshaling the decoded BackupConfig, so a non-omitempty field would
	// serialise as "portForwards":null for older v2 backups (which lack the key)
	// and break their checksum. omitempty keeps nil/empty slices out of the JSON,
	// preserving byte-for-byte compatibility without a schema-version bump.
	PortForwards []PortForward `json:"portForwards,omitempty"`
	// DhcpHealthSettings (issue #78) uses the same pointer + omitempty pattern
	// as PortForwards for the same reason: keeps older backups (which lack
	// this key) checksum-compatible without a schema-version bump.
	DhcpHealthSettings *DhcpHealthSettings `json:"dhcpHealthSettings,omitempty"`
	// Presets carries every saved Wi-Fi network, INCLUDING its plaintext
	// password (unlike the API's GET path, a backup must be restorable, so it
	// cannot rely on SanitizeWifiPresetForRead — mirrors how Interfaces already
	// exports WifiPassword/BackupWifiPassword in plaintext). MUST stay
	// omitempty for the same checksum-compatibility reason as PortForwards
	// above: older v2 backups lack this key entirely.
	Presets []WifiPreset `json:"presets,omitempty"`
	// BlockedDomains (docs/ref/todo/dns-blocked-domains-plan.md) MUST stay
	// omitempty for the same checksum-compatibility reason as PortForwards
	// above: older backups (which lack this key) must keep re-marshalling to
	// the same bytes, or their checksum breaks and the whole file fails to
	// import.
	BlockedDomains []BlockedDomain `json:"blockedDomains,omitempty"`
	// Blocklists and BlocklistFiles (docs/ref/todo/dns-blocklist-import-plan.md
	// §2.4/T-09) carry the DNS blocklist import feature's manifest entries
	// (Blocklists — including each list's blockMode, plan §2.3) and, for a
	// subset of them, the underlying <id>.hosts file content (BlocklistFiles).
	// Both MUST stay omitempty for the same checksum-compatibility reason as
	// PortForwards above: older backups (which lack these keys) must keep
	// re-marshalling to the same bytes, or their checksum breaks and the whole
	// file fails to import. Only <id>.hosts is ever carried — <id>.conf (the
	// nxdomain-mode derived artifact) is never included, since it can always
	// be regenerated from the .hosts content on import (plan §2.1.1/§2.4).
	Blocklists     []DNSBlocklist            `json:"blocklists,omitempty"`
	BlocklistFiles []DNSBlocklistFilePayload `json:"blocklistFiles,omitempty"`
	// WanUplinks/WanFailoverSettings (docs/ref/todo/multi-wan-failover-plan.md
	// Task 12) MUST stay omitempty (WanFailoverSettings is a pointer, same
	// reasoning as DhcpHealthSettings above) for the same checksum-
	// compatibility reason as PortForwards: an older backup that predates
	// this feature lacks these keys entirely, and re-marshalling it through
	// BackupConfig must reproduce byte-for-byte the same JSON it started
	// with, or its checksum breaks and the whole file fails to import.
	WanUplinks          []WanUplink          `json:"wanUplinks,omitempty"`
	WanFailoverSettings *WanFailoverSettings `json:"wanFailoverSettings,omitempty"`
}

// DNSBlocklistFilePayload carries one blocklist's canonical <id>.hosts file
// content inside a backup (plan §2.4) — gzip-compressed then base64-encoded
// to keep the JSON backup file a reasonable size for a 90k+ domain list.
// Sha256 is verified against the decoded/decompressed content on import
// BEFORE it is ever written to disk (plan §3 T-09 item 3), since that content
// is later loaded straight into dnsmasq.
type DNSBlocklistFilePayload struct {
	ID         string `json:"id"`
	Sha256     string `json:"sha256"`
	GzipBase64 string `json:"gzipBase64"`
}

// BackupUser mirrors a users row for backup purposes. Unlike model.User it
// intentionally serialises PasswordHash (bcrypt) so accounts can be restored;
// callers must treat a backup containing users as credential material.
type BackupUser struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
	IsInitial    bool   `json:"isInitial"`
	Role         string `json:"role"`
	Status       string `json:"status"`
	CreatedAt    string `json:"createdAt"`
}

// ImportOptions carries the caller's intent and identity into an import so the
// service can honour the include-users toggle and guard against the actor
// locking themselves out.
type ImportOptions struct {
	IncludeUsers  bool
	ActorUserID   string
	ActorUsername string
	// Passphrase decrypts an encrypted backup; empty for plaintext files.
	Passphrase string
}

// ImportResult summarises what an import applied so the UI can report counts,
// non-fatal apply warnings, and whether the operation may have disrupted the
// admin's own connectivity.
type ImportResult struct {
	SchemaVersion     int            `json:"schemaVersion"`
	Counts            map[string]int `json:"counts"`
	Warnings          []string       `json:"warnings"`
	InterfacesChanged bool           `json:"interfacesChanged"`
	UsersImported     bool           `json:"usersImported"`
	// RemovedUsernames lists users that existed before but are absent/disabled
	// after the import, so the API layer can purge their sessions. Not part of
	// the JSON response.
	RemovedUsernames []string `json:"-"`
}
