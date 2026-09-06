package kernel

import (
	"context"
	"net"
	"time"

	"pigate/internal/model"
)

// FirewallManager abstracts nftables kernel modifications
type FirewallManager interface {
	ApplyRules(
		rules []model.PolicyRule,
		ifaces []model.NetworkInterface,
		addrs []model.AddressObject,
		svcs []model.ServiceObject,
		dhcpServerIfaces []string,
		dnsServerIfaces []string,
		portForwards []model.PortForward,
	) error

	// FQDNResolutions returns a copy of the FQDN -> resolved IPv4 (as
	// strings) map that reflects exactly what the most recent successful
	// ApplyRules call used to build the currently-applied nft rules (docs/
	// ref/todo/fqdn-retry-and-monitored-counters-plan.md D-1, issue #141).
	// Only FQDN address-object entries actually referenced by an enabled
	// PolicyRule are present. A key with an empty slice value means that
	// FQDN failed to resolve (or resolved to no IPv4 address) on the last
	// apply — this is the signal FQDNRefresher polls to know when to retry.
	// Never returns nil; an empty map means either no FQDN entries are in
	// use, or ApplyRules hasn't succeeded yet.
	FQDNResolutions() map[string][]string
}

// TrafficLogManager streams packet PASS/DROP events for all three firewall
// chains (forward, input, output) into the app. The real implementation
// subscribes to two NFLOG netlink groups — ForwardNflogGroup for the forward
// chain and LocalNflogGroup for input/output (the chains' log statements are
// configured to log to a group instead of printk); the mock implementation
// synthesizes events for all three chains so dev/mock mode has a live log
// feed. Both Watch* methods block until ctx is cancelled, invoking cb once
// per event. cb must return promptly — implementations must not let a slow
// consumer stall the netlink read loop (see real_traffic_log.go).
type TrafficLogManager interface {
	WatchForwardTraffic(ctx context.Context, cb func(model.FirewallLog)) error
	// WatchLocalTraffic streams input+output chain events (NFLOG group
	// LocalNflogGroup). Entries carry model.FirewallLog.Chain set to
	// "input" or "output" per the log prefix (see real_traffic_log.go
	// parseNflogAttr).
	WatchLocalTraffic(ctx context.Context, cb func(model.FirewallLog)) error
}

// TrafficAccountingManager abstracts read-only traffic accounting used by the
// Dashboard "Detailed" tab's Protocol Breakdown / Top Talkers / Top Rules
// cards (docs/ref/todo/dashboard-traffic-detail-plan.md). Both methods are
// strictly read-only (a dump/list, never a mutation) and MUST degrade
// gracefully rather than fail the whole request: a real implementation
// requires `net.netfilter.nf_conntrack_acct=1` to be set on the host for
// DumpFlows to return non-zero byte counts (see the "conntrack" capability
// probe) — an unset sysctl is not itself an error, it just yields
// FlowSample.BytesOrig==0 and FlowSample.BytesReply==0 for every flow.
// Callers (service.TrafficStatsService)
// are responsible for polling on a background goroutine and caching the
// result; neither method may be called directly from an HTTP request handler
// (plan Caution 6).
type TrafficAccountingManager interface {
	// DumpFlows returns a snapshot of the conntrack table (IPv4 + IPv6) at the
	// moment of the call. A family that errors (e.g. IPv6 disabled) is logged
	// and skipped rather than failing the whole dump; only when every family
	// fails does DumpFlows return an error.
	DumpFlows() ([]model.FlowSample, error)
	// DumpRuleCounters returns the current bytes/packets nftables has counted
	// for each DB policy-rule id (decoded from the rule's UserData comment —
	// see real_firewall.go applyUserRules). Rules with no UserData (the fixed
	// structural rules: ct-state checks, final drop-log, etc.) are omitted.
	DumpRuleCounters() (map[string]model.RuleCounter, error)
	// WatchFlowEnd streams the final byte count of every conntrack flow at
	// teardown (conntrack DESTROY event), so a flow that starts and dies
	// entirely between two DumpFlows polls is not lost (docs/ref/todo/
	// traffic-accounting-accuracy-phase2-plan.md §2.1). Blocking; returns when
	// ctx is done or the subscription fails — a returned error means the
	// caller must degrade to poll-only (DumpFlows) rather than fail startup
	// (plan Caution 6). cb must return promptly, mirroring
	// TrafficLogManager.WatchForwardTraffic above.
	WatchFlowEnd(ctx context.Context, cb func(model.FlowSample)) error
}

// NetworkManager abstracts Wi-Fi scanning and interface control
type NetworkManager interface {
	ToggleInterface(name string, up bool) error
	ScanWifi(name string) ([]model.WifiScanResult, error)
	// ConfigureInterface applies IP/mode/gateway to an interface.
	// metric sets the default-route priority in static mode; metric <= 0 means
	// "unset" and falls back to the historical default of 100.
	ConfigureInterface(name string, mode string, ip string, netmask string, gateway string, metric int) error
	ConfigureWifi(name string, ssid string, password string, security string, backupSSID string, backupPassword string, backupSecurity string, macMode string, prefer5GHz bool) error
	GetWifiStatus(name string) (*model.WifiConnectionStatus, error)
	// CreateVlan creates an 802.1Q VLAN sub-interface named "<parent>.<vlanID>"
	// on top of the given parent interface (e.g. CreateVlan("eth0", 100) -> "eth0.100").
	CreateVlan(parent string, vlanID int) error
	// DeleteVlan removes a VLAN link previously created on this host. It must
	// refuse to delete a link whose kernel type is not "vlan" (a guard against
	// deleting a physical interface such as eth0/wlan0).
	DeleteVlan(name string) error
	// GetIPv4Addresses returns the current IPv4 addresses assigned to the
	// interface as CIDR strings (e.g. "169.254.1.2/16"). Used by the DHCP
	// health-checker (issue #78) to classify link-local-only/no-IP states
	// without disturbing other addresses on the interface.
	GetIPv4Addresses(name string) ([]string, error)
	// DeleteAddress removes a single address (given as CIDR) from the
	// interface, leaving any other addresses untouched. Used by the DHCP
	// health-checker (issue #78) to strip a stray 169.254.x.x APIPA address
	// while a real IP coexists on the same interface.
	DeleteAddress(name string, cidr string) error
}

// RoutingManager abstracts netlink route modifications
type RoutingManager interface {
	ApplyRoutes(routes []model.StaticRoute) error
	AddRoute(route model.StaticRoute) error
	DeleteRoute(route model.StaticRoute) error
	SetEnableEditSystemRoute(enable bool)
	// EnforceDefaultRouteMetric ensures the IPv4 default gateway route on ifaceName
	// has the given priority, deleting and re-adding it (preserving proto/scope/src/gw)
	// if the current priority differs. Used to override the metric of dhcpcd-managed
	// default routes for multi-WAN failover ordering. IPv4 only.
	EnforceDefaultRouteMetric(ifaceName string, metric int) error
}

// DhcpManager abstracts DHCP configuration updates and active lease logs parsing
type DhcpManager interface {
	ApplyConfig(cfgs []model.DhcpConfig, reservations []model.DhcpReservation) error
	GetActiveLeases() ([]model.ActiveDhcpLease, error)
	ReloadConfig() error
	WatchLeases(ctx context.Context, callback func(event string, lease model.ActiveDhcpLease)) error
}

// DNSManager abstracts systemd-resolved modifications and status checks
type DNSManager interface {
	GetLinkDNS(ifaceName string) ([]string, error)
	SetLinkDNS(ifaceName string, servers []string) error
	RevertLinkDNS(ifaceName string) error
	SetGlobalDNS(servers []string, searchDomain string) error
}

// QosManager abstracts Linux Traffic Control (tc) via netlink for bandwidth shaping.
// Phase 1: Egress (Client Download) shaping via HTB Qdisc.
// Phase 2: Ingress (Client Upload) shaping via IFB device redirect (not yet implemented).
type QosManager interface {
	// ApplyQosRules rebuilds HTB qdisc + classes + filters on all affected interfaces.
	// It is idempotent: it clears existing rules before re-applying.
	// Only rules with Status=true are applied to the kernel.
	ApplyQosRules(rules []model.QosRule) error

	// ClearQosRules removes the root qdisc from a specific interface,
	// which cascades and removes all classes and filters underneath.
	ClearQosRules(ifaceName string) error

	// GetIfaceQosStatus returns the live qdisc and class state from the kernel
	// for a given interface. Does not read from the database.
	GetIfaceQosStatus(ifaceName string) (*model.QosIfaceStatus, error)
}

// DNSServerManager abstracts local DNS zone configurations and cache clearing.
// upstreamServers carries the explicit forward resolvers (from System DNS) that
// dnsmasq should use, replacing the broken resolvconf-populated resolv.conf.
type DNSServerManager interface {
	// ApplyZones now also takes queryLog: when true, dnsmasq's `log-queries`
	// directive (writing to a tmpfs file) is enabled so WatchDNSLog below has
	// something to read; when false, any previously-written log file is
	// removed (docs/ref/todo/statistics-dns-top-domain-plan.md T-03/T-05).
	// TTL/cap of the reverse cache are NOT passed here — they are pure
	// service-layer parameters with no effect on the dnsmasq config file.
	// blocked is the deny-list (docs/ref/todo/dns-blocked-domains-plan.md):
	// each enabled entry is rendered as a `server=/<domain>/` (nxdomain) or
	// `address=/<domain>/<ip>` (sinkhole) directive appended after all zones;
	// an empty/all-skipped list produces byte-for-byte the same output as
	// before this parameter existed.
	//
	// blocklists is the bulk-import blocklist feature (docs/ref/todo/
	// dns-blocklist-import-plan.md §2.1/§2.7, T-02): one BlocklistRef per
	// enabled list with DomainCount>0 that the service layer wants enforced.
	// The implementation MUST os.Stat the file each ref resolves to (per its
	// BlockMode) and only emit a directive for a file that actually exists
	// and is non-empty — never emit `addn-hosts=`/`conf-file=` pointing at a
	// missing file (a missing conf-file= target makes dnsmasq refuse to
	// start entirely). An empty/all-skipped blocklists slice produces
	// byte-for-byte the same output as before this parameter existed.
	ApplyZones(zones []model.DNSZone, interfaces []string, upstreamServers []string, queryLog bool, blocked []model.BlockedDomain, blocklists []model.BlocklistRef) error
	ClearCache() error
	// WatchDNSLog streams both query and answer (reply/cached ... is <IP>)
	// events parsed from dnsmasq's query log. Blocking until ctx is done; cb
	// must return promptly (it runs on the log read loop, mirroring
	// TrafficLogManager.WatchForwardTraffic's contract). It is NOT an error
	// for the log file to not exist or for query logging to be disabled — the
	// implementation simply waits quietly rather than erroring.
	WatchDNSLog(ctx context.Context, cb func(model.DNSLogEvent)) error

	// --- Blocklist import (docs/ref/todo/dns-blocklist-import-plan.md T-02) ---
	// All of the following operate on files under /var/lib/pigate/blocklists
	// (kept OUTSIDE /etc/dnsmasq.d on purpose — dnsmasq only auto-scans
	// /etc/dnsmasq.d, so a disabled list's file sitting in this directory is
	// never loaded implicitly; ApplyZones above is the only thing that
	// references it, via an explicit addn-hosts=/conf-file= directive it
	// builds itself). id is always validated against
	// model.ValidateDNSBlocklistID (^bl-[a-z0-9]{1,32}$) before being used to
	// build any path — id comes from the manifest / API layer, i.e. is
	// external input, and is concatenated directly into a filesystem path.

	// WriteBlocklistFile atomically (over)writes <id>.hosts — the canonical,
	// always-present artifact for a list regardless of BlockMode (plan
	// §2.1.1).
	WriteBlocklistFile(id string, content []byte) error
	// WriteBlocklistConfFile atomically (over)writes <id>.conf — the
	// dnsmasq conf-file used only for BlockMode == DNSBlockModeNXDomain,
	// always derived from (never the source of) <id>.hosts.
	WriteBlocklistConfFile(id string, content []byte) error
	// RemoveBlocklistFile deletes both <id>.hosts and <id>.conf for id (used
	// when a list is deleted). Missing files are not an error.
	RemoveBlocklistFile(id string) error
	// RemoveBlocklistConfFile deletes only <id>.conf (used when a list
	// switches from nxdomain back to sinkhole mode, so no derived file is
	// left orphaned on disk). Missing file is not an error.
	RemoveBlocklistConfFile(id string) error
	// BlocklistFileInfo reports the size/existence of <id>.hosts without
	// reading its contents. exists=false (size=0) covers both "never
	// written" and "id fails validation" — callers that need to distinguish
	// those cases should validate id themselves first.
	BlocklistFileInfo(id string) (size int64, exists bool)
	// BlocklistConfFileInfo is BlocklistFileInfo for <id>.conf.
	BlocklistConfFileInfo(id string) (size int64, exists bool)
	// StreamBlocklistFile reads <id>.hosts back line-by-line, invoking fn
	// once per line (used to rebuild the statistics index and to re-render
	// <id>.conf when a list's BlockMode is switched without re-fetching —
	// both cases where holding the whole file in memory would be wasteful).
	// A missing file is not an error (fn is simply never called). fn
	// returning a non-nil error stops the scan and that error is returned.
	StreamBlocklistFile(id string, fn func(line string) error) error
	// ReadBlocklistManifest reads manifest.json's raw bytes. A missing file
	// returns (nil, nil) — NOT an error — so the service layer's Load()
	// treats "never written yet" the same as "empty manifest" (plan §2.3
	// item 3).
	ReadBlocklistManifest() ([]byte, error)
	// WriteBlocklistManifest atomically (over)writes manifest.json.
	WriteBlocklistManifest(content []byte) error
	// QuarantineBlocklistManifest renames a corrupt/unparsable manifest.json
	// to manifest.json.corrupt-<unix-timestamp> so the feature can start
	// fresh with a new empty manifest instead of being permanently stuck
	// (plan §2.3 item 3). Not finding a manifest to quarantine is not an
	// error.
	QuarantineBlocklistManifest() error
	// SupportsBulkNXDomain reports whether the local dnsmasq binary is new
	// enough (>= 2.86, plan §2.1.5) to serve BlockMode == DNSBlockModeNXDomain
	// blocklists efficiently at scale. The real implementation runs
	// `dnsmasq --version` once (cached via sync.Once) and fails OPEN (returns
	// true) when the version can't be determined — an unnecessarily-enabled
	// nxdomain mode on an old dnsmasq is merely slow, whereas fail-closed
	// would break the feature on boards that are actually fine. The mock
	// implementation always returns true (dev workstations aren't running
	// the board's dnsmasq at all).
	SupportsBulkNXDomain() bool
}

// DhcpcdManager abstracts starting/stopping the per-interface dhcpcd@ systemd
// service. dhcpcd runs as its own root-owned systemd service so its internal
// privilege-separation (chroot + setuid/setgid) works correctly; pigate only
// asks systemd to start/stop it.
type DhcpcdManager interface {
	StartDhcpcd(ifaceName string) error
	StopDhcpcd(ifaceName string) error
	// SetShareHostname writes/clears the `hostname` directive in the pigate-owned
	// dhcpcd config file (/var/lib/pigate/dhcpcd.conf) that dhcpcd@.service reads.
	// share=true makes dhcpcd send DHCP Option 12 with the system's current hostname.
	SetShareHostname(share bool) error
	// RestartDhcpcd restarts the per-interface dhcpcd@ service so a config change
	// (e.g. SetShareHostname) takes effect. Causes a brief WAN lease renewal.
	RestartDhcpcd(ifaceName string) error
}

// MaxFlowsPerDump caps how many conntrack flows a single DumpFlows call
// processes (per IP family), so a port-scan/DDoS that inflates the conntrack
// table cannot turn a routine poll into an unbounded memory/CPU spike (plan
// Caution 5). Exported (and declared in this build-tag-free file) so the
// service layer can compare a dump's length against it without needing the
// linux-only real_traffic_account.go build.
const MaxFlowsPerDump = 50000

// SystemStatsManager abstracts host telemetry reads (/proc, /sys, statfs,
// netlink counters). It is strictly read-only: no method mutates system state.
// Implementations must degrade gracefully — a missing sysfs node (thermal zone,
// cpufreq, device-tree) yields an "unavailable" field, never a whole-response
// error, so the mock-free real path still works on WSL / x86 dev boxes.
type SystemStatsManager interface {
	// GetCPUSnapshot returns raw cumulative jiffies from /proc/stat. The service
	// computes usage% from the delta between two snapshots — a single call alone
	// is not a usage figure.
	GetCPUSnapshot() (*model.CPUSnapshot, error)
	// GetCPUInfo returns model name, core count, and current frequency
	// (FreqAvailable=false when cpufreq is absent).
	GetCPUInfo() (*model.CPUInfo, error)
	// GetMemoryInfo returns total/used bytes from /proc/meminfo.
	GetMemoryInfo() (*model.MemoryInfo, error)
	// GetTemperature returns SoC temperature; Available=false when no thermal
	// zone is present.
	GetTemperature() (*model.TemperatureInfo, error)
	// GetDiskUsage returns filesystem usage for the given mount path via statfs.
	GetDiskUsage(path string) (*model.DiskUsage, error)
	// GetHostInfo returns OS/board/kernel identity and uptime.
	GetHostInfo() (*model.HostInfo, error)
	// GetNetCounters returns cumulative rx/tx byte counters keyed by interface name.
	GetNetCounters() (map[string]model.NetCounters, error)
	// GetConntrackCount returns the live conntrack table occupancy from
	// /proc/sys/net/netfilter/nf_conntrack_count|max. available=false (with
	// count=max=0) when the nodes are absent (WSL/dev box, nf_conntrack not
	// loaded) — never an error, never a per-call log line.
	GetConntrackCount() (count int, max int, available bool)
}

// HostnameManager abstracts reading/writing the system hostname via
// org.freedesktop.hostname1 (systemd-hostnamed) over D-Bus.
type HostnameManager interface {
	GetHostname() (string, error)
	SetHostname(name string) error
}

// TimeManager abstracts timezone / NTP / manual-clock control via
// org.freedesktop.timedate1 (systemd-timedated) over D-Bus, plus the
// systemd-timesyncd drop-in used to point NTP at a custom server.
type TimeManager interface {
	// GetTimeStatus reads live state (current time + whether NTP has synced).
	GetTimeStatus() (*model.TimeStatus, error)
	// SetTimezone sets the IANA timezone (timedated writes /etc/localtime).
	SetTimezone(tz string) error
	// SetNTP enables/disables automatic time sync (timedated starts/stops
	// and enables/disables systemd-timesyncd).
	SetNTP(enable bool) error
	// SetTime sets the wall clock manually. Rejected by timedated while NTP
	// is enabled — callers must guard against that first.
	SetTime(t time.Time) error
	// SetNTPServer writes the pigate-owned timesyncd drop-in with the given
	// server(s) and restarts timesyncd (only while NTP is enabled). An empty
	// server clears the drop-in back to distro defaults.
	SetNTPServer(server string) error
}

// PowerManager abstracts host power control via org.freedesktop.login1
// (systemd-logind) over D-Bus. Both operations are irreversible: Reboot
// restarts the board and PowerOff halts it (requiring physical intervention
// to power back on). logind performs a graceful shutdown, stopping services
// (including pigate.service) so SQLite closes cleanly on its own.
type PowerManager interface {
	Reboot() error
	PowerOff() error
}

// SystemServiceManager abstracts read/restart control of arbitrary systemd
// units via D-Bus, for the Settings "Network Services Status" panel. It is a
// thin, policy-free wrapper around the unit name it is given — it does not
// know (and must not need to know) which units are safe to expose or restart.
// That whitelist/catalog policy lives in service.SystemServiceService, not
// here, mirroring how PowerManager stays free of audit/business logic.
type SystemServiceManager interface {
	// GetStatus reads the live ActiveState/LoadState of the given systemd unit.
	GetStatus(unit string) (model.ServiceRuntimeState, error)
	// Restart asks systemd to restart the given unit. Callers MUST have
	// already resolved unit from a server-side whitelist — never pass a raw,
	// client-supplied string straight through (unit-name injection).
	Restart(unit string) error
}

// PathProbeManager abstracts sending ICMP/TCP-connect health probes out a
// specific network interface, for the Multi-WAN Failover health monitor
// (docs/ref/todo/multi-wan-failover-plan.md, Phase 1 — read-only with
// respect to routing/nftables, D-1). Both methods:
//  1. are strictly read-only: they never modify routing, firewall, or any
//     other system state — this is a measurement probe, nothing else;
//  2. MUST bind the probe socket to ifaceName via SO_BINDTODEVICE (not just
//     rely on source-IP selection), since a multi-WAN host has more than one
//     default route active at once and the kernel's normal route selection
//     would otherwise not exercise the path being asked about;
//  3. MUST respect ctx and always return within count*timeout — a caller
//     (the periodic WAN monitor) must never be blocked indefinitely by a
//     socket that never gets a reply;
//  4. treat "the destination never replied" as a normal, non-error result
//     (the returned model.WanProbeSample simply has Received==0/a shorter
//     RTTsMs) — an error return is reserved for the probe mechanism itself
//     failing (e.g. socket() failed, permission denied, interface does not
//     exist), which is a different condition the health monitor must
//     distinguish from "target is unreachable";
//  5. MUST always set Sample.Method and Sample.MetricQuality on every
//     return (including the zero-value/error paths a caller might still
//     read fields off of) — ProbeTCP always reports MetricQuality
//     "connect-only" (TCP-connect cannot measure jitter, D-6), while
//     ProbeICMP reports "full".
//
// Deciding WHEN to fall back from ICMP to TCP (the "auto" ProbeMethod,
// D-5) is entirely a service-layer (service.WanMonitor) concern — this
// interface has no notion of "auto" at all, it only ever probes the one
// method it was asked for.
type PathProbeManager interface {
	// ProbeICMP sends count ICMP Echo Requests to target out ifaceName,
	// waiting up to timeout for each reply, and returns a summary sample.
	ProbeICMP(ctx context.Context, ifaceName string, target net.IP, count int, timeout time.Duration) (model.WanProbeSample, error)
	// ProbeTCP attempts count TCP connections to target:port out ifaceName,
	// waiting up to timeout for each to establish, and returns a summary
	// sample. A connection actively refused by the remote host counts as the
	// destination being reachable (the path works, nothing is listening on
	// that port) — see real_path_probe.go for why that is counted as success
	// in the reachability sense despite being a "connection error".
	ProbeTCP(ctx context.Context, ifaceName string, target net.IP, port, count int, timeout time.Duration) (model.WanProbeSample, error)
}

// CapabilityProber abstracts read-only detection of whether the kernel
// subsystems PiGate depends on (nftables, D-Bus/systemd units, ...) are
// actually usable in the current environment (e.g. WSL lacks nf_tables and/or
// systemd entirely). Implementations MUST be:
//   - read-only: never create/delete/modify any table, chain, qdisc, or bind
//     an NFLOG group — this is a detection probe, not a mutation;
//   - bounded: ProbeAll must return within a fixed internal timeout rather
//     than blocking a request handler indefinitely if a socket never answers.
type CapabilityProber interface {
	// ProbeAll probes every registered subsystem and returns one result per
	// id, regardless of whether individual probes succeeded or failed.
	ProbeAll() []model.CapabilityProbeResult
}
