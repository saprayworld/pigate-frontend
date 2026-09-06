package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	// Embed the IANA timezone database so timezone validation
	// (time.LoadLocation) works even on minimal environments that lack a system
	// tzdata package (dev containers, etc.). ~450KB. On the Pi this simply
	// mirrors the system tzdata.
	_ "time/tzdata"

	"github.com/google/uuid"

	"pigate/internal/api"
	"pigate/internal/config"
	"pigate/internal/db"
	"pigate/internal/kernel"
	"pigate/internal/logs"
	"pigate/internal/model"
	"pigate/internal/service"
)

// defaultConfigPath is used when -config is not passed on the command line.
// If the file doesn't exist there yet, main() writes the code defaults to it
// (see resolveConfig) rather than failing — unlike an explicitly-passed
// -config path, which must already exist.
const defaultConfigPath = "/var/lib/pigate/pigate.conf"

// version is the PiGate build version. It is overridable at build time via
// -ldflags "-X main.version=<tag>" (see build.sh); the default applies to plain
// `go build` / `go run` during development.
var version = "v0.2.0"

func main() {
	// 1. Register CLI flags. Their default values here must stay 1:1 with
	// config.Defaults() (see internal/config/config.go) — except the two
	// file-only keys dns-stats-max-pairs/dns-stats-max-clients, which
	// intentionally have no flag counterpart at all (see internal/config's
	// package doc comment). The returned pointers
	// are intentionally not captured for most of these: flag.Parse() still
	// validates/parses them (e.g. -port=abc still fails fast the same way it
	// always has), but the resolved value each subsystem actually uses comes
	// from cfg.* below (code default < config file < CLI flag explicitly
	// passed — see resolveConfig). Only -v and -config are needed as values
	// before cfg exists, so only those two are kept as named pointers.
	flag.Int("port", 2479, "Port to run the API server on")
	flag.String("db", "pigate.db", "Path to SQLite database file")
	flag.Bool("mock", true, "Use mocked kernel operations (default true on PC)")
	flag.Bool("mock-from-real", false, "Mock operations but initialize/pull from real kernel data at startup")
	flag.Bool("disable-edit", false, "Disable edit operations (Read-only mode)")
	flag.Bool("allow-edit-system-routes", false, "Allow editing and deleting system predefined static routes")
	flag.Bool("enable-edit-system-route", false, "Enable direct kernel management of system/kernel-only routes without database")
	flag.Bool("prioritize-kernel-routes", false, "Prioritize kernel route information over database if duplicate")
	flag.Bool("docker-compat", false, "Enable Docker compatibility (bypass docker0 and br-* interfaces). Off by default; opt in only on a gateway that also runs Docker/bridge networks.")
	flag.Int("https-port", 0, "HTTPS port (0 = HTTP only; the systemd unit passes 443 to make HTTPS the primary channel)")
	flag.String("tls-dir", "", "Directory for the self-signed TLS cert/key (default: <dir of -db>/tls)")
	flag.Bool("allow-dev-cors", false, "Echo CORS headers for frontend dev-server origins (localhost:5173/3000). Off by default; only needed when running `yarn dev` against this backend.")
	printVersion := flag.Bool("v", false, "Print Version")
	configPath := flag.String("config", "", "Path to a key=value bootstrap config file (default: "+defaultConfigPath+"). CLI flags explicitly passed always override the file.")
	flag.Parse()
	if *printVersion {
		log.Printf("PiGate Server version %s", version)
		return
	}

	// 1b. Resolve bootstrap config: code defaults < config file < CLI flags
	// explicitly passed on this invocation. See internal/config and
	// docs/ref/todo/config-file-loader-plan.md for the full precedence/rationale.
	cfg := resolveConfig(*configPath)

	log.Printf("[Main] Starting PiGate Backend Server (Go v1.26.4)...")
	log.Printf("[Main] Port: %d", cfg.Port)
	log.Printf("[Main] Database: %s", cfg.DBPath)
	log.Printf("[Main] Mock OS Integration: %t", cfg.Mock)
	log.Printf("[Main] Mock From Real Data: %t", cfg.MockFromReal)
	log.Printf("[Main] Disable Edit Mode: %t", cfg.DisableEdit)
	log.Printf("[Main] Allow Dev CORS Origins: %t", cfg.AllowDevCORS)
	log.Printf("[Main] Allow Edit System Routes: %t", cfg.AllowEditSystemRoutes)
	log.Printf("[Main] Enable Edit System Route (Bypass DB): %t", cfg.EnableEditSystemRoute)
	log.Printf("[Main] Prioritize Kernel Routes: %t", cfg.PrioritizeKernelRoutes)
	log.Printf("[Main] Docker Compatibility: %t", cfg.DockerCompat)
	log.Printf("[Main] HTTPS Port: %d (0 = HTTP only)", cfg.HTTPSPort)
	log.Printf("[Main] DNS Stats Max Pairs/Clients per bucket: %d / %d", cfg.DNSStatsMaxPairs, cfg.DNSStatsMaxClients)
	log.Printf("[Main] Traffic Stats Max Hosts/Dests/Conversations per bucket: %d / %d / %d", cfg.TrafficStatsMaxHosts, cfg.TrafficStatsMaxDests, cfg.TrafficStatsMaxConversations)
	log.Printf("[Main] DNS Stats Max Domains/IPs-per-domain: %d / %d", cfg.DNSStatsMaxDomains, cfg.DNSStatsMaxIPsPerDomain)
	log.Printf("[Main] IPInfo (Public IP Info card) Enabled: %t", cfg.IPInfoEnabled)
	log.Printf("[Main] Deny Stats Max Sources/Ports per bucket: %d / %d", cfg.DenyStatsMaxSources, cfg.DenyStatsMaxPorts)
	log.Printf("[Main] Traffic Log Buffer Capacity: %d", cfg.TrafficLogBufferCapacity)

	// 2. Initialize in-memory forward-traffic logs circular buffer (Ring Buffer).
	// Fed live by the TrafficLogManager watcher below (real NFLOG or mock
	// generator); powers both the Forward Traffic page and the Dashboard Recent
	// Logs widget. RAM-only — never persisted (SD card wear, tech_stack_design.md
	// §8). Capacity comes from the file-only traffic-log-buffer-capacity config
	// key (default 10000, accepted range 500-100000 — see internal/config's
	// two-tier validation) rather than a compile-time constant, so an operator
	// can raise/lower it via pigate.conf without a rebuild (docs/ref/todo/
	// firewall-log-buffer-capacity-plan.md T-00/T-05, issue #134). It is only
	// read here, once, at startup — changing the key takes effect on the NEXT
	// restart, never live (the ring can't be resized/re-subscribed while
	// running).
	ringBuffer := logs.NewRingBuffer(cfg.TrafficLogBufferCapacity)

	// 3. Initialize SQLite DB & run migrations
	sqliteDB, err := db.InitDB(cfg.DBPath, cfg.Mock)
	if err != nil {
		log.Fatalf("Fatal error initializing SQLite DB: %v", err)
	}
	defer sqliteDB.Close()

	repo := db.NewRepository(sqliteDB)
	repo.SetMockMode(cfg.Mock, cfg.MockFromReal)
	repo.SetAllowEditSystemRoutes(cfg.AllowEditSystemRoutes)
	repo.SetPrioritizeKernelRoutes(cfg.PrioritizeKernelRoutes)
	// Per-Address/Service-Object entry cap comes from the file-only
	// max-object-entries config key (docs/ref/todo/
	// multi-value-address-service-objects-plan.md §2.1) — no CLI flag by
	// design. Read once at startup; changing the key only takes effect on
	// the next restart.
	repo.SetObjectLimits(cfg.MaxObjectEntries)
	// Per-direction PolicyRule interfaces cap comes from the file-only
	// max-policy-interfaces-per-direction config key (docs/ref/todo/
	// multi-interface-firewall-rule-plan.md §2.2, D-2) — no CLI flag by
	// design. Read once at startup; changing the key only takes effect on
	// the next restart.
	repo.SetPolicyInterfaceLimit(cfg.MaxPolicyInterfacesPerDirection)

	// 4. Instantiate Kernel managers (Force Mock layer for now)
	var fw kernel.FirewallManager
	var net kernel.NetworkManager
	var rt kernel.RoutingManager
	var dhcp kernel.DhcpManager
	var qos kernel.QosManager
	var dnsServer kernel.DNSServerManager
	var dhcpcd kernel.DhcpcdManager
	var hostnameMgr kernel.HostnameManager
	var timeMgr kernel.TimeManager
	var sysStats kernel.SystemStatsManager
	var powerMgr kernel.PowerManager
	var trafficLog kernel.TrafficLogManager
	var systemServiceMgr kernel.SystemServiceManager
	var capProber kernel.CapabilityProber
	var trafficAcct kernel.TrafficAccountingManager
	var pathProbe kernel.PathProbeManager
	dns := kernel.NewDNSManager(cfg.Mock)

	if cfg.Mock || cfg.MockFromReal {
		fw = kernel.NewMockFirewall(cfg.DockerCompat)
		net = kernel.NewMockNetwork()
		rt = kernel.NewMockRouting()
		qos = kernel.NewMockQos()
		mDhcp := kernel.NewMockDhcp()
		mDhcp.MockFromReal = cfg.MockFromReal
		dhcp = mDhcp
		dnsServer = kernel.NewMockDNSServerManager()
		dhcpcd = kernel.NewMockDhcpcdManager()
		hostnameMgr = kernel.NewMockHostnameManager()
		timeMgr = kernel.NewMockTimeManager()
		sysStats = kernel.NewMockSystemStats()
		powerMgr = kernel.NewMockPowerManager()
		mTrafficLog := kernel.NewMockTrafficLog()
		// SetRuleIDProvider wires live DB policy-rule ids into the mock
		// traffic-log samples (docs/ref/todo/
		// firewall-rule-matched-endpoints-plan.md T-07), so
		// GET /api/policies/{id}/endpoints has real data to show under
		// -mock=true. A one-time read at startup is enough for dev/test
		// purposes — kernel must never import db, so this is a plain
		// closure over repo captured here in main.go, same pattern as
		// trafficAcct's ruleIDs provider just above.
		mTrafficLog.SetRuleIDProvider(func() []string {
			rules, err := repo.GetPolicies()
			if err != nil {
				return nil
			}
			ids := make([]string, 0, len(rules))
			for _, r := range rules {
				ids = append(ids, r.ID)
			}
			return ids
		})
		trafficLog = mTrafficLog
		systemServiceMgr = kernel.NewMockSystemServiceManager()
		capProber = kernel.NewMockCapabilityProber()
		pathProbe = kernel.NewMockPathProbe()
		// ruleIDs supplies live DB policy-rule ids so MockTrafficAccounting's
		// synthetic Top Rules entries actually match something in the DB
		// (docs/ref/todo/dashboard-traffic-detail-plan.md T-05).
		trafficAcct = kernel.NewMockTrafficAccounting(func() []string {
			rules, err := repo.GetPolicies()
			if err != nil {
				return nil
			}
			ids := make([]string, 0, len(rules))
			for _, r := range rules {
				ids = append(ids, r.ID)
			}
			return ids
		})
	} else {
		// Real kernel integrations via netlink — used on Raspberry Pi 5 production.
		// Requires: sudo setcap cap_net_admin,cap_net_raw+ep ./pigate-backend
		realFw := kernel.NewRealFirewall(cfg.DockerCompat)
		// Per-policy-rule expanded nft rule cap comes from the file-only
		// max-expanded-rules-per-policy config key (docs/ref/todo/
		// multi-value-address-service-objects-plan.md §2.1) — no CLI flag by
		// design, mock mode does not need it. Must be set on the concrete
		// *RealFirewall before it is assigned to the fw interface variable, since
		// FirewallManager itself does not (and must not) expose this method.
		realFw.SetMaxExpandedRulesPerPolicy(cfg.MaxExpandedRulesPerPolicy)
		fw = realFw
		net = kernel.NewRealNetwork()
		rt = kernel.NewRealRouting(cfg.AllowEditSystemRoutes)
		qos = kernel.NewRealQos()
		dhcp = kernel.NewRealDhcpManager()
		dnsServer = kernel.NewRealDNSServerManager()
		dhcpcd = kernel.NewRealDhcpcdManager()
		hostnameMgr = kernel.NewRealHostnameManager()
		timeMgr = kernel.NewRealTimeManager()
		sysStats = kernel.NewRealSystemStats()
		powerMgr = kernel.NewRealPowerManager()
		trafficLog = kernel.NewRealTrafficLog()
		systemServiceMgr = kernel.NewRealSystemServiceManager()
		capProber = kernel.NewRealCapabilityProber()
		trafficAcct = kernel.NewRealTrafficAccounting()
		pathProbe = kernel.NewRealPathProbe()
	}

	// 5. Instantiate Server & Router
	ifaceService := service.NewInterfaceService(repo, net)
	// Wi-Fi saved-networks (preset) library (issue #66). No kernel capability of
	// its own — apply just prepares a NetworkInterface and reuses ifaceService's
	// existing ApplyInterfaceConfig path, so there is nothing to apply at startup
	// (interfaces retain their own copy once a preset has been applied to them).
	wifiPresetService := service.NewWifiPresetService(repo, ifaceService)
	dhcpcdService := service.NewDhcpcdService(repo, ifaceService, dhcpcd)
	routingService := service.NewRoutingService(repo, rt)
	routingService.SetEnableEditSystemRoute(cfg.EnableEditSystemRoute)
	firewallService := service.NewFirewallService(repo, fw, ifaceService)
	// Rule-matched-name snapshot for the traffic log (docs/ref/todo/
	// traffic-log-rule-name-and-domain-plan.md T-05/T-08): an O(1),
	// I/O-free lookup used from the NFLOG hot path in stampAndPush below.
	// SetRuleNameResolver wires it so every successful SyncFirewallRules
	// also refreshes the snapshot immediately (see FirewallService.
	// recordApply) — the resolver's own background ticker (started later,
	// once monitorCtx exists) is only the fallback cadence.
	ruleNameResolver := service.NewRuleNameResolver(repo)
	firewallService.SetRuleNameResolver(ruleNameResolver)
	dnsService := service.NewDNSService(repo, dns)
	qosService := service.NewQosService(repo, qos)
	dhcpServerService := service.NewDhcpServerService(repo, dhcp)
	dnsServerService := service.NewDNSServerService(repo, dnsServer, dnsService)
	hostnameService := service.NewHostnameService(repo, hostnameMgr, dhcpcd, ifaceService)
	timeService := service.NewTimeService(repo, timeMgr)
	userService := service.NewUserService(repo)
	powerService := service.NewPowerService(powerMgr)
	systemServiceService := service.NewSystemServiceService(systemServiceMgr, repo)
	systemStatusService := service.NewSystemStatusService(sysStats, repo, hostnameService, timeService, version)
	// Dashboard "Detailed" tab traffic-analytics pipeline (Protocol Breakdown /
	// Top Talkers / Top Rules by Traffic — docs/ref/todo/dashboard-traffic-detail-plan.md).
	// TrafficStatsMaxHosts/Dests/Conversations come from the file-only
	// bootstrap keys traffic-stats-max-hosts / -max-dests / -max-conversations
	// (no CLI flag by design — docs/ref/todo/statistics-traffic-page-plan.md §1.6).
	trafficStatsService := service.NewTrafficStatsService(trafficAcct, repo, dhcp, sysStats, cfg.TrafficStatsMaxHosts, cfg.TrafficStatsMaxDests, cfg.TrafficStatsMaxConversations)
	// Wire the Active Sessions snapshot into the SSE metrics push after both
	// services exist above, to avoid a circular dependency between them
	// (docs/ref/todo/dashboard-active-sessions-graph-plan.md Step 5).
	systemStatusService.SetSessionCurrentFn(trafficStatsService.SessionCurrent)

	// Persisted, opt-in "Monitor" per-rule counters (docs/ref/todo/
	// fqdn-retry-and-monitored-counters-plan.md D-5/D-6, issue #141) — built
	// right after trafficStatsService, which it drains deltas from.
	// MonitoredCounterFlushIntervalSeconds is file-only config (D-3). Load()
	// seeds the RAM cache from whatever is already in SQLite; a failure here
	// only warns (an empty cache just means totals start at 0 for this boot,
	// same as a genuinely fresh DB — never worth blocking startup over).
	policyCounterStore := service.NewPolicyCounterStore(repo, trafficStatsService, time.Duration(cfg.MonitoredCounterFlushIntervalSeconds)*time.Second)
	if err := policyCounterStore.Load(); err != nil {
		log.Printf("[Main] Warning: failed to load persisted Monitor counters: %v", err)
	}
	firewallService.SetPolicyCounterStore(policyCounterStore)
	firewallService.SetTrafficStats(trafficStatsService)

	// Persisted rule endpoints (docs/ref/todo/persisted-rule-endpoints-plan.md
	// E-08, issue #141 follow-up) — the RAM recorder fed by the stampAndPush
	// hook below, and drained by policyCounterStore's existing flush cycle
	// (no new ticker/goroutine — E-D5). MonitoredEndpointsEnabled/
	// MonitoredEndpointsMaxPerRule are file-only config (E-D9).
	endpointRecorder := service.NewPolicyEndpointRecorder(cfg.MonitoredEndpointsEnabled, cfg.MonitoredEndpointsMaxPerRule)
	policyCounterStore.SetEndpointRecorder(endpointRecorder, cfg.MonitoredEndpointsMaxPerRule)
	// Prime the recorder's monitored-rule set right after policyCounterStore.
	// Load() above, so the first ~flush-interval of uptime after a restart
	// doesn't silently miss traffic for rules that were already monitored
	// before this boot (Record() never queries the DB itself — E-D1). A
	// failure here only warns: the recorder just starts with an empty set,
	// self-healing at the very next Flush() tick.
	if ids, err := repo.GetMonitoredPolicyIDs(); err != nil {
		log.Printf("[Main] Warning: failed to prime endpoint recorder's monitored-rule set: %v", err)
	} else {
		endpointRecorder.SetMonitoredRules(ids)
	}

	// Statistics page (Top Source Hosts / Top Destinations / Top
	// Conversations / Top Denied — docs/ref/todo/statistics-page-plan.md).
	// No ticker/goroutine of its own: byte figures ride TrafficStatsService's
	// existing poller, and the deny ring is fed by the stampAndPush hook
	// below as NFLOG events arrive.
	// DNSStatsMaxPairs/DNSStatsMaxClients come from the file-only bootstrap
	// keys dns-stats-max-pairs / dns-stats-max-clients (no CLI flag by design).
	// DenyStatsMaxSources/DenyStatsMaxPorts come from deny-stats-max-sources/
	// -ports (docs/ref/todo/statistics-capacity-visibility-plan.md T-14).
	statisticsService := service.NewStatisticsService(trafficStatsService, repo, dhcp, cfg.DNSStatsMaxPairs, cfg.DNSStatsMaxClients, cfg.DenyStatsMaxSources, cfg.DenyStatsMaxPorts)
	// SetLogBuffer wires the traffic log ring buffer in so
	// GetCapacityStatistics can report the firewall.logBuffer ring (docs/ref/
	// todo/firewall-log-buffer-capacity-plan.md T-03/T-05, issue #134) —
	// mirrors SetPolicyStatsService below rather than a constructor parameter.
	statisticsService.SetLogBuffer(ringBuffer)
	// SetFirewallService wires FirewallService.LastAppliedAt() into
	// GetFirewallStatistics' CountersSince field (docs/ref/todo/
	// statistics-firewall-page-plan.md T-05/T-06) — same post-construction
	// setter pattern as SetLogBuffer above.
	statisticsService.SetFirewallService(firewallService)
	// SetBlockedStatsLimit sets the per-bucket cap on distinct blocked
	// domains tracked (docs/ref/todo/dns-blocked-query-statistics-plan.md
	// T-07/T-08) — file-only bootstrap key dns-stats-max-blocked-domains, no
	// CLI flag, same pattern as DNSStatsMaxPairs/DNSStatsMaxClients above.
	statisticsService.SetBlockedStatsLimit(cfg.DNSStatsMaxBlockedDomains)
	// SetBlockedDomainsSink wires DNSServerService.ApplyAll to prime the
	// RAM-only deny-list matcher behind the "Blocked Domain Query"
	// statistics feature every time the deny-list is (re)applied (plan
	// T-08). MUST run before dnsServerService.InitApplyConfig() further down
	// so the index is primed from this boot's very first Apply DNS Zones,
	// not left Empty() until the next config change.
	dnsServerService.SetBlockedDomainsSink(statisticsService.SetBlockedDomains)

	// DNS blocklist import (docs/ref/todo/dns-blocklist-import-plan.md T-07)
	// — bulk hosts-file blocklists (subscribe URL / upload), metadata kept in
	// a JSON manifest under /var/lib/pigate/blocklists rather than SQLite
	// (plan §2.3/R1). Load() reads that manifest into RAM; a failure here
	// only warns (same "must not brick the boot" rule as policyCounterStore.
	// Load() above) — an empty in-memory list just means blocklists behave
	// as if none were configured until the next successful write.
	//
	// Note: dnsBlocklistService's HTTP fetcher (T-04) still makes real
	// outbound HTTPS requests even when -mock=true (it is a plain outbound
	// client, not OS/kernel access), but every file it writes (.hosts/.conf/
	// manifest.json) goes through kernel.DNSServerManager, so under -mock=true
	// they all land in MockDNSServerManager's in-memory maps, never on disk.
	// MockDNSServerManager.SupportsBulkNXDomain() always returns true, so the
	// nxdomain blockMode can be exercised on a dev workstation too.
	dnsBlocklistService := service.NewDNSBlocklistService(repo, dnsServer)
	if err := dnsBlocklistService.Load(); err != nil {
		log.Printf("[Main] Warning: failed to load DNS blocklist manifest: %v", err)
	}
	// SetBlocklistProvider/SetBlocklistSink mirror SetBlockedDomainsSink just
	// above: they MUST run before dnsServerService.InitApplyConfig() further
	// down so both dnsServerService.ApplyAll (which pulls the list of
	// enabled blocklists to render into pigate-dns.conf) and the Statistics
	// blocklist-hit index are primed from this boot's very first Apply DNS
	// Zones, not left empty until the next config change.
	dnsServerService.SetBlocklistProvider(dnsBlocklistService)
	dnsServerService.SetBlocklistSink(statisticsService.SetBlocklists)
	// SetApplyDNSCallback is the reverse-direction wiring: it lets
	// dnsBlocklistService.Delete/UpdateInfo regenerate pigate-dns.conf (via
	// dnsServerService.ApplyAll) BEFORE removing a <id>.hosts/<id>.conf file
	// that config might still reference — closes the stale-directive window
	// found at final tech-lead sign-off (same class of problem as Caution
	// 16/issue #50: dnsmasq refuses to start if any conf-file=/addn-hosts=
	// target is missing). Order relative to SetBlocklistProvider above does
	// not matter (different callback directions on different objects), only
	// that it happens before any HTTP request could call Delete/UpdateInfo.
	dnsBlocklistService.SetApplyDNSCallback(dnsServerService.ApplyAll)
	// statisticsService needs a kernel.DNSServerManager handle of its own
	// (SetDNSServerManager, T-06) to stream domains back out of the .hosts
	// files named in SetBlocklists' []model.DNSBlocklist when building the
	// blocklist hit index.
	statisticsService.SetDNSServerManager(dnsServer)
	// No separate InitApplyConfig() call for blocklists: they are applied to
	// dnsmasq as part of dnsServerService.InitApplyConfig() below, exactly
	// like the existing deny-list (dns_blocked_domains) is — blocklists are
	// just another input ApplyAll gathers via the provider wired above.
	//
	// dnsBlocklistService itself is passed into api.NewServer below (T-08) —
	// it backs the /api/dns/blocklists* HTTP handlers/routes.

	// Public IP Info card backend proxy (docs/ref/todo/
	// statistics-host-ipinfo-plan.md T-06) — opt-in, default OFF via the
	// file-only ipinfo-enabled config key (no CLI flag, no UI toggle). The
	// mock provider is selected under -mock/-mock-from-real exactly like
	// every other kernel-adjacent dependency above, so `-mock=true` never
	// makes an outbound request even when ipinfo-enabled=true.
	var ipInfoProvider service.IPInfoProvider
	if cfg.Mock || cfg.MockFromReal {
		ipInfoProvider = service.NewMockIPInfoProvider()
	} else {
		// token is always "" in this phase (plan T-04 item 4 — no token
		// support yet).
		ipInfoProvider = service.NewIPInfoIOProvider("")
	}
	ipInfoService := service.NewIPInfoService(cfg.IPInfoEnabled, ipInfoProvider)

	// Central event log: every subsystem funnels audit events through this one
	// service (RAM queue + async batch writer to SQLite; see event_log.go).
	eventLogService := service.NewEventLogService(repo)
	dhcpServerService.SetEventLog(eventLogService)

	// Kernel capability detection (issue #94): probes whether the kernel
	// subsystems PiGate depends on (nftables, D-Bus/systemd units) are
	// actually usable in this environment, so the UI can warn instead of
	// silently failing (e.g. real mode on WSL). -mock-from-real must count as
	// mock here too, same as the kernel-manager selection above — it does not
	// write to the kernel either (docs/ref/todo/kernel-capability-detection-plan.md
	// §5 Caution 11).
	capabilityService := service.NewSystemCapabilityService(capProber, cfg.Mock || cfg.MockFromReal, eventLogService)
	capabilityService.RegisterApplyHealth("firewall", firewallService)

	// Self-healing internal event bus: NetlinkMonitor translates raw kernel events
	// into semantic NetEvents (InterfaceAdded/Removed, LinkChanged, AddrRouteChanged)
	// and publishes them here; interested services subscribe below. This is what makes
	// an interface that vanished and came back re-apply its config on its own without
	// the user touching the UI (issue #48). Subscriptions are registered before the
	// monitor is started (further down, after all startup applies complete).
	eventBus := service.NewNetEventBus()

	// InterfaceService: only a genuinely new/returned interface (InterfaceAdded)
	// re-applies its DB config — a mere flag flap (LinkChanged) must not, or a
	// blinking link would trigger a re-apply storm. Debounced + scoped by name.
	eventBus.Subscribe("interface", []service.NetEventKind{service.InterfaceAdded}, service.Debounced,
		func(e service.NetEvent) {
			log.Printf("[Self-heal] Interface %q returned; re-applying its configuration", e.Name)
			ifaceService.ReapplyInterfaceByName(e.Name)
		})

	// dhcpcd: must observe every link transition in order (Wi-Fi waits for RUNNING),
	// so Immediate mode across Added/Changed/Removed. HandleLinkEvent itself defers
	// a "down" decision behind a short settle-window timer (stopSettleDelay in
	// dhcpcd.go) before actually stopping the client, so a brief link flap never
	// stops it at all; "up" is never deferred (StartUnit is idempotent), so Wi-Fi
	// lease acquisition latency is unaffected. See
	// docs/ref/todo/dhcpcd-event-debounce-plan.md.
	eventBus.Subscribe("dhcpcd",
		[]service.NetEventKind{service.InterfaceAdded, service.LinkChanged, service.InterfaceRemoved},
		service.Immediate,
		func(e service.NetEvent) {
			dhcpcdService.HandleLinkEvent(e.Name, e.Up, e.Running)
		})

	// Routing reconciles on any address/route change or link flag change — routes
	// genuinely can shift when a link flaps, so it must observe those.
	// Debounced: coalesce a burst into a single full reconcile (idempotent).
	eventBus.Subscribe("routing",
		[]service.NetEventKind{service.AddrRouteChanged, service.LinkChanged},
		service.Debounced,
		func(e service.NetEvent) {
			if err := routingService.ReconcileKernelRoutingTable(); err != nil {
				log.Printf("[Self-heal] Error reconciling routing table: %v", err)
			}
		})

	// DNS client only reacts to a genuinely new/returned interface (InterfaceAdded),
	// NOT to LinkChanged. The global DNS config is a system-wide resolved drop-in
	// that does not depend on any single link's up/running state, so a Wi-Fi
	// scan/reconnect flap must not trigger a re-apply (which would restart
	// systemd-resolved and drop DNS). ApplyDNSConfig is idempotent-guarded, so even
	// this InterfaceAdded path is a no-op when the config is unchanged (issue #57).
	eventBus.Subscribe("dns",
		[]service.NetEventKind{service.InterfaceAdded},
		service.Debounced,
		func(e service.NetEvent) {
			if err := dnsService.ApplyDNSConfig(); err != nil {
				log.Printf("[Self-heal] Error applying DNS configuration: %v", err)
			}
		})

	// DHCP server: when an interface returns, re-run the full config so its dhcp-range
	// (which was skipped while the interface was gone) is restored.
	eventBus.Subscribe("dhcp-server", []service.NetEventKind{service.InterfaceAdded}, service.Debounced,
		func(e service.NetEvent) {
			if err := dhcpServerService.ApplyAll(); err != nil {
				log.Printf("[Self-heal] Error re-applying DHCP server config: %v", err)
			}
		})

	// QoS: re-attach qdiscs/classes to an interface that came back.
	eventBus.Subscribe("qos", []service.NetEventKind{service.InterfaceAdded}, service.Debounced,
		func(e service.NetEvent) {
			if err := qosService.SyncToKernel(); err != nil {
				log.Printf("[Self-heal] Error re-syncing QoS to kernel: %v", err)
			}
		})

	// Event log: surface interface come-and-go to the user (self-healing must be
	// observable). Immediate so the log ordering matches reality.
	eventBus.Subscribe("event-log",
		[]service.NetEventKind{service.InterfaceAdded, service.InterfaceRemoved},
		service.Immediate,
		func(e service.NetEvent) {
			switch e.Kind {
			case service.InterfaceAdded:
				eventLogService.Log(model.EventCategoryNetwork, "network.interface.up", model.EventSeverityInfo,
					model.EventActorSystem, e.Name, "Interface "+e.Name+" appeared; re-applying configuration")
			case service.InterfaceRemoved:
				eventLogService.Log(model.EventCategoryNetwork, "network.interface.down", model.EventSeverityWarning,
					model.EventActorSystem, e.Name, "Interface "+e.Name+" removed from kernel")
			}
		})

	// DHCP health-checker (issue #78): background self-heal loop for
	// interfaces stuck with only a link-local (169.254.x.x) address or no
	// IPv4 at all despite being carrier-ready. Constructed here (needs
	// eventLogService + eventBus, both now available) but started further
	// down, after the netlink monitor, since it is a background loop rather
	// than part of the startup-apply sequence.
	dhcpHealthChecker := service.NewDhcpHealthChecker(repo, ifaceService, dhcpcdService, net, eventLogService, eventBus)

	// Multi-WAN Failover health monitor (docs/ref/todo/
	// multi-wan-failover-plan.md Task 7/8) — Phase 1 only: this is a
	// read-only observer (probes configured WAN uplinks, tracks up/degraded/
	// down state + latency/jitter/loss in RAM) with no ability to change
	// routing at all yet. Constructed here (needs eventLogService + eventBus,
	// both now available) but started further down, after both the netlink
	// monitor and the DHCP health-checker, since it is a third independent
	// background self-heal/observation loop, not part of the startup-apply
	// sequence. wanMetricsRing is RAM-only (D-3) and also handed to the API
	// server via SetWanMonitor below.
	wanMetricsRing := service.NewWanUplinkMetricsRing()
	wanMonitor := service.NewWanMonitor(repo, pathProbe, eventLogService, eventBus, wanMetricsRing)

	// Netlink monitor is created here (but started later, after startup config is
	// applied) so it can be injected into the BackupService, which pauses it (and
	// hence the whole bus) around a config import.
	netlinkMonitor := service.NewNetlinkMonitor(repo, eventBus)

	backupService := service.NewBackupService(
		repo, cfg.DBPath, version,
		ifaceService, routingService, firewallService, dnsService, dnsServerService,
		qosService, dhcpServerService, dhcpcdService, hostnameService, timeService,
		netlinkMonitor,
	)
	// SetCounterStore wires the persisted Monitor counter store so a config
	// import reloads its RAM cache from the post-import DB state (docs/ref/
	// todo/fqdn-retry-and-monitored-counters-plan.md T-12) — additive, same
	// pattern as the other Set* calls below.
	backupService.SetCounterStore(policyCounterStore)
	// SetBlocklistService wires the DNS blocklist import feature (docs/ref/
	// todo/dns-blocklist-import-plan.md §2.4/T-09) so a config export/import
	// carries the blocklist manifest + selected .hosts payloads too —
	// additive, same pattern as SetCounterStore above.
	backupService.SetBlocklistService(dnsBlocklistService)

	server := api.NewServer(repo, fw, net, rt, dhcp, ringBuffer, cfg.DisableEdit, cfg.AllowDevCORS, ifaceService, dhcpcdService, routingService, firewallService, dnsService, qosService, dhcpServerService, dnsServerService, hostnameService, timeService, userService, backupService, systemStatusService, powerService, eventLogService, dhcpHealthChecker, wifiPresetService, systemServiceService, capabilityService, trafficStatsService, statisticsService, ipInfoService, dnsBlocklistService)

	// SetPolicyStatsService wires the optional per-rule usage stats service
	// (docs/ref/todo/firewall-policy-rule-usage-stats-plan.md T-07) — additive,
	// after NewServer, exactly like FirewallService.SetRuleNameResolver above,
	// so NewServer's signature stays unchanged.
	policyStatsService := service.NewPolicyStatsService(repo, firewallService, trafficStatsService, ringBuffer)
	// SetDomainLookup wires the DNS reverse-cache batch lookup (docs/ref/todo/
	// firewall-rule-matched-endpoints-plan.md T-05) so GetRuleEndpoints can
	// resolve EndpointHit.Domain — statisticsService already exists above
	// (constructed before policyStatsService), same additive-setter pattern
	// as statisticsService.SetLogBuffer(ringBuffer) further up.
	policyStatsService.SetDomainLookup(statisticsService.LookupDomains)
	// SetCounterStore wires the persisted Monitor counter store into the
	// stats response (docs/ref/todo/fqdn-retry-and-monitored-counters-plan.md
	// T-10).
	policyStatsService.SetCounterStore(policyCounterStore)
	// SetEndpointStore wires the persisted rule-endpoints read path (docs/
	// ref/todo/persisted-rule-endpoints-plan.md E-08, issue #141 follow-up)
	// so GetRuleEndpoints can serve source="persisted" for monitored rules.
	policyStatsService.SetEndpointStore(policyCounterStore, endpointRecorder, cfg.MonitoredEndpointsEnabled, cfg.MonitoredEndpointsMaxPerRule)
	server.SetPolicyStatsService(policyStatsService)
	// SetPolicyCounterStore wires the toggle-monitor/monitor-reset endpoints
	// (docs/ref/todo/fqdn-retry-and-monitored-counters-plan.md T-11).
	server.SetPolicyCounterStore(policyCounterStore)
	// SetWanMonitor wires the Multi-WAN Failover status/metrics endpoints
	// (docs/ref/todo/multi-wan-failover-plan.md Task 8/9) — additive, same
	// pattern as SetPolicyStatsService/SetPolicyCounterStore above.
	server.SetWanMonitor(wanMonitor)

	// Apply config form database to kernel

	// 6.0 Apply Time (timezone / NTP) configuration first. Correct time makes
	// log timestamps and any TLS validation in the following steps sane. This
	// applies only timezone + NTP config — never the wall clock itself (see
	// TimeService.InitApplyConfig).
	log.Printf("[Main] Applying database-configured time/NTP settings to kernel at startup...")
	if err := timeService.InitApplyConfig(); err != nil {
		log.Printf("[Main] Warning: Failed to apply time/NTP settings at startup: %v", err)
		eventLogService.Log(model.EventCategorySystem, "system.startup_apply_failed",
			model.EventSeverityWarning, "", "time", err.Error())
	}

	// 6.1 Apply Network Interfaces configuration at startup
	log.Printf("[Main] Applying database-configured network interfaces to kernel at startup...")
	if err := ifaceService.InitApplyConfigurationAtStartup(); err != nil {
		log.Printf("[Main] Warning: Failed to apply network interfaces to kernel at startup: %v", err)
		eventLogService.Log(model.EventCategorySystem, "system.startup_apply_failed",
			model.EventSeverityWarning, "", "interfaces", err.Error())
	}

	// 6.2 Apply Static Routes configuration at startup
	log.Printf("[Main] Applying database-configured static routes to kernel at startup...")
	if err := routingService.InitApplyConfig(); err != nil {
		log.Printf("[Main] Warning: Failed to apply static routes to kernel at startup: %v", err)
		eventLogService.Log(model.EventCategorySystem, "system.startup_apply_failed",
			model.EventSeverityWarning, "", "routes", err.Error())
	}

	// The netlink monitor is started later (after every subsystem's startup apply has
	// completed) so boot-time link events don't race the startup path — but its
	// context is created here because the watchers/samplers below share it.
	monitorCtx, cancelMonitor := context.WithCancel(context.Background())
	defer cancelMonitor()

	// Prime the rule-name snapshot and start its background refresher now,
	// BEFORE either traffic-log watcher below starts consuming NFLOG events:
	// StartRuleNameRefresher does one synchronous Refresh() first, so the
	// very first log entries stamped by stampAndPush can already resolve a
	// rule name instead of getting an empty RuleName until the first ticker
	// tick (docs/ref/todo/traffic-log-rule-name-and-domain-plan.md T-08).
	ruleNameResolver.StartRuleNameRefresher(monitorCtx)

	// stampAndPush is the shared callback for both traffic-log watchers below:
	// it stamps a unique id + timestamp then pushes into the one shared ring
	// buffer (see docs/ref/todo/traffic-log-pagination-and-local-traffic-plan.md
	// §2.1 for why one buffer covers all three chains). Timestamp uses
	// RFC3339Nano (not plain RFC3339) — the API's cursor pagination falls back
	// to comparing this timestamp when a beforeId has been evicted from the
	// buffer, and second-level RFC3339 precision would make many entries
	// arriving within the same second indistinguishable, silently dropping
	// siblings out of that fallback (plan §6 Caution 4).
	stampAndPush := func(entry model.FirewallLog) {
		entry.Time = time.Now().UTC().Format(time.RFC3339Nano)
		entry.ID = uuid.NewString()
		// Snapshot-on-write rule name (plan design decision 3): resolve
		// once, here, from the current ruleNameResolver snapshot, and never
		// touch it again — a later rename/delete of the matching policy
		// must not change what already-buffered entries display.
		entry.RuleName = ruleNameResolver.Resolve(entry.RuleID)
		ringBuffer.Add(entry)
		// Feeds the Statistics page's deny ring (Top Denied Sources/Ports —
		// docs/ref/todo/statistics-page-plan.md T-06). Must stay after
		// ringBuffer.Add and be O(1)/non-blocking/panic-free: this closure
		// runs on the NFLOG read loop (plan Caution 4).
		statisticsService.RecordFirewallLog(entry)
		// Feeds the persisted rule-endpoints RAM recorder (docs/ref/todo/
		// persisted-rule-endpoints-plan.md E-08, issue #141 follow-up). Same
		// hard constraints as RecordFirewallLog above (this is a sibling hook
		// on the same NFLOG read loop): must stay O(1), non-blocking, no I/O,
		// no DB query, never panic. Deliberately last in this closure.
		endpointRecorder.Record(entry)
	}

	// Start the forward-traffic log watcher. It feeds the shared ring buffer that
	// backs the Forward Traffic page and Dashboard Recent Logs. Real mode reads
	// NFLOG group 100; mock mode synthesizes events. If the watcher errors (e.g.
	// NFLOG unavailable), the buffer simply stays empty — packets are unaffected.
	log.Printf("[Main] Starting forward-traffic log watcher (NFLOG group %d)...", kernel.ForwardNflogGroup)
	go func() {
		err := trafficLog.WatchForwardTraffic(monitorCtx, stampAndPush)
		if err != nil && monitorCtx.Err() == nil {
			log.Printf("[Main] Warning: forward-traffic log watcher (NFLOG group %d) stopped: %v", kernel.ForwardNflogGroup, err)
		}
	}()

	// Start the local-traffic (input+output chain) log watcher — a second,
	// independent NFLOG socket/goroutine (LocalNflogGroup) feeding the SAME
	// ring buffer, distinguished by entry.Chain. Kept as a separate warning
	// message so an operator can tell which NFLOG group failed to bind.
	log.Printf("[Main] Starting local-traffic log watcher (NFLOG group %d)...", kernel.LocalNflogGroup)
	go func() {
		err := trafficLog.WatchLocalTraffic(monitorCtx, stampAndPush)
		if err != nil && monitorCtx.Err() == nil {
			log.Printf("[Main] Warning: local-traffic log watcher (NFLOG group %d) stopped: %v", kernel.LocalNflogGroup, err)
		}
	}()

	// Start the event log batch writer (flushes queued events to SQLite in
	// batches to preserve the SD card).
	eventLogService.Start(monitorCtx)

	// Start the session sweeper: reaps in-memory sessions past their idle deadline
	// so abandoned tokens don't linger in the map until restart.
	api.StartSessionSweeper(monitorCtx)

	// Start the rate-limiter sweeper: reaps idle per-IP token buckets so the
	// limiter map stays bounded (backstopped by a hard cap during bursts).
	api.StartLimiterSweeper(monitorCtx)

	// Start the dashboard telemetry sampler (CPU usage + WAN traffic history).
	// Shares the monitor context so it stops on shutdown.
	log.Printf("[Main] Starting system status telemetry sampler...")
	systemStatusService.Start(monitorCtx)

	// Dashboard traffic-detail collector (conntrack + nftables rule counters
	// poller) — shares the monitor context so it stops on shutdown, same as
	// systemStatusService above.
	log.Printf("[Main] Starting dashboard traffic-detail collector...")
	trafficStatsService.Start(monitorCtx)

	// Persisted Monitor counter flush ticker (docs/ref/todo/
	// fqdn-retry-and-monitored-counters-plan.md D-5, issue #141) — shares
	// monitorCtx so it stops on shutdown, same as trafficStatsService above.
	// Ticks are skipped in mock mode internally (see PolicyCounterStore.run).
	log.Printf("[Main] Starting persisted Monitor counter flush ticker...")
	policyCounterStore.Start(monitorCtx)

	// Conntrack DESTROY event watcher — augments the poller above with
	// per-flow byte counts at teardown, closing the gap for flows that start
	// and die entirely between two polls (docs/ref/todo/
	// traffic-accounting-accuracy-phase2-plan.md T-06/T-08). Shares
	// monitorCtx so its netlink socket is closed on shutdown; no
	// InitApplyConfig() needed — there is no kernel state to apply and no
	// boot-ordering dependency (poll-only degrade is safe at any time).
	log.Printf("[Main] Starting conntrack flow-end event watcher...")
	trafficStatsService.StartFlowEndWatcher(monitorCtx)

	log.Printf("[Main] Applying database-configured hostname settings to kernel at startup...")
	if err := hostnameService.InitApplyConfig(); err != nil {
		log.Printf("[Main] Warning: Failed to apply hostname settings at startup: %v", err)
		eventLogService.Log(model.EventCategorySystem, "system.startup_apply_failed",
			model.EventSeverityWarning, "", "hostname", err.Error())
	}

	log.Printf("[Main] Synchronizing active DHCP interfaces status...")
	dhcpcdService.SyncActiveInterfaces()

	log.Printf("[Main] Applying database-configured DHCP settings to kernel at startup...")
	if err := dhcpServerService.InitApplyConfig(); err != nil {
		log.Printf("[Main] Warning: Failed to apply DHCP configurations at startup: %v", err)
		eventLogService.Log(model.EventCategorySystem, "system.startup_apply_failed",
			model.EventSeverityWarning, "", "dhcp_server", err.Error())
	}

	// Start D-Bus lease watcher in production mode (non-mock)
	if !cfg.Mock {
		go func() {
			if err := dhcpServerService.StartLeaseWatcher(monitorCtx); err != nil {
				log.Printf("[Main] Warning: DHCP lease watcher encountered error: %v", err)
			}
		}()
	}

	log.Printf("[Main] Applying database-configured DNS local zones to kernel at startup...")
	if err := dnsServerService.InitApplyConfig(); err != nil {
		log.Printf("[Main] Warning: Failed to apply DNS local zones at startup: %v", err)
		eventLogService.Log(model.EventCategorySystem, "system.startup_apply_failed",
			model.EventSeverityWarning, "", "dns_server", err.Error())
	}

	// DNS Statistics (Top Queried Domains + IP->domain enrichment —
	// docs/ref/todo/statistics-dns-top-domain-plan.md T-09): load the
	// opt-in switch + reverse-cache TTL/cap from DB once at boot, then start
	// the query-log watcher. A read failure falls back to the package
	// defaults (60min/4096 entries, logging disabled) with a warning rather
	// than failing startup — this is display-only enrichment, never a boot
	// dependency.
	dnsServerSettings, err := repo.GetDNSServerSettings()
	if err != nil {
		log.Printf("[Main] Warning: failed to read DNS server settings at startup, using defaults: %v", err)
		dnsServerSettings = model.DNSServerSettings{
			QueryLogging:       false,
			DNSCacheTTLMinutes: model.DNSCacheTTLDefault,
			DNSCacheMaxEntries: model.DNSCacheEntriesDefault,
		}
	}
	statisticsService.SetDNSLoggingEnabled(dnsServerSettings.QueryLogging)
	statisticsService.SetReverseCacheLimits(dnsServerSettings.DNSCacheTTLMinutes, dnsServerSettings.DNSCacheMaxEntries)
	// Domain->IP forward index caps come from the file-only bootstrap config
	// (dns-stats-max-domains / dns-stats-max-ips-per-domain), not the DB —
	// same TTL as the reverse cache above so both indices stay in sync
	// (docs/ref/todo/statistics-dns-page-revamp-plan.md §2.1/T-05).
	statisticsService.SetDomainIPsLimits(dnsServerSettings.DNSCacheTTLMinutes, cfg.DNSStatsMaxDomains, cfg.DNSStatsMaxIPsPerDomain)

	log.Printf("[Main] Starting DNS query-log watcher...")
	go func() {
		if err := dnsServer.WatchDNSLog(monitorCtx, statisticsService.RecordDNSEvent); err != nil && monitorCtx.Err() == nil {
			log.Printf("[Main] Warning: DNS query-log watcher stopped: %v", err)
		}
	}()

	log.Printf("[Main] Applying database-configured DNS settings to kernel at startup...")
	if err := dnsService.ApplyDNSConfig(); err != nil {
		log.Printf("[Main] Warning: Failed to apply DNS configurations to kernel at startup: %v", err)
		eventLogService.Log(model.EventCategorySystem, "system.startup_apply_failed",
			model.EventSeverityWarning, "", "dns", err.Error())
	}

	// 6.3 Apply Firewall Rules at startup
	log.Printf("[Main] Applying database-configured firewall rules to kernel at startup...")
	if err := firewallService.InitApplyConfig(); err != nil {
		log.Printf("[Main] Warning: Failed to apply firewall rules to kernel at startup: %v", err)
		eventLogService.Log(model.EventCategorySystem, "system.startup_apply_failed",
			model.EventSeverityWarning, "", "firewall", err.Error())
	}

	// Probe kernel capabilities right after the firewall's own startup apply,
	// so the last-apply outcome above is already reflected by the time this
	// runs (docs/ref/todo/kernel-capability-detection-plan.md T-07). Logs an
	// event for every capability found unavailable.
	log.Printf("[Main] Probing kernel capabilities...")
	capabilityService.Refresh()

	// 6.4 Apply QoS Rules at startup
	log.Printf("[Main] Applying database-configured QoS rules to kernel at startup...")
	if err := qosService.InitApplyConfig(); err != nil {
		log.Printf("[Main] Warning: Failed to apply QoS rules to kernel at startup: %v", err)
		eventLogService.Log(model.EventCategorySystem, "system.startup_apply_failed",
			model.EventSeverityWarning, "", "qos", err.Error())
	}

	// 6.5 Start the Netlink event monitor LAST, once every subsystem's startup apply
	// has completed. Starting it earlier would let the flurry of boot-time link events
	// (dhcpcd bringing links up) fire self-heal re-applies that race the startup path
	// above (issue #48). A brief drift window between the applies and Start is
	// acceptable — the startup applies just ran.
	log.Printf("[Main] Starting Netlink event monitor (self-healing event bus)...")
	netlinkMonitor.Start(monitorCtx, ifaceService.StartupSkippedInterfaces())

	// Start the DHCP health-checker (issue #78) after the netlink monitor: it
	// is a background self-heal loop reading DB state on its own ticker, not
	// part of the startup-apply sequence above.
	log.Printf("[Main] Starting DHCP health-checker (link-local/no-IP self-heal)...")
	dhcpHealthChecker.Start(monitorCtx)

	// Start the Multi-WAN Failover health monitor after both the netlink
	// monitor and the DHCP health-checker (docs/ref/todo/
	// multi-wan-failover-plan.md Task 8) — read-only in Phase 1: it never
	// touches routing, it only probes configured WAN uplinks and records
	// their health/metrics for the UI/API. Safe to start even with zero
	// uplinks configured (its tick() simply has nothing to do).
	log.Printf("[Main] Starting Multi-WAN Failover health monitor...")
	wanMonitor.Start(monitorCtx)

	// FQDN re-resolve retry ticker (docs/ref/todo/
	// fqdn-retry-and-monitored-counters-plan.md D-1, issue #141) — started
	// last, after firewallService.InitApplyConfig() (so there is an initial
	// FQDNResolutions() snapshot to compare against) and after
	// netlinkMonitor.Start (so its bus.IsPaused() guard reads real state).
	// Disabled/skipped internally in mock mode (repo.IsMockMode()) and via
	// the fqdn-refresh-enabled kill switch.
	log.Printf("[Main] Starting FQDN re-resolve retry ticker (steady=%ds retry=%ds enabled=%t)...",
		cfg.FQDNRefreshIntervalSeconds, cfg.FQDNRefreshRetryIntervalSeconds, cfg.FQDNRefreshEnabled)
	fqdnRefresher := service.NewFQDNRefresher(repo, firewallService, fw, eventBus, eventLogService,
		cfg.FQDNRefreshEnabled,
		time.Duration(cfg.FQDNRefreshIntervalSeconds)*time.Second,
		time.Duration(cfg.FQDNRefreshRetryIntervalSeconds)*time.Second,
	)
	fqdnRefresher.Start(monitorCtx)

	handler := api.RegisterRoutes(server)

	// Record the boot event — the persisted counterpart of system.reboot /
	// system.shutdown, proving the box came back up.
	eventLogService.Log(model.EventCategorySystem, "system.boot", model.EventSeverityInfo,
		model.EventActorSystem, "host", "PiGate backend started (version "+version+")")

	// 7. Start HTTP/HTTPS API listeners.
	// See docs/ref/todo/https-server-foundation-plan.md for the full rationale.
	// Ladder:
	//   httpsPort > 0 (systemd unit passes 443 → HTTPS is the primary channel):
	//     (1) cert OK + :443 binds → HTTPS serves the real handler (TLS 1.2+),
	//         HTTP :<port> (and bonus :80 when httpsPort==443) 308-redirect to HTTPS.
	//     (2) cert fails OR :443 won't bind → warn loudly + event log, then HTTP
	//         :<port> serves the real handler (last-resort fallback; admin must be
	//         able to reach the box no matter what).
	//   httpsPort == 0 (dev/mock, no flag): HTTP :<port> serves the real handler —
	//     identical to the legacy behavior.
	httpAddr := ":" + strconv.Itoa(cfg.Port)

	if cfg.HTTPSPort > 0 {
		tlsDirResolved := cfg.TLSDir
		if tlsDirResolved == "" {
			tlsDirResolved = filepath.Join(filepath.Dir(cfg.DBPath), "tls")
		}

		hostname := "pigate"
		if hs, hErr := hostnameService.Get(); hErr == nil && hs.Hostname != "" {
			hostname = hs.Hostname
		}

		certPath, keyPath, tlsErr := setupTLS(tlsDirResolved, hostname, eventLogService)
		if tlsErr == nil {
			httpsAddr := ":" + strconv.Itoa(cfg.HTTPSPort)
			// Probe-bind :443 up front: if it fails we fall through to the HTTP
			// fallback instead of dying after HTTP has already become a redirect.
			// (bindTCP wraps net.Listen; the local kernel manager variable named
			// "net" shadows the net package inside main.)
			ln, bindErr := bindTCP(httpsAddr)
			if bindErr == nil {
				redirect := newHTTPSRedirectHandler(cfg.HTTPSPort)
				startRedirectListener(httpAddr, redirect)
				if cfg.HTTPSPort == 443 {
					// Bonus: catch users who type the bare http://<ip> (port 80).
					startRedirectListener(":80", redirect)
				}

				httpsServer := &http.Server{
					Handler:           handler,
					TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
					ReadHeaderTimeout: 10 * time.Second,
					ReadTimeout:       30 * time.Second,
					WriteTimeout:      60 * time.Second,
					IdleTimeout:       120 * time.Second,
				}
				log.Printf("[Main] ===== PiGate API Backend is listening at https://localhost%s (HTTP %s → 308 redirect) =====", httpsAddr, httpAddr)
				if err := httpsServer.ServeTLS(ln, certPath, keyPath); err != nil {
					log.Fatalf("HTTPS server listener failed: %v", err)
				}
				return
			}
			log.Printf("[Main] Warning: could not bind HTTPS port %s: %v", httpsAddr, bindErr)
		} else {
			log.Printf("[Main] Warning: could not set up TLS certificate: %v", tlsErr)
		}

		// Fallthrough — TLS could not be started. Serve full HTTP so the admin can
		// still reach the box, but make the degradation impossible to miss.
		log.Printf("[Main] ***** WARNING: HTTPS unavailable — serving PLAIN HTTP on %s. Re-run install.sh to restore HTTPS. *****", httpAddr)
		eventLogService.Log(model.EventCategorySystem, "system.https_fallback", model.EventSeverityWarning,
			model.EventActorSystem, "host", "HTTPS could not start; serving plain HTTP as a fallback (re-run install.sh)")
	}

	// Plain HTTP: dev/mock (no -https-port) or the last-resort fallback above.
	httpServer := &http.Server{
		Addr:              httpAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("[Main] ===== PiGate API Backend is listening at http://localhost%s =====", httpAddr)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("Server listener failed: %v", err)
	}
}

// resolveConfig implements the bootstrap config precedence described in
// docs/ref/todo/config-file-loader-plan.md: code default < config file < CLI
// flag explicitly passed on this invocation.
//
//   - explicitPath == "" (the -config flag was not passed): the config file
//     path defaults to defaultConfigPath. If no file exists there yet, its
//     absence is not an error — resolveConfig writes the code defaults to it
//     (so the operator has something to edit next time) and continues with
//     an empty file layer. A write failure here is only a warning (common on
//     a dev workstation with no /var/lib/pigate) — never fatal.
//   - explicitPath != "" (the -config flag was passed): that exact file must
//     exist. A missing file here means the operator made a typo, so it is a
//     fatal, fail-fast error rather than silently falling back to defaults.
//
// Any config file that does exist must parse and type-convert cleanly —
// malformed syntax or a malformed int/bool value is always fatal, regardless
// of which of the two cases above produced the path. Unknown keys are
// logged as warnings but do not stop startup.
func resolveConfig(explicitPath string) config.Config {
	path := explicitPath
	useDefaultPath := path == ""
	if useDefaultPath {
		path = defaultConfigPath
	}

	var fileVals map[string]string
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		parsed, perr := config.Parse(bytes.NewReader(data))
		if perr != nil {
			log.Fatalf("[Main] Failed to parse config file %s: %v", path, perr)
		}
		fileVals = parsed
	case os.IsNotExist(err) && !useDefaultPath:
		// The user passed -config explicitly and it doesn't exist: fail fast
		// rather than silently booting on defaults (docs plan Caution: "-config
		// ที่ไฟล์ไม่มี ต้อง fail ชัด ไม่ auto-create").
		log.Fatalf("[Main] Config file %q (from -config) not found", path)
	case os.IsNotExist(err):
		// Default path missing: write the code defaults so there's something
		// to edit next time, then continue booting on those same defaults
		// (fileVals stays nil). A write failure (e.g. dev workstation with no
		// /var/lib/pigate) is only a warning, never fatal.
		var buf bytes.Buffer
		if werr := config.Write(&buf, config.Defaults()); werr == nil {
			werr = os.WriteFile(path, buf.Bytes(), 0644)
			if werr != nil {
				log.Printf("[Main] Warning: could not write default config file %s: %v", path, werr)
			} else {
				log.Printf("[Main] Wrote default config file %s", path)
			}
		} else {
			log.Printf("[Main] Warning: could not render default config file %s: %v", path, werr)
		}
	default:
		log.Fatalf("[Main] Failed to read config file %s: %v", path, err)
	}

	// Only flags the user actually passed on this invocation must win over the
	// file — flag.Visit (not flag.VisitAll) is what gives us that distinction.
	// "config" and "v" are not config-file keys and must be excluded.
	explicit := map[string]string{}
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "config" || f.Name == "v" {
			return
		}
		explicit[f.Name] = f.Value.String()
	})

	cfg, warnings, err := config.Resolve(config.Defaults(), fileVals, explicit)
	if err != nil {
		log.Fatalf("[Main] Invalid configuration: %v", err)
	}
	for _, w := range warnings {
		log.Printf("[Main] Warning: %s", w)
	}
	return cfg
}

// bindTCP opens a TCP listener on addr. It exists so main() can bind a socket
// without referencing the net package directly — the local kernel.NetworkManager
// variable named "net" shadows the package inside main().
func bindTCP(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// newHTTPSRedirectHandler returns a handler that 308-redirects any request to the
// same host+path over HTTPS on httpsPort (the port is omitted from the target when
// it is the standard 443). 308 (Permanent Redirect) preserves the method/body,
// unlike 301/302, which matters for API clients that POST to /api over HTTP.
func newHTTPSRedirectHandler(httpsPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		target := "https://" + host
		if httpsPort != 443 {
			target += ":" + strconv.Itoa(httpsPort)
		}
		target += r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}

// startRedirectListener starts an HTTP server on addr in a background goroutine
// serving the redirect handler. Bind/serve failures are logged, never fatal — a
// failed :80 bonus listener (or a :<port> already in use) must not take the whole
// process, including the primary HTTPS listener, down with it.
func startRedirectListener(addr string, h http.Handler) {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("[Main] HTTP redirect listener starting on %s (308 → HTTPS)", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Main] Warning: HTTP redirect listener on %s stopped: %v", addr, err)
		}
	}()
}

// setupTLS ensures a self-signed certificate/key pair exists under tlsDir and
// returns their paths. A newly generated cert is recorded in the event log.
func setupTLS(tlsDir, hostname string, eventLog *service.EventLogService) (certPath, keyPath string, err error) {
	certPath, keyPath, generated, err := service.EnsureSelfSignedCert(tlsDir, hostname, service.LocalInterfaceIPs())
	if err != nil {
		return "", "", err
	}
	if generated {
		log.Printf("[Main] Generated self-signed TLS certificate in %s", tlsDir)
		if eventLog != nil {
			eventLog.Log(model.EventCategorySystem, "system.tls_cert_generated", model.EventSeverityInfo,
				model.EventActorSystem, "host", "Generated self-signed TLS certificate for HTTPS")
		}
	}
	return certPath, keyPath, nil
}
