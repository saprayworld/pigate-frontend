package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"pigate/internal/db"
	"pigate/internal/kernel"
	"pigate/internal/logs"
	"pigate/internal/model"
	"pigate/internal/service"
)

type Server struct {
	repo              *db.Repository
	firewall          kernel.FirewallManager
	network           kernel.NetworkManager
	routing           kernel.RoutingManager
	dhcp              kernel.DhcpManager
	logs              *logs.RingBuffer
	disableEdit       bool
	allowDevCORS      bool
	interfaceService  *service.InterfaceService
	dhcpcdService     *service.DhcpcdService
	routingService    *service.RoutingService
	firewallService   *service.FirewallService
	dnsService        *service.DNSService
	qosService        *service.QosService
	dhcpServerService *service.DhcpServerService
	dnsServerService  *service.DNSServerService
	hostnameService   *service.HostnameService
	timeService       *service.TimeService
	userService       *service.UserService
	backupService     *service.BackupService
	systemStatus      *service.SystemStatusService
	powerService      *service.PowerService
	eventLog          *service.EventLogService
	dhcpHealthChecker *service.DhcpHealthChecker
	wifiPresetService *service.WifiPresetService
	systemServiceSvc  *service.SystemServiceService
	capabilityService *service.SystemCapabilityService
	trafficStats      *service.TrafficStatsService
	statistics        *service.StatisticsService
	ipInfo            *service.IPInfoService

	// policyStats is optional (nil until SetPolicyStatsService is called by
	// main.go) — additive, like SetRuleNameResolver on FirewallService, so
	// NewServer's already-30-parameter signature stays unchanged (docs/ref/
	// todo/firewall-policy-rule-usage-stats-plan.md T-06).
	policyStats *service.PolicyStatsService

	// policyCounterStore is optional (nil until SetPolicyCounterStore is
	// called by main.go) — same additive-setter pattern as policyStats above
	// (docs/ref/todo/fqdn-retry-and-monitored-counters-plan.md T-11, issue
	// #141). Used by HandleTogglePolicyMonitor/HandleResetPolicyMonitorCounter.
	policyCounterStore *service.PolicyCounterStore

	// dnsBlocklistService backs the /api/dns/blocklists* handlers (docs/ref/
	// todo/dns-blocklist-import-plan.md T-08) — bulk hosts-file blocklist
	// import (subscribe URL / upload), metadata kept in a JSON manifest
	// rather than SQLite (plan §2.3/R1). Unlike policyStats/policyCounterStore
	// above this is a required NewServer parameter, not an optional setter,
	// since every deployment wires it (main.go constructs it unconditionally);
	// it may still be nil in tests that don't need it, so every handler below
	// checks for that explicitly rather than assuming it is always set.
	dnsBlocklistService *service.DNSBlocklistService

	// wanMonitor backs the /api/wan/status and /api/wan/metrics handlers
	// (docs/ref/todo/multi-wan-failover-plan.md Task 8/9) — optional (nil
	// until SetWanMonitor is called by main.go), same additive-setter
	// pattern as policyStats/policyCounterStore above, since NewServer's
	// signature is already long. Every wan_handlers.go handler that reads it
	// must nil-check explicitly rather than assume it is always set.
	wanMonitor *service.WanMonitor
}

// SetWanMonitor wires the Multi-WAN Failover health monitor into the server
// (docs/ref/todo/multi-wan-failover-plan.md Task 8). Safe to call once after
// NewServer, and safe to never call at all (the status/metrics endpoints
// then degrade to reporting every uplink as unknown/no data, mirroring
// SetPolicyStatsService's "safe to never call" contract).
func (s *Server) SetWanMonitor(m *service.WanMonitor) {
	s.wanMonitor = m
}

// SetPolicyStatsService wires the optional per-rule usage stats service into
// the server. Safe to call once after NewServer, and safe to never call at
// all (HandleGetPolicyStats then reports 503).
func (s *Server) SetPolicyStatsService(p *service.PolicyStatsService) {
	s.policyStats = p
}

// SetPolicyCounterStore wires the optional persisted "Monitor" counter store
// into the server — see the policyCounterStore field doc comment above.
func (s *Server) SetPolicyCounterStore(store *service.PolicyCounterStore) {
	s.policyCounterStore = store
}

func NewServer(
	repo *db.Repository,
	fw kernel.FirewallManager,
	net kernel.NetworkManager,
	rt kernel.RoutingManager,
	dhcp kernel.DhcpManager,
	l *logs.RingBuffer,
	disableEdit bool,
	allowDevCORS bool,
	ifaceService *service.InterfaceService,
	dhcpcdService *service.DhcpcdService,
	routingService *service.RoutingService,
	fwService *service.FirewallService,
	dnsService *service.DNSService,
	qosService *service.QosService,
	dhcpServerService *service.DhcpServerService,
	dnsServerService *service.DNSServerService,
	hostnameService *service.HostnameService,
	timeService *service.TimeService,
	userService *service.UserService,
	backupService *service.BackupService,
	systemStatus *service.SystemStatusService,
	powerService *service.PowerService,
	eventLog *service.EventLogService,
	dhcpHealthChecker *service.DhcpHealthChecker,
	wifiPresetService *service.WifiPresetService,
	systemServiceSvc *service.SystemServiceService,
	capabilityService *service.SystemCapabilityService,
	trafficStats *service.TrafficStatsService,
	statistics *service.StatisticsService,
	ipInfo *service.IPInfoService,
	dnsBlocklistService *service.DNSBlocklistService,
) *Server {
	return &Server{
		repo:                repo,
		firewall:            fw,
		network:             net,
		routing:             rt,
		dhcp:                dhcp,
		logs:                l,
		disableEdit:         disableEdit,
		allowDevCORS:        allowDevCORS,
		interfaceService:    ifaceService,
		dhcpcdService:       dhcpcdService,
		routingService:      routingService,
		firewallService:     fwService,
		dnsService:          dnsService,
		qosService:          qosService,
		dhcpServerService:   dhcpServerService,
		dnsServerService:    dnsServerService,
		hostnameService:     hostnameService,
		timeService:         timeService,
		userService:         userService,
		backupService:       backupService,
		systemStatus:        systemStatus,
		powerService:        powerService,
		eventLog:            eventLog,
		dhcpHealthChecker:   dhcpHealthChecker,
		wifiPresetService:   wifiPresetService,
		systemServiceSvc:    systemServiceSvc,
		capabilityService:   capabilityService,
		trafficStats:        trafficStats,
		statistics:          statistics,
		ipInfo:              ipInfo,
		dnsBlocklistService: dnsBlocklistService,
	}
}

// Helpers
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"message": message})
}

func maskInterfacePasswords(iface *model.NetworkInterface) {
	if iface.WifiPassword != nil && *iface.WifiPassword != "" {
		masked := "••••••••"
		iface.WifiPassword = &masked
	}
	if iface.BackupWifiPassword != nil && *iface.BackupWifiPassword != "" {
		masked := "••••••••"
		iface.BackupWifiPassword = &masked
	}
}

// generateRandomToken returns 16 bytes of crypto-random data hex-encoded. It is
// fail-closed: if the OS entropy source errors, it returns the error rather than
// a predictable/zero token. Session tokens and resource IDs are security-relevant
// (a guessable session token = takeover; guessable IDs = collision/enumeration),
// so every caller must handle the error and refuse the operation, never proceed
// with a zero value.
func generateRandomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// randomID builds a short prefixed resource ID (e.g. "rule-1a2b3c4d"). Propagates
// the entropy error so the caller can fail the request with 500 instead of
// minting a predictable ID.
func randomID(prefix string) (string, error) {
	tok, err := generateRandomToken()
	if err != nil {
		return "", err
	}
	return prefix + tok[:8], nil
}

// logLoginFailed records a failed login attempt. Only the attempted username is
// logged — never the password field (see plan §5.4).
func (s *Server) logLoginFailed(username, reason string) {
	if s.eventLog == nil {
		return
	}
	s.eventLog.Log(model.EventCategoryAuth, "login.failed", model.EventSeverityWarning,
		username, username, "Login failed for "+username+" ("+reason+")")
}

// logEvent records a system event with the authenticated user from the request
// context as actor. Handlers call it only after the operation succeeded (except
// login.failed, which logs directly via s.eventLog). Nil-safe so tests that
// build a Server without an EventLogService keep working.
func (s *Server) logEvent(r *http.Request, category, action, severity, target, msg string) {
	if s.eventLog == nil {
		return
	}
	actor, _ := r.Context().Value(UserContextKey).(string)
	s.eventLog.Log(category, action, severity, actor, target, msg)
}

// =========================================================================
// AUTHENTICATION HANDLERS
// =========================================================================

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	user, err := s.repo.GetUserByUsername(req.Username)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if user == nil {
		s.logLoginFailed(req.Username, "unknown username")
		s.writeError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	// Verify Password hash using Bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		s.logLoginFailed(req.Username, "wrong password")
		s.writeError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	// Reject disabled accounts after verifying the password so we don't leak
	// account existence to a wrong-password attempt. This is an internal admin
	// box, so a clear message for the legitimate owner is acceptable.
	if user.Status == model.StatusDisabled {
		s.logLoginFailed(req.Username, "account disabled")
		s.writeError(w, http.StatusUnauthorized, "บัญชีนี้ถูกปิดใช้งาน")
		return
	}

	tok, err := generateRandomToken()
	if err != nil {
		// Fail closed: never issue a session cookie backed by a predictable token.
		s.writeError(w, http.StatusInternalServerError, "Could not generate session")
		return
	}
	token := "session_id_" + tok
	AddSession(token, user.Username)

	if s.eventLog != nil {
		s.eventLog.Log(model.EventCategoryAuth, "login.success", model.EventSeverityInfo,
			user.Username, user.Username, "User "+user.Username+" logged in")
	}

	// Issue the session cookie via the shared helper so login and mid-session
	// renewal always write identical attributes (Caution 4). The idle TTL is the
	// server-side deadline; the browser cookie is slid forward on use and capped
	// at the absolute max server-side.
	setSessionCookie(w, r, token, time.Now().Add(sessionTTL))

	s.writeJSON(w, http.StatusOK, model.LoginResponse{
		MustChangePassword: user.IsInitial,
		Role:               user.Role,
	})
}

func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// Session token lives only in the HttpOnly cookie (cookie-only auth).
	var token string
	if cookie, err := r.Cookie(SessionKey); err == nil {
		token = cookie.Value
	}

	if token != "" {
		RemoveSession(token)
	}

	// Clear cookie. Mirror the login cookie's Secure attribute (per-request from
	// r.TLS) so the browser reliably matches and removes it under both schemes.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionKey,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})

	w.WriteHeader(http.StatusOK)
}

func (s *Server) HandleCheckSession(w http.ResponseWriter, r *http.Request) {
	// AuthMiddleware has already validated the session and injected the real
	// username + role — no hardcoded fallback.
	username, _ := r.Context().Value(UserContextKey).(string)
	role, _ := r.Context().Value(RoleContextKey).(string)

	user, err := s.repo.GetUserByUsername(username)
	mustChangePassword := false
	if err == nil && user != nil {
		mustChangePassword = user.IsInitial
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":              true,
		"username":           username,
		"role":               role,
		"mustChangePassword": mustChangePassword,
	})
}

// =========================================================================
// DASHBOARD HANDLERS
// =========================================================================

func mapWpaState(state string) string {
	switch state {
	case "COMPLETED":
		return "Connected"
	case "DISCONNECTED":
		return "Disconnected"
	case "INACTIVE":
		return "Inactive"
	case "SCANNING":
		return "Scanning"
	case "ASSOCIATING", "AUTHENTICATING", "ASSOCIATED", "4WAY_HANDSHAKE", "GROUP_HANDSHAKE":
		return "Connecting"
	case "INTERFACE_DISABLED":
		return "Disabled"
	default:
		return state
	}
}

func (s *Server) HandleGetDashboardStats(w http.ResponseWriter, r *http.Request) {
	leases, _ := s.dhcp.GetActiveLeases()
	ifaces, _ := s.interfaceService.GetDataLayerInterface()

	wifiSSID := "None"
	wifiStatus := "Disconnected"
	for _, iface := range ifaces {
		if iface.Type == "wireless" {
			if wifiStat, err := s.network.GetWifiStatus(iface.Name); err == nil {
				wifiStatus = mapWpaState(wifiStat.State)
				if wifiStat.SSID != "" {
					wifiSSID = wifiStat.SSID
				} else {
					wifiSSID = "None"
				}
			} else {
				if iface.WifiSSID != nil && *iface.WifiSSID != "" {
					wifiSSID = *iface.WifiSSID
					wifiStatus = "Connected (DB)"
				}
			}
		}
	}

	trafficIn, trafficOut := s.systemStatus.GetTrafficTotals()

	stats := model.DashboardStats{
		FirewallStatus:       "Active",
		TotalTrafficInBytes:  trafficIn,
		TotalTrafficOutBytes: trafficOut,
		DhcpLeasesCount:      len(leases),
		WifiStatus:           wifiStatus,
		WifiSSID:             wifiSSID,
	}

	s.writeJSON(w, http.StatusOK, stats)
}

// HandleGetPerformanceMetrics returns real host telemetry (CPU/mem/temp/storage)
// composed by SystemStatusService. The flat cpu/memory/temp fields are retained
// for backward-compatibility; *Detail objects carry the richer data.
func (s *Server) HandleGetPerformanceMetrics(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, s.systemStatus.GetSystemMetrics())
}

// HandleGetSystemInfo returns hostname / version / OS / uptime / system time for
// the Dashboard's System Information card.
func (s *Server) HandleGetSystemInfo(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, s.systemStatus.GetSystemInfo())
}

// HandleGetSystemCapabilities returns whether the kernel subsystems PiGate
// depends on (nftables, D-Bus/systemd units) are actually usable in this
// environment (issue #94) — e.g. real mode on WSL reports nftables
// unavailable instead of silently failing. Pass ?force=1 to bypass the
// service's internal cache and probe again immediately (the "ตรวจสอบใหม่"
// button). Read-only; safe for every logged-in role.
func (s *Server) HandleGetSystemCapabilities(w http.ResponseWriter, r *http.Request) {
	if s.capabilityService == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Capability service not available")
		return
	}
	force := r.URL.Query().Get("force") == "1"
	s.writeJSON(w, http.StatusOK, s.capabilityService.Get(force))
}

// HandleGetTrafficHistory returns the RAM-buffered rx/tx history for the
// Bandwidth chart. Buckets accumulate since boot (fewer buckets right after a
// reboot is expected; the frontend copes).
func (s *Server) HandleGetTrafficHistory(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, s.systemStatus.GetTrafficHistory())
}

// statsWindowValues is the api-layer whitelist for the `window` query param,
// shared by every handler that accepts one (docs/ref/todo/
// statistics-window-granularity-plan.md T-05) — must stay in sync with
// service.statsWindowBuckets (backend/internal/service/traffic_stats.go),
// which the service layer re-normalizes against independently as
// defense-in-depth. Kept as its own set (not exported from service) so the
// api package doesn't need an import just to validate a query string.
var statsWindowValues = map[string]bool{
	"15m": true, "30m": true, "1h": true, "3h": true, "6h": true, "12h": true, "24h": true,
}

// statsWindowParam reads and whitelists the `window` query param to the 7
// supported statistics windows — any other value (including empty, wrong
// case like "1H", or garbage) silently falls back to "1h" rather than
// passing a client-supplied raw string into the service (plan §0 D-3: no
// error response, so an old bookmark/link with `?window=24h` — or no window
// at all — keeps working). Every handler below that accepts `window` (the
// Dashboard traffic-detail endpoint included, per plan §0 D-2) calls this
// single helper.
func statsWindowParam(r *http.Request) string {
	window := r.URL.Query().Get("window")
	if !statsWindowValues[window] {
		return "1h"
	}
	return window
}

// HandleGetTrafficDetail backs the Dashboard "Detailed" tab's Protocol
// Breakdown / Top Talkers / Top Rules by Traffic cards
// (docs/ref/todo/dashboard-traffic-detail-plan.md). window is whitelisted via
// statsWindowParam (7 values — plan §0 D-2: the Dashboard UI itself still
// only ever sends "1h"/"24h", but the endpoint accepts all 7 like every other
// statistics endpoint) — any other value (including empty) silently falls
// back to "1h" rather than passing a client-supplied raw string into the
// service (plan T-09: "ห้ามส่งค่าดิบจาก client ต่อเข้า service").
func (s *Server) HandleGetTrafficDetail(w http.ResponseWriter, r *http.Request) {
	window := statsWindowParam(r)
	s.writeJSON(w, http.StatusOK, s.trafficStats.GetTrafficDetail(window))
}

// HandleGetStatistics backs the Statistics page (Top Source Hosts / Top
// Destinations / Top Conversations / Top Denied —
// docs/ref/todo/statistics-page-plan.md). window is whitelisted via
// statsWindowParam exactly like HandleGetTrafficDetail above.
func (s *Server) HandleGetStatistics(w http.ResponseWriter, r *http.Request) {
	window := statsWindowParam(r)
	s.writeJSON(w, http.StatusOK, s.statistics.GetStatistics(window))
}

// HandleGetDNSQueryStatistics backs the Statistics -> DNS page's two
// top-level tables (Top Domains / Top Clients — drilldown plan T-03,
// extended with volume/drill-down fields by
// docs/ref/todo/statistics-dns-page-revamp-plan.md T-04/T-07). The response
// (model.DNSQueryStatistics) now also carries, per row, distinct
// client/domain counts and an APPROXIMATE byte volume joined in from
// TrafficStatsService by IP (model.DNSDomainStat.Bytes/BytesUp/BytesDown/
// BytesPercent, model.DNSClientStat.Bytes/...) — see those struct's doc
// comments in model/statistics.go for the exact join semantics and
// denominators (DomainBytes for domain rows, ObservedBytes for client rows).
// No client-supplied input besides the whitelisted window: there is still no
// sort-key parameter accepted here — ranking within each list, and any
// re-sorting of the table beyond that, is done entirely client-side in the
// browser (plan §1.4), never by this handler or the service it calls. The
// response also carries querySeries (docs/ref/todo/
// statistics-dns-query-bar-chart-plan.md T-02/T-03/T-05), a time series of
// DNS query counts per 5-minute bucket for the Statistics -> DNS overview
// page's bar chart — sourced from the same RAM-only ring the tables above
// already read, with no additional input from the client.
//
// Since docs/ref/todo/dns-blocked-query-statistics-plan.md T-10, the
// response also carries the "Blocked Domain Query" statistics fields:
// BlockedQueries/BlockedPercent/BlockedSeries/BlockedTruncated/
// TotalBlockedDomains/TotalBlockedClients/TopBlockedDomains/
// TopBlockedClients, plus a per-row Blocked/BlockedRule/BlockedMode badge on
// every DNSDomainStat in TopDomains. Still NO new query parameter — this
// endpoint's request shape is unchanged; only the response grew additively.
// Important caveats surfaced on the frontend (see model.DNSQueryStatistics'
// own doc comments for the full list):
//   - Display-only / RAM-only, never persisted to SQLite, and opt-in (same
//     DNS Query Logging switch as everything else on this endpoint) — a
//     blocked query is never dropped from TotalQueries, it is simply ALSO
//     counted in BlockedQueries.
//   - Classification is RECORD-TIME: it reflects the deny-list that was
//     actually applied to dnsmasq at the moment each query happened, not
//     the CURRENT deny-list — editing/removing a deny-list rule never
//     re-classifies historical data already in the ring.
//   - NOT proof a query was actually blocked end-to-end: it only reflects
//     whether the queried domain matched an ENABLED deny-list entry that
//     had been successfully applied to dnsmasq; it says nothing about
//     upstream DNS-over-HTTPS, a client's own DNS cache, or a client using
//     a different resolver entirely.
func (s *Server) HandleGetDNSQueryStatistics(w http.ResponseWriter, r *http.Request) {
	window := statsWindowParam(r)
	s.writeJSON(w, http.StatusOK, s.statistics.GetDNSQueryStatistics(window))
}

// HandleGetDNSDomainClients backs the domain -> clients drill-down page
// (drilldown plan T-03, extended by statistics-dns-page-revamp-plan.md
// T-04/T-07). The response (model.DNSDomainDrilldown) now also carries the
// domain's known resolved IPs (`ips`, ranked by APPROXIMATE per-IP byte
// volume, with a `shared` flag when an IP is also referenced by another
// domain) plus `totalBytes`/`totalBytesUp`/`totalBytesDown`, a `series` time
// series, and per-client volume figures on `clients` — all derived by
// joining the RAM-only domain->IP index against TrafficStatsService by IP,
// never a true per-domain packet count (see model/statistics.go for the full
// caveat list). This domain->IP mapping is display-only and MUST NEVER be
// used for firewall rule generation, policy matching, routing, or QoS
// decisions — it can be poisoned by any LAN client's DNS traffic. `domain` is
// untrusted client input: it is validated/normalized via
// model.NormalizeQueryDomain (same rules as the DNS log parser's
// sanitizeDomain, so the normalized value matches the ring's key) before
// being passed to the service. On validation failure it returns 400 with a
// generic message — the raw value the caller sent is never echoed back (plan
// §5 item 5: avoid reflecting attacker-controlled input into the response
// body even as JSON). A domain that validates but was never queried still
// returns 200 with an empty client list (plan T-03: "not found" is a normal
// outcome of window/timing, not an error). No sort-key or other new
// parameter is accepted from the client — sorting/filtering of `clients` and
// `ips` is done entirely client-side in the browser (plan §1.4).
func (s *Server) HandleGetDNSDomainClients(w http.ResponseWriter, r *http.Request) {
	window := statsWindowParam(r)
	raw := r.URL.Query().Get("domain")
	if raw == "" {
		s.writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	domain, ok := model.NormalizeQueryDomain(raw)
	if !ok {
		s.writeError(w, http.StatusBadRequest, "invalid domain")
		return
	}
	s.writeJSON(w, http.StatusOK, s.statistics.GetDNSDomainClients(window, domain))
}

// HandleGetDNSClientDomains backs the client -> domains drill-down page
// (drilldown plan T-03, extended by statistics-dns-page-revamp-plan.md
// T-04/T-07). The response (model.DNSClientDrilldown) now also carries
// `domains` as []model.DNSDomainStat (bytes exchanged with THIS client only,
// via a conversation-level join — plan §1.2, a stricter/more accurate join
// than the network-wide approximation used by HandleGetDNSQueryStatistics)
// plus this client's `totalBytes`/`totalBytesUp`/`totalBytesDown` and
// `series`. For the reserved "unknown" client bucket there is no IP to join
// against, so no byte/series join is attempted and those fields stay zero —
// the service never fabricates a value for it. `client` is untrusted client
// input: it must either parse as an IP address (netip.ParseAddr) or equal
// the reserved "unknown" bucket exactly. A parsed IP is re-serialized via
// addr.String() before being passed to the service so it matches the ring's
// normalized key (e.g. IPv6 written in a non-canonical form still resolves
// to the same bucket — plan §5 item 5). On validation failure it returns 400
// with a generic message; the raw value sent is never echoed back. No
// sort-key or other new parameter is accepted — sorting/filtering of
// `domains` is done entirely client-side in the browser (plan §1.4).
func (s *Server) HandleGetDNSClientDomains(w http.ResponseWriter, r *http.Request) {
	window := statsWindowParam(r)
	raw := r.URL.Query().Get("client")
	if raw == "" {
		s.writeError(w, http.StatusBadRequest, "client is required")
		return
	}
	client := raw
	if raw != dnsUnknownClientParam {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid client")
			return
		}
		client = addr.String()
	}
	s.writeJSON(w, http.StatusOK, s.statistics.GetDNSClientDomains(window, client))
}

// HandleGetDNSIPDomains backs the Statistics -> DNS page's IP-filter mode
// (docs/ref/todo/statistics-dns-ip-filter-plan.md T-04): given an IP, every
// domain the RAM-only reverse index (service/dns_domain_ips.go's
// DomainsForIP) remembers resolving to it — answering "this IP shows up
// under more than one domain, which ones?" for CDN/shared-hosting IP reuse.
// This domain<->IP mapping is display-only and derived from dnsmasq's
// answer log, which any LAN client can influence by simply querying
// attacker-controlled domains — it MUST NEVER be used for firewall rule
// generation, policy matching, routing, or QoS decisions.
//
// 🔒 `ip` is the one REQUIRED, security-sensitive input here: it MUST parse
// via netip.ParseAddr, and on failure this returns 400 with a generic
// message and NEVER calls the service — the raw client-supplied string is
// never echoed back in the response body (plan §4 item 4/Caution 4). The
// parsed address is re-serialized via addr.String() before being passed
// down, exactly like HandleGetTrafficHostDetail/HandleGetDNSClientDomains
// above, so a non-canonical IPv6 literal (e.g. "2001:DB8::1") hits the same
// index key the forward index itself uses. window is whitelisted via
// statsWindowParam like every other statistics endpoint. No sort/limit
// parameter is accepted — sorting/filtering of `domains` is done entirely
// client-side in the browser, same convention as the other DNS statistics
// endpoints.
func (s *Server) HandleGetDNSIPDomains(w http.ResponseWriter, r *http.Request) {
	window := statsWindowParam(r)

	raw := r.URL.Query().Get("ip")
	if raw == "" {
		s.writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	ip := addr.String()

	s.writeJSON(w, http.StatusOK, s.statistics.GetDNSIPDomains(window, ip))
}

// HandleGetCapacityStatistics backs the Statistics -> Capacity page and the
// CapacityIndicator pills on Overview/Traffic/DNS (docs/ref/todo/
// statistics-capacity-visibility-plan.md T-07, GitHub issue #123): current
// usage vs configured cap for all 9 RAM-only tracking rings/indices. window
// is whitelisted via statsWindowParam exactly like every other statistics
// endpoint. `series` is the only other input, read as a strict whitelist —
// "1" or "true" (case-sensitive, matching the convention every other
// boolean-ish query param in this file follows: no client-supplied string
// ever reaches service logic unvalidated) means true, literally anything
// else (missing, empty, "0", "false", garbage) means false — never a 400,
// mirroring the graceful-fallback rule statsWindowParam/clampQueryLimit
// already use for their own inputs.
//
// 🔒 The response (model.CapacityStatistics) contains ONLY counts and
// percentages — no domain name, IP address, or hostname ever appears in it,
// which is why this route is authRoute rather than superAdminRoute (see
// router.go). Nothing from the request is ever echoed back.
func (s *Server) HandleGetCapacityStatistics(w http.ResponseWriter, r *http.Request) {
	window := statsWindowParam(r)
	seriesRaw := r.URL.Query().Get("series")
	withSeries := seriesRaw == "1" || seriesRaw == "true"
	s.writeJSON(w, http.StatusOK, s.statistics.GetCapacityStatistics(window, withSeries))
}

// firewallStatsDefaultLimit/firewallStatsMaxLimit mirror the same constants
// in service/statistics_firewall.go — duplicated here for the same reason as
// trafficTopHostsDefaultLimit/-MaxLimit above (plan §1.2/Caution 5: the HTTP
// layer decides what an invalid/out-of-range `limit` means before it ever
// reaches the service).
const (
	firewallStatsDefaultLimit = 100
	firewallStatsMaxLimit     = 500
)

// HandleGetFirewallStatistics backs the Statistics -> Firewall page
// (docs/ref/todo/statistics-firewall-page-plan.md T-06): rule-counter +
// NFLOG-sourced firewall traffic/blocked-event summary. window is
// whitelisted via statsWindowParam exactly like every other statistics
// endpoint; limit is clamped via clampQueryLimit, never rejected — no other
// query parameter is accepted or read.
func (s *Server) HandleGetFirewallStatistics(w http.ResponseWriter, r *http.Request) {
	window := statsWindowParam(r)
	limit := clampQueryLimit(r, firewallStatsDefaultLimit, firewallStatsMaxLimit)

	stats, err := s.statistics.GetFirewallStatistics(window, limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to load firewall statistics")
		return
	}
	s.writeJSON(w, http.StatusOK, stats)
}

// trafficTopHostsDefaultLimit/trafficTopHostsMaxLimit and
// trafficHostDetailDefaultLimit/trafficHostDetailMaxLimit mirror the same
// constants in service/statistics_traffic.go — duplicated here (rather than
// exported from service) because the HTTP layer's job is to decide what an
// invalid/out-of-range `limit` means for THIS endpoint (silently fall back /
// clamp, never 400) before the value ever reaches the service, per plan §1.2/
// Caution 5 ("no client-supplied string ever reaches backend aggregation
// logic ... only a whitelisted enum + a netip.ParseAddr-validated IP + a
// clamped integer").
const (
	trafficTopHostsDefaultLimit   = 100
	trafficTopHostsMaxLimit       = 500
	trafficHostDetailDefaultLimit = 100
	trafficHostDetailMaxLimit     = 300
)

// clampQueryLimit parses the `limit` query param: a missing/empty/
// unparseable value silently falls back to def (never a 400 — plan §1.2), and
// any value outside [1, max] is CLAMPED into range, never rejected.
func clampQueryLimit(r *http.Request, def, max int) int {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// HandleGetTrafficTopHosts backs the Statistics -> Traffic page's two
// top-level tables (Top Source Hosts / Top Destinations —
// docs/ref/todo/statistics-traffic-page-plan.md T-04). Unlike
// HandleGetStatistics's statsTopN-cut response, this endpoint returns up to
// `limit` rows (default 100, clamped to 500) so the page can filter/sort
// beyond the Overview page's top-10 cards. window is whitelisted exactly like
// statsWindowParam/HandleGetStatistics; limit is clamped, never rejected — the
// only validated client input on this route.
func (s *Server) HandleGetTrafficTopHosts(w http.ResponseWriter, r *http.Request) {
	window := statsWindowParam(r)
	limit := clampQueryLimit(r, trafficTopHostsDefaultLimit, trafficTopHostsMaxLimit)
	s.writeJSON(w, http.StatusOK, s.statistics.GetTrafficTopHosts(window, limit))
}

// HandleGetTrafficHostDetail backs the Statistics -> Traffic per-IP
// drill-down page (plan T-04). 🔒 `ip` is the one REQUIRED, security-sensitive
// input in this whole feature: it MUST parse via netip.ParseAddr, and on
// failure this returns 400 and never calls the service (plan Caution 5 — no
// client string reaches backend aggregation logic unvalidated). The parsed
// address is re-serialized via addr.String() before being passed down so a
// non-canonical IPv6 literal (e.g. "2001:DB8::1") hits the same bucket keys
// the conntrack sampler itself uses (matches HandleGetDNSClientDomains's
// client-normalization rule above). window/limit are handled exactly like
// HandleGetTrafficTopHosts, with the drill-down's own (lower) limit ceiling.
func (s *Server) HandleGetTrafficHostDetail(w http.ResponseWriter, r *http.Request) {
	window := statsWindowParam(r)
	limit := clampQueryLimit(r, trafficHostDetailDefaultLimit, trafficHostDetailMaxLimit)

	raw := r.URL.Query().Get("ip")
	if raw == "" {
		s.writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	ip := addr.String()

	s.writeJSON(w, http.StatusOK, s.statistics.GetTrafficHostDetail(window, ip, limit))
}

// HandleGetIPInfo backs the Statistics -> Traffic -> Host page's "Public IP
// Info" card (docs/ref/todo/statistics-host-ipinfo-plan.md T-07) — modeled
// on HandleGetTrafficHostDetail above: `ip` MUST parse via netip.ParseAddr,
// and on failure this returns 400 and NEVER calls the service (same rule as
// every other IP-taking statistics endpoint in this file). The parsed
// address is re-serialized via addr.String() before being passed down.
//
// Error mapping is deliberately opaque about *why* something failed beyond
// what the client needs to render a state:
//   - ErrIPInfoDisabled  -> 404 (not 403 — doesn't hint at server config)
//   - ErrIPInfoNotPublic -> 400 (same class as an invalid `ip` — client sent
//     something this endpoint will never serve)
//   - ErrIPInfoRateLimited -> 429
//   - anything else (provider failure/timeout) -> 502 with a generic
//     message; the raw upstream error is deliberately never sent to the
//     client.
func (s *Server) HandleGetIPInfo(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("ip")
	if raw == "" {
		s.writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	ip := addr.String()

	result, err := s.ipInfo.Lookup(r.Context(), ip)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrIPInfoDisabled):
			s.writeError(w, http.StatusNotFound, "not found")
		case errors.Is(err, service.ErrIPInfoNotPublic):
			s.writeError(w, http.StatusBadRequest, "invalid ip")
		case errors.Is(err, service.ErrIPInfoRateLimited):
			s.writeError(w, http.StatusTooManyRequests, "rate limited, try again later")
		default:
			s.writeError(w, http.StatusBadGateway, "ip info lookup failed")
		}
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

// referenceDefaultLimit/referenceMaxLimit back clampQueryLimit for the two
// reference-popover handlers below (docs/ref/todo/reference-popover-plan.md
// Step 3) — mirrors service/statistics_reference.go's
// referenceDefaultLimit/referenceMaxLimit consts (kept separate on purpose,
// same "HTTP layer decides what an invalid/out-of-range limit means" split
// as trafficTopHostsDefaultLimit/-MaxLimit above).
const (
	referenceDefaultLimit = 3
	referenceMaxLimit     = 10
)

// HandleGetIPReference backs the reference popover's IP hover summary
// (docs/ref/todo/reference-popover-plan.md Step 3) — a lightweight sibling
// of HandleGetDNSIPDomains/HandleGetTrafficHostDetail, deliberately returning
// only the top few domain references + counts (never a full drill-down
// payload) since a hover popover can fire dozens of times a minute.
//
// 🔒 `ip` MUST parse via netip.ParseAddr, exactly like every other IP-taking
// statistics endpoint in this file — on failure this returns 400 with a
// generic message and NEVER calls the service; the raw client-supplied
// string is never echoed back. The parsed address is re-serialized via
// addr.String() before being passed down so a non-canonical IPv6 literal
// hits the same index/scope-classification key the rest of the DNS
// statistics endpoints use.
//
// `scope` (public vs LAN) is decided entirely inside the service by
// isGloballyRoutable — this handler never accepts or forwards a `scope`
// query parameter even if the client sends one (plan §2.3: a security
// boundary, not a UX guard). `window` is likewise silently ignored: unlike
// every other statistics endpoint, this route never calls statsWindowParam
// at all — the response's window is always the fixed 1h the service
// hardcodes (plan §2.4/Q4). `limit` is clamped via clampQueryLimit, never
// rejected, same convention as every other limit-taking endpoint here.
func (s *Server) HandleGetIPReference(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("ip")
	if raw == "" {
		s.writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	ip := addr.String()
	limit := clampQueryLimit(r, referenceDefaultLimit, referenceMaxLimit)

	s.writeJSON(w, http.StatusOK, s.statistics.GetIPReference(ip, limit))
}

// HandleGetDomainReference backs the reference popover's Domain hover
// summary (docs/ref/todo/reference-popover-plan.md Step 3) — the domain-side
// sibling of HandleGetIPReference above, same "top few entries only" shape.
//
// `domain` is untrusted client input, validated/normalized via
// model.NormalizeQueryDomain exactly like HandleGetDNSDomainClients; on
// failure this returns 400 with a generic message and the raw value is never
// echoed back. `window`/`scope` are not accepted (same as
// HandleGetIPReference — this route has no scope concept at all, a domain is
// always looked up the same way). `limit` is clamped, never rejected.
func (s *Server) HandleGetDomainReference(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("domain")
	if raw == "" {
		s.writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	domain, ok := model.NormalizeQueryDomain(raw)
	if !ok {
		s.writeError(w, http.StatusBadRequest, "invalid domain")
		return
	}
	limit := clampQueryLimit(r, referenceDefaultLimit, referenceMaxLimit)

	s.writeJSON(w, http.StatusOK, s.statistics.GetDomainReference(domain, limit))
}

// dnsUnknownClientParam is the one non-IP value HandleGetDNSClientDomains
// accepts for `client` — must match the dnsUnknownClient constant the
// service's ring uses as its reserved bucket key
// (service/dns_query_stats.go).
const dnsUnknownClientParam = "unknown"

// HandleGetRecentLogs backs the Dashboard "Recent Logs" widget. It reads the
// same shared ring buffer as HandleGetTrafficLogs (so entries from all three
// chains appear here — deliberate, see plan §6 Caution 7) but MUST cap how
// much it returns: at the configured traffic-log-buffer-capacity (default
// 10,000, docs/ref/todo/firewall-log-buffer-capacity-plan.md T-05) entries, an
// unbounded GetAll() here would ship several MB of JSON on every page
// load/SSE reconnect (plan §6 Caution 5), which this small, frequently-hit
// widget never needs.
func (s *Server) HandleGetRecentLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	if limit > 500 {
		limit = 500
	}

	all := s.logs.GetAll() // newest-first
	if limit > len(all) {
		limit = len(all)
	}
	page := all[:limit]
	s.enrichTrafficLogs(page)
	s.writeJSON(w, http.StatusOK, page)
}

// enrichTrafficLogs fills SrcDomain/DestDomain/SrcHostname/DestHostname on
// every entry of logs, in place, as a read-time enrichment step
// (docs/ref/todo/traffic-log-rule-name-and-domain-plan.md T-09). Callers
// must pass a slice they own a copy of (never the ring buffer's internal
// storage) — see RingBuffer.GetAll, which already copies.
//
// Exactly one batch domain lookup and one batch hostname lookup happen for
// the whole slice, never per row (both StatisticsService.LookupDomains and
// TrafficStatsService.LookupHostnames document why: the reverse-DNS cache
// takes a full mutex per call, and the hostname cache re-reads DHCP
// state on a cache miss). This is why callers must cap the slice they pass
// in — see the ≤1000-row limit enforced by HandleGetTrafficLogs and the
// ≤500-row limit in HandleGetRecentLogs — enriching the whole 10,000-entry
// ring buffer is never done.
//
// RuleName/RuleID are NOT touched here: RuleName is a snapshot captured once
// at write time (cmd/pigate/main.go stampAndPush), never re-resolved on
// read — see model.FirewallLog's doc comment for the snapshot-on-write vs
// enrich-on-read distinction this whole feature hinges on.
func (s *Server) enrichTrafficLogs(logs []model.FirewallLog) {
	if len(logs) == 0 {
		return
	}
	ipSet := make(map[string]struct{}, len(logs)*2)
	for _, entry := range logs {
		if entry.Src != "" && entry.Src != "-" {
			ipSet[entry.Src] = struct{}{}
		}
		if entry.Dest != "" && entry.Dest != "-" {
			ipSet[entry.Dest] = struct{}{}
		}
	}
	if len(ipSet) == 0 {
		return
	}
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	var domains map[string]string
	if s.statistics != nil {
		domains = s.statistics.LookupDomains(ips)
	}
	var hostnames map[string]string
	if s.trafficStats != nil {
		hostnames = s.trafficStats.LookupHostnames(ips)
	}

	for i := range logs {
		logs[i].SrcDomain = domains[logs[i].Src]
		logs[i].DestDomain = domains[logs[i].Dest]
		// DHCP hostname is only a fallback for when the DNS reverse cache
		// has nothing for that IP (plan design decision 5) — an entry never
		// carries both a domain and a hostname for the same address.
		if logs[i].SrcDomain == "" {
			logs[i].SrcHostname = hostnames[logs[i].Src]
		}
		if logs[i].DestDomain == "" {
			logs[i].DestHostname = hostnames[logs[i].Dest]
		}
	}
}

func (s *Server) HandleClearLogs(w http.ResponseWriter, r *http.Request) {
	s.logs.Clear()
	// Wiping the live traffic/firewall log buffer must itself be attributable —
	// same rationale as HandleClearSystemEvents re-logging the actor of a wipe.
	s.logEvent(r, model.EventCategoryFirewall, "firewall.logs_cleared", model.EventSeverityWarning,
		"ringbuffer", "Dashboard traffic/firewall log buffer cleared")
	w.WriteHeader(http.StatusOK)
}

// trafficLogChainMatches reports whether entry belongs to the requested
// chain filter. chainParam is already validated by the caller to be one of
// "", "forward", "input", "output", "local" ("local" = input+output).
func trafficLogChainMatches(entry model.FirewallLog, chainParam string) bool {
	switch chainParam {
	case "":
		return true
	case "local":
		return entry.Chain == model.PolicyChainInput || entry.Chain == model.PolicyChainOutput
	default:
		return entry.Chain == chainParam
	}
}

// HandleGetTrafficLogs returns packet logs (forward/input/output, newest
// first) from the shared RAM ring buffer, filtered in memory by the query
// params below. It reads the same buffer as the Dashboard Recent Logs
// widget; it never touches SQLite.
//
//	action     PASS | DROP                         (case-insensitive; empty = all)
//	q          substring matched against src/dest/port/proto/interface/reason/
//	           chain/ruleName/ruleId (case-insensitive; docs/ref/todo/
//	           firewall-rule-matched-endpoints-plan.md T-12 added ruleName/
//	           ruleId, e.g. for the RuleStatsDrawer "ดู log ของกฎนี้" deep-link)
//	chain      forward | input | output | local (=input+output) | "" (=all); unknown value -> 400
//	limit      max rows to return (default 100, capped at min(1000, buffer capacity))
//	beforeId   cursor: id of the last row the client already has under the current filter
//	beforeTime cursor fallback (RFC3339Nano, RFC3339 also accepted): used only when beforeId
//	           is no longer present in the buffer (evicted) — see plan §2.7/§6 Caution 4
//
// Cursor pagination contract (docs/ref/todo/traffic-log-pagination-and-local-traffic-plan.md
// §2.7): filter the WHOLE buffer first (action/q/chain), THEN locate the
// cursor within the filtered result, THEN cut `limit` rows — never cut by
// limit before filtering, or entries deeper in the buffer that match the
// filter would be silently skipped. The cursor is the (id, time) of the last
// row the client already rendered, not a numeric offset, because the ring
// buffer is prepended to continuously by the NFLOG watchers — a numeric
// offset would drift under the client's feet. Returning fewer than `limit`
// rows is the client's signal that there is nothing older left; this handler
// always returns `[]`, never `null`, so the frontend's array methods never
// see a nil.
func (s *Server) HandleGetTrafficLogs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	action := strings.ToUpper(strings.TrimSpace(query.Get("action")))
	needle := strings.ToLower(strings.TrimSpace(query.Get("q")))
	chainParam := strings.ToLower(strings.TrimSpace(query.Get("chain")))
	beforeID := strings.TrimSpace(query.Get("beforeId"))
	beforeTimeRaw := strings.TrimSpace(query.Get("beforeTime"))

	switch chainParam {
	case "", model.PolicyChainForward, model.PolicyChainInput, model.PolicyChainOutput, "local":
		// ok
	default:
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid chain %q: must be one of forward, input, output, local", chainParam))
		return
	}

	limit := 100
	if v, err := strconv.Atoi(query.Get("limit")); err == nil && v > 0 {
		limit = v
	}
	if maxLimit := s.logs.Capacity(); limit > maxLimit {
		limit = maxLimit
	}
	if limit > 1000 {
		limit = 1000
	}

	// Filter the entire buffer first (see doc comment above) — do not break
	// out of this loop at `limit`.
	all := s.logs.GetAll() // newest-first
	matched := make([]model.FirewallLog, 0, len(all))
	for _, entry := range all {
		if action != "" && strings.ToUpper(entry.Action) != action {
			continue
		}
		if !trafficLogChainMatches(entry, chainParam) {
			continue
		}
		if needle != "" {
			// ruleName/ruleId added by T-12 (see doc comment above) so the
			// "ดู log ของกฎนี้" deep-link can search by rule name — this
			// haystack MUST stay in lockstep with TrafficLogPage.tsx's
			// client-side matchesFilter mirror (see that file's comment).
			hay := strings.ToLower(entry.Src + " " + entry.Dest + " " + entry.SrcPort + " " + entry.Port + " " + entry.Proto + " " + entry.InIface + " " + entry.OutIface + " " + entry.Reason + " " + entry.Chain + " " + entry.RuleName + " " + entry.RuleID)
			if !strings.Contains(hay, needle) {
				continue
			}
		}
		matched = append(matched, entry)
	}

	// Locate the cursor within the filtered result, then take rows after it.
	start := 0
	if beforeID != "" {
		idx := -1
		for i, entry := range matched {
			if entry.ID == beforeID {
				idx = i
				break
			}
		}
		if idx >= 0 {
			start = idx + 1
		} else {
			// beforeId no longer present (evicted) — fall back to time-based cut.
			beforeTime, ok := parseTrafficLogCursorTime(beforeTimeRaw)
			if !ok {
				// No usable fallback: nothing more to return, not "start over".
				s.writeJSON(w, http.StatusOK, []model.FirewallLog{})
				return
			}
			filteredByTime := matched[:0:0]
			for _, entry := range matched {
				entryTime, err := time.Parse(time.RFC3339Nano, entry.Time)
				if err != nil {
					continue
				}
				if entryTime.Before(beforeTime) {
					filteredByTime = append(filteredByTime, entry)
				}
			}
			matched = filteredByTime
			start = 0
		}
	}

	page := matched[start:]
	if len(page) > limit {
		page = page[:limit]
	}
	result := make([]model.FirewallLog, len(page))
	copy(result, page)
	s.enrichTrafficLogs(result)
	s.writeJSON(w, http.StatusOK, result)
}

// parseTrafficLogCursorTime parses the beforeTime cursor fallback param,
// accepting RFC3339Nano (the format entries are actually stamped with, see
// main.go) and plain RFC3339 for leniency. ok=false for an empty/unparseable
// value, which the caller treats as "no more data" rather than "start over".
func parseTrafficLogCursorTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// HandleGetTrafficLogUsage returns the traffic log ring buffer's current fill
// state — used/capacity/oldest/newest/evicted — for the small summary bar the
// Forward/Local Traffic log pages show (docs/ref/todo/
// firewall-log-buffer-capacity-plan.md T-04, issue #134). Deliberately a tiny,
// purpose-built payload instead of reusing GET /api/statistics/capacity: it
// reads s.logs.Usage() directly (a single O(1) RLock snapshot, see
// RingBuffer.Usage's doc comment) and never calls GetAll(), never touches
// SQLite, and never talks to the kernel. The numbers are for the WHOLE ring
// buffer (all three chains share it), same caveat as HandleGetTrafficLogs.
func (s *Server) HandleGetTrafficLogUsage(w http.ResponseWriter, r *http.Request) {
	if s.logs == nil {
		s.writeError(w, http.StatusInternalServerError, "log buffer not available")
		return
	}
	used, capacity, oldest, newest, evicted := s.logs.Usage()
	var usedPercent float64
	if capacity > 0 {
		usedPercent = float64(used) / float64(capacity) * 100
	}
	s.writeJSON(w, http.StatusOK, model.TrafficLogBufferUsage{
		Used:        used,
		Capacity:    capacity,
		UsedPercent: usedPercent,
		OldestEntry: oldest,
		NewestEntry: newest,
		Evicted:     evicted,
	})
}

// HandleGetSystemEvents returns central event log entries (newest first) with
// optional category/severity/q filters and limit/offset paging.
func (s *Server) HandleGetSystemEvents(w http.ResponseWriter, r *http.Request) {
	if s.eventLog == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Event log service not available")
		return
	}

	query := r.URL.Query()
	category := query.Get("category")
	severity := query.Get("severity")
	q := query.Get("q")

	limit := 50
	if v, err := strconv.Atoi(query.Get("limit")); err == nil && v > 0 {
		limit = v
	}
	if limit > 200 {
		limit = 200
	}
	offset := 0
	if v, err := strconv.Atoi(query.Get("offset")); err == nil && v > 0 {
		offset = v
	}

	events, total, err := s.eventLog.Query(category, severity, q, limit, offset)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  total,
	})
}

// HandleClearSystemEvents wipes the audit trail. super_admin only (see router);
// EventLogService.Clear immediately re-logs who performed the wipe.
func (s *Server) HandleClearSystemEvents(w http.ResponseWriter, r *http.Request) {
	if s.eventLog == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Event log service not available")
		return
	}
	actor, _ := r.Context().Value(UserContextKey).(string)
	if err := s.eventLog.Clear(actor); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, true)
}

// =========================================================================
// INTERFACES HANDLERS
// =========================================================================

func (s *Server) HandleGetInterfaces(w http.ResponseWriter, r *http.Request) {
	list, err := s.interfaceService.GetDataLayerInterfaceIncludingOffline()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range list {
		maskInterfacePasswords(&list[i])
	}
	s.writeJSON(w, http.StatusOK, list)
}

// rejectIfOffline writes a 409 and returns true when the interface has no live kernel link
// (Status=="offline"). Handlers that mutate kernel state must not run against a phantom
// interface — only delete/reset are allowed for an offline row.
func (s *Server) rejectIfOffline(w http.ResponseWriter, iface *model.NetworkInterface) bool {
	if iface.Status == "offline" {
		s.writeError(w, http.StatusConflict, "interface is offline; only delete is allowed")
		return true
	}
	return false
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int)
	for _, x := range a {
		m[strings.TrimSpace(strings.ToUpper(x))]++
	}
	for _, x := range b {
		m[strings.TrimSpace(strings.ToUpper(x))]--
	}
	for _, count := range m {
		if count != 0 {
			return false
		}
	}
	return true
}

func (s *Server) HandleUpdateInterface(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	iface, err := s.interfaceService.GetDataLayerInterfaceByID(id)
	if err != nil || iface == nil {
		s.writeError(w, http.StatusNotFound, "Interface not found")
		return
	}
	if s.rejectIfOffline(w, iface) {
		return
	}

	var updates model.NetworkInterface
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Check if admin access has changed
	adminAccessChanged := !equalStringSlices(iface.AdminAccess, updates.AdminAccess)

	// Apply updates to existing interface object
	iface.Alias = updates.Alias
	iface.Role = updates.Role
	iface.AddressingMode = updates.AddressingMode
	iface.IP = updates.IP
	iface.Netmask = updates.Netmask
	iface.Gateway = updates.Gateway
	iface.MacAddress = updates.MacAddress
	iface.AdminAccess = updates.AdminAccess
	// Status is intentionally NOT taken from the request: saving configuration must not
	// change the interface's administrative state. iface.Status already holds the live
	// kernel state and is persisted as-is. Up/down is changed only via the toggle route.

	if updates.MacMode != nil {
		iface.MacMode = updates.MacMode
	}
	if updates.LaaMacAddress != nil {
		iface.LaaMacAddress = updates.LaaMacAddress
	}
	if updates.RandomizeOnReconnect != nil {
		iface.RandomizeOnReconnect = updates.RandomizeOnReconnect
	}
	if updates.Prefer5GHz != nil {
		iface.Prefer5GHz = updates.Prefer5GHz
	}
	if updates.BackupSSID != nil {
		iface.BackupSSID = updates.BackupSSID
	}
	// Safe password updates in PUT: only set if password is not empty and not masked, or if security is Open
	if updates.BackupWifiPassword != nil {
		backupSec := ""
		if updates.BackupWifiSecurity != nil {
			backupSec = *updates.BackupWifiSecurity
		} else if iface.BackupWifiSecurity != nil {
			backupSec = *iface.BackupWifiSecurity
		}
		if *updates.BackupWifiPassword != "••••••••" {
			if *updates.BackupWifiPassword != "" || backupSec == "Open" {
				iface.BackupWifiPassword = updates.BackupWifiPassword
			}
		}
	}
	if updates.WifiSSID != nil {
		iface.WifiSSID = updates.WifiSSID
	}
	if updates.WifiPassword != nil {
		primarySec := ""
		if updates.WifiSecurity != nil {
			primarySec = *updates.WifiSecurity
		} else if iface.WifiSecurity != nil {
			primarySec = *iface.WifiSecurity
		}
		if *updates.WifiPassword != "••••••••" {
			if *updates.WifiPassword != "" || primarySec == "Open" {
				iface.WifiPassword = updates.WifiPassword
			}
		}
	}
	if updates.WifiSecurity != nil {
		iface.WifiSecurity = updates.WifiSecurity
	}
	if updates.BackupWifiSecurity != nil {
		iface.BackupWifiSecurity = updates.BackupWifiSecurity
	}
	if updates.FailoverEnabled != nil {
		iface.FailoverEnabled = updates.FailoverEnabled
	}
	if updates.IPCheckTimeout != nil {
		iface.IPCheckTimeout = updates.IPCheckTimeout
	}
	if updates.PrimaryMaxRetries != nil {
		iface.PrimaryMaxRetries = updates.PrimaryMaxRetries
	}
	if updates.FailoverCooldown != nil {
		iface.FailoverCooldown = updates.FailoverCooldown
	}
	if updates.Metric != nil {
		iface.Metric = updates.Metric
	}

	// Mirror the service-side alias normalization on our copy so the response body
	// matches what is persisted (ApplyInterfaceConfig receives the struct by value).
	iface.Alias = strings.TrimSpace(iface.Alias)
	if iface.Alias == "" {
		iface.Alias = iface.Name
	}

	if err := s.interfaceService.ApplyInterfaceConfig(*iface); err != nil {
		switch {
		case errors.Is(err, service.ErrAliasConflict):
			s.writeError(w, http.StatusConflict, err.Error())
		case errors.Is(err, service.ErrAliasInvalid):
			s.writeError(w, http.StatusBadRequest, err.Error())
		default:
			s.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// Reconcile the dhcpcd client for the (possibly changed) addressing mode. A
	// Static->DHCP switch on an already-up interface fires no netlink Link event, so
	// without this dhcpcd would not start until the interface is toggled. Non-fatal:
	// the config is already persisted, a dhcpcd hiccup must not turn Save into a 500.
	s.dhcpcdService.SyncInterface(iface.Name)

	if adminAccessChanged {
		if err := s.syncFirewallRules(); err != nil {
			s.writeError(w, http.StatusInternalServerError, "OS Firewall update failed: "+err.Error())
			return
		}
	}

	s.logEvent(r, model.EventCategoryNetwork, "network.interface_changed", model.EventSeverityInfo,
		iface.Name, "Interface "+iface.Name+" configuration updated")
	maskInterfacePasswords(iface)
	s.writeJSON(w, http.StatusOK, iface)
}

// HandleCreateVlan creates an 802.1Q VLAN sub-interface (POST /api/interfaces/vlan).
func (s *Server) HandleCreateVlan(w http.ResponseWriter, r *http.Request) {
	var input model.CreateVlanInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	iface, err := s.interfaceService.CreateVlanInterface(input)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrVlanExists), errors.Is(err, service.ErrAliasConflict):
			s.writeError(w, http.StatusConflict, err.Error())
		case errors.Is(err, service.ErrVlanInvalid), errors.Is(err, service.ErrAliasInvalid):
			s.writeError(w, http.StatusBadRequest, err.Error())
		default:
			s.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// The new interface carries adminAccess rules that must reach nftables, same as the
	// admin-access-changed path in HandleUpdateInterface.
	if err := s.syncFirewallRules(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "OS Firewall update failed: "+err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryNetwork, "network.interface_created", model.EventSeverityInfo,
		iface.Name, "VLAN interface "+iface.Name+" created")
	s.writeJSON(w, http.StatusCreated, iface)
}

func (s *Server) HandlePatchInterface(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	iface, err := s.interfaceService.GetDataLayerInterfaceByID(id)
	if err != nil || iface == nil {
		s.writeError(w, http.StatusNotFound, "Interface not found")
		return
	}
	if s.rejectIfOffline(w, iface) {
		return
	}

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Check if admin access has changed
	adminAccessChanged := false
	if val, ok := body["adminAccess"]; ok {
		var access []string
		if err := json.Unmarshal(val, &access); err == nil {
			adminAccessChanged = !equalStringSlices(iface.AdminAccess, access)
			iface.AdminAccess = access
		}
	}

	updateString := func(key string, field *string) {
		if val, ok := body[key]; ok {
			var str string
			if err := json.Unmarshal(val, &str); err == nil {
				*field = str
			}
		}
	}

	updatePtrString := func(key string, field **string) {
		if val, ok := body[key]; ok {
			var str *string
			if err := json.Unmarshal(val, &str); err == nil {
				*field = str
			}
		}
	}

	updatePtrBool := func(key string, field **bool) {
		if val, ok := body[key]; ok {
			var b *bool
			if err := json.Unmarshal(val, &b); err == nil {
				*field = b
			}
		}
	}

	updatePtrInt := func(key string, field **int) {
		if val, ok := body[key]; ok {
			var valInt *int
			if err := json.Unmarshal(val, &valInt); err == nil {
				*field = valInt
			}
		}
	}

	updateString("alias", &iface.Alias)
	updateString("role", &iface.Role)
	updateString("addressingMode", &iface.AddressingMode)
	updateString("ip", &iface.IP)
	updateString("netmask", &iface.Netmask)
	updateString("gateway", &iface.Gateway)
	updateString("macAddress", &iface.MacAddress)
	// "status" is intentionally not accepted here: saving configuration must not toggle
	// the interface. iface.Status keeps its live kernel value and is persisted unchanged.
	// Up/down is changed only via POST /interfaces/{id}/toggle.

	updatePtrString("wifiSSID", &iface.WifiSSID)
	updatePtrString("wifiSecurity", &iface.WifiSecurity)
	updatePtrString("macMode", &iface.MacMode)
	updatePtrString("laaMacAddress", &iface.LaaMacAddress)
	updatePtrBool("randomizeOnReconnect", &iface.RandomizeOnReconnect)
	updatePtrBool("prefer5GHz", &iface.Prefer5GHz)
	updatePtrBool("failoverEnabled", &iface.FailoverEnabled)
	updatePtrString("backupSsid", &iface.BackupSSID)
	updatePtrString("backupWifiSecurity", &iface.BackupWifiSecurity)
	updatePtrInt("ipCheckTimeout", &iface.IPCheckTimeout)
	updatePtrInt("primaryMaxRetries", &iface.PrimaryMaxRetries)
	updatePtrInt("failoverCooldown", &iface.FailoverCooldown)
	updatePtrInt("metric", &iface.Metric) // null clears it back to "unset" (auto)

	// Safe password updates: only if non-empty and not masked, or if security is explicitly set to Open
	if val, ok := body["wifiPassword"]; ok {
		var pass *string
		if err := json.Unmarshal(val, &pass); err == nil {
			secMode := ""
			if iface.WifiSecurity != nil {
				secMode = *iface.WifiSecurity
			}
			if pass != nil && *pass != "••••••••" {
				if *pass != "" || secMode == "Open" {
					iface.WifiPassword = pass
				}
			}
		}
	}

	if val, ok := body["backupWifiPassword"]; ok {
		var pass *string
		if err := json.Unmarshal(val, &pass); err == nil {
			backupSecMode := ""
			if iface.BackupWifiSecurity != nil {
				backupSecMode = *iface.BackupWifiSecurity
			}
			if pass != nil && *pass != "••••••••" {
				if *pass != "" || backupSecMode == "Open" {
					iface.BackupWifiPassword = pass
				}
			}
		}
	}

	// Mirror the service-side alias normalization on our copy so the response body
	// matches what is persisted (ApplyInterfaceConfig receives the struct by value).
	iface.Alias = strings.TrimSpace(iface.Alias)
	if iface.Alias == "" {
		iface.Alias = iface.Name
	}

	if err := s.interfaceService.ApplyInterfaceConfig(*iface); err != nil {
		switch {
		case errors.Is(err, service.ErrAliasConflict):
			s.writeError(w, http.StatusConflict, err.Error())
		case errors.Is(err, service.ErrAliasInvalid):
			s.writeError(w, http.StatusBadRequest, err.Error())
		default:
			s.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// Reconcile the dhcpcd client for the (possibly changed) addressing mode. A
	// Static->DHCP switch on an already-up interface fires no netlink Link event, so
	// without this dhcpcd would not start until the interface is toggled. Non-fatal:
	// the config is already persisted, a dhcpcd hiccup must not turn Save into a 500.
	s.dhcpcdService.SyncInterface(iface.Name)

	if adminAccessChanged {
		if err := s.syncFirewallRules(); err != nil {
			s.writeError(w, http.StatusInternalServerError, "OS Firewall update failed: "+err.Error())
			return
		}
	}

	s.logEvent(r, model.EventCategoryNetwork, "network.interface_changed", model.EventSeverityInfo,
		iface.Name, "Interface "+iface.Name+" configuration updated")
	maskInterfacePasswords(iface)
	s.writeJSON(w, http.StatusOK, iface)
}

func (s *Server) HandleToggleInterface(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	iface, err := s.interfaceService.GetDataLayerInterfaceByID(id)
	if err != nil || iface == nil {
		s.writeError(w, http.StatusNotFound, "Interface not found")
		return
	}
	if s.rejectIfOffline(w, iface) {
		return
	}

	nextStatus := "up"
	if iface.Status == "up" {
		nextStatus = "down"
	}

	// Route through the service layer: the "up" leg brings the link up and reapplies the
	// DB configuration (static IP, gateway route, metric); status is persisted with a
	// targeted UPDATE so an unmanaged interface is not silently adopted into the DB.
	if err := s.interfaceService.SetInterfaceState(*iface, nextStatus == "up"); err != nil {
		s.writeError(w, http.StatusInternalServerError, "OS level configuration failed")
		return
	}

	iface.Status = nextStatus
	s.logEvent(r, model.EventCategoryNetwork, "network.interface_changed", model.EventSeverityInfo,
		iface.Name, "Interface "+iface.Name+" toggled "+nextStatus)
	maskInterfacePasswords(iface)
	s.writeJSON(w, http.StatusOK, iface)
}

func (s *Server) HandleScanWifi(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	iface, err := s.interfaceService.GetDataLayerInterfaceByID(id)
	if err != nil || iface == nil {
		s.writeError(w, http.StatusNotFound, "Interface not found")
		return
	}
	if s.rejectIfOffline(w, iface) {
		return
	}

	if iface.Type != "wireless" {
		s.writeError(w, http.StatusBadRequest, "Interface is not a wireless interface")
		return
	}

	if iface.Status != "up" {
		s.writeError(w, http.StatusConflict, "Interface must be brought up before scanning for Wi-Fi networks.")
		return
	}

	results, err := s.network.ScanWifi(iface.Name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, results)
}

func (s *Server) HandleGetWifiStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	iface, err := s.interfaceService.GetDataLayerInterfaceByID(id)
	if err != nil || iface == nil {
		s.writeError(w, http.StatusNotFound, "Interface not found")
		return
	}
	if s.rejectIfOffline(w, iface) {
		return
	}

	if iface.Type != "wireless" {
		s.writeError(w, http.StatusBadRequest, "Interface is not a wireless interface")
		return
	}

	status, err := s.network.GetWifiStatus(iface.Name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, status)
}

func (s *Server) HandleDeleteInterface(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	iface, err := s.interfaceService.GetDataLayerInterfaceByID(id)
	if err != nil || iface == nil {
		s.writeError(w, http.StatusNotFound, "Interface not found")
		return
	}

	// VLAN sub-interfaces are deleted differently: they are removed via netlink (link +
	// DB row) and CAN be deleted while up — that is the only way to tear a VLAN down, and
	// unlike a physical port there is no offline state to wait for. The kernel layer still
	// guards against deleting a non-vlan link, so the offline check is skipped only here.
	if iface.Subtype == "vlan" {
		if err := s.interfaceService.DeleteVlanInterface(id); err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.syncFirewallRules(); err != nil {
			s.writeError(w, http.StatusInternalServerError, "OS Firewall update failed: "+err.Error())
			return
		}
		s.logEvent(r, model.EventCategoryNetwork, "network.interface_deleted", model.EventSeverityInfo,
			iface.Name, "VLAN interface "+iface.Name+" deleted")
		s.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
		return
	}

	if iface.Status != "offline" {
		s.writeError(w, http.StatusBadRequest, "Cannot delete active interfaces. Only offline interfaces can be deleted.")
		return
	}

	if err := s.repo.DeleteInterface(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Match the VLAN path: drop any DNS Server binding to this now-deleted interface so it
	// doesn't linger as a dangling "Missing" chip. dhcp-range/QoS refs are left as tolerated
	// dangling rows (the user sees and fixes those on their own pages).
	s.interfaceService.PruneDNSServerBinding(iface.Name)

	s.logEvent(r, model.EventCategoryNetwork, "network.interface_deleted", model.EventSeverityInfo,
		iface.Name, "Offline interface "+iface.Name+" configuration deleted")
	s.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (s *Server) HandleResetInterface(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	iface, err := s.interfaceService.GetDataLayerInterfaceByID(id)
	if err != nil || iface == nil {
		s.writeError(w, http.StatusNotFound, "Interface not found")
		return
	}

	wasOffline := iface.Status == "offline"

	if err := s.interfaceService.FlushInterfaceConfig(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryNetwork, "network.interface_reset", model.EventSeverityWarning,
		iface.Name, "Interface \""+iface.Name+"\" configuration reset to defaults")

	// Refreshed default settings from kernel. For an offline interface there is no kernel
	// link, so flushing the config leaves nothing to return — that's success, not an error.
	refreshed, err := s.interfaceService.GetDataLayerInterfaceByID(id)
	if err != nil || refreshed == nil {
		if wasOffline && err == nil {
			s.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to load refreshed interface default config")
		return
	}

	maskInterfacePasswords(refreshed)
	s.writeJSON(w, http.StatusOK, refreshed)
}

// =========================================================================
// FIREWALL POLICY HANDLERS
// =========================================================================

// defaultPolicyEndpointsLimit/min/maxPolicyEndpointsLimit are the `limit`
// query param bounds for GET /api/policies/{id}/endpoints (plan §3): unlike
// the traffic-stats `limit` params above, an out-of-range or unparseable
// value here is a 400, not a silent clamp (plan T-06).
const (
	defaultPolicyEndpointsLimit = 10
	minPolicyEndpointsLimit     = 1
	maxPolicyEndpointsLimit     = 50
)

func (s *Server) HandleGetPolicies(w http.ResponseWriter, r *http.Request) {
	chain := r.URL.Query().Get("chain")
	switch chain {
	case "", model.PolicyChainForward, model.PolicyChainInput, model.PolicyChainOutput:
	default:
		s.writeError(w, http.StatusBadRequest, "Invalid chain query parameter")
		return
	}

	list, err := s.firewallService.GetPolicies(chain)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, list)
}

// HandleGetPolicyStats serves GET /api/policies/stats — per-rule usage
// statistics (bytes/packets/percent/last-matched) since the last successful
// firewall apply. authRoute (see router.go), not superAdminRoute: the
// payload is only rule id + byte/packet counts, same sensitivity level as
// the existing /api/statistics/* endpoints (docs/ref/todo/
// firewall-policy-rule-usage-stats-plan.md Design decision 5). Read-only, so
// it stays reachable under -disable-edit=true like every other GET route.
func (s *Server) HandleGetPolicyStats(w http.ResponseWriter, r *http.Request) {
	chain := r.URL.Query().Get("chain")
	switch chain {
	case "", model.PolicyChainForward, model.PolicyChainInput, model.PolicyChainOutput:
	default:
		s.writeError(w, http.StatusBadRequest, "Invalid chain query parameter")
		return
	}

	if s.policyStats == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Policy usage statistics are not available")
		return
	}

	stats, err := s.policyStats.GetPolicyRuleStats(chain)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, stats)
}

// HandleGetPolicyRuleEndpoints serves GET /api/policies/{id}/endpoints — the
// top IPs/services observed matching one rule, aggregated live from the
// traffic-log ring buffer (docs/ref/todo/
// firewall-rule-matched-endpoints-plan.md T-06). Same authRoute sensitivity
// as HandleGetPolicyStats/HandleGetTrafficLogs — GET only, so it stays
// reachable under -disable-edit=true. {id} is only ever used as an
// in-memory/DB lookup key here, never concatenated into a query string.
func (s *Server) HandleGetPolicyRuleEndpoints(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	limit := defaultPolicyEndpointsLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < minPolicyEndpointsLimit || n > maxPolicyEndpointsLimit {
			s.writeError(w, http.StatusBadRequest, "Invalid limit query parameter (must be an integer 1-50)")
			return
		}
		limit = n
	}

	if s.policyStats == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Policy usage statistics are not available")
		return
	}

	result, err := s.policyStats.GetRuleEndpoints(id, limit)
	if err != nil {
		if errors.Is(err, service.ErrPolicyRuleNotFound) {
			s.writeError(w, http.StatusNotFound, "Policy rule not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) HandleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var input model.PolicyRuleInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	// Accept both the new list fields (inInterfaces/outInterfaces) and the
	// legacy scalar (inInterface/outInterface); when both are present the
	// list wins (docs/ref/todo/multi-interface-firewall-rule-plan.md §2.5).
	model.NormalizePolicyRuleInputInterfaces(&input)

	id, err := randomID("rule-")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not generate ID")
		return
	}
	rule := model.PolicyRule{
		ID:            id,
		Name:          input.Name,
		Chain:         input.Chain,
		InInterface:   input.InInterface,
		OutInterface:  input.OutInterface,
		InInterfaces:  input.InInterfaces,
		OutInterfaces: input.OutInterfaces,
		Source:        input.Source,
		Destination:   input.Destination,
		Service:       input.Service,
		Action:        input.Action,
		Log:           input.Log,
		Nat:           input.Nat,
		Status:        input.Status,
	}

	if err := s.firewallService.CreatePolicy(rule); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryFirewall, "firewall.policy_created", model.EventSeverityInfo,
		rule.Name, "Firewall policy \""+rule.Name+"\" created")
	s.writeJSON(w, http.StatusOK, rule)
}

func (s *Server) HandleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.firewallService.GetPolicyByID(id)
	if err != nil || existing == nil {
		s.writeError(w, http.StatusNotFound, "Policy rule not found")
		return
	}

	// Body is read into a byte slice (rather than json.NewDecoder(r.Body)
	// directly) so it can be unmarshaled twice: once into the typed
	// PolicyRuleInput, and once into a raw key-presence map. The latter is
	// needed because a PUT that omits inInterfaces/inInterface entirely must
	// keep the rule's existing interfaces (same "don't clear on omission"
	// contract as `chain` above), but an *empty* string/list is a
	// legitimate, distinct value (interpreted as "ALL" by Normalize) — a
	// simple zero-value check on the decoded struct cannot tell "key absent"
	// apart from "key present but empty" the way a raw JSON key-presence
	// check can (docs/ref/todo/multi-interface-firewall-rule-plan.md §2.5).
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	var input model.PolicyRuleInput
	if err := json.Unmarshal(bodyBytes, &input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	var rawFields map[string]json.RawMessage
	// Best-effort: bodyBytes already unmarshaled successfully above as a
	// PolicyRuleInput, so this only fails for pathological inputs (e.g. a
	// bare JSON array/scalar instead of an object) — treat that the same as
	// "no interface keys present" (preserve existing) rather than erroring a
	// request that otherwise decoded fine.
	_ = json.Unmarshal(bodyBytes, &rawFields)

	// Caution 2: an empty/omitted chain in the request body must keep the
	// rule's existing chain, never silently fall back to "forward" — a client
	// (or an old client that predates this field) that PUTs a rule without
	// `chain` must not move an input/output rule into forward.
	chain := input.Chain
	if chain == "" {
		chain = existing.Chain
	}

	// Resolve inInterface(s)/outInterface(s) the same list-wins-over-scalar
	// way HandleCreatePolicy does, but only when the client sent at least
	// one of the two keys for that direction; otherwise carry the existing
	// rule's interfaces forward untouched (PUT must never widen a rule to
	// ALL just because an old client didn't know about this field).
	normalizedInput := input
	model.NormalizePolicyRuleInputInterfaces(&normalizedInput)

	_, hasInList := rawFields["inInterfaces"]
	_, hasInScalar := rawFields["inInterface"]
	inInterface, inInterfaces := existing.InInterface, existing.InInterfaces
	if hasInList || hasInScalar {
		inInterface, inInterfaces = normalizedInput.InInterface, normalizedInput.InInterfaces
	}

	_, hasOutList := rawFields["outInterfaces"]
	_, hasOutScalar := rawFields["outInterface"]
	outInterface, outInterfaces := existing.OutInterface, existing.OutInterfaces
	if hasOutList || hasOutScalar {
		outInterface, outInterfaces = normalizedInput.OutInterface, normalizedInput.OutInterfaces
	}

	rule := model.PolicyRule{
		ID:            id,
		Name:          input.Name,
		Chain:         chain,
		InInterface:   inInterface,
		OutInterface:  outInterface,
		InInterfaces:  inInterfaces,
		OutInterfaces: outInterfaces,
		Source:        input.Source,
		Destination:   input.Destination,
		Service:       input.Service,
		Action:        input.Action,
		Log:           input.Log,
		Nat:           input.Nat,
		Status:        input.Status,
		// The general edit form has no Monitor control (it's a dedicated
		// toggle-monitor endpoint, docs/ref/todo/
		// fqdn-retry-and-monitored-counters-plan.md T-11) — always carry the
		// existing value forward here so a plain edit can never silently
		// turn Monitor off (D-6: "ไม่รีเซ็ตอัตโนมัติทุกกรณี").
		Monitored: existing.Monitored,
	}

	if err := s.firewallService.UpdatePolicy(rule); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryFirewall, "firewall.policy_updated", model.EventSeverityInfo,
		rule.Name, "Firewall policy \""+rule.Name+"\" updated")
	s.writeJSON(w, http.StatusOK, rule)
}

func (s *Server) HandleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	target := id
	if p, _ := s.firewallService.GetPolicyByID(id); p != nil {
		target = p.Name
	}
	if err := s.firewallService.DeletePolicy(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryFirewall, "firewall.policy_deleted", model.EventSeverityInfo,
		target, "Firewall policy \""+target+"\" deleted")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleReorderPolicies(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Chain    string             `json:"chain"`
		Policies []model.PolicyRule `json:"policies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	chain := model.NormalizePolicyChain(body.Chain)
	ids := make([]string, 0, len(body.Policies))
	for _, p := range body.Policies {
		ids = append(ids, p.ID)
	}

	if err := s.firewallService.ReorderPolicies(chain, ids); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryFirewall, "firewall.policy_reordered", model.EventSeverityInfo,
		"policies", fmt.Sprintf("Firewall policies reordered (%d rule(s))", len(body.Policies)))
	s.writeJSON(w, http.StatusOK, body.Policies)
}

func (s *Server) HandleTogglePolicyLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.firewallService.TogglePolicyLog(id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	state := "disabled"
	if p.Log {
		state = "enabled"
	}
	s.logEvent(r, model.EventCategoryFirewall, "firewall.policy_log_toggled", model.EventSeverityInfo,
		p.Name, "Logging on firewall policy \""+p.Name+"\" "+state)
	s.writeJSON(w, http.StatusOK, p)
}

func (s *Server) HandleTogglePolicyStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.firewallService.TogglePolicyStatus(id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	state := "disabled"
	if p.Status {
		state = "enabled"
	}
	s.logEvent(r, model.EventCategoryFirewall, "firewall.policy_toggled", model.EventSeverityInfo,
		p.Name, "Firewall policy \""+p.Name+"\" "+state)
	s.writeJSON(w, http.StatusOK, p)
}

// HandleTogglePolicyMonitor serves POST /api/policies/{id}/toggle-monitor —
// flips the persisted "Monitor" opt-in on a rule (docs/ref/todo/
// fqdn-retry-and-monitored-counters-plan.md D-6/T-11, issue #141). Same
// authRoute sensitivity as toggle-log/toggle-status (a POST, so it's already
// blocked for read-only roles/-disable-edit by RoleReadOnlyMiddleware).
func (s *Server) HandleTogglePolicyMonitor(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.firewallService.GetPolicyByID(id)
	if err != nil || p == nil {
		s.writeError(w, http.StatusNotFound, "Policy rule not found")
		return
	}
	if s.policyCounterStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Monitor counters are not available")
		return
	}

	newState := !p.Monitored
	if err := s.policyCounterStore.SetMonitored(id, newState); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	updated, err := s.firewallService.GetPolicyByID(id)
	if err != nil || updated == nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to reload policy after toggling monitor")
		return
	}

	state := "disabled"
	if updated.Monitored {
		state = "enabled"
	}
	s.logEvent(r, model.EventCategoryFirewall, "firewall.policy_monitor_toggled", model.EventSeverityInfo,
		updated.Name, "Monitor on firewall policy \""+updated.Name+"\" "+state)
	s.writeJSON(w, http.StatusOK, updated)
}

// HandleResetPolicyMonitorCounter serves POST /api/policies/{id}/monitor/reset
// — zeroes a rule's persisted Monitor counter and refreshes its "started at"
// (docs/ref/todo/fqdn-retry-and-monitored-counters-plan.md D-6/T-11, issue
// #141). The frontend is responsible for a confirm dialog before calling
// this — the backend does not require re-confirmation.
func (s *Server) HandleResetPolicyMonitorCounter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.firewallService.GetPolicyByID(id)
	if err != nil || p == nil {
		s.writeError(w, http.StatusNotFound, "Policy rule not found")
		return
	}
	if s.policyCounterStore == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Monitor counters are not available")
		return
	}
	if !p.Monitored {
		s.writeError(w, http.StatusBadRequest, "Policy rule is not monitored")
		return
	}

	if err := s.policyCounterStore.ResetRule(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryFirewall, "firewall.policy_monitor_reset", model.EventSeverityInfo,
		p.Name, "Monitor counter on firewall policy \""+p.Name+"\" reset")
	s.writeJSON(w, http.StatusOK, map[string]bool{"reset": true})
}

func (s *Server) syncFirewallRules() error {
	return s.firewallService.SyncFirewallRules()
}

// =========================================================================
// Port Forwarding (DNAT) Handlers
// =========================================================================

func (s *Server) HandleGetPortForwards(w http.ResponseWriter, r *http.Request) {
	list, err := s.firewallService.GetPortForwards()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, list)
}

func (s *Server) HandleCreatePortForward(w http.ResponseWriter, r *http.Request) {
	var input model.PortForwardInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	id, err := randomID("pf-")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not generate ID")
		return
	}
	pf := model.PortForward{
		ID:           id,
		Name:         input.Name,
		InInterface:  input.InInterface,
		ExternalPort: input.ExternalPort,
		Protocol:     input.Protocol,
		InternalIP:   input.InternalIP,
		InternalPort: input.InternalPort,
		Status:       input.Status,
	}

	if err := s.firewallService.CreatePortForward(pf); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryFirewall, "firewall.port_forward_created", model.EventSeverityInfo,
		pf.Name, "Port forward \""+pf.Name+"\" created")
	s.writeJSON(w, http.StatusOK, pf)
}

func (s *Server) HandleUpdatePortForward(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.firewallService.GetPortForwardByID(id)
	if err != nil || existing == nil {
		s.writeError(w, http.StatusNotFound, "Port forward not found")
		return
	}

	var input model.PortForwardInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	pf := model.PortForward{
		ID:           id,
		Name:         input.Name,
		InInterface:  input.InInterface,
		ExternalPort: input.ExternalPort,
		Protocol:     input.Protocol,
		InternalIP:   input.InternalIP,
		InternalPort: input.InternalPort,
		Status:       input.Status,
	}

	if err := s.firewallService.UpdatePortForward(pf); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryFirewall, "firewall.port_forward_updated", model.EventSeverityInfo,
		pf.Name, "Port forward \""+pf.Name+"\" updated")
	s.writeJSON(w, http.StatusOK, pf)
}

func (s *Server) HandleDeletePortForward(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	target := id
	if pf, _ := s.firewallService.GetPortForwardByID(id); pf != nil {
		target = pf.Name
	}
	if err := s.firewallService.DeletePortForward(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryFirewall, "firewall.port_forward_deleted", model.EventSeverityInfo,
		target, "Port forward \""+target+"\" deleted")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleApplyPolicies(w http.ResponseWriter, r *http.Request) {
	if err := s.syncFirewallRules(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "OS Firewall update failed: "+err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryFirewall, "firewall.applied", model.EventSeverityInfo,
		"nftables", "Firewall policies applied to kernel")
	s.writeJSON(w, http.StatusOK, true)
}

// =========================================================================
// ADDRESS OBJECTS HANDLERS
// =========================================================================

func (s *Server) HandleGetAddresses(w http.ResponseWriter, r *http.Request) {
	list, err := s.firewallService.GetAddresses()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, list)
}

func (s *Server) HandleCreateAddress(w http.ResponseWriter, r *http.Request) {
	var input model.AddressObjectInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	model.NormalizeAddressObjectInput(&input)
	if len(input.Entries) == 0 {
		s.writeError(w, http.StatusBadRequest, "At least one entry (or legacy type/value) is required")
		return
	}

	id, err := randomID("addr-")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not generate ID")
		return
	}
	addr := model.AddressObject{
		ID:          id,
		Name:        input.Name,
		Type:        input.Type,
		Value:       input.Value,
		System:      false,
		RefPolicies: []string{},
		Entries:     input.Entries,
	}

	if err := s.firewallService.CreateAddress(addr); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	model.NormalizeAddressObject(&addr)
	s.logEvent(r, model.EventCategoryFirewall, "firewall.address_created", model.EventSeverityInfo,
		addr.Name, fmt.Sprintf("Address object \"%s\" created (%d entries)", addr.Name, len(addr.Entries)))
	s.writeJSON(w, http.StatusOK, addr)
}

func (s *Server) HandleUpdateAddress(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.firewallService.GetAddressByID(id)
	if err != nil || existing == nil {
		s.writeError(w, http.StatusNotFound, "Address object not found")
		return
	}

	var input model.AddressObjectInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	model.NormalizeAddressObjectInput(&input)
	if len(input.Entries) == 0 {
		s.writeError(w, http.StatusBadRequest, "At least one entry (or legacy type/value) is required")
		return
	}

	addr := model.AddressObject{
		ID:      id,
		Name:    input.Name,
		Type:    input.Type,
		Value:   input.Value,
		System:  false,
		Entries: input.Entries,
	}

	if err := s.firewallService.UpdateAddress(addr); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	model.NormalizeAddressObject(&addr)
	s.logEvent(r, model.EventCategoryFirewall, "firewall.address_updated", model.EventSeverityInfo,
		addr.Name, fmt.Sprintf("Address object \"%s\" updated (%d entries)", addr.Name, len(addr.Entries)))
	s.writeJSON(w, http.StatusOK, addr)
}

func (s *Server) HandleDeleteAddress(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.firewallService.DeleteAddress(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryFirewall, "firewall.address_deleted", model.EventSeverityWarning,
		id, "Address object "+id+" deleted")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleBulkDeleteAddresses(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	deleted, err := s.firewallService.BulkDeleteAddresses(body.IDs)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryFirewall, "firewall.address_deleted", model.EventSeverityWarning,
		"bulk", fmt.Sprintf("Bulk-deleted %d address object(s)", deleted))
	s.writeJSON(w, http.StatusOK, true)
}

// =========================================================================
// SERVICE OBJECTS HANDLERS
// =========================================================================

func (s *Server) HandleGetServices(w http.ResponseWriter, r *http.Request) {
	list, err := s.firewallService.GetServices()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, list)
}

func (s *Server) HandleCreateService(w http.ResponseWriter, r *http.Request) {
	var input model.ServiceObjectInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	model.NormalizeServiceObjectInput(&input)
	if len(input.Entries) == 0 {
		s.writeError(w, http.StatusBadRequest, "At least one entry (or legacy protocol/port) is required")
		return
	}

	id, err := randomID("svc-")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not generate ID")
		return
	}
	svc := model.ServiceObject{
		ID:          id,
		Name:        input.Name,
		Protocol:    input.Protocol,
		Port:        input.Port,
		Type:        "custom",
		RefPolicies: []string{},
		Entries:     input.Entries,
	}

	if err := s.firewallService.CreateService(svc); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	model.NormalizeServiceObject(&svc)
	s.logEvent(r, model.EventCategoryFirewall, "firewall.service_created", model.EventSeverityInfo,
		svc.Name, fmt.Sprintf("Service object \"%s\" created (%d entries)", svc.Name, len(svc.Entries)))
	s.writeJSON(w, http.StatusOK, svc)
}

func (s *Server) HandleUpdateService(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.firewallService.GetServiceByID(id)
	if err != nil || existing == nil {
		s.writeError(w, http.StatusNotFound, "Service object not found")
		return
	}

	var input model.ServiceObjectInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	model.NormalizeServiceObjectInput(&input)
	if len(input.Entries) == 0 {
		s.writeError(w, http.StatusBadRequest, "At least one entry (or legacy protocol/port) is required")
		return
	}

	svc := model.ServiceObject{
		ID:       id,
		Name:     input.Name,
		Protocol: input.Protocol,
		Port:     input.Port,
		Type:     "custom",
		Entries:  input.Entries,
	}

	if err := s.firewallService.UpdateService(svc); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	model.NormalizeServiceObject(&svc)
	s.logEvent(r, model.EventCategoryFirewall, "firewall.service_updated", model.EventSeverityInfo,
		svc.Name, fmt.Sprintf("Service object \"%s\" updated (%d entries)", svc.Name, len(svc.Entries)))
	s.writeJSON(w, http.StatusOK, svc)
}

func (s *Server) HandleDeleteService(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.firewallService.DeleteService(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryFirewall, "firewall.service_deleted", model.EventSeverityWarning,
		id, "Service object "+id+" deleted")
	s.writeJSON(w, http.StatusOK, true)
}

// =========================================================================
// STATIC ROUTES HANDLERS
// =========================================================================

func (s *Server) HandleGetRoutes(w http.ResponseWriter, r *http.Request) {
	list, err := s.routingService.GetRouting()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, list)
}

func (s *Server) HandleCreateRoute(w http.ResponseWriter, r *http.Request) {
	var input model.StaticRouteInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	id, err := randomID("route-")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not generate ID")
		return
	}
	route := model.StaticRoute{
		ID:          id,
		Destination: input.Destination,
		Gateway:     input.Gateway,
		Interface:   input.Interface,
		Metric:      input.Metric,
		Description: input.Description,
		Status:      input.Status,
		Type:        "custom",
		Scope:       input.Scope,
		Src:         input.Src,
		Proto:       input.Proto,
	}

	if err := s.routingService.ApplyConfigRoute(route); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryRoute, "route.created", model.EventSeverityInfo,
		route.Destination, "Static route to "+route.Destination+" created")
	s.writeJSON(w, http.StatusOK, route)
}

func (s *Server) HandleUpdateRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var existing *model.StaticRoute
	var err error

	if s.routingService.IsEnableEditSystemRoute() && strings.HasPrefix(id, "route-sys-") {
		routes, getErr := s.routingService.GetRouting()
		if getErr == nil {
			for _, r := range routes {
				if r.ID == id {
					existing = &r
					break
				}
			}
		}
	} else {
		existing, err = s.repo.GetRouteByID(id)
	}

	if err != nil || existing == nil {
		s.writeError(w, http.StatusNotFound, "Route not found")
		return
	}

	var input model.StaticRouteInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	routeType := "custom"
	if s.routingService.IsEnableEditSystemRoute() && strings.HasPrefix(id, "route-sys-") {
		routeType = existing.Type
	}

	route := model.StaticRoute{
		ID:          id,
		Destination: input.Destination,
		Gateway:     input.Gateway,
		Interface:   input.Interface,
		Metric:      input.Metric,
		Description: input.Description,
		Status:      input.Status,
		Type:        routeType,
		Scope:       input.Scope,
		Src:         input.Src,
		Proto:       input.Proto,
	}

	if err := s.routingService.ApplyConfigRoute(route); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryRoute, "route.updated", model.EventSeverityInfo,
		route.Destination, "Static route to "+route.Destination+" updated")
	s.writeJSON(w, http.StatusOK, route)
}

func (s *Server) HandleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	target := id
	if rt, _ := s.repo.GetRouteByID(id); rt != nil {
		target = rt.Destination
	}
	if err := s.routingService.RemoveConfigRoute(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryRoute, "route.deleted", model.EventSeverityInfo,
		target, "Static route to "+target+" deleted")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleBulkDeleteRoutes(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	removed, err := s.routingService.BulkRemoveConfigRoutes(body.IDs)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryRoute, "route.deleted", model.EventSeverityInfo,
		"bulk", fmt.Sprintf("Bulk-deleted %d static route(s)", removed))
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleToggleRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.routingService.ToggleConfigRoute(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryRoute, "route.toggled", model.EventSeverityInfo,
		id, "Static route "+id+" toggled")

	var route *model.StaticRoute
	if s.routingService.IsEnableEditSystemRoute() && strings.HasPrefix(id, "route-sys-") {
		routes, err := s.routingService.GetRouting()
		if err == nil {
			for _, r := range routes {
				if r.ID == id {
					route = &r
					break
				}
			}
		}
	} else {
		route, _ = s.repo.GetRouteByID(id)
	}
	s.writeJSON(w, http.StatusOK, route)
}

func (s *Server) HandleApplyRoutes(w http.ResponseWriter, r *http.Request) {
	if err := s.routingService.InitApplyConfig(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "OS routing configuration update failed: "+err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryRoute, "route.applied", model.EventSeverityInfo,
		"routing", "Static routes applied to kernel")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleGetRoutesConfig(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"allowEditSystemRoutes":  s.repo.GetAllowEditSystemRoutes(),
		"prioritizeKernelRoutes": s.repo.GetPrioritizeKernelRoutes(),
		"enableEditSystemRoute":  s.routingService.IsEnableEditSystemRoute(),
	})
}

// =========================================================================
// DHCP SERVER HANDLERS
// =========================================================================

func (s *Server) HandleGetDHCPConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.repo.GetDHCPConfig()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) HandleUpdateDHCPConfig(w http.ResponseWriter, r *http.Request) {
	var cfg model.DhcpConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if err := model.ValidateDhcpConfig(cfg); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.repo.UpdateDHCPConfig(cfg); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDhcp, "dhcp.config_changed", model.EventSeverityInfo,
		cfg.Interface, "DHCP server config for "+cfg.Interface+" updated")
	s.writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) HandleGetDHCPReservations(w http.ResponseWriter, r *http.Request) {
	list, err := s.repo.GetDHCPReservations()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, list)
}

func (s *Server) HandleCreateDHCPReservation(w http.ResponseWriter, r *http.Request) {
	var input model.DhcpReservationInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	id, err := randomID("res-")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not generate ID")
		return
	}
	res := model.DhcpReservation{
		ID:         id,
		DeviceName: input.DeviceName,
		MacAddress: input.MacAddress,
		IPAddress:  input.IPAddress,
	}

	if err := model.ValidateReservation(res); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.repo.CreateDHCPReservation(res); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDhcp, "dhcp.reservation_created", model.EventSeverityInfo,
		res.DeviceName, "DHCP reservation for \""+res.DeviceName+"\" ("+res.MacAddress+" → "+res.IPAddress+") created")
	s.writeJSON(w, http.StatusOK, res)
}

func (s *Server) HandleUpdateDHCPReservation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.repo.GetDHCPReservationByID(id)
	if err != nil || existing == nil {
		s.writeError(w, http.StatusNotFound, "DHCP Reservation not found")
		return
	}

	var input model.DhcpReservationInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	res := model.DhcpReservation{
		ID:         id,
		DeviceName: input.DeviceName,
		MacAddress: input.MacAddress,
		IPAddress:  input.IPAddress,
	}

	if err := model.ValidateReservation(res); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.repo.UpdateDHCPReservation(res); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDhcp, "dhcp.reservation_updated", model.EventSeverityInfo,
		res.DeviceName, "DHCP reservation for \""+res.DeviceName+"\" updated")
	s.writeJSON(w, http.StatusOK, res)
}

func (s *Server) HandleDeleteDHCPReservation(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.repo.DeleteDHCPReservation(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDhcp, "dhcp.reservation_deleted", model.EventSeverityWarning,
		id, "DHCP reservation "+id+" deleted")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleGetDHCPLeases(w http.ResponseWriter, r *http.Request) {
	leases, err := s.repo.GetDHCPLeases()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Fallback to active leases from system/kernel if DB is empty
	if len(leases) == 0 {
		leases, err = s.dhcp.GetActiveLeases()
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if leases == nil {
		leases = []model.ActiveDhcpLease{}
	}
	s.writeJSON(w, http.StatusOK, leases)
}

func (s *Server) HandleApplyDHCP(w http.ResponseWriter, r *http.Request) {
	if err := s.dhcpServerService.ApplyAll(); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.firewallService.SyncFirewallRules(); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDhcp, "dhcp.applied", model.EventSeverityInfo,
		"dnsmasq", "DHCP server configuration applied")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleGetDHCPConfigs(w http.ResponseWriter, r *http.Request) {
	cfgs, err := s.repo.GetDHCPConfigs()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfgs == nil {
		cfgs = []model.DhcpConfig{}
	}
	s.writeJSON(w, http.StatusOK, cfgs)
}

func (s *Server) HandleCreateDHCPConfig(w http.ResponseWriter, r *http.Request) {
	var cfg model.DhcpConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if err := model.ValidateDhcpConfig(cfg); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.repo.CreateDHCPConfig(cfg); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDhcp, "dhcp.config_created", model.EventSeverityInfo,
		cfg.Interface, "DHCP scope on "+cfg.Interface+" created")
	s.writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) HandleUpdateDHCPConfigByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var cfg model.DhcpConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	cfg.ID = id

	if err := model.ValidateDhcpConfig(cfg); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.repo.UpdateDHCPConfigByID(cfg); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDhcp, "dhcp.config_updated", model.EventSeverityInfo,
		cfg.Interface, "DHCP scope on "+cfg.Interface+" updated")
	s.writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) HandleDeleteDHCPConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.repo.DeleteDHCPConfig(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDhcp, "dhcp.config_deleted", model.EventSeverityWarning,
		id, "DHCP scope "+id+" deleted")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleToggleDHCPConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// If this toggle would ENABLE the scope, validate it first. Create/update
	// reject invalid scopes, but a malformed legacy row (saved before this
	// validator existed) could otherwise be flipped live here only to be silently
	// skipped at apply time — reporting "active" in the UI while the LAN gets no
	// DHCP. Fail with 400 instead so the reason is visible.
	cfgs, err := s.repo.GetDHCPConfigs()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, c := range cfgs {
		if c.ID == id {
			if !c.Enabled { // currently disabled → about to be enabled
				if err := model.ValidateDhcpConfig(c); err != nil {
					s.writeError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
			break
		}
	}

	if err := s.repo.ToggleDHCPConfig(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDhcp, "dhcp.config_toggled", model.EventSeverityInfo,
		id, "DHCP scope "+id+" toggled")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleGetAvailableInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := s.repo.GetInterfaces()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	cfgs, err := s.repo.GetDHCPConfigs()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	configured := make(map[string]bool)
	for _, c := range cfgs {
		configured[c.Interface] = true
	}

	available := []string{}
	for _, iface := range ifaces {
		if iface.Role == "LAN" && !configured[iface.Name] {
			available = append(available, iface.Name)
		}
	}

	s.writeJSON(w, http.StatusOK, available)
}

// =========================================================================
// SYSTEM SETTINGS & MAINTENANCE HANDLERS
// =========================================================================

func (s *Server) HandleGetSystemTime(w http.ResponseWriter, r *http.Request) {
	settings, err := s.timeService.Get()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, settings)
}

func (s *Server) HandleUpdateSystemTime(w http.ResponseWriter, r *http.Request) {
	var settings model.SystemTimeSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Validation errors are the user's fault (400); anything else is a
	// kernel/D-Bus failure (500).
	if err := service.ValidateTimezone(settings.Timezone); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := service.ValidateNTPServer(settings.NTPServer); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.timeService.Update(settings); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.logEvent(r, model.EventCategorySystem, "system.time_changed", model.EventSeverityInfo,
		settings.Timezone, "System time settings updated (timezone "+settings.Timezone+")")

	// Return the fresh state (config + live status) so the UI can refresh.
	updated, err := s.timeService.Get()
	if err != nil {
		s.writeJSON(w, http.StatusOK, settings)
		return
	}
	s.writeJSON(w, http.StatusOK, updated)
}

func (s *Server) HandleSetManualTime(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Datetime string `json:"datetime"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Distinguish validation/state errors (400) from kernel failures (500).
	if _, err := service.ValidateManualTime(body.Datetime); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.timeService.SetManualTime(body.Datetime); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logEvent(r, model.EventCategorySystem, "system.time_changed", model.EventSeverityInfo,
		"clock", "System clock set manually")

	settings, err := s.timeService.Get()
	if err != nil {
		s.writeJSON(w, http.StatusOK, map[string]string{"message": "ตั้งเวลาสำเร็จ"})
		return
	}
	s.writeJSON(w, http.StatusOK, settings)
}

func (s *Server) HandleGetHostname(w http.ResponseWriter, r *http.Request) {
	settings, err := s.hostnameService.Get()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, settings)
}

func (s *Server) HandleUpdateHostname(w http.ResponseWriter, r *http.Request) {
	var settings model.SystemHostnameSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if err := service.ValidateHostname(settings.Hostname); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.hostnameService.Update(settings); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategorySystem, "system.hostname_changed", model.EventSeverityInfo,
		settings.Hostname, "Hostname changed to "+settings.Hostname)
	s.writeJSON(w, http.StatusOK, settings)
}

// HandleGetDhcpHealthSettings returns the current DHCP health-checker settings
// (issue #78: 169.254.x.x link-local fallback self-heal).
func (s *Server) HandleGetDhcpHealthSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.dhcpHealthChecker.GetSettings()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, settings)
}

// HandleUpdateDhcpHealthSettings updates the DHCP health-checker settings.
// Range validation happens inside DhcpHealthChecker.UpdateSettings, not here.
func (s *Server) HandleUpdateDhcpHealthSettings(w http.ResponseWriter, r *http.Request) {
	var settings model.DhcpHealthSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if err := s.dhcpHealthChecker.UpdateSettings(settings); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	saved, err := s.dhcpHealthChecker.GetSettings()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryDhcp, "dhcp.health_settings_changed", model.EventSeverityInfo,
		"system", "DHCP health-checker settings updated")
	s.writeJSON(w, http.StatusOK, saved)
}

func (s *Server) HandleGetDNSConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.dnsService.GetDNSConfig()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) HandleUpdateDNSConfig(w http.ResponseWriter, r *http.Request) {
	var input model.DNSConfigInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if input.LocalDomain == "" {
		input.LocalDomain = "pigate.local"
	}

	// 🔒 T-09: primaryDns/secondaryDns/localDomain are interpolated verbatim
	// into /etc/systemd/resolved.conf.d/pigate.conf (DNS=/Domains=) — validate
	// after the default LocalDomain substitution above, before any write.
	if err := model.ValidateDNSConfigInput(input.Mode, input.PrimaryDNS, input.SecondaryDNS, input.LocalDomain); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.dnsService.UpdateDNSConfig(input); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// System DNS affects systemd-resolved ONLY, for this device itself. It no
	// longer writes to or restarts the local DNS server (dnsmasq) — the DNS
	// Server has its own upstream resolver setting (upstreamMode, see
	// DNSServerSettings) configured on the DNS Server page → Settings tab.
	// pigate-dns.conf is only (re)generated by the DNS Server's own paths:
	// POST /api/dns/apply, PUT /api/dns/settings, boot, and restore. In
	// upstreamMode "system" the new System DNS value takes effect the next
	// time one of those paths runs (docs/ref/todo/
	// dns-server-settings-tab-and-upstream-plan.md T-06) — DO NOT re-add a
	// call to s.dnsServerService.ApplyAll() here; there is a test asserting
	// this handler never bumps MockDNSServerManager.ApplyCount.

	s.logEvent(r, model.EventCategoryDns, "dns.config_changed", model.EventSeverityInfo,
		"system-dns", "System DNS settings updated (mode "+input.Mode+")")
	s.writeJSON(w, http.StatusOK, input)
}

func (s *Server) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req model.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Enforce the shared password policy server-side. The frontend already checks
	// length, but an API caller could bypass the UI, so re-validate here using the
	// same rule as user creation/reset (single source of truth in the service).
	if err := service.ValidatePassword(req.NewPassword); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Resolve the authenticated user from context (set by AuthMiddleware) so a
	// user only ever changes their own password — never a hardcoded account.
	username, _ := r.Context().Value(UserContextKey).(string)
	if username == "" {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user, err := s.repo.GetUserByUsername(username)
	if err != nil || user == nil {
		s.writeError(w, http.StatusInternalServerError, "User context resolution failed")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "รหัสผ่านปัจจุบันไม่ถูกต้อง")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 10)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Crypto generation failed")
		return
	}

	if err := s.repo.ChangePassword(username, string(newHash)); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryAuth, "auth.password_changed", model.EventSeverityInfo,
		username, "User "+username+" changed their password")
	w.WriteHeader(http.StatusOK)
}

// =========================================================================
// USER MANAGEMENT HANDLERS (super_admin only — see router superAdminRoute)
// =========================================================================

// writeUserServiceError maps a UserService error to an HTTP status: a missing
// target is 404, everything else (validation + guard rails) is 400 with the
// service's Thai message surfaced to the UI.
func (s *Server) writeUserServiceError(w http.ResponseWriter, err error) {
	if err == service.ErrUserNotFound {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.writeError(w, http.StatusBadRequest, err.Error())
}

func (s *Server) HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.userService.List()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, users)
}

func (s *Server) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req model.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	user, err := s.userService.Create(req)
	if err != nil {
		s.writeUserServiceError(w, err)
		return
	}
	s.logEvent(r, model.EventCategoryUser, "user.created", model.EventSeverityInfo,
		user.Username, "User "+user.Username+" created (role "+user.Role+")")
	s.writeJSON(w, http.StatusCreated, user)
}

func (s *Server) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req model.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	actor, _ := r.Context().Value(UserContextKey).(string)
	if err := s.userService.Update(actor, id, req); err != nil {
		s.writeUserServiceError(w, err)
		return
	}
	target := id
	if u, _ := s.repo.GetUserByID(id); u != nil {
		target = u.Username
	}
	s.logEvent(r, model.EventCategoryUser, "user.updated", model.EventSeverityInfo,
		target, "User "+target+" updated")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor, _ := r.Context().Value(UserContextKey).(string)

	// Capture the username before deletion so we can purge lingering sessions.
	target, _ := s.repo.GetUserByID(id)

	if err := s.userService.Delete(actor, id); err != nil {
		s.writeUserServiceError(w, err)
		return
	}
	targetName := id
	if target != nil {
		RemoveSessionsForUser(target.Username)
		targetName = target.Username
	}
	s.logEvent(r, model.EventCategoryUser, "user.deleted", model.EventSeverityWarning,
		targetName, "User "+targetName+" deleted")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) HandleToggleUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor, _ := r.Context().Value(UserContextKey).(string)
	if err := s.userService.Toggle(actor, id); err != nil {
		s.writeUserServiceError(w, err)
		return
	}
	// If the account is now disabled, purge its sessions immediately.
	if u, _ := s.repo.GetUserByID(id); u != nil {
		if u.Status == model.StatusDisabled {
			RemoveSessionsForUser(u.Username)
		}
		s.logEvent(r, model.EventCategoryUser, "user.toggled", model.EventSeverityInfo,
			u.Username, "User "+u.Username+" status changed to "+u.Status)
	}
	w.WriteHeader(http.StatusOK)
}

// HandleGetSystemServices returns the live status of every systemd unit in
// SystemServiceService's catalog (static singletons + per-interface dynamic
// entries), read fresh from D-Bus on every call — nothing here is persisted.
// A read failure (e.g. D-Bus unreachable) is surfaced as 500, never silently
// downgraded to a fake status, so an admin isn't misled about what's running.
func (s *Server) HandleGetSystemServices(w http.ResponseWriter, r *http.Request) {
	list, err := s.systemServiceSvc.List()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to read system service status: "+err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, list)
}

// HandleRestartService restarts one systemd unit selected by {id}, a
// client-facing slug that SystemServiceService.RestartByID resolves through
// its server-side catalog whitelist — {id} is NEVER used as a raw systemd
// unit name (unit-name-injection guard, see the plan doc's Caution 1).
func (s *Server) HandleRestartService(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.systemServiceSvc.RestartByID(id); err != nil {
		switch {
		case errors.Is(err, service.ErrSystemServiceNotFound):
			s.writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, service.ErrSystemServiceRestartForbidden):
			s.writeError(w, http.StatusForbidden, err.Error())
		default:
			s.writeError(w, http.StatusInternalServerError, "Failed to restart service: "+err.Error())
		}
		return
	}
	s.logEvent(r, model.EventCategorySystem, "service.restarted", model.EventSeverityWarning,
		id, "Service "+id+" restarted")
	w.WriteHeader(http.StatusOK)
}

// HandleReboot restarts the physical host. super_admin only (see router). The
// service delays the actual login1 D-Bus call ~1s so this 200 reaches the
// browser before logind stops pigate.service.
//
// The event MUST be flushed synchronously before powerService fires: once
// logind starts stopping pigate.service, anything still queued in the batch
// writer is lost — the exact failure mode of the old RAM-only logPowerEvent.
func (s *Server) HandleReboot(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(UserContextKey).(string)
	s.logPowerEvent(r, "system.reboot", "Reboot", username)
	if err := s.powerService.Reboot(username); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to reboot: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

// HandleShutdown powers off the physical host. super_admin only (see router).
// Same log-then-flush-then-power ordering as HandleReboot.
func (s *Server) HandleShutdown(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(UserContextKey).(string)
	s.logPowerEvent(r, "system.shutdown", "Shutdown", username)
	if err := s.powerService.Shutdown(username); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to shutdown: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

// logPowerEvent persists a power action (critical severity) and flushes it to
// SQLite before returning, so it survives the imminent process shutdown.
func (s *Server) logPowerEvent(r *http.Request, action, verb, username string) {
	if s.eventLog == nil {
		return
	}
	if username == "" {
		username = "unknown"
	}
	s.logEvent(r, model.EventCategorySystem, action, model.EventSeverityCritical,
		"host", verb+" requested by "+username)
	if err := s.eventLog.Flush(); err != nil {
		log.Printf("[Power] Failed to flush event log before power action: %v", err)
	}
}

// HandleExportConfig streams a full, typed configuration backup (schema v2).
// Restricted to super_admin (see router) because the payload contains real
// Wi-Fi passwords and, optionally, user credential hashes. Pass ?includeUsers=1
// to embed the users table.
func (s *Server) HandleExportConfig(w http.ResponseWriter, r *http.Request) {
	includeUsers := r.URL.Query().Get("includeUsers") == "1" || r.URL.Query().Get("includeUsers") == "true"
	// Optional passphrase encrypts the config; sent via header (not query) to
	// keep it out of access logs.
	passphrase := r.Header.Get("X-Backup-Passphrase")
	// includeBlocklistFiles opts into carrying subscribe-URL blocklists' .hosts
	// content too (upload-sourced lists are always carried — they cannot be
	// re-fetched). Default off: plan §2.4 (docs/ref/todo/
	// dns-blocklist-import-plan.md) — a URL-sourced list can be recovered with
	// Refresh, so most exports should stay small.
	includeBlocklistFiles := r.URL.Query().Get("includeBlocklistFiles") == "1" || r.URL.Query().Get("includeBlocklistFiles") == "true"

	backup, err := s.backupService.Export(includeUsers, passphrase, includeBlocklistFiles)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to export configuration: "+err.Error())
		return
	}

	// Content-Disposition helps direct endpoint calls; the SPA builds its own
	// filename (§3.1) since it downloads via fetch+Blob.
	filename := fmt.Sprintf("pigate-backup-%s-%s.json",
		sanitizeFilenamePart(backup.Meta.Hostname),
		time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	s.logEvent(r, model.EventCategoryConfig, "config.exported", model.EventSeverityWarning,
		filename, "Configuration exported")
	s.writeJSON(w, http.StatusOK, backup)
}

// HandleImportConfig validates, snapshots, restores (single transaction), and
// re-applies a configuration backup. Restricted to super_admin and blocked in
// -disable-edit mode by DisableEditMiddleware. Returns an ImportResult with
// counts + non-fatal warnings on success, or a 4xx/5xx with the reason (and no
// DB changes) on failure.
func (s *Server) HandleImportConfig(w http.ResponseWriter, r *http.Request) {
	// Cap the request body at 10 MB — a backup is small; anything larger is
	// abuse or corruption.
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body (max 10 MB): "+err.Error())
		return
	}

	actor, _ := r.Context().Value(UserContextKey).(string)
	var actorID string
	if u, _ := s.repo.GetUserByUsername(actor); u != nil {
		actorID = u.ID
	}

	// includeUsers is driven by whether the file carries users AND the caller
	// opted in via query flag; default is to ignore users in the file.
	includeUsers := r.URL.Query().Get("includeUsers") == "1" || r.URL.Query().Get("includeUsers") == "true"

	result, err := s.backupService.Import(raw, model.ImportOptions{
		IncludeUsers:  includeUsers,
		ActorUserID:   actorID,
		ActorUsername: actor,
		Passphrase:    r.Header.Get("X-Backup-Passphrase"),
	})
	if err != nil {
		// An encrypted backup without a passphrase gets a specific signal so the
		// UI can prompt for one instead of showing a generic failure.
		if errors.Is(err, service.ErrPassphraseRequired) {
			s.writeJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{
				"message":        err.Error(),
				"needPassphrase": true,
			})
			return
		}
		s.writeError(w, http.StatusBadRequest, "Import failed: "+err.Error())
		return
	}

	// Purge sessions of users removed/disabled by the import so they can't keep
	// acting with a stale token.
	for _, uname := range result.RemovedUsernames {
		RemoveSessionsForUser(uname)
	}

	s.logEvent(r, model.EventCategoryConfig, "config.imported", model.EventSeverityWarning,
		"database", "Configuration imported and re-applied")
	s.writeJSON(w, http.StatusOK, result)
}

// sanitizeFilenamePart keeps a hostname safe for use inside a download filename.
func sanitizeFilenamePart(s string) string {
	if s == "" {
		return "pigate"
	}
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// =========================================================================
// LOG SSE STREAMING HANDLER
// =========================================================================

func (s *Server) HandleLogStream(w http.ResponseWriter, r *http.Request) {
	// Set SSE HTTP Headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// CORS for the credentialed EventSource is handled by CORSMiddleware (which
	// echoes a specific Origin + Allow-Credentials). A wildcard ACAO here would
	// make the browser reject the withCredentials stream — see the plan Caution 3.

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// Clear the per-connection write deadline for this stream only. The server's
	// global WriteTimeout (60s) would otherwise kill this long-lived SSE response
	// every ~60s (masked by EventSource auto-reconnect). A zero deadline disables
	// it for this connection while every normal endpoint keeps the 60s cap.
	// Ignore the error: on a ResponseWriter that doesn't support it (e.g. tests),
	// the stream just keeps the old 60s behavior — no worse than before.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	// Read the session token at connect time so the heartbeat can re-check that
	// the session is still alive without touching request state. The route is
	// already behind AuthMiddleware, so a token is present here; a stream that
	// outlives its session (logout / revoke / idle timeout) is torn down below.
	var token string
	if c, err := r.Cookie(SessionKey); err == nil {
		token = c.Value
	}

	// Subscribe to the ring buffer for real push. A small buffer absorbs short
	// bursts; if this client stalls, the producer drops events (non-blocking, see
	// RingBuffer.notifyLocked) and the client re-syncs from its next snapshot
	// fetch — the NFLOG watcher loop is never stalled by a slow browser.
	events, cancel := s.logs.Subscribe(64)
	defer cancel()

	// Heartbeat: a comment line keeps intermediaries from idle-closing the stream
	// and lets us notice a dead peer; it also drives the periodic session re-check.
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()

	// Initial message
	_, _ = w.Write([]byte("event: connected\ndata: connection established\n\n"))
	flusher.Flush()

	clientDone := r.Context().Done()

	for {
		select {
		case <-clientDone:
			return
		case ev := <-events:
			switch ev.Kind {
			case "log":
				// Enrich this single pushed entry the same way the snapshot
				// fetch handlers do, so a live SSE row and a page-load row
				// for the same event look identical (plan T-09 acceptance).
				rows := []model.FirewallLog{ev.Entry}
				s.enrichTrafficLogs(rows)
				data, err := json.Marshal(rows[0])
				if err != nil {
					continue
				}
				// Default message event — the frontend's es.onmessage consumes it
				// as a FirewallLog, so no custom event name here.
				_, _ = w.Write([]byte("data: " + string(data) + "\n\n"))
				flusher.Flush()
			case "clear":
				_, _ = w.Write([]byte("event: clear\ndata: {}\n\n"))
				flusher.Flush()
			}
		case <-heartbeat.C:
			// Re-check the session WITHOUT sliding its idle deadline (SessionAlive,
			// not ValidateSession — see plan Caution 2). A revoked/expired session
			// tears the stream down within ~1 heartbeat.
			if token == "" || !SessionAlive(token) {
				return
			}
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		}
	}
}

// HandleMetricsStream pushes live host telemetry (SystemMetrics: CPU/mem/temp/
// storage) over SSE, replacing the Dashboard StatGrid + site-header temp badge
// polling of GET /dashboard/performance. Unlike the log stream, metrics are
// sampled values: each push is a full snapshot the client replaces wholesale, so
// there is no dedupe/snapshot-merge and no separate heartbeat is needed — a
// snapshot every metricsPushInterval (~5s) already keeps the connection warm.
func (s *Server) HandleMetricsStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// Same WriteTimeout escape as the log stream — without this the global 60s
	// WriteTimeout silently kills the stream every ~60s (#33 regression guard).
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	var token string
	if c, err := r.Cookie(SessionKey); err == nil {
		token = c.Value
	}

	metrics, cancel := s.systemStatus.SubscribeMetrics(4)
	defer cancel()

	// Handshake + an immediate snapshot so the UI paints at once instead of
	// waiting up to one push interval for the first tick.
	_, _ = w.Write([]byte("event: connected\ndata: connection established\n\n"))
	if data, err := json.Marshal(s.systemStatus.GetSystemMetrics()); err == nil {
		_, _ = w.Write([]byte("data: " + string(data) + "\n\n"))
	}
	flusher.Flush()

	clientDone := r.Context().Done()

	for {
		select {
		case <-clientDone:
			return
		case snap := <-metrics:
			// Re-check the session on every push WITHOUT sliding its idle deadline
			// (SessionAlive, not ValidateSession). Since a snapshot arrives ~every 5s,
			// a revoked/expired session tears the stream down within ~5s. No separate
			// heartbeat ticker is needed.
			if token == "" || !SessionAlive(token) {
				return
			}
			data, err := json.Marshal(snap)
			if err != nil {
				continue
			}
			_, _ = w.Write([]byte("data: " + string(data) + "\n\n"))
			flusher.Flush()
		}
	}
}

// =============================================================================
// QoS Handlers
// =============================================================================

// HandleGetQosRules returns all QoS bandwidth rules.
func (s *Server) HandleGetQosRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.qosService.GetRules()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to retrieve QoS rules")
		return
	}
	if rules == nil {
		rules = []model.QosRule{}
	}
	s.writeJSON(w, http.StatusOK, rules)
}

// HandleGetQosRule returns a single QoS rule by ID.
func (s *Server) HandleGetQosRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rule, err := s.qosService.GetRuleByID(id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "QoS rule not found")
		return
	}
	s.writeJSON(w, http.StatusOK, rule)
}

// HandleCreateQosRule creates a new QoS rule and applies it to the kernel.
func (s *Server) HandleCreateQosRule(w http.ResponseWriter, r *http.Request) {
	var input model.QosRuleInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if input.Name == "" || input.Interface == "" {
		s.writeError(w, http.StatusBadRequest, "name and interface are required")
		return
	}
	rule, err := s.qosService.CreateRule(input)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to create QoS rule")
		return
	}
	s.logEvent(r, model.EventCategoryQos, "qos.rule_created", model.EventSeverityInfo,
		rule.Name, "QoS rule \""+rule.Name+"\" created on "+rule.Interface)
	s.writeJSON(w, http.StatusCreated, rule)
}

// HandleUpdateQosRule updates an existing QoS rule and re-syncs the kernel.
func (s *Server) HandleUpdateQosRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var input model.QosRuleInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rule, err := s.qosService.UpdateRule(id, input)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to update QoS rule")
		return
	}
	s.logEvent(r, model.EventCategoryQos, "qos.rule_updated", model.EventSeverityInfo,
		rule.Name, "QoS rule \""+rule.Name+"\" updated on "+rule.Interface)
	s.writeJSON(w, http.StatusOK, rule)
}

// HandleDeleteQosRule removes a QoS rule and re-syncs the kernel.
func (s *Server) HandleDeleteQosRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.qosService.DeleteRule(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to delete QoS rule")
		return
	}
	s.logEvent(r, model.EventCategoryQos, "qos.rule_deleted", model.EventSeverityWarning,
		id, "QoS rule "+id+" deleted")
	s.writeJSON(w, http.StatusOK, map[string]string{"message": "QoS rule deleted"})
}

// HandleToggleQosRule toggles the enabled/disabled status of a QoS rule.
func (s *Server) HandleToggleQosRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rule, err := s.qosService.ToggleRuleStatus(id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to toggle QoS rule status")
		return
	}
	state := "disabled"
	if rule.Status {
		state = "enabled"
	}
	s.logEvent(r, model.EventCategoryQos, "qos.rule_toggled", model.EventSeverityInfo,
		rule.Name, "QoS rule \""+rule.Name+"\" "+state)
	s.writeJSON(w, http.StatusOK, rule)
}

// HandleSyncQosRules forces a full re-sync of all QoS rules from DB to kernel.
func (s *Server) HandleSyncQosRules(w http.ResponseWriter, r *http.Request) {
	if err := s.qosService.SyncToKernel(); err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to sync QoS rules to kernel")
		return
	}
	s.logEvent(r, model.EventCategoryQos, "qos.synced", model.EventSeverityInfo,
		"kernel", "QoS rules synced from database to kernel")
	s.writeJSON(w, http.StatusOK, map[string]string{"message": "QoS rules synced to kernel"})
}

// HandleGetQosIfaceStatus returns the live kernel qdisc/class state for an interface.
func (s *Server) HandleGetQosIfaceStatus(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	status, err := s.qosService.GetIfaceStatus(iface)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to get QoS status for interface")
		return
	}
	s.writeJSON(w, http.StatusOK, status)
}

// HandleClearQosIface disables all DB rules for an interface and clears the kernel qdisc.
func (s *Server) HandleClearQosIface(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if err := s.qosService.ClearIface(iface); err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to clear QoS for interface")
		return
	}
	s.logEvent(r, model.EventCategoryQos, "qos.iface_cleared", model.EventSeverityWarning,
		iface, "QoS rules disabled and qdisc cleared on "+iface)
	s.writeJSON(w, http.StatusOK, map[string]string{"message": "QoS cleared for interface " + iface})
}

// =========================================================================
// DNS SERVER (dnsmasq Local DNS) HANDLERS
// =========================================================================

func (s *Server) HandleGetDNSZones(w http.ResponseWriter, r *http.Request) {
	zones, err := s.repo.GetDNSZones()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if zones == nil {
		zones = []model.DNSZone{}
	}
	s.writeJSON(w, http.StatusOK, zones)
}

func (s *Server) HandleCreateDNSZone(w http.ResponseWriter, r *http.Request) {
	var input model.DNSZoneInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	id, err := randomID("zone-")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not generate ID")
		return
	}
	zone := model.DNSZone{
		ID:              id,
		ZoneName:        input.ZoneName,
		ForwardTo:       input.ForwardTo,
		AllowedIPs:      input.AllowedIPs,
		IsAuthoritative: input.IsAuthoritative,
		Enabled:         input.Enabled,
		Records:         []model.DNSRecord{},
	}

	if err := model.ValidateDNSZone(zone); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.repo.CreateDNSZone(zone); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.zone_created", model.EventSeverityInfo,
		zone.ZoneName, "DNS zone \""+zone.ZoneName+"\" created")
	s.writeJSON(w, http.StatusOK, zone)
}

func (s *Server) HandleUpdateDNSZone(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.repo.GetDNSZoneByID(id)
	if err != nil || existing == nil {
		s.writeError(w, http.StatusNotFound, "DNS Zone not found")
		return
	}

	var input model.DNSZoneInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	zone := model.DNSZone{
		ID:              id,
		ZoneName:        input.ZoneName,
		ForwardTo:       input.ForwardTo,
		AllowedIPs:      input.AllowedIPs,
		IsAuthoritative: input.IsAuthoritative,
		Enabled:         input.Enabled,
		Records:         existing.Records,
	}

	if err := model.ValidateDNSZone(zone); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.repo.UpdateDNSZone(zone); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.zone_updated", model.EventSeverityInfo,
		zone.ZoneName, "DNS zone \""+zone.ZoneName+"\" updated")
	s.writeJSON(w, http.StatusOK, zone)
}

func (s *Server) HandleDeleteDNSZone(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.repo.DeleteDNSZone(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.zone_deleted", model.EventSeverityWarning,
		id, "DNS zone "+id+" deleted")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleToggleDNSZone(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.repo.ToggleDNSZone(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.zone_toggled", model.EventSeverityInfo,
		id, "DNS zone "+id+" toggled")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleGetDNSRecords(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	records, err := s.repo.GetDNSRecordsByZone(id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if records == nil {
		records = []model.DNSRecord{}
	}
	s.writeJSON(w, http.StatusOK, records)
}

// nsRecordEmitsDelegation reports whether an NS record will make
// buildDNSConfig emit a `server=` delegation line for it — either the
// pre-existing glue-IP forwarding, or the newer "upstream" mode
// (docs/ref/todo/dns-ns-delegation-cname-fix-plan.md §3/T-05), which emits
// `server=/<fqdn>/#` even with zero glue IPs. Both call sites below
// (validateNSGlueAgainstZone's apex guard and the create/update handlers)
// must use this single helper so the apex guard can never miss the
// glue-IP-less upstream case (Caution 1 — an apex record in upstream mode
// with no glue IPs must still be rejected).
func nsRecordEmitsDelegation(r model.DNSRecord) bool {
	return strings.EqualFold(r.Type, "NS") &&
		(len(r.GlueIPs) > 0 || model.EffectiveNSDelegationMode(r) == model.DNSNSDelegationModeUpstream)
}

// validateNSGlueAgainstZone enforces the apex guard for NS-delegation
// forwarding (docs/ref/todo/dns-ns-delegation-plan.md T-06, extended by
// dns-ns-delegation-cname-fix-plan.md §3/T-05 for upstream mode): an NS
// record at the zone apex must never emit a server= delegation line (glue
// IPs OR upstream mode), because the generator would have to skip it to
// avoid forwarding the entire zone away (buildDNSConfig already refuses to
// emit it as defense-in-depth, but the API must reject it outright so the
// user gets a clear 400 instead of a silently-ignored setting). Shared by
// both create and update so the two call sites can never drift apart.
// Returns a non-nil error with a user-facing message when the record must be
// rejected.
func validateNSGlueAgainstZone(zone *model.DNSZone, record model.DNSRecord) error {
	if !nsRecordEmitsDelegation(record) {
		return nil
	}
	name := strings.TrimSpace(record.Name)
	if name == "" || name == "@" || strings.EqualFold(name, zone.ZoneName) {
		return fmt.Errorf("ไม่สามารถส่งต่อ (forward) NS record ที่ apex ของโซนได้ ไม่ว่าจะด้วย glue IP หรือโหมด upstream เพราะจะทำให้ทั้งโซนถูกส่งต่อออกไปทั้งหมด หากต้องการส่งต่อทั้งโซน กรุณาใช้ \"Forward Zone\" แทน")
	}
	return nil
}

func (s *Server) HandleCreateDNSRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("id")
	var input model.DNSRecordInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	id, err := randomID("rec-")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not generate ID")
		return
	}
	record := model.DNSRecord{
		ID:             id,
		ZoneID:         zoneID,
		Name:           input.Name,
		Type:           input.Type,
		Value:          input.Value,
		TTL:            input.TTL,
		GlueIPs:        input.GlueIPs,
		DelegationMode: input.DelegationMode,
	}

	if err := model.ValidateDNSRecord(record); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if nsRecordEmitsDelegation(record) {
		zone, err := s.repo.GetDNSZoneByID(zoneID)
		if err != nil || zone == nil {
			s.writeError(w, http.StatusBadRequest, "DNS zone not found")
			return
		}
		if err := validateNSGlueAgainstZone(zone, record); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if err := s.repo.CreateDNSRecord(record); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.record_created", model.EventSeverityInfo,
		record.Name, "DNS record \""+record.Name+"\" ("+record.Type+") created")
	s.writeJSON(w, http.StatusOK, record)
}

func (s *Server) HandleUpdateDNSRecord(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.repo.GetDNSRecordByID(id)
	if err != nil || existing == nil {
		s.writeError(w, http.StatusNotFound, "DNS Record not found")
		return
	}

	var input model.DNSRecordInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	record := model.DNSRecord{
		ID:             id,
		ZoneID:         existing.ZoneID,
		Name:           input.Name,
		Type:           input.Type,
		Value:          input.Value,
		TTL:            input.TTL,
		GlueIPs:        input.GlueIPs,
		DelegationMode: input.DelegationMode,
	}

	if err := model.ValidateDNSRecord(record); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if nsRecordEmitsDelegation(record) {
		zone, err := s.repo.GetDNSZoneByID(existing.ZoneID)
		if err != nil || zone == nil {
			s.writeError(w, http.StatusBadRequest, "DNS zone not found")
			return
		}
		if err := validateNSGlueAgainstZone(zone, record); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if err := s.repo.UpdateDNSRecord(record); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.record_updated", model.EventSeverityInfo,
		record.Name, "DNS record \""+record.Name+"\" ("+record.Type+") updated")
	s.writeJSON(w, http.StatusOK, record)
}

// HandleResolveNameserver auto-looks-up the IP address(es) of an
// NS-delegation nameserver name (docs/ref/todo/dns-ns-delegation-plan.md
// T-06), for the "ค้นหา IP อัตโนมัติ" button next to an NS record's glue IP
// field. Deliberately GET (a pure read, issues an outbound DNS query but
// never mutates PiGate's own config) so DisableEditMiddleware and
// RoleReadOnlyMiddleware — which only gate POST/PUT/DELETE/PATCH — never
// block it, matching GET /api/interfaces/{id}/scan. Not logged via
// s.logEvent: this reads/queries, it does not change any stored config.
func (s *Server) HandleResolveNameserver(w http.ResponseWriter, r *http.Request) {
	if s.dnsServerService == nil {
		s.writeError(w, http.StatusServiceUnavailable, "DNS Server service not available")
		return
	}
	name := r.URL.Query().Get("name")
	ips, err := s.dnsServerService.ResolveNameserver(r.Context(), name)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrNSLookupInvalidName):
			s.writeError(w, http.StatusBadRequest, "Invalid nameserver name")
		case errors.Is(err, service.ErrNSLookupNotFound):
			s.writeError(w, http.StatusNotFound, "Nameserver name did not resolve to any address")
		case errors.Is(err, service.ErrNSLookupRateLimited):
			s.writeError(w, http.StatusTooManyRequests, "Too many lookups, please wait")
		default:
			s.writeError(w, http.StatusBadGateway, "DNS lookup failed")
		}
		return
	}
	// Echo back the validated/normalized name only — never the raw query
	// param — so the response can never carry back anything that failed
	// validation.
	validatedName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"name": validatedName,
		"ips":  ips,
	})
}

func (s *Server) HandleDeleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.repo.DeleteDNSRecord(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.record_deleted", model.EventSeverityWarning,
		id, "DNS record "+id+" deleted")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleApplyDNSServer(w http.ResponseWriter, r *http.Request) {
	if err := s.dnsServerService.ApplyAll(); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.firewallService.SyncFirewallRules(); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.server_applied", model.EventSeverityInfo,
		"dnsmasq", "DNS server zones/records applied")
	s.writeJSON(w, http.StatusOK, true)
}

func (s *Server) HandleClearDNSCache(w http.ResponseWriter, r *http.Request) {
	if err := s.dnsServerService.ClearCache(); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.cache_cleared", model.EventSeverityInfo,
		"dnsmasq", "DNS server cache cleared")
	s.writeJSON(w, http.StatusOK, true)
}

// HandleGetDNSServerSettings returns the interfaces the DNS Server is currently
// bound to plus the DNS Statistics fields (queryLogging/dnsCacheTtlMinutes/
// dnsCacheMaxEntries — docs/ref/todo/statistics-dns-top-domain-plan.md T-10).
func (s *Server) HandleGetDNSServerSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.repo.GetDNSServerSettings()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, settings)
}

// HandleUpdateDNSServerSettings saves the set of real interfaces (from Interface Service)
// the DNS Server should bind to, plus the DNS Statistics fields (query logging switch +
// reverse-cache TTL/cap). Kept independent from DHCP Server configuration.
//
// Validation tolerates dangling refs: interfaces already saved in dns_server_settings
// are grandfathered through even if they no longer exist in the kernel (e.g. a VLAN
// whose parent went away), so the user can always keep or remove them via the UI
// without hitting a 400 deadlock. Only names newly *added* in this request are
// validated against real interfaces, to keep rejecting typos/garbage from API clients.
//
// 🔒 The TTL/cap fields are validated via model.ValidateDNSServerSettings before
// anything is written — out of range returns 400 and the DB is left untouched (plan
// §5 item 17). Which side effect fires depends on WHAT changed: interfaces/queryLogging
// changing triggers dnsServerService.ApplyAll() (writes config + restarts dnsmasq);
// TTL/cap changing on their own only calls statisticsService.SetReverseCacheLimits —
// ApplyZones/dnsmasq are never touched for a TTL/cap-only change (plan §5 item 18,
// T-11 item 7).
func (s *Server) HandleUpdateDNSServerSettings(w http.ResponseWriter, r *http.Request) {
	var input model.DNSServerSettings
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if err := model.ValidateDNSServerSettings(input); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Normalize empty mode from an old client to "system" before persisting
	// (matches the ValidateDNSServerSettings treatment of an empty mode).
	if input.UpstreamMode == "" {
		input.UpstreamMode = model.DNSUpstreamModeSystem
	}

	realIfaces, err := s.interfaceService.GetDataLayerInterface()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	valid := make(map[string]bool)
	for _, iface := range realIfaces {
		valid[iface.Name] = true
	}

	// Load the previously saved settings BEFORE writing so we can (a) grandfather
	// dangling interface refs (Caution 2: must read before writing, otherwise the
	// grandfather set would be the new input and validation would pass everything)
	// and (b) detect exactly what changed, to decide restart vs. no-restart below.
	saved, err := s.repo.GetDNSServerSettings()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	savedSet := make(map[string]bool)
	for _, name := range saved.Interfaces {
		savedSet[name] = true
	}

	for _, name := range input.Interfaces {
		if !valid[name] && !savedSet[name] {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("interface %s does not exist", name))
			return
		}
	}

	if err := s.repo.SetDNSServerInterfaces(input.Interfaces); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.repo.SetDNSServerSettings(input.QueryLogging, input.DNSCacheTTLMinutes, input.DNSCacheMaxEntries, input.UpstreamMode, input.UpstreamServers); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	interfacesChanged := stringSliceSetChanged(saved.Interfaces, input.Interfaces)
	queryLoggingChanged := saved.QueryLogging != input.QueryLogging
	// Upstream mode/list changing (docs/ref/todo/
	// dns-server-settings-tab-and-upstream-plan.md T-05) requires regenerating
	// pigate-dns.conf + restarting dnsmasq, same as interfaces/queryLogging —
	// TTL/cap alone must NOT trigger this (plan §5 item 6, regression guard).
	upstreamChanged := saved.UpstreamMode != input.UpstreamMode || stringSliceSetChanged(saved.UpstreamServers, input.UpstreamServers)

	if interfacesChanged || queryLoggingChanged || upstreamChanged {
		if err := s.dnsServerService.ApplyAll(); err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if queryLoggingChanged {
			s.statistics.SetDNSLoggingEnabled(input.QueryLogging)
		}
	}
	// TTL/cap take effect immediately regardless of whether ApplyAll ran above —
	// this call never touches dnsmasq (plan §5 item 18).
	s.statistics.SetReverseCacheLimits(input.DNSCacheTTLMinutes, input.DNSCacheMaxEntries)

	s.logEvent(r, model.EventCategoryDns, "dns.server_settings_changed", model.EventSeverityInfo,
		"dns-server", fmt.Sprintf("DNS server bound to %d interface(s), query logging: %t, upstream mode: %s (%d server(s))", len(input.Interfaces), input.QueryLogging, input.UpstreamMode, len(input.UpstreamServers)))
	s.writeJSON(w, http.StatusOK, input)
}

// stringSliceSetChanged reports whether a and b differ as sets of strings,
// ignoring order — used to detect whether the DNS Server "interfaces"
// selection actually changed (order is not meaningful for this field, so a
// pure order-sensitive comparison would trigger a spurious dnsmasq restart).
func stringSliceSetChanged(a, b []string) bool {
	if len(a) != len(b) {
		return true
	}
	setA := make(map[string]bool, len(a))
	for _, s := range a {
		setA[s] = true
	}
	for _, s := range b {
		if !setA[s] {
			return true
		}
		delete(setA, s)
	}
	return len(setA) != 0
}

// =========================================================================
// DNS SERVER — BLOCKED DOMAINS (deny-list, docs/ref/todo/
// dns-blocked-domains-plan.md)
// =========================================================================
// SENSITIVE: domain/comment here are interpolated verbatim into
// pigate-dns.conf (`server=/<domain>/` or `address=/<domain>/<ip>`), so every
// write path (create/update, and the backup importer separately) MUST run
// the value through model.ValidateBlockedDomain before it reaches the DB —
// dnsmasq is directive-per-line, so an un-validated newline injects an
// arbitrary config line (plan §5 Caution 1). CRUD handlers below write the DB
// only — they never call dnsServerService.ApplyAll(); the user applies the
// change explicitly via "Apply DNS Zones" (plan §5 Caution 6, avoids
// restarting dnsmasq/DHCP on every single edit).

// HandleGetBlockedDomains returns the full deny-list, ordered by domain.
func (s *Server) HandleGetBlockedDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := s.repo.GetBlockedDomains()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if domains == nil {
		domains = []model.BlockedDomain{}
	}
	s.writeJSON(w, http.StatusOK, domains)
}

// HandleCreateBlockedDomain validates and inserts a new deny-list entry.
// The domain is normalized (lower-cased, trailing dot stripped) BEFORE
// validation, matching how the user is expected to type a name and keeping
// the stored/validated value in sync with what buildDNSConfig will emit.
func (s *Server) HandleCreateBlockedDomain(w http.ResponseWriter, r *http.Request) {
	var input model.BlockedDomainInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	domain := strings.ToLower(strings.TrimSuffix(input.Domain, "."))
	mode := input.Mode
	if mode == "" {
		mode = model.DNSBlockModeNXDomain
	}

	count, err := s.repo.CountBlockedDomains()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if count >= model.DNSBlockedDomainsMax {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("blocked domains list is at its maximum of %d entries", model.DNSBlockedDomainsMax))
		return
	}

	id, err := randomID("blk-")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not generate ID")
		return
	}
	blocked := model.BlockedDomain{
		ID:      id,
		Domain:  domain,
		Mode:    mode,
		Enabled: input.Enabled,
		Comment: input.Comment,
	}

	if err := model.ValidateBlockedDomain(blocked); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// A block target that exactly matches an enabled zone name is ambiguous
	// (plan §2 "การชนกับ zone เดิม" / §5 Caution 3) — reject up front so the
	// user gets an explicit reason rather than the entry silently being
	// skipped later by the generator.
	zones, err := s.repo.GetDNSZones()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, z := range zones {
		if z.Enabled && strings.EqualFold(strings.TrimSpace(z.ZoneName), domain) {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("domain %q matches an existing enabled DNS zone name", domain))
			return
		}
	}

	if err := s.repo.CreateBlockedDomain(blocked); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("domain %q already exists in the blocked domains list", domain))
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.blocked_domain_created", model.EventSeverityInfo,
		domain, "Blocked domain \""+domain+"\" created")
	s.writeJSON(w, http.StatusOK, blocked)
}

// HandleUpdateBlockedDomain replaces the domain/mode/enabled/comment of an
// existing entry. Same normalization/validation/collision checks as create.
func (s *Server) HandleUpdateBlockedDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.repo.GetBlockedDomainByID(id)
	if err != nil || existing == nil {
		s.writeError(w, http.StatusNotFound, "Blocked domain not found")
		return
	}

	var input model.BlockedDomainInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	domain := strings.ToLower(strings.TrimSuffix(input.Domain, "."))
	mode := input.Mode
	if mode == "" {
		mode = model.DNSBlockModeNXDomain
	}

	blocked := model.BlockedDomain{
		ID:      id,
		Domain:  domain,
		Mode:    mode,
		Enabled: input.Enabled,
		Comment: input.Comment,
	}

	if err := model.ValidateBlockedDomain(blocked); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	zones, err := s.repo.GetDNSZones()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, z := range zones {
		if z.Enabled && strings.EqualFold(strings.TrimSpace(z.ZoneName), domain) {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("domain %q matches an existing enabled DNS zone name", domain))
			return
		}
	}

	if err := s.repo.UpdateBlockedDomain(blocked); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("domain %q already exists in the blocked domains list", domain))
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.blocked_domain_updated", model.EventSeverityInfo,
		domain, "Blocked domain \""+domain+"\" updated")
	s.writeJSON(w, http.StatusOK, blocked)
}

// HandleDeleteBlockedDomain removes an entry.
func (s *Server) HandleDeleteBlockedDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.repo.DeleteBlockedDomain(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.blocked_domain_deleted", model.EventSeverityWarning,
		id, "Blocked domain "+id+" deleted")
	s.writeJSON(w, http.StatusOK, true)
}

// HandleToggleBlockedDomain flips enabled on/off.
func (s *Server) HandleToggleBlockedDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.repo.ToggleBlockedDomain(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.blocked_domain_toggled", model.EventSeverityInfo,
		id, "Blocked domain "+id+" toggled")
	s.writeJSON(w, http.StatusOK, true)
}

// =========================================================================
// DNS BLOCKLISTS (bulk hosts-file import — subscribe URL / upload,
// docs/ref/todo/dns-blocklist-import-plan.md T-08)
// =========================================================================
// SENSITIVE: unlike the deny-list above, these routes make the board fetch a
// user-supplied HTTPS URL (CreateFromURL/Refresh) and write multi-MB files
// to disk (any of create/upload/refresh) — router.go therefore puts every
// mutation on superAdminRoute explicitly, not just RoleReadOnlyMiddleware.
// Every handler re-validates name/url/blockMode itself (model.ValidateDNSBlocklist*
// / model.NormalizeBlocklistBlockMode) before calling the service, even
// though the service validates again internally — same "validate at both
// layers" pattern the deny-list handlers use just above. Service errors are
// never forwarded to the client verbatim: writeBlocklistServiceError below
// decides what is safe to show (validation/quota/version messages) versus
// what must be summarized (anything that could carry a fetcher error with a
// URL/host, or an internal filesystem path).

// writeBlocklistServiceError classifies an error returned by
// DNSBlocklistService and writes the appropriate HTTP response. Known,
// user-actionable messages (quota exceeded, dnsmasq version too old, not
// found, wrong sourceType) are passed through as-is — they never contain
// anything sensitive. Everything else is assumed to potentially carry
// fetcher/filesystem internals (e.g. "fetch blocklist: ...", which wraps the
// raw net/http error including the target host) and is replaced with a
// generic message; the real error is still logged server-side for
// diagnosis.
func (s *Server) writeBlocklistServiceError(w http.ResponseWriter, err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "requires dnsmasq >= 2.86"),
		strings.Contains(msg, "exceeding the maximum"),
		strings.Contains(msg, "exceeds maximum"),
		strings.Contains(msg, "already reached"),
		strings.Contains(msg, "cannot refresh"),
		strings.Contains(msg, "is not a subscribe-URL list"):
		s.writeError(w, http.StatusBadRequest, msg)
	case strings.Contains(strings.ToLower(msg), "not found"):
		s.writeError(w, http.StatusNotFound, msg)
	case strings.HasPrefix(msg, "fetch blocklist:"):
		log.Printf("[DNSBlocklist] fetch failed: %v", err)
		s.writeError(w, http.StatusBadGateway, "Failed to fetch the blocklist from the configured URL. Check that the URL is reachable and returns a plain hosts file.")
	default:
		log.Printf("[DNSBlocklist] internal error: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to process the blocklist request. See server logs for details.")
	}
}

// HandleGetDNSBlocklists returns every blocklist's metadata from the
// manifest (never the domain list itself — that only ever lives in the
// generated <id>.hosts/<id>.conf files, plan §0/§2.3).
func (s *Server) HandleGetDNSBlocklists(w http.ResponseWriter, r *http.Request) {
	if s.dnsBlocklistService == nil {
		s.writeJSON(w, http.StatusOK, []model.DNSBlocklist{})
		return
	}
	list := s.dnsBlocklistService.List()
	if list == nil {
		list = []model.DNSBlocklist{}
	}
	s.writeJSON(w, http.StatusOK, list)
}

// HandleCreateDNSBlocklist subscribes to a new URL-sourced blocklist: fetches
// it synchronously (SSRF-guarded fetcher, T-04) before ever writing to the
// manifest, so a bad URL never leaves a stale entry behind.
func (s *Server) HandleCreateDNSBlocklist(w http.ResponseWriter, r *http.Request) {
	if s.dnsBlocklistService == nil {
		s.writeError(w, http.StatusServiceUnavailable, "DNS blocklist feature is not available")
		return
	}
	var input model.DNSBlocklistInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if err := model.ValidateDNSBlocklistName(input.Name); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := model.ValidateDNSBlocklistURL(input.URL); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// blockMode: validated here at the handler layer too (not just inside the
	// service) so an unknown value is rejected with 400 before any network
	// fetch happens — plan §3 T-08 item 2b. An empty value is left alone;
	// the service applies model.DNSBlocklistDefaultBlockMode (sinkhole).
	mode, err := model.NormalizeBlocklistBlockMode(input.BlockMode)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	entry, err := s.dnsBlocklistService.CreateFromURL(r.Context(), input.Name, input.URL, mode, input.Enabled)
	if err != nil {
		s.writeBlocklistServiceError(w, err)
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.blocklist_created", model.EventSeverityInfo,
		entry.ID, "DNS blocklist \""+entry.Name+"\" created from URL")
	s.writeJSON(w, http.StatusOK, entry)
}

// HandleUploadDNSBlocklist adds a new upload-sourced blocklist from a raw
// hosts-format file in the request body (Content-Type: text/plain), with the
// list name and (optional) blockMode passed as query parameters — there is
// no JSON body here, only the file bytes. The body is explicitly capped with
// http.MaxBytesReader at model.DNSBlocklistMaxFileBytes (same pattern as
// HandleImportConfig) BEFORE reading it, and this path is registered in
// bodyLimitExemptPaths (middleware.go) so BodyLimitMiddleware's global 1 MB
// cap does not truncate it first.
func (s *Server) HandleUploadDNSBlocklist(w http.ResponseWriter, r *http.Request) {
	if s.dnsBlocklistService == nil {
		s.writeError(w, http.StatusServiceUnavailable, "DNS blocklist feature is not available")
		return
	}

	name := r.URL.Query().Get("name")
	if err := model.ValidateDNSBlocklistName(name); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	mode, err := model.NormalizeBlocklistBlockMode(r.URL.Query().Get("blockMode"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// enabled defaults to true for an upload (the whole point of uploading a
	// file is to use it immediately) but can be overridden with ?enabled=false.
	enabled := true
	if v := r.URL.Query().Get("enabled"); v != "" {
		enabled = v == "1" || v == "true"
	}

	r.Body = http.MaxBytesReader(w, r.Body, model.DNSBlocklistMaxFileBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to read upload (max %d bytes): %s", model.DNSBlocklistMaxFileBytes, err.Error()))
		return
	}

	entry, err := s.dnsBlocklistService.CreateFromUpload(name, raw, mode, enabled)
	if err != nil {
		s.writeBlocklistServiceError(w, err)
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.blocklist_created", model.EventSeverityInfo,
		entry.ID, "DNS blocklist \""+entry.Name+"\" created from upload")
	s.writeJSON(w, http.StatusOK, entry)
}

// HandleUpdateDNSBlocklist updates a list's name/url/blockMode/enabled. It
// never re-fetches or re-parses content — a blockMode change re-derives
// <id>.conf purely from the already-written <id>.hosts (service.UpdateInfo /
// renderArtifacts, plan §2.1.1), which is why this works offline and for
// upload-sourced lists.
func (s *Server) HandleUpdateDNSBlocklist(w http.ResponseWriter, r *http.Request) {
	if s.dnsBlocklistService == nil {
		s.writeError(w, http.StatusServiceUnavailable, "DNS blocklist feature is not available")
		return
	}
	id := r.PathValue("id")
	if err := model.ValidateDNSBlocklistID(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var input model.DNSBlocklistInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if err := model.ValidateDNSBlocklistName(input.Name); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// URL is only meaningful for subscribe-URL lists (UpdateInfo ignores it
	// for upload-sourced ones) but is still validated here whenever non-empty
	// so an obviously malformed/injected value is rejected up front.
	if input.URL != "" {
		if err := model.ValidateDNSBlocklistURL(input.URL); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	mode, err := model.NormalizeBlocklistBlockMode(input.BlockMode)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	entry, err := s.dnsBlocklistService.UpdateInfo(id, input.Name, input.URL, mode, input.Enabled)
	if err != nil {
		s.writeBlocklistServiceError(w, err)
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.blocklist_updated", model.EventSeverityInfo,
		entry.ID, "DNS blocklist \""+entry.Name+"\" updated")
	s.writeJSON(w, http.StatusOK, entry)
}

// HandleDeleteDNSBlocklist removes a blocklist's files (both .hosts and
// .conf) and its manifest entry.
func (s *Server) HandleDeleteDNSBlocklist(w http.ResponseWriter, r *http.Request) {
	if s.dnsBlocklistService == nil {
		s.writeError(w, http.StatusServiceUnavailable, "DNS blocklist feature is not available")
		return
	}
	id := r.PathValue("id")
	if err := model.ValidateDNSBlocklistID(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.dnsBlocklistService.Delete(id); err != nil {
		s.writeBlocklistServiceError(w, err)
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.blocklist_deleted", model.EventSeverityWarning,
		id, "DNS blocklist "+id+" deleted")
	s.writeJSON(w, http.StatusOK, true)
}

// HandleToggleDNSBlocklist flips a list's enabled flag. Enabling a currently
// disabled list is re-checked against the cross-list domain-count quotas
// (service.Toggle).
func (s *Server) HandleToggleDNSBlocklist(w http.ResponseWriter, r *http.Request) {
	if s.dnsBlocklistService == nil {
		s.writeError(w, http.StatusServiceUnavailable, "DNS blocklist feature is not available")
		return
	}
	id := r.PathValue("id")
	if err := model.ValidateDNSBlocklistID(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	entry, err := s.dnsBlocklistService.Toggle(id)
	if err != nil {
		s.writeBlocklistServiceError(w, err)
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.blocklist_toggled", model.EventSeverityInfo,
		id, "DNS blocklist "+id+" toggled")
	s.writeJSON(w, http.StatusOK, entry)
}

// HandleRefreshDNSBlocklist re-fetches a subscribe-URL list's content. A
// fetch/parse failure leaves the existing files and DomainCount completely
// untouched (service.Refresh records only LastError), so a transient network
// problem never takes down a list that is currently working.
func (s *Server) HandleRefreshDNSBlocklist(w http.ResponseWriter, r *http.Request) {
	if s.dnsBlocklistService == nil {
		s.writeError(w, http.StatusServiceUnavailable, "DNS blocklist feature is not available")
		return
	}
	id := r.PathValue("id")
	if err := model.ValidateDNSBlocklistID(id); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	entry, err := s.dnsBlocklistService.Refresh(r.Context(), id)
	if err != nil {
		s.writeBlocklistServiceError(w, err)
		return
	}
	s.logEvent(r, model.EventCategoryDns, "dns.blocklist_refreshed", model.EventSeverityInfo,
		id, "DNS blocklist "+id+" refreshed")
	s.writeJSON(w, http.StatusOK, entry)
}

// =========================================================================
// WI-FI SAVED NETWORKS (PRESETS) HANDLERS — issue #66
// =========================================================================
// SENSITIVE: every response body built in this section MUST run each
// model.WifiPreset through model.SanitizeWifiPresetForRead before writeJSON,
// and every response carrying a model.NetworkInterface (the /apply result)
// MUST run through maskInterfacePasswords first — plaintext password must
// never reach the browser (wifi-presets-plan.md Caution "password รั่วออก
// GET"). All five routes are superAdminRoute (router.go), not authRoute.

// HandleGetWifiPresets lists every saved Wi-Fi preset with its password
// stripped (list.hasPassword substitutes for the plaintext value).
func (s *Server) HandleGetWifiPresets(w http.ResponseWriter, r *http.Request) {
	list, err := s.wifiPresetService.GetAll()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sanitized := make([]model.WifiPreset, len(list))
	for i, p := range list {
		sanitized[i] = model.SanitizeWifiPresetForRead(p)
	}
	s.writeJSON(w, http.StatusOK, sanitized)
}

// HandleCreateWifiPreset creates a new saved Wi-Fi network. Duplicate names
// are rejected with 409 (checked explicitly here rather than surfacing the
// DB's raw UNIQUE constraint error as an opaque 500/400).
func (s *Server) HandleCreateWifiPreset(w http.ResponseWriter, r *http.Request) {
	var input model.WifiPreset
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	input.Name = strings.TrimSpace(input.Name)

	if err := model.ValidateWifiPreset(input); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	exists, err := s.wifiPresetService.NameExists(input.Name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if exists {
		s.writeError(w, http.StatusConflict, "a wifi preset with this name already exists")
		return
	}

	id, err := randomID("wifi-")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Could not generate ID")
		return
	}
	input.ID = id

	if err := s.wifiPresetService.Create(input); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryNetwork, "network.wifi_preset_created", model.EventSeverityInfo,
		input.Name, "Wi-Fi preset \""+input.Name+"\" created")
	// input already carries exactly the password it was just created with, so
	// sanitizing it directly (rather than re-reading from the DB) is safe here —
	// unlike Update, there is no "empty means keep existing" ambiguity on create.
	s.writeJSON(w, http.StatusOK, model.SanitizeWifiPresetForRead(input))
}

// HandleUpdateWifiPreset updates an existing preset. An empty submitted
// password means "keep the currently stored credential" (db.UpdateWifiPreset
// handles that), so the response is built from a fresh GetByID after the
// write rather than echoing the request body — otherwise HasPassword would
// wrongly compute false whenever the caller left the password blank to keep
// it unchanged.
func (s *Server) HandleUpdateWifiPreset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.wifiPresetService.GetByID(id)
	if err != nil || existing == nil {
		s.writeError(w, http.StatusNotFound, "Wi-Fi preset not found")
		return
	}

	var input model.WifiPreset
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	input.ID = id
	input.Name = strings.TrimSpace(input.Name)

	if err := model.ValidateWifiPreset(input); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if input.Name != existing.Name {
		nameTaken, err := s.wifiPresetService.NameExists(input.Name)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if nameTaken {
			s.writeError(w, http.StatusConflict, "a wifi preset with this name already exists")
			return
		}
	}

	if err := s.wifiPresetService.Update(input); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := s.wifiPresetService.GetByID(id)
	if err != nil || updated == nil {
		s.writeError(w, http.StatusInternalServerError, "failed to reload updated wifi preset")
		return
	}

	s.logEvent(r, model.EventCategoryNetwork, "network.wifi_preset_updated", model.EventSeverityInfo,
		updated.Name, "Wi-Fi preset \""+updated.Name+"\" updated")
	s.writeJSON(w, http.StatusOK, model.SanitizeWifiPresetForRead(*updated))
}

// HandleDeleteWifiPreset removes a preset. Deleting a preset never touches
// interfaces that previously applied it (a preset is a template, not a live
// link — wifi-presets-plan.md section 0).
func (s *Server) HandleDeleteWifiPreset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.wifiPresetService.GetByID(id)
	if err != nil || existing == nil {
		s.writeError(w, http.StatusNotFound, "Wi-Fi preset not found")
		return
	}

	if err := s.wifiPresetService.Delete(id); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.logEvent(r, model.EventCategoryNetwork, "network.wifi_preset_deleted", model.EventSeverityWarning,
		existing.Name, "Wi-Fi preset \""+existing.Name+"\" deleted")
	s.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// HandleApplyWifiPreset is the SENSITIVE server-side apply flow: it reads the
// preset's password from the DB and writes it straight into the target
// interface via WifiPresetService.ApplyPresetToInterface — the request body
// only ever carries {interfaceId, slot}, never a password, and the response
// interface is masked the same way HandleUpdateInterface's is
// (wifi-presets-plan.md section 2.3 / Caution "/apply ต้องผ่าน review เข้ม").
func (s *Server) HandleApplyWifiPreset(w http.ResponseWriter, r *http.Request) {
	presetID := r.PathValue("id")

	var body struct {
		InterfaceID string `json:"interfaceId"`
		Slot        string `json:"slot"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	iface, err := s.wifiPresetService.ApplyPresetToInterface(presetID, body.InterfaceID, body.Slot)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWifiPresetInvalidSlot):
			s.writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, service.ErrWifiPresetNotFound), errors.Is(err, service.ErrWifiPresetInterfaceNotFound):
			s.writeError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, service.ErrWifiPresetNotWireless):
			s.writeError(w, http.StatusBadRequest, err.Error())
		default:
			s.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	s.logEvent(r, model.EventCategoryNetwork, "network.wifi_preset_applied", model.EventSeverityInfo,
		iface.Name, "Wi-Fi preset applied to interface \""+iface.Name+"\" ("+body.Slot+" slot)")

	maskInterfacePasswords(iface)
	s.writeJSON(w, http.StatusOK, iface)
}
