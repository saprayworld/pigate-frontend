package api

import (
	"net/http"
)

func RegisterRoutes(s *Server) http.Handler {
	mux := http.NewServeMux()

	// 1. Authentication (Rate-limited, bypass auth header check)
	mux.Handle("POST /api/auth/login", RateLimitMiddleware(http.HandlerFunc(s.HandleLogin)))
	mux.HandleFunc("POST /api/auth/logout", s.HandleLogout)

	// Helper wrapper for authentication-protected endpoints. Order matters:
	// AuthMiddleware runs first (validates session, injects username+role), then
	// RoleReadOnlyMiddleware blocks mutations for non-super_admin roles.
	authRoute := func(pattern string, handler func(http.ResponseWriter, *http.Request)) {
		mux.Handle(pattern, s.AuthMiddleware(RoleReadOnlyMiddleware(http.HandlerFunc(handler))))
	}

	// superAdminRoute restricts a route to super_admin only (including GET), so
	// a read-only admin can't even see the account list.
	superAdminRoute := func(pattern string, handler func(http.ResponseWriter, *http.Request)) {
		mux.Handle(pattern, s.AuthMiddleware(SuperAdminMiddleware(http.HandlerFunc(handler))))
	}

	authRoute("GET /api/auth/session", s.HandleCheckSession)

	// User Management (super_admin only)
	superAdminRoute("GET /api/users", s.HandleGetUsers)
	superAdminRoute("POST /api/users", s.HandleCreateUser)
	superAdminRoute("PUT /api/users/{id}", s.HandleUpdateUser)
	superAdminRoute("DELETE /api/users/{id}", s.HandleDeleteUser)
	superAdminRoute("POST /api/users/{id}/toggle", s.HandleToggleUser)

	// 2. Dashboard Widgets
	authRoute("GET /api/dashboard/stats", s.HandleGetDashboardStats)
	authRoute("GET /api/dashboard/performance", s.HandleGetPerformanceMetrics)
	authRoute("GET /api/dashboard/performance/stream", s.HandleMetricsStream)
	authRoute("GET /api/dashboard/traffic", s.HandleGetTrafficHistory)
	authRoute("GET /api/dashboard/traffic-detail", s.HandleGetTrafficDetail)
	authRoute("GET /api/statistics/traffic", s.HandleGetStatistics)
	// Statistics -> Traffic page (docs/ref/todo/statistics-traffic-page-plan.md
	// T-04): full top-hosts lists + per-IP drill-down, additive to the
	// existing /api/statistics/traffic above (distinct paths, no shadowing).
	authRoute("GET /api/statistics/traffic/hosts", s.HandleGetTrafficTopHosts)
	authRoute("GET /api/statistics/traffic/host", s.HandleGetTrafficHostDetail)
	// DNS Query Statistics tab (docs/ref/todo/dns-query-statistics-drilldown-plan.md
	// T-03/§2.3 option A): authRoute like the traffic statistics endpoint above —
	// the data exposed (domain + source IP) is the same sensitivity level as
	// /api/statistics/traffic, which already shows both.
	authRoute("GET /api/statistics/dns", s.HandleGetDNSQueryStatistics)
	authRoute("GET /api/statistics/dns/domain", s.HandleGetDNSDomainClients)
	authRoute("GET /api/statistics/dns/client", s.HandleGetDNSClientDomains)
	// IP -> domains reverse lookup for the Statistics -> DNS page's IP-filter
	// mode (docs/ref/todo/statistics-dns-ip-filter-plan.md T-04): same
	// sensitivity level as the 3 DNS statistics routes above, authRoute only
	// (not superAdminRoute); GET, so DisableEditMiddleware never blocks it —
	// this is a pure read.
	authRoute("GET /api/statistics/dns/ip", s.HandleGetDNSIPDomains)
	// Public IP Info card backend proxy to ipinfo.io (docs/ref/todo/
	// statistics-host-ipinfo-plan.md T-07) — authRoute (not superAdminRoute):
	// same read-only sensitivity level as the statistics endpoints above. GET
	// only, so DisableEditMiddleware never blocks it. Opt-in/default-OFF is
	// enforced entirely server-side by IPInfoService (ErrIPInfoDisabled ->
	// 404), not by this route registration.
	authRoute("GET /api/statistics/ipinfo", s.HandleGetIPInfo)
	// Reference popover ("hover ที่ IP/Domain แล้วเห็นสรุปข้อมูลอ้างอิงแบบ
	// FortiGate" — docs/ref/todo/reference-popover-plan.md Step 3): two
	// lightweight hover-summary endpoints, authRoute same as the DNS/traffic
	// statistics routes above (same sensitivity level — IP/domain/hostname).
	// GET only, so DisableEditMiddleware never blocks them; window is fixed
	// server-side (no query param accepted at all — plan §2.4).
	authRoute("GET /api/statistics/reference/ip", s.HandleGetIPReference)
	authRoute("GET /api/statistics/reference/domain", s.HandleGetDomainReference)
	// Capacity visibility (docs/ref/todo/statistics-capacity-visibility-plan.md
	// T-07, GitHub issue #123): current usage vs cap for all 9 RAM-only
	// tracking rings/indices — authRoute (not superAdminRoute), because the
	// response is pure counts/percentages with no domain/IP/hostname at all,
	// a strictly LOWER sensitivity than every other /api/statistics/* route
	// above.
	authRoute("GET /api/statistics/capacity", s.HandleGetCapacityStatistics)
	// Statistics -> Firewall page (docs/ref/todo/statistics-firewall-page-plan.md
	// T-06): rule-counter + NFLOG-sourced firewall traffic/blocked-event
	// summary — authRoute (not superAdminRoute), same sensitivity level as
	// /api/statistics/traffic (source IPs, rule names) which is also
	// authRoute only.
	authRoute("GET /api/statistics/firewall", s.HandleGetFirewallStatistics)
	authRoute("GET /api/dashboard/logs", s.HandleGetRecentLogs)
	authRoute("POST /api/dashboard/logs/clear", s.HandleClearLogs)
	authRoute("GET /api/dashboard/logs/stream", s.HandleLogStream)

	// 2.1 Central Event Log (audit trail). Reads are open to any logged-in role;
	// clearing destroys the audit trail so it is explicitly super_admin only
	// (and blocked entirely in -disable-edit mode like every other POST).
	authRoute("GET /api/logs/events", s.HandleGetSystemEvents)
	superAdminRoute("POST /api/logs/events/clear", s.HandleClearSystemEvents)

	// 2.2 Forward Traffic Log — live PASS/DROP packet events from the firewall
	// forward chain, read from the same RAM ring buffer as the dashboard logs
	// (never persisted). Read-only; clearing reuses /api/dashboard/logs/clear.
	authRoute("GET /api/logs/traffic", s.HandleGetTrafficLogs)

	// 2.2.1 Traffic log buffer usage summary (used/capacity/oldest/newest/
	// evicted) for the Forward/Local Traffic page header — a small dedicated
	// payload separate from /api/statistics/capacity's 11-ring response
	// (docs/ref/todo/firewall-log-buffer-capacity-plan.md T-04, issue #134).
	authRoute("GET /api/logs/traffic/usage", s.HandleGetTrafficLogUsage)

	// 3. Network Interfaces
	authRoute("GET /api/interfaces", s.HandleGetInterfaces)
	authRoute("POST /api/interfaces/vlan", s.HandleCreateVlan)
	authRoute("PUT /api/interfaces/{id}", s.HandleUpdateInterface)
	authRoute("PATCH /api/interfaces/{id}", s.HandlePatchInterface)
	authRoute("POST /api/interfaces/{id}/toggle", s.HandleToggleInterface)
	authRoute("POST /api/interfaces/{id}/reset", s.HandleResetInterface)
	authRoute("DELETE /api/interfaces/{id}", s.HandleDeleteInterface)
	authRoute("GET /api/interfaces/{id}/scan", s.HandleScanWifi)
	authRoute("GET /api/interfaces/{id}/wifi-status", s.HandleGetWifiStatus)

	// 3.1 Wi-Fi Saved Networks (presets, issue #66) — SENSITIVE: every route
	// here (including the list GET) handles Wi-Fi credentials, so all five are
	// explicit superAdminRoute rather than authRoute, unlike most list/read
	// endpoints elsewhere in this file (decision locked in
	// wifi-presets-plan.md section 0.1).
	superAdminRoute("GET /api/wifi-presets", s.HandleGetWifiPresets)
	superAdminRoute("POST /api/wifi-presets", s.HandleCreateWifiPreset)
	superAdminRoute("PUT /api/wifi-presets/{id}", s.HandleUpdateWifiPreset)
	superAdminRoute("DELETE /api/wifi-presets/{id}", s.HandleDeleteWifiPreset)
	superAdminRoute("POST /api/wifi-presets/{id}/apply", s.HandleApplyWifiPreset)

	// 4. Firewall Policies
	authRoute("GET /api/policies", s.HandleGetPolicies)
	// GET /api/policies/stats: per-rule usage statistics (docs/ref/todo/
	// firewall-policy-rule-usage-stats-plan.md T-06) — authRoute, not
	// superAdminRoute, same sensitivity level as /api/statistics/*.
	authRoute("GET /api/policies/stats", s.HandleGetPolicyStats)
	// GET /api/policies/{id}/endpoints: per-rule matched IP/service endpoints
	// (docs/ref/todo/firewall-rule-matched-endpoints-plan.md T-06) — same
	// authRoute sensitivity as /api/policies/stats and /api/logs/traffic (read
	// of data every logged-in role can already see).
	authRoute("GET /api/policies/{id}/endpoints", s.HandleGetPolicyRuleEndpoints)
	authRoute("POST /api/policies", s.HandleCreatePolicy)
	authRoute("PUT /api/policies/{id}", s.HandleUpdatePolicy)
	authRoute("DELETE /api/policies/{id}", s.HandleDeletePolicy)
	authRoute("PUT /api/policies/reorder", s.HandleReorderPolicies)
	authRoute("POST /api/policies/{id}/toggle-log", s.HandleTogglePolicyLog)
	authRoute("POST /api/policies/{id}/toggle-status", s.HandleTogglePolicyStatus)
	// Persisted "Monitor" opt-in counters (docs/ref/todo/
	// fqdn-retry-and-monitored-counters-plan.md D-6/T-11, issue #141) — same
	// authRoute level as toggle-log/toggle-status just above.
	authRoute("POST /api/policies/{id}/toggle-monitor", s.HandleTogglePolicyMonitor)
	authRoute("POST /api/policies/{id}/monitor/reset", s.HandleResetPolicyMonitorCounter)
	authRoute("POST /api/policies/apply", s.HandleApplyPolicies)

	// 4.1 Port Forwarding (DNAT / Virtual IP). Flat path per convention (like
	// /api/policies). Mutations re-apply the firewall automatically and are
	// blocked for read-only roles / -disable-edit by RoleReadOnlyMiddleware.
	authRoute("GET /api/port-forwards", s.HandleGetPortForwards)
	authRoute("POST /api/port-forwards", s.HandleCreatePortForward)
	authRoute("PUT /api/port-forwards/{id}", s.HandleUpdatePortForward)
	authRoute("DELETE /api/port-forwards/{id}", s.HandleDeletePortForward)

	// 5. Address Objects
	authRoute("GET /api/addresses", s.HandleGetAddresses)
	authRoute("POST /api/addresses", s.HandleCreateAddress)
	authRoute("PUT /api/addresses/{id}", s.HandleUpdateAddress)
	authRoute("DELETE /api/addresses/{id}", s.HandleDeleteAddress)
	authRoute("POST /api/addresses/bulk-delete", s.HandleBulkDeleteAddresses)

	// 6. Service Objects
	authRoute("GET /api/services", s.HandleGetServices)
	authRoute("POST /api/services", s.HandleCreateService)
	authRoute("PUT /api/services/{id}", s.HandleUpdateService)
	authRoute("DELETE /api/services/{id}", s.HandleDeleteService)

	// 7. Static Routes
	authRoute("GET /api/routes", s.HandleGetRoutes)
	authRoute("GET /api/routes/config", s.HandleGetRoutesConfig)
	authRoute("POST /api/routes", s.HandleCreateRoute)
	authRoute("PUT /api/routes/{id}", s.HandleUpdateRoute)
	authRoute("DELETE /api/routes/{id}", s.HandleDeleteRoute)
	authRoute("POST /api/routes/bulk-delete", s.HandleBulkDeleteRoutes)
	authRoute("POST /api/routes/{id}/toggle", s.HandleToggleRoute)
	authRoute("POST /api/routes/apply", s.HandleApplyRoutes)

	// 8. DHCP Server Settings
	authRoute("GET /api/dhcp/config", s.HandleGetDHCPConfig)
	authRoute("PUT /api/dhcp/config", s.HandleUpdateDHCPConfig)
	authRoute("GET /api/dhcp/configs", s.HandleGetDHCPConfigs)
	authRoute("POST /api/dhcp/configs", s.HandleCreateDHCPConfig)
	authRoute("PUT /api/dhcp/configs/{id}", s.HandleUpdateDHCPConfigByID)
	authRoute("DELETE /api/dhcp/configs/{id}", s.HandleDeleteDHCPConfig)
	authRoute("POST /api/dhcp/configs/{id}/toggle", s.HandleToggleDHCPConfig)
	authRoute("GET /api/dhcp/interfaces", s.HandleGetAvailableInterfaces)
	authRoute("GET /api/dhcp/reservations", s.HandleGetDHCPReservations)
	authRoute("POST /api/dhcp/reservations", s.HandleCreateDHCPReservation)
	authRoute("PUT /api/dhcp/reservations/{id}", s.HandleUpdateDHCPReservation)
	authRoute("DELETE /api/dhcp/reservations/{id}", s.HandleDeleteDHCPReservation)
	authRoute("GET /api/dhcp/leases", s.HandleGetDHCPLeases)
	authRoute("POST /api/dhcp/apply", s.HandleApplyDHCP)

	// 8.1 DNS Server Settings (dnsmasq Local Zone/Records)
	authRoute("GET /api/dns/zones", s.HandleGetDNSZones)
	authRoute("POST /api/dns/zones", s.HandleCreateDNSZone)
	authRoute("PUT /api/dns/zones/{id}", s.HandleUpdateDNSZone)
	authRoute("DELETE /api/dns/zones/{id}", s.HandleDeleteDNSZone)
	authRoute("POST /api/dns/zones/{id}/toggle", s.HandleToggleDNSZone)
	authRoute("GET /api/dns/zones/{id}/records", s.HandleGetDNSRecords)
	authRoute("POST /api/dns/zones/{id}/records", s.HandleCreateDNSRecord)
	authRoute("PUT /api/dns/records/{id}", s.HandleUpdateDNSRecord)
	authRoute("DELETE /api/dns/records/{id}", s.HandleDeleteDNSRecord)
	authRoute("POST /api/dns/apply", s.HandleApplyDNSServer)
	authRoute("POST /api/dns/clear-cache", s.HandleClearDNSCache)
	authRoute("GET /api/dns/settings", s.HandleGetDNSServerSettings)
	authRoute("PUT /api/dns/settings", s.HandleUpdateDNSServerSettings)
	// NS-delegation glue auto-lookup (docs/ref/todo/dns-ns-delegation-plan.md
	// T-06): a read-only GET, so DisableEditMiddleware/RoleReadOnlyMiddleware
	// never block it (they only gate POST/PUT/DELETE/PATCH), same as
	// GET /api/interfaces/{id}/scan above.
	authRoute("GET /api/dns/resolve-ns", s.HandleResolveNameserver)

	// 8.2 DNS Server — Blocked Domains (deny-list, docs/ref/todo/
	// dns-blocked-domains-plan.md)
	authRoute("GET /api/dns/blocked-domains", s.HandleGetBlockedDomains)
	authRoute("POST /api/dns/blocked-domains", s.HandleCreateBlockedDomain)
	authRoute("PUT /api/dns/blocked-domains/{id}", s.HandleUpdateBlockedDomain)
	authRoute("DELETE /api/dns/blocked-domains/{id}", s.HandleDeleteBlockedDomain)
	authRoute("POST /api/dns/blocked-domains/{id}/toggle", s.HandleToggleBlockedDomain)

	// 8.3 DNS Server — Blocklists (bulk hosts-file import, docs/ref/todo/
	// dns-blocklist-import-plan.md T-08). GET is authRoute like the deny-list
	// above, but every mutation is explicit superAdminRoute (not just
	// RoleReadOnlyMiddleware) because these endpoints make the board fetch a
	// user-supplied URL and write multi-MB files to disk — same reasoning as
	// reboot/config-export below.
	authRoute("GET /api/dns/blocklists", s.HandleGetDNSBlocklists)
	superAdminRoute("POST /api/dns/blocklists", s.HandleCreateDNSBlocklist)
	superAdminRoute("POST /api/dns/blocklists/upload", s.HandleUploadDNSBlocklist)
	superAdminRoute("PUT /api/dns/blocklists/{id}", s.HandleUpdateDNSBlocklist)
	superAdminRoute("DELETE /api/dns/blocklists/{id}", s.HandleDeleteDNSBlocklist)
	superAdminRoute("POST /api/dns/blocklists/{id}/toggle", s.HandleToggleDNSBlocklist)
	superAdminRoute("POST /api/dns/blocklists/{id}/refresh", s.HandleRefreshDNSBlocklist)

	// 9. System Management & Backup
	authRoute("GET /api/system/info", s.HandleGetSystemInfo)
	authRoute("GET /api/system/capabilities", s.HandleGetSystemCapabilities)
	authRoute("GET /api/system/time", s.HandleGetSystemTime)
	authRoute("PUT /api/system/time", s.HandleUpdateSystemTime)
	authRoute("POST /api/system/time/manual", s.HandleSetManualTime)
	authRoute("GET /api/system/hostname", s.HandleGetHostname)
	authRoute("PUT /api/system/hostname", s.HandleUpdateHostname)
	authRoute("GET /api/system/dhcp-health", s.HandleGetDhcpHealthSettings)
	authRoute("PUT /api/system/dhcp-health", s.HandleUpdateDhcpHealthSettings)
	authRoute("GET /api/system/dns", s.HandleGetDNSConfig)
	authRoute("PUT /api/system/dns", s.HandleUpdateDNSConfig)
	authRoute("PUT /api/system/password", s.HandleChangePassword)
	authRoute("GET /api/system/services", s.HandleGetSystemServices)
	authRoute("POST /api/system/services/{id}/restart", s.HandleRestartService)
	// Reboot/shutdown physically power-cycle the board — super_admin only, made
	// explicit here (same as config export/import) rather than relying on
	// RoleReadOnlyMiddleware to block the POST for lower roles.
	superAdminRoute("POST /api/system/reboot", s.HandleReboot)
	superAdminRoute("POST /api/system/shutdown", s.HandleShutdown)
	// Export/Import handle real Wi-Fi passwords and (optionally) user credential
	// hashes, so both are super_admin only — a read-only admin must not be able
	// to exfiltrate secrets via a backup.
	superAdminRoute("GET /api/system/config/export", s.HandleExportConfig)
	superAdminRoute("POST /api/system/config/import", s.HandleImportConfig)

	// 10. QoS Bandwidth Rules
	authRoute("GET /api/qos/rules", s.HandleGetQosRules)
	authRoute("POST /api/qos/rules", s.HandleCreateQosRule)
	authRoute("GET /api/qos/rules/{id}", s.HandleGetQosRule)
	authRoute("PUT /api/qos/rules/{id}", s.HandleUpdateQosRule)
	authRoute("DELETE /api/qos/rules/{id}", s.HandleDeleteQosRule)
	authRoute("POST /api/qos/rules/{id}/toggle", s.HandleToggleQosRule)
	authRoute("POST /api/qos/sync", s.HandleSyncQosRules)
	authRoute("GET /api/qos/status/{iface}", s.HandleGetQosIfaceStatus)
	authRoute("DELETE /api/qos/iface/{iface}", s.HandleClearQosIface)

	// 11. Multi-WAN Failover (docs/ref/todo/multi-wan-failover-plan.md Task 9,
	// Phase 1 only). All authRoute (same sensitivity as Static Routes/QoS
	// above) — the superAdminRoute-gated kill switch/manual override
	// endpoints are Phase 2 (Task 16) and are not registered yet.
	authRoute("GET /api/wan/uplinks", s.HandleGetWanUplinks)
	authRoute("POST /api/wan/uplinks", s.HandleCreateWanUplink)
	authRoute("PUT /api/wan/uplinks/{id}", s.HandleUpdateWanUplink)
	authRoute("DELETE /api/wan/uplinks/{id}", s.HandleDeleteWanUplink)
	authRoute("GET /api/wan/status", s.HandleGetWanStatus)
	authRoute("GET /api/wan/metrics", s.HandleGetWanMetrics)

	// Serve embedded static frontend files
	serveStatic(mux)

	// Body cap sits innermost (closest to the mux) so the config/import path can
	// still install its own larger 10 MB cap; every other endpoint gets 1 MB.
	var handler http.Handler = BodyLimitMiddleware(mux)
	if s.disableEdit {
		handler = DisableEditMiddleware(handler)
	}
	// Security headers wrap everything below; CORS stays OUTERMOST so even a 403
	// from an inner middleware still carries CORS (and now security) headers.
	return s.CORSMiddleware(SecurityHeadersMiddleware(handler))
}
