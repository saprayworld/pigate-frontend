package kernel

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"pigate/internal/model"
)

// MockFirewall implements FirewallManager for local testing
type MockFirewall struct {
	dockerCompat bool
	ApplyCount   int
}

func NewMockFirewall(dockerCompat bool) *MockFirewall {
	return &MockFirewall{
		dockerCompat: dockerCompat,
		ApplyCount:   0,
	}
}

// ApplyRules is a log-only no-op: it never parses addrs/svcs entry values
// (model.AddressEntry.Value / model.ServiceEntry.Port) — it only counts
// objects/rules for the log lines below. The real multi-value entry
// expansion (cartesian product over Entries, FQDN resolution, protocol
// splitting, etc.) lives exclusively in real_firewall.go's addressCombos/
// serviceCombos/addUserChainRules (docs/ref/todo/
// multi-value-address-service-objects-plan.md T-04/T-05).
func (m *MockFirewall) ApplyRules(
	rules []model.PolicyRule,
	ifaces []model.NetworkInterface,
	addrs []model.AddressObject,
	svcs []model.ServiceObject,
	dhcpServerIfaces []string,
	dnsServerIfaces []string,
	portForwards []model.PortForward,
) error {
	m.ApplyCount++
	log.Printf("[MockFirewall] Applying %d rules to mock kernel (Docker Compatibility: %t, Addresses: %d, Services: %d, PortForwards: %d):", len(rules), m.dockerCompat, len(addrs), len(svcs), len(portForwards))
	if m.dockerCompat {
		log.Printf("  [Docker Compat] Bypassing docker0 and br-* interfaces")
	}
	if len(dhcpServerIfaces) > 0 {
		log.Printf("  [DHCP Server] Opening udp/67 on interfaces: %v", dhcpServerIfaces)
	}
	if len(dnsServerIfaces) > 0 {
		log.Printf("  [DNS Server] Opening tcp+udp/53 on interfaces: %v", dnsServerIfaces)
	}

	// Log rule counts grouped by chain (T-08) so mock-mode dev runs can see
	// at a glance whether Local-In/Local-Out policies made it into the batch,
	// same as the real kernel now applies input/output/forward separately.
	byChain := map[string]int{
		model.PolicyChainForward: 0,
		model.PolicyChainInput:   0,
		model.PolicyChainOutput:  0,
	}
	for _, r := range rules {
		byChain[model.NormalizePolicyChain(r.Chain)]++
	}
	log.Printf("  [MockFirewall] forward: %d rule(s), input: %d rule(s), output: %d rule(s)",
		byChain[model.PolicyChainForward], byChain[model.PolicyChainInput], byChain[model.PolicyChainOutput])

	for _, r := range rules {
		statusStr := "DISABLED"
		if r.Status {
			statusStr = "ENABLED"
		}
		// Normalize before logging so mock mode reflects the same
		// multi-interface list the real kernel expands rules against
		// (docs/ref/todo/multi-interface-firewall-rule-plan.md §2.4, T-07) —
		// mock never expands rules per interface, it just needs to show the
		// full list instead of the (possibly stale) legacy scalar mirror.
		model.NormalizePolicyRuleInterfaces(&r)
		log.Printf("  [%s][%s] Name: %s, In: %v, Out: %v, Src: %v, Dest: %v, Svc: %v, Action: %s, Log: %t",
			statusStr, model.NormalizePolicyChain(r.Chain), r.Name, r.InInterfaces, r.OutInterfaces, r.Source, r.Destination, r.Service, r.Action, r.Log)
	}
	for _, pf := range portForwards {
		statusStr := "DISABLED"
		if pf.Status {
			statusStr = "ENABLED"
		}
		internal := pf.InternalIP
		if pf.InternalPort != "" {
			internal += ":" + pf.InternalPort
		}
		log.Printf("  [PortForward %s] Name: %s, In: %s, %s dport %s -> %s",
			statusStr, pf.Name, pf.InInterface, pf.Protocol, pf.ExternalPort, internal)
	}
	return nil
}

// FQDNResolutions implements kernel.FirewallManager.FQDNResolutions. Always
// returns an empty (non-nil) map — MockFirewall never resolves FQDN entries
// (see the ApplyRules doc comment above), and FQDNRefresher itself is never
// started in mock mode (repo.IsMockMode() guard, docs/ref/todo/
// fqdn-retry-and-monitored-counters-plan.md D-1/Caution 5), so this exists
// purely to satisfy the FirewallManager interface.
func (m *MockFirewall) FQDNResolutions() map[string][]string {
	return map[string][]string{}
}

// MockNetwork implements NetworkManager for local testing
type MockNetwork struct{}

func NewMockNetwork() *MockNetwork {
	return &MockNetwork{}
}

func (m *MockNetwork) ToggleInterface(name string, up bool) error {
	// Mock success
	return nil
}

func (m *MockNetwork) ConfigureInterface(name string, mode string, ip string, netmask string, gateway string, metric int) error {
	// Mock success
	log.Printf("[MockNetwork] ConfigureInterface: %s mode=%s ip=%s gateway=%s metric=%d", name, mode, ip, gateway, metric)
	return nil
}

func (m *MockNetwork) ConfigureWifi(name string, ssid string, password string, security string, backupSSID string, backupPassword string, backupSecurity string, macMode string, prefer5GHz bool) error {
	// Mock success
	log.Printf("[MockNetwork] ConfigureWifi: %s SSID=%q Security=%s MacMode=%s Prefer5GHz=%t", name, ssid, security, macMode, prefer5GHz)
	return nil
}

func (m *MockNetwork) ScanWifi(name string) ([]model.WifiScanResult, error) {
	return []model.WifiScanResult{
		{SSID: "MyHome_5G", Signal: 85, Security: "WPA2-PSK", Channel: 36, Frequency: "5 GHz"},
		{SSID: "MyHome_2G", Signal: 72, Security: "WPA2-PSK", Channel: 6, Frequency: "2.4 GHz"},
		{SSID: "Neighbor_AP", Signal: 45, Security: "WPA3", Channel: 11, Frequency: "2.4 GHz"},
		{SSID: "Cafe_Free_WiFi", Signal: 30, Security: "Open", Channel: 1, Frequency: "2.4 GHz"},
		{SSID: "Office_5G_Secured", Signal: 62, Security: "WPA2-Enterprise", Channel: 149, Frequency: "5 GHz"},
	}, nil
}

// CreateVlan is a log-only no-op in mock mode (never touches the OS). The VLAN
// still appears in the UI because GetKernelInterfaces' mock branch appends any DB
// row not already in the interface list.
func (m *MockNetwork) CreateVlan(parent string, vlanID int) error {
	log.Printf("[MockNetwork] CreateVlan: parent=%s vlanID=%d -> %s.%d", parent, vlanID, parent, vlanID)
	return nil
}

// DeleteVlan is a log-only no-op in mock mode.
func (m *MockNetwork) DeleteVlan(name string) error {
	log.Printf("[MockNetwork] DeleteVlan: %s", name)
	return nil
}

// GetIPv4Addresses always returns an empty slice in mock mode: there is no
// simulated address state to report, and the DHCP health-checker (issue #78)
// already guards against touching netlink at all in mock mode via
// repo.IsMockMode(). This is a safety net for any other future caller.
func (m *MockNetwork) GetIPv4Addresses(name string) ([]string, error) {
	log.Printf("[MockNetwork] GetIPv4Addresses: %s", name)
	return []string{}, nil
}

// DeleteAddress is a log-only no-op in mock mode.
func (m *MockNetwork) DeleteAddress(name string, cidr string) error {
	log.Printf("[MockNetwork] DeleteAddress: interface=%s cidr=%s", name, cidr)
	return nil
}

func (m *MockNetwork) GetWifiStatus(name string) (*model.WifiConnectionStatus, error) {
	return &model.WifiConnectionStatus{
		State:     "COMPLETED",
		SSID:      "MyHome_5G",
		BSSID:     "00:11:22:33:44:55",
		ActiveMac: "00:11:22:33:44:55",
		Freq:      5745,
		KeyMgmt:   "WPA3",
		WifiGen:   "WiFi 6",
	}, nil
}

// MockRouting implements RoutingManager for local testing
type MockRouting struct {
	enableEditSystemRoute bool
}

func NewMockRouting() *MockRouting {
	return &MockRouting{}
}

func (m *MockRouting) SetEnableEditSystemRoute(enable bool) {
	m.enableEditSystemRoute = enable
}

func (m *MockRouting) EnforceDefaultRouteMetric(ifaceName string, metric int) error {
	log.Printf("[MockRouting] EnforceDefaultRouteMetric called: Interface: %s, Metric: %d", ifaceName, metric)
	return nil
}

func (m *MockRouting) AddRoute(route model.StaticRoute) error {
	log.Printf("[MockRouting] AddRoute called: Dest: %s, Gateway: %s, Interface: %s", route.Destination, route.Gateway, route.Interface)
	return nil
}

func (m *MockRouting) DeleteRoute(route model.StaticRoute) error {
	log.Printf("[MockRouting] DeleteRoute called: Dest: %s, Gateway: %s, Interface: %s", route.Destination, route.Gateway, route.Interface)
	return nil
}

func (m *MockRouting) ApplyRoutes(routes []model.StaticRoute) error {
	log.Printf("[MockRouting] Applying %d static routes to mock kernel:", len(routes))
	for _, rt := range routes {
		statusStr := "DISABLED"
		if rt.Status {
			statusStr = "ENABLED"
		}
		log.Printf("  [%s] Dest: %s, Gateway: %s, Interface: %s, Metric: %d, Type: %s",
			statusStr, rt.Destination, rt.Gateway, rt.Interface, rt.Metric, rt.Type)
	}
	return nil
}

// MockDhcp implements DhcpManager for local testing
type MockDhcp struct {
	MockFromReal bool
}

func NewMockDhcp() *MockDhcp {
	return &MockDhcp{}
}

func (m *MockDhcp) ApplyConfig(cfgs []model.DhcpConfig, reservations []model.DhcpReservation) error {
	// Mirror RealDhcpManager.ApplyConfig's validate-and-skip so a -mock=true dev
	// loop surfaces the same behavior: an enabled-but-invalid scope is skipped
	// (with a log line), not silently treated as applied.
	for _, cfg := range cfgs {
		if !cfg.Enabled {
			continue
		}
		if err := model.ValidateDhcpConfig(cfg); err != nil {
			log.Printf("[MockDhcp] Skipping invalid DHCP config (iface=%q start=%q end=%q): %v", cfg.Interface, cfg.StartIP, cfg.EndIP, err)
			continue
		}
	}
	return nil
}

func (m *MockDhcp) ReloadConfig() error {
	return nil
}

func (m *MockDhcp) WatchLeases(ctx context.Context, callback func(event string, lease model.ActiveDhcpLease)) error {
	// Mock no-op watcher
	<-ctx.Done()
	return nil
}

func parseDnsmasqLeases(filePath string) ([]model.ActiveDhcpLease, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var leases []model.ActiveDhcpLease
	lines := strings.Split(string(data), "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mac := fields[1]
		ip := fields[2]
		hostname := fields[3]
		if hostname == "*" {
			hostname = "Unknown"
		}
		leases = append(leases, model.ActiveDhcpLease{
			ID:         fmt.Sprintf("lease-real-%d", idx),
			IPAddress:  ip,
			MacAddress: mac,
			Hostname:   hostname,
			ExpiresIn:  "Active (Real)",
		})
	}
	return leases, nil
}

func parseDhcpdLeases(filePath string) ([]model.ActiveDhcpLease, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var leases []model.ActiveDhcpLease
	content := string(data)
	parts := strings.Split(content, "lease ")
	idx := 0
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || !strings.Contains(part, "{") {
			continue
		}
		subParts := strings.SplitN(part, "{", 2)
		ip := strings.TrimSpace(subParts[0])
		body := subParts[1]

		var mac, hostname string
		lines := strings.Split(body, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "hardware ethernet ") {
				mac = strings.TrimPrefix(line, "hardware ethernet ")
				mac = strings.TrimSuffix(mac, ";")
				mac = strings.TrimSpace(mac)
			} else if strings.HasPrefix(line, "client-hostname ") {
				hostname = strings.TrimPrefix(line, "client-hostname ")
				hostname = strings.TrimSuffix(hostname, ";")
				hostname = strings.Trim(hostname, "\"")
				hostname = strings.TrimSpace(hostname)
			}
		}
		if mac != "" {
			if hostname == "" {
				hostname = "Unknown"
			}
			leases = append(leases, model.ActiveDhcpLease{
				ID:         fmt.Sprintf("lease-real-%d", idx),
				IPAddress:  ip,
				MacAddress: mac,
				Hostname:   hostname,
				ExpiresIn:  "Active (Real)",
			})
			idx++
		}
	}
	return leases, nil
}

func (m *MockDhcp) GetActiveLeases() ([]model.ActiveDhcpLease, error) {
	if m.MockFromReal {
		// Try parsing dnsmasq leases
		if leases, err := parseDnsmasqLeases("/var/lib/misc/dnsmasq.leases"); err == nil && len(leases) > 0 {
			return leases, nil
		}
		// Try parsing dhcpd leases
		if leases, err := parseDhcpdLeases("/var/lib/dhcp/dhcpd.leases"); err == nil && len(leases) > 0 {
			return leases, nil
		}
	}

	return []model.ActiveDhcpLease{
		{ID: "lease-1", IPAddress: "192.168.1.101", MacAddress: "99:88:77:66:55:44", Hostname: "iPhone-13", ExpiresIn: "11 hours, 45 mins"},
		{ID: "lease-2", IPAddress: "192.168.1.102", MacAddress: "AA:BB:CC:DD:EE:FF", Hostname: "Android-SmartTV", ExpiresIn: "23 hours, 10 mins"},
		{ID: "lease-3", IPAddress: "192.168.1.105", MacAddress: "B4:F1:DA:C8:E2:10", Hostname: "iPad-Pro", ExpiresIn: "2 hours, 15 mins"},
	}, nil
}

// MockQos implements QosManager for local development and testing.
// All operations are no-ops but log their parameters for visibility.
type MockQos struct{}

func NewMockQos() *MockQos {
	return &MockQos{}
}

func (m *MockQos) ApplyQosRules(rules []model.QosRule) error {
	log.Printf("[MockQos] ApplyQosRules called with %d rule(s):", len(rules))
	for _, r := range rules {
		statusStr := "DISABLED"
		if r.Status {
			statusStr = "ENABLED"
		}
		log.Printf("  [%s] %s — iface=%s src=%s dst=%s egress=%d/%dMbps ingress=%d/%dMbps prio=%d",
			statusStr, r.Name, r.Interface,
			r.MatchSrcIP, r.MatchDstIP,
			r.EgressRateMbps, r.EgressCeilMbps,
			r.IngressRateMbps, r.IngressCeilMbps,
			r.Priority,
		)
	}
	return nil
}

func (m *MockQos) ClearQosRules(ifaceName string) error {
	log.Printf("[MockQos] ClearQosRules called for interface: %s", ifaceName)
	return nil
}

func (m *MockQos) GetIfaceQosStatus(ifaceName string) (*model.QosIfaceStatus, error) {
	log.Printf("[MockQos] GetIfaceQosStatus called for interface: %s", ifaceName)
	return &model.QosIfaceStatus{
		Interface:        ifaceName,
		HasQdisc:         false,
		Classes:          []model.QosClass{},
		IngressSupported: true, // mock runs on a dev workstation; assume supported
	}, nil
}

// MockDNSServerManager implements DNSServerManager for local testing.
// ApplyCount lets tests assert exactly how many times ApplyZones (== a
// dnsmasq config write + restart) fired — e.g. a TTL/cap-only settings
// change must NOT increment it (docs/ref/todo/
// statistics-dns-top-domain-plan.md §5 item 18 / T-11 item 7).
//
// blocklists/blocklistConfs/manifest (docs/ref/todo/
// dns-blocklist-import-plan.md T-02) are held ENTIRELY in RAM — this mock
// must never touch the real filesystem, so `-mock=true` dev/CI runs stay
// 100% safe regardless of what the blocklist feature does.
type MockDNSServerManager struct {
	ApplyCount int

	mu             sync.Mutex
	blocklists     map[string][]byte // id -> <id>.hosts content
	blocklistConfs map[string][]byte // id -> <id>.conf content
	manifest       []byte
}

func NewMockDNSServerManager() *MockDNSServerManager {
	return &MockDNSServerManager{
		blocklists:     make(map[string][]byte),
		blocklistConfs: make(map[string][]byte),
	}
}

func (m *MockDNSServerManager) ApplyZones(zones []model.DNSZone, interfaces []string, upstreamServers []string, queryLog bool, blocked []model.BlockedDomain, blocklists []model.BlocklistRef) error {
	m.ApplyCount++
	log.Printf("[MockDNSServer] ApplyZones called with %d zones, interfaces: %v, upstream servers: %v, queryLog: %t, %d blocked domains, %d blocklists", len(zones), interfaces, upstreamServers, queryLog, len(blocked), len(blocklists))
	return nil
}

func (m *MockDNSServerManager) ClearCache() error {
	log.Printf("[MockDNSServer] ClearCache called")
	return nil
}

// --- Blocklist import (T-02) — in-memory equivalents of dns_blocklist.go ---

func (m *MockDNSServerManager) WriteBlocklistFile(id string, content []byte) error {
	if err := model.ValidateDNSBlocklistID(id); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocklists[id] = append([]byte(nil), content...)
	return nil
}

func (m *MockDNSServerManager) WriteBlocklistConfFile(id string, content []byte) error {
	if err := model.ValidateDNSBlocklistID(id); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocklistConfs[id] = append([]byte(nil), content...)
	return nil
}

func (m *MockDNSServerManager) RemoveBlocklistFile(id string) error {
	if err := model.ValidateDNSBlocklistID(id); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blocklists, id)
	delete(m.blocklistConfs, id)
	return nil
}

func (m *MockDNSServerManager) RemoveBlocklistConfFile(id string) error {
	if err := model.ValidateDNSBlocklistID(id); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blocklistConfs, id)
	return nil
}

func (m *MockDNSServerManager) BlocklistFileInfo(id string) (int64, bool) {
	if err := model.ValidateDNSBlocklistID(id); err != nil {
		return 0, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	content, ok := m.blocklists[id]
	if !ok {
		return 0, false
	}
	return int64(len(content)), true
}

func (m *MockDNSServerManager) BlocklistConfFileInfo(id string) (int64, bool) {
	if err := model.ValidateDNSBlocklistID(id); err != nil {
		return 0, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	content, ok := m.blocklistConfs[id]
	if !ok {
		return 0, false
	}
	return int64(len(content)), true
}

// BlocklistConfContent is a MOCK-ONLY test helper (NOT part of the
// DNSServerManager interface, so it requires no change to the real
// implementation) that returns the raw bytes last written via
// WriteBlocklistConfFile for id — used by service-layer tests (docs/ref/todo/
// dns-blocklist-import-plan.md T-05) to assert the actual rendered content of
// <id>.conf (e.g. that it contains "address=/<domain>/" for every domain),
// which BlocklistConfFileInfo's size-only return cannot verify.
func (m *MockDNSServerManager) BlocklistConfContent(id string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	content, ok := m.blocklistConfs[id]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), content...), true
}

func (m *MockDNSServerManager) StreamBlocklistFile(id string, fn func(line string) error) error {
	if err := model.ValidateDNSBlocklistID(id); err != nil {
		return err
	}
	m.mu.Lock()
	content, ok := m.blocklists[id]
	m.mu.Unlock()
	if !ok {
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		if err := fn(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (m *MockDNSServerManager) ReadBlocklistManifest() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.manifest) == 0 {
		return nil, nil
	}
	return append([]byte(nil), m.manifest...), nil
}

func (m *MockDNSServerManager) WriteBlocklistManifest(content []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.manifest = append([]byte(nil), content...)
	return nil
}

func (m *MockDNSServerManager) QuarantineBlocklistManifest() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Printf("[MockDNSServer] Quarantining corrupt manifest (in-memory, discarded — nothing written to disk)")
	m.manifest = nil
	return nil
}

// SupportsBulkNXDomain always returns true in mock mode: dev workstations
// don't run the board's dnsmasq at all, so there is no real version to
// probe, and the whole point of mock mode is to let nxdomain-mode
// blocklists be exercised without a Pi (plan §3 T-07 item 6).
func (m *MockDNSServerManager) SupportsBulkNXDomain() bool {
	return true
}

// mockDNSQueryEvents are the synthetic query events WatchDNSLog cycles
// through in -mock=true dev mode (docs/ref/todo/
// statistics-dns-top-domain-plan.md T-06, extended by
// dns-query-statistics-drilldown-plan.md T-04). Deliberately a (domain,
// client) *matrix* rather than a 1:1 mapping so both drill-down directions
// in -mock=true show more than a single row:
//   - www.youtube.com is queried from 3 distinct clients (.101/.102/.105)
//     at different weights, for the domain->clients drill-down test.
//   - netflix.com is queried from 2 distinct clients (.101/.102).
//   - line-apps.com and cdn.jsdelivr.net are each queried from a single
//     client, to exercise the single-row drill-down edge case.
//   - ads.doubleclick.net and ads.googlesyndication.com are two obviously
//     ad-network domains (docs/ref/todo/dns-blocked-query-statistics-plan.md
//     T-14), so `-mock=true` dev mode has real query traffic to classify as
//     "blocked" once a matching deny-list entry is configured — this file
//     never touches the deny-list itself (that's real DB data, unaffected by
//     mock mode); it only ensures the query-log side of the pipeline has
//     something a deny-list rule for "doubleclick.net"/"googlesyndication.com"
//     would actually match.
//
// Weights keep the same few LAN clients MockDhcp/mockFlowTemplates already
// use, at different relative frequencies so the "Top Queried Domains" card
// ranking visibly differs row to row.
var mockDNSQueryEvents = []struct {
	domain   string
	qtype    string
	clientIP string
	weight   int // higher = queried more often
}{
	{"www.youtube.com", "A", "192.168.1.101", 5},
	{"www.youtube.com", "A", "192.168.1.102", 3},
	{"www.youtube.com", "A", "192.168.1.105", 1},
	{"googlevideo.com", "A", "192.168.1.101", 4},
	{"netflix.com", "A", "192.168.1.102", 3},
	{"netflix.com", "A", "192.168.1.101", 2},
	{"line-apps.com", "A", "192.168.1.105", 2},
	{"cdn.jsdelivr.net", "A", "192.168.1.105", 1},
	{"ads.doubleclick.net", "A", "192.168.1.101", 2},
	{"ads.googlesyndication.com", "A", "192.168.1.102", 1},
}

// mockDNSAnswerEvents map IPs to domains that intentionally mirror
// mockFlowTemplates' dstIP values (plan T-06 of
// statistics-dns-page-revamp-plan.md), so both the legacy Top Destinations/
// Conversations cards and the DNS statistics volume table (domain -> IP ->
// bytes join) show real, non-zero numbers in -mock=true dev mode:
//   - www.youtube.com resolves to 3 IPs, two of which (142.250.80.46,
//     64.233.166.127) match dstIP values in mockFlowTemplates.
//   - googlevideo.com resolves to 2 IPs, one of which (173.194.76.94)
//     matches a mockFlowTemplates dstIP.
//   - 64.233.166.127 is deliberately shared between www.youtube.com and
//     googlevideo.com so the "shared IP" flag/badge has a real case to
//     exercise in mock mode (plan §1.1 item 1 / DNSDomainIP.Shared).
//   - cdn.jsdelivr.net keeps a single IP match, for the plain single-row
//     case.
//   - line-apps.com is intentionally left with no answer entries at all, so
//     the "domain with unknown IPs" empty-case is exercisable.
//   - 8.8.8.8 and 203.0.113.55 remain deliberately unmapped so the "IP with
//     no known domain" fallback path is exercised too.
var mockDNSAnswerEvents = []struct {
	domain string
	ip     string
}{
	{"www.youtube.com", "142.250.80.46"},
	{"www.youtube.com", "64.233.166.127"},
	{"www.youtube.com", "172.217.16.14"},
	{"googlevideo.com", "173.194.76.94"},
	{"googlevideo.com", "64.233.166.127"},
	{"cdn.jsdelivr.net", "151.101.1.69"},
}

// mockDNSLogInterval mirrors mockFlowEndInterval's dev-visibility rationale —
// fast enough to see the cards move without spamming.
const mockDNSLogInterval = 2 * time.Second

// WatchDNSLog synthesizes query and answer events on a ticker. It never
// touches the filesystem (plan §5 item 14/Caution 9: -mock=true must be
// 100% safe on a dev workstation).
func (m *MockDNSServerManager) WatchDNSLog(ctx context.Context, cb func(model.DNSLogEvent)) error {
	ticker := time.NewTicker(mockDNSLogInterval)
	defer ticker.Stop()
	tick := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Emit a query, weighted by picking from a flattened list so
			// higher-weight domains show up more often across ticks.
			total := 0
			for _, e := range mockDNSQueryEvents {
				total += e.weight
			}
			if total > 0 {
				pick := tick % total
				acc := 0
				for _, e := range mockDNSQueryEvents {
					acc += e.weight
					if pick < acc {
						cb(model.DNSLogEvent{
							Kind:      model.DNSLogQuery,
							Domain:    e.domain,
							QueryType: e.qtype,
							ClientIP:  e.clientIP,
						})
						break
					}
				}
			}
			// Emit every mockDNSAnswerEvents entry every other tick, so the
			// reverse cache *and* the new domain->IP forward index (plan
			// T-02 of statistics-dns-page-revamp-plan.md) both get fully
			// populated in dev mode — a subset would silently hide the
			// multi-IP/shared-IP cases mockDNSAnswerEvents was built for.
			if len(mockDNSAnswerEvents) > 0 && tick%2 == 0 {
				for _, a := range mockDNSAnswerEvents {
					cb(model.DNSLogEvent{
						Kind:     model.DNSLogAnswer,
						Domain:   a.domain,
						AnswerIP: a.ip,
					})
				}
			}
			tick++
		}
	}
}

// MockDhcpcdManager implements DhcpcdManager for local testing
type MockDhcpcdManager struct{}

func NewMockDhcpcdManager() *MockDhcpcdManager {
	return &MockDhcpcdManager{}
}

func (m *MockDhcpcdManager) StartDhcpcd(ifaceName string) error {
	log.Printf("[MockDhcpcd] Simulating starting dhcpcd for %s", ifaceName)
	return nil
}

func (m *MockDhcpcdManager) StopDhcpcd(ifaceName string) error {
	log.Printf("[MockDhcpcd] Simulating stopping/releasing dhcpcd for %s", ifaceName)
	return nil
}

func (m *MockDhcpcdManager) SetShareHostname(share bool) error {
	log.Printf("[MockDhcpcd] Simulating writing dhcpcd.conf (share hostname: %t)", share)
	return nil
}

func (m *MockDhcpcdManager) RestartDhcpcd(ifaceName string) error {
	log.Printf("[MockDhcpcd] Simulating restarting dhcpcd for %s", ifaceName)
	return nil
}

// MockHostnameManager implements HostnameManager in-memory for local testing
type MockHostnameManager struct {
	hostname string
}

func NewMockHostnameManager() *MockHostnameManager {
	return &MockHostnameManager{hostname: "pigate-mock"}
}

func (m *MockHostnameManager) GetHostname() (string, error) {
	return m.hostname, nil
}

func (m *MockHostnameManager) SetHostname(name string) error {
	log.Printf("[MockHostname] Simulating setting hostname to %q", name)
	m.hostname = name
	return nil
}

// MockPowerManager implements PowerManager for local testing. It MUST NOT have
// any side effect — dev machines run with -mock=true and a real reboot/poweroff
// here would take down the developer's own workstation. It only logs.
type MockPowerManager struct{}

func NewMockPowerManager() *MockPowerManager {
	return &MockPowerManager{}
}

func (m *MockPowerManager) Reboot() error {
	log.Printf("[MockPower] Simulating system reboot (no-op)")
	return nil
}

func (m *MockPowerManager) PowerOff() error {
	log.Printf("[MockPower] Simulating system power-off (no-op)")
	return nil
}

// MockSystemServiceManager implements SystemServiceManager for local testing.
// It MUST NOT have any side effect — dev machines run with -mock=true and a
// real RestartUnit call here could disrupt the developer's own workstation
// services. GetStatus always reports every unit as active/loaded; Restart
// only logs (mirrors MockPowerManager).
type MockSystemServiceManager struct{}

func NewMockSystemServiceManager() *MockSystemServiceManager {
	return &MockSystemServiceManager{}
}

func (m *MockSystemServiceManager) GetStatus(unit string) (model.ServiceRuntimeState, error) {
	return model.ServiceRuntimeState{ActiveState: "active", Loaded: true}, nil
}

func (m *MockSystemServiceManager) Restart(unit string) error {
	log.Printf("[MockSystemService] Simulating restart of %s (no-op)", unit)
	return nil
}

// MockCapabilityProber implements CapabilityProber for local/dev testing. It
// has no side effects and always reports every subsystem as available with
// reason "mock", so dev machines running -mock=true never see a capability
// warning banner (docs/ref/todo/kernel-capability-detection-plan.md §0).
// Its id set MUST stay in sync with RealCapabilityProber's registry
// (firewall, dbus, dnsmasq, resolved, conntrack, conntrack-events,
// icmp-probe).
type MockCapabilityProber struct{}

func NewMockCapabilityProber() *MockCapabilityProber {
	return &MockCapabilityProber{}
}

func (m *MockCapabilityProber) ProbeAll() []model.CapabilityProbeResult {
	ids := []string{"firewall", "dbus", "dnsmasq", "resolved", "conntrack", "conntrack-events", "icmp-probe"}
	out := make([]model.CapabilityProbeResult, 0, len(ids))
	for _, id := range ids {
		out = append(out, model.CapabilityProbeResult{
			ID:        id,
			Available: true,
			Reason:    model.CapabilityReasonMock,
		})
	}
	return out
}

// MockTimeManager implements TimeManager in-memory for local testing. It keeps
// the last-applied timezone/NTP/server values and simulates a synced clock.
type MockTimeManager struct {
	timezone  string
	ntpOn     bool
	ntpServer string
	manual    time.Time // zero unless SetTime was called
}

func NewMockTimeManager() *MockTimeManager {
	return &MockTimeManager{timezone: "Asia/Bangkok", ntpOn: true, ntpServer: "pool.ntp.org"}
}

func (m *MockTimeManager) GetTimeStatus() (*model.TimeStatus, error) {
	now := time.Now()
	if !m.ntpOn && !m.manual.IsZero() {
		now = m.manual
	}
	return &model.TimeStatus{
		CurrentTime:     now.Format(time.RFC3339),
		NTPSynchronized: m.ntpOn,
	}, nil
}

func (m *MockTimeManager) SetTimezone(tz string) error {
	log.Printf("[MockTime] Simulating set timezone to %q", tz)
	m.timezone = tz
	return nil
}

func (m *MockTimeManager) SetNTP(enable bool) error {
	log.Printf("[MockTime] Simulating set NTP to %t", enable)
	m.ntpOn = enable
	return nil
}

func (m *MockTimeManager) SetTime(t time.Time) error {
	log.Printf("[MockTime] Simulating set clock to %s", t.Format(time.RFC3339))
	m.manual = t
	return nil
}

func (m *MockTimeManager) SetNTPServer(server string) error {
	log.Printf("[MockTime] Simulating set NTP server to %q", server)
	m.ntpServer = server
	return nil
}

// MockSystemStats implements SystemStatsManager with simulated values that drift
// over time, so the dashboard visibly moves during -mock development on WSL. The
// CPU snapshot advances monotonically each call with a busy/idle mix that swings
// gently, which the service's delta logic turns into a plausible usage%.
type MockSystemStats struct {
	mu       sync.Mutex
	tick     uint64
	totalJif uint64
	idleJif  uint64
}

func NewMockSystemStats() *MockSystemStats {
	return &MockSystemStats{}
}

// wave returns a smooth 0..1 oscillation offset by phase, driven by tick.
func (m *MockSystemStats) wave(phase float64) float64 {
	return (math.Sin(float64(m.tick)/6.0+phase) + 1) / 2
}

func (m *MockSystemStats) GetCPUSnapshot() (*model.CPUSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tick++
	// Each tick adds ~1000 jiffies total; the busy fraction swings ~10-45%.
	busyFrac := 0.10 + 0.35*m.wave(0)
	const step = 1000
	m.totalJif += step
	m.idleJif += uint64(float64(step) * (1 - busyFrac))
	return &model.CPUSnapshot{Idle: m.idleJif, Total: m.totalJif}, nil
}

func (m *MockSystemStats) GetCPUInfo() (*model.CPUInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &model.CPUInfo{
		Cores:         4,
		ModelName:     "Mock Cortex-A76 (simulated)",
		FreqMHz:       round1(1500 + 900*m.wave(1)),
		FreqAvailable: true,
	}, nil
}

func (m *MockSystemStats) GetMemoryInfo() (*model.MemoryInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	const total = uint64(8) * 1024 * 1024 * 1024 // 8 GB
	pct := 45 + 20*m.wave(2)
	used := uint64(float64(total) * pct / 100.0)
	return &model.MemoryInfo{UsedBytes: used, TotalBytes: total, Percent: round1(pct)}, nil
}

func (m *MockSystemStats) GetTemperature() (*model.TemperatureInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &model.TemperatureInfo{
		Celsius:         round1(52 + 10*m.wave(3)),
		ThrottleCelsius: 80,
		Available:       true,
	}, nil
}

func (m *MockSystemStats) GetDiskUsage(path string) (*model.DiskUsage, error) {
	const total = uint64(128) * 1024 * 1024 * 1024 // 128 GB
	used := total * 32 / 100                       // ~32% used
	return &model.DiskUsage{
		Path:       path,
		UsedBytes:  used,
		TotalBytes: total,
		Percent:    32.0,
	}, nil
}

func (m *MockSystemStats) GetHostInfo() (*model.HostInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &model.HostInfo{
		OSName:        "PiGate Mock OS (simulated)",
		BoardModel:    "Raspberry Pi 5 Model B (mock)",
		KernelVersion: "6.6.31-mock",
		// Fixed base + drift so the uptime advances during a session.
		UptimeSeconds: int64(273153 + m.tick),
	}, nil
}

func (m *MockSystemStats) GetNetCounters() (map[string]model.NetCounters, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Advance counters monotonically so the traffic collector sees positive
	// deltas. rx grows faster than tx (typical download-heavy gateway). Counters
	// are emitted for every interface the mock DB might mark WAN (eth0/eth1/
	// wlan0) so the traffic chart moves regardless of which one is the WAN role.
	rx := uint64(float64(m.tick) * (400_000 + 300_000*m.wave(4)))
	tx := uint64(float64(m.tick) * (120_000 + 80_000*m.wave(5)))
	return map[string]model.NetCounters{
		"eth0":  {RxBytes: rx, TxBytes: tx},
		"eth1":  {RxBytes: rx / 3, TxBytes: tx / 3},
		"wlan0": {RxBytes: rx / 2, TxBytes: tx / 2},
		"lo":    {RxBytes: rx * 4, TxBytes: rx * 4}, // must be excluded by collector
	}, nil
}

// GetConntrackCount returns a synthetic conntrack occupancy that drifts over
// time (never reads /proc), so the mock Active Sessions chart visibly moves
// during -mock development.
func (m *MockSystemStats) GetConntrackCount() (count int, max int, available bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count = 400 + int(300*m.wave(4))
	max = 262144
	available = true
	return count, max, available
}

// MockTrafficLog implements TrafficLogManager for local/mock testing. It
// synthesizes forward-traffic events on a timer (no netlink socket is ever
// opened — safe to run on a dev workstation) so the Forward Traffic page and
// the Dashboard Recent Logs widget have a live feed without a real kernel.
type MockTrafficLog struct {
	// ruleIDProvider is optional (opt-in via SetRuleIDProvider): when unset,
	// behavior is unchanged from before — every sample below uses its
	// hardcoded ruleID literally, which never matches a real DB policy id
	// (docs/ref/todo/firewall-rule-matched-endpoints-plan.md T-07 "สภาพ
	// ปัจจุบัน"). When set, samples whose ruleID is meant to look like a
	// resolvable DB rule get a random id drawn from the provider instead, so
	// -mock=true has real data for GET /api/policies/{id}/endpoints. At least
	// one sample per Watch* method keeps a deliberately-unresolvable id and
	// one keeps an empty id, regardless of whether a provider is set — those
	// two cases (a rule that can't be resolved, and "no rule at all") must
	// stay exercisable in mock mode.
	ruleIDProvider func() []string
}

func NewMockTrafficLog() *MockTrafficLog {
	return &MockTrafficLog{}
}

// SetRuleIDProvider wires an opt-in source of live DB policy-rule ids (see
// the ruleIDProvider field doc comment). fn is called once per synthesized
// sample that wants a "real" id — main.go's mock wiring reads the DB once at
// startup and returns that static snapshot, which is enough for dev/test
// purposes and keeps this package free of any DB dependency.
func (m *MockTrafficLog) SetRuleIDProvider(fn func() []string) {
	m.ruleIDProvider = fn
}

// pickRuleID returns a random id from m.ruleIDProvider() when set and
// non-empty, otherwise falls back to fallback unchanged (preserves the
// pre-T-07 behavior when no provider is wired, or the provider has nothing
// to offer yet).
func (m *MockTrafficLog) pickRuleID(rng *rand.Rand, fallback string) string {
	if m.ruleIDProvider == nil {
		return fallback
	}
	ids := m.ruleIDProvider()
	if len(ids) == 0 {
		return fallback
	}
	return ids[rng.Intn(len(ids))]
}

func (m *MockTrafficLog) WatchForwardTraffic(ctx context.Context, cb func(model.FirewallLog)) error {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	type sample struct {
		action string
		dest   string
		port   string
		proto  string
		in     string
		out    string
		reason string
		// ruleID exercises the three cases the ruleName resolver has to
		// handle (docs/ref/todo/traffic-log-rule-name-and-domain-plan.md):
		// an id that resolves against a real DB policy, one that doesn't
		// (rule was deleted/never existed — resolver falls back to a muted
		// "unknown rule" display), and empty (structural drop, no single
		// rule to blame).
		ruleID string
		// liveID: when a ruleIDProvider is wired (T-07), replace ruleID with
		// a randomly-chosen real DB rule id for this sample. Left false on
		// the two samples above that must keep exercising the
		// unresolvable/empty cases even with a provider set.
		liveID bool
	}
	samples := []sample{
		{"PASS", "8.8.8.8", "53", "UDP", "eth0", "eth1", "Allowed (forward)", "rule-allow-dns", true},
		{"PASS", "142.250.80.46", "443", "TCP", "eth0", "eth1", "Allowed (forward)", "rule-allow-web", true},
		{"PASS", "1.1.1.1", "443", "TCP", "wlan0", "eth1", "Allowed (forward)", "rule-allow-web", true},
		{"DROP", "185.220.101.4", "23", "TCP", "eth0", "eth1", "Blocked (forward)", "rule-block-telnet", true},
		{"DROP", "45.13.104.9", "3389", "TCP", "wlan0", "eth1", "Blocked (forward)", "rule-deleted-demo", false},
		{"PASS", "140.82.113.3", "22", "TCP", "eth0", "eth1", "Allowed (forward)", "", false},
		{"DROP", "203.0.113.99", "443", "TCP", "eth0", "eth1", "Blocked (forward)", "sys-forward-defaultdrop", false},
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s := samples[rng.Intn(len(samples))]
			ruleID := s.ruleID
			if s.liveID {
				ruleID = m.pickRuleID(rng, s.ruleID)
			}
			cb(model.FirewallLog{
				Action:   s.action,
				Src:      fmt.Sprintf("192.168.1.%d", 100+rng.Intn(50)),
				SrcPort:  fmt.Sprintf("%d", 32768+rng.Intn(28232)), // ephemeral range
				Dest:     s.dest,
				Port:     s.port,
				Proto:    s.proto,
				InIface:  s.in,
				OutIface: s.out,
				Reason:   s.reason,
				Chain:    model.PolicyChainForward,
				RuleID:   ruleID,
			})
		}
	}
}

// WatchLocalTraffic synthesizes input+output chain events (admin/self
// traffic hitting or leaving the board itself) on a timer, alternating
// between "input" (e.g. admin reaching the web UI, ping, an unsolicited scan
// from the WAN) and "output" (e.g. the board's own DNS/NTP lookups) samples,
// using the same reason text as the real parser (§2.4 of the plan).
func (m *MockTrafficLog) WatchLocalTraffic(ctx context.Context, cb func(model.FirewallLog)) error {
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + 1))
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	type sample struct {
		chain   string
		action  string
		src     string
		dest    string
		srcPort string
		port    string
		proto   string
		in      string
		out     string
		reason  string
		// ruleID: see the matching comment in WatchForwardTraffic — mixes a
		// system token (admin-access/default-drop, always resolvable via
		// the static table), a plausible DB rule id, and empty.
		ruleID string
		// liveID: see the matching field in WatchForwardTraffic's sample
		// struct. System tokens (sys-*) are intentionally never replaced —
		// they resolve via the static system table regardless of DB state.
		liveID bool
	}
	samples := []sample{
		// input: traffic destined to the board itself.
		{model.PolicyChainInput, "PASS", "192.168.1.10", "192.168.1.1", "51422", "443", "TCP", "eth1", "-", "Allowed (local-in)", "sys-admin-https", false},
		{model.PolicyChainInput, "PASS", "192.168.1.20", "192.168.1.1", "58311", "22", "TCP", "eth1", "-", "Allowed (local-in)", "sys-admin-ssh", false},
		{model.PolicyChainInput, "PASS", "192.168.1.15", "192.168.1.1", "-", "-", "ICMP", "eth1", "-", "Allowed (local-in)", "sys-admin-ping", false},
		{model.PolicyChainInput, "DROP", "203.0.113.77", "203.0.113.1", "44502", "23", "TCP", "eth0", "-", "Blocked (local-in)", "sys-input-defaultdrop", false},
		{model.PolicyChainInput, "DROP", "198.51.100.5", "203.0.113.1", "60123", "3389", "TCP", "eth0", "-", "Blocked (local-in)", "sys-input-defaultdrop", false},
		// output: traffic the board itself originates.
		{model.PolicyChainOutput, "PASS", "203.0.113.1", "8.8.8.8", "51234", "53", "UDP", "-", "eth0", "Allowed (local-out)", "rule-allow-dns-out", true},
		{model.PolicyChainOutput, "PASS", "203.0.113.1", "129.6.15.28", "123", "123", "UDP", "-", "eth0", "Allowed (local-out)", "", false},
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s := samples[rng.Intn(len(samples))]
			ruleID := s.ruleID
			if s.liveID {
				ruleID = m.pickRuleID(rng, s.ruleID)
			}
			cb(model.FirewallLog{
				Chain:    s.chain,
				Action:   s.action,
				Src:      s.src,
				Dest:     s.dest,
				SrcPort:  s.srcPort,
				Port:     s.port,
				Proto:    s.proto,
				InIface:  s.in,
				OutIface: s.out,
				Reason:   s.reason,
				RuleID:   ruleID,
			})
		}
	}
}

// mockFlowTemplate is one synthetic conntrack flow (or a small group of
// near-identical flows) used to seed MockTrafficAccounting.DumpFlows.
// ratePerSec is the combined bytes/sec across all `instances` of this
// template; elapsed real time since MockTrafficAccounting was constructed is
// what drives monotonic byte growth (see DumpFlows).
type mockFlowTemplate struct {
	srcIP      string
	dstIP      string
	proto      uint8
	dstPort    uint16
	ratePerSec float64
	instances  int
	// upRatio is the fraction of ratePerSec attributed to the orig direction
	// (srcIP -> dstIP, i.e. "upload" relative to srcIP); the remainder goes to
	// reply (dstIP -> srcIP, "download"). Deliberately asymmetric per traffic
	// type (e.g. a video stream is mostly download) so -mock=true dev mode
	// visibly exercises the Statistics page's up/down split (plan T-04).
	upRatio float64
}

// mockFlowTemplates deliberately reuses the same LAN IPs as MockDhcp's
// hardcoded lease list (192.168.1.101/102/105 — iPhone-13/Android-SmartTV/
// iPad-Pro) so Top Talkers shows real hostnames in -mock=true dev mode, per
// docs/ref/todo/dashboard-traffic-detail-plan.md T-05. Ports span common
// Service Object categories (443 HTTPS, 53 DNS, 5060 VoIP/SIP, 80 HTTP) plus
// a couple of unmatched ports (51820, 6881, 22-ish) that deliberately fall
// into the "Other" category, so both matched and unmatched Protocol
// Breakdown segments are exercised in dev.
var mockFlowTemplates = []mockFlowTemplate{
	{"192.168.1.101", "142.250.80.46", 6, 443, 9000, 3, 0.08},   // iPhone-13: HTTPS video/streaming (mostly download)
	{"192.168.1.101", "1.1.1.1", 17, 53, 40, 2, 0.45},           // iPhone-13: DNS (roughly balanced)
	{"192.168.1.102", "173.194.76.94", 6, 443, 26000, 3, 0.08},  // Android-SmartTV: HTTPS video (dominant talker, mostly download)
	{"192.168.1.102", "64.233.166.127", 17, 5060, 1200, 2, 0.5}, // Android-SmartTV: VoIP/SIP (symmetric)
	{"192.168.1.102", "8.8.8.8", 17, 53, 35, 2, 0.45},           // Android-SmartTV: DNS
	{"192.168.1.105", "151.101.1.69", 6, 80, 3000, 3, 0.15},     // iPad-Pro: HTTP browsing (mostly download)
	{"192.168.1.105", "151.101.1.69", 6, 443, 4500, 3, 0.15},    // iPad-Pro: HTTPS browsing (mostly download)
	{"192.168.1.105", "203.0.113.55", 6, 51820, 800, 2, 0.5},    // iPad-Pro: unmatched port -> "Other" (VPN, roughly symmetric)
	{"192.168.1.101", "45.33.32.156", 17, 6881, 500, 2, 0.35},   // iPhone-13: unmatched port -> "Other" (P2P, upload-heavy)
	{"192.168.1.102", "198.51.100.9", 6, 22, 150, 2, 0.6},       // Android-SmartTV: unmatched port -> "Other" (SSH, upload-leaning)
}

// MockTrafficAccounting implements TrafficAccountingManager for local/mock
// testing. It synthesizes ~20-40 flows across mockFlowTemplates rather than
// opening any real netlink socket, and per-flow byte counts grow
// monotonically with wall-clock time since construction — exactly like a
// real conntrack entry's cumulative Bytes field — so the Dashboard traffic
// cards visibly move during -mock=true development. ruleIDs (optional)
// supplies live DB policy-rule ids so DumpRuleCounters can synthesize
// realistic Top Rules entries the service layer can actually match against
// the DB instead of ids nothing will ever match; when nil, DumpRuleCounters
// returns an empty map.
type MockTrafficAccounting struct {
	start   time.Time
	ruleIDs func() []string
}

// NewMockTrafficAccounting constructs the mock. ruleIDs may be nil (Top
// Rules will simply stay empty in that case).
func NewMockTrafficAccounting(ruleIDs func() []string) *MockTrafficAccounting {
	return &MockTrafficAccounting{start: time.Now(), ruleIDs: ruleIDs}
}

func (m *MockTrafficAccounting) DumpFlows() ([]model.FlowSample, error) {
	elapsed := time.Since(m.start).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	out := make([]model.FlowSample, 0, 32)
	for ti, t := range mockFlowTemplates {
		if t.instances <= 0 {
			continue
		}
		perInstance := t.ratePerSec / float64(t.instances)
		for i := 0; i < t.instances; i++ {
			// Small per-instance jitter (deterministic, not time-based) so
			// instances of the same template aren't perfectly identical.
			jitter := 0.85 + 0.3*float64(i)/float64(t.instances)
			bytes := uint64(perInstance * elapsed * jitter)
			origBytes := uint64(float64(bytes) * t.upRatio)
			replyBytes := bytes - origBytes
			out = append(out, model.FlowSample{
				Key:        fmt.Sprintf("mock-flow-%d-%d", ti, i),
				SrcIP:      t.srcIP,
				DstIP:      t.dstIP,
				Proto:      t.proto,
				DstPort:    t.dstPort,
				BytesOrig:  origBytes,
				BytesReply: replyBytes,
			})
		}
	}
	return out, nil
}

func (m *MockTrafficAccounting) DumpRuleCounters() (map[string]model.RuleCounter, error) {
	out := make(map[string]model.RuleCounter)
	if m.ruleIDs == nil {
		return out, nil
	}
	elapsed := time.Since(m.start).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	for i, id := range m.ruleIDs() {
		if id == "" {
			continue
		}
		// Vary the synthetic rate per rule so the Top Rules ranking isn't a
		// flat tie in dev mode. Every 4th rule (deterministic on its position
		// in the DB-ordered id list, never random) gets a rate of 0 so
		// -mock=true can exercise the "Unused" status in the per-rule usage
		// stats UI (docs/ref/todo/firewall-policy-rule-usage-stats-plan.md T-08).
		ratePerSec := 300.0 + float64(i%5)*450.0
		if i%4 == 3 {
			ratePerSec = 0
		}
		bytes := uint64(ratePerSec * elapsed)
		out[id] = model.RuleCounter{Bytes: bytes, Packets: bytes / 512}
	}
	return out, nil
}

// mockFlowEndInterval is how often WatchFlowEnd synthesizes a "flow death"
// event in mock/dev mode — arbitrary, just fast enough that the Top Talkers
// card visibly reacts to events (not only the poll) during -mock=true
// development (plan T-05).
const mockFlowEndInterval = 7 * time.Second

// WatchFlowEnd synthesizes a periodic flow-end event from mockFlowTemplates,
// reusing the same synthetic IPs as DumpFlows above so Top Talkers keeps
// moving in dev mode even when the flow-end event path is exercised in
// isolation from the poll path. It deliberately opens no socket and reads no
// /proc file — dev machines running -mock=true (frequently WSL, with no real
// conntrack) must never touch the host (plan Caution 9). Returns nil when ctx
// is cancelled, mirroring the real implementation's contract.
func (m *MockTrafficAccounting) WatchFlowEnd(ctx context.Context, cb func(model.FlowSample)) error {
	ticker := time.NewTicker(mockFlowEndInterval)
	defer ticker.Stop()
	tick := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if len(mockFlowTemplates) == 0 {
				continue
			}
			ti := tick % len(mockFlowTemplates)
			tick++
			t := mockFlowTemplates[ti]
			elapsed := time.Since(m.start).Seconds()
			if elapsed < 0 {
				elapsed = 0
			}
			bytes := uint64((t.ratePerSec / float64(max(t.instances, 1))) * elapsed)
			origBytes := uint64(float64(bytes) * t.upRatio)
			replyBytes := bytes - origBytes
			cb(model.FlowSample{
				Key:        fmt.Sprintf("mock-flow-%d-0", ti),
				SrcIP:      t.srcIP,
				DstIP:      t.dstIP,
				Proto:      t.proto,
				DstPort:    t.dstPort,
				BytesOrig:  origBytes,
				BytesReply: replyBytes,
			})
		}
	}
}

// MockPathProbe implements kernel.PathProbeManager for local/dev testing
// (docs/ref/todo/multi-wan-failover-plan.md Task 5). It never opens a real
// socket (no net.ListenPacket, no net.Dialer) and never sleeps for anything
// resembling a real probe timeout — every call returns immediately with a
// synthetic sample, so `-mock=true` never sends a single ICMP/TCP packet off
// the box.
//
// SetICMPDead/SetAllDead let tests deterministically drive the two
// interesting failure scenarios the D-5 auto-fallback/sticky logic
// (service.WanMonitor) needs to exercise: "ICMP is dead but TCP still
// works" (SetICMPDead) and "the whole uplink is down" (SetAllDead). Both are
// keyed by ifaceName since that is the only per-uplink identifier every
// PathProbeManager call receives.
//
// SetProbeError additionally lets tests exercise the third, distinct
// scenario: the PathProbeManager call itself fails (socket/permission/
// interface-not-found), as opposed to the target simply not answering. This
// is what service.WanMonitor's probeUplink must fold into a "down"-uplink
// classification NOT reported as "unknown" (see wan_monitor_test.go's
// TestWanMonitor_ProbeErrorProducesUnknownNotDown, plan Task 7 acceptance:
// "probe error (ระบบพัง) != down เป็น unknown+log").
type MockPathProbe struct {
	mu       sync.Mutex
	icmpDead map[string]bool
	allDead  map[string]bool
	probeErr map[string]error
	// ICMPCalls/TCPCalls count invocations per interface so tests can assert
	// e.g. "ProbeMethod=icmp never calls ProbeTCP even under 100% loss"
	// (plan Task 7 acceptance).
	ICMPCalls map[string]int
	TCPCalls  map[string]int
}

func NewMockPathProbe() *MockPathProbe {
	return &MockPathProbe{
		icmpDead:  make(map[string]bool),
		allDead:   make(map[string]bool),
		probeErr:  make(map[string]error),
		ICMPCalls: make(map[string]int),
		TCPCalls:  make(map[string]int),
	}
}

// SetICMPDead forces ProbeICMP (only) to report 100% loss for ifaceName;
// ProbeTCP on the same interface is unaffected.
func (m *MockPathProbe) SetICMPDead(ifaceName string, dead bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.icmpDead[ifaceName] = dead
}

// SetAllDead forces both ProbeICMP and ProbeTCP to report 100% loss for
// ifaceName (the "uplink is fully down" scenario).
func (m *MockPathProbe) SetAllDead(ifaceName string, dead bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allDead[ifaceName] = dead
}

// SetProbeError makes both ProbeICMP and ProbeTCP return err for ifaceName
// instead of a sample, simulating a probe-system failure rather than the
// target being unreachable. Pass a nil err to clear the injected failure.
func (m *MockPathProbe) SetProbeError(ifaceName string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		delete(m.probeErr, ifaceName)
		return
	}
	m.probeErr[ifaceName] = err
}

// mockPathProbeRTTPattern is a fixed, non-random sequence of plausible RTTs
// (milliseconds) cycled through to fill a sample's RTTsMs — deterministic
// (plan Task 5: "deterministic-ish") so dev-mode runs are reproducible,
// while still varying enough to produce a non-zero jitter figure downstream.
var mockPathProbeRTTPattern = []float64{15, 22, 18, 27, 12, 20, 25, 14, 19, 23}

func mockPathProbeRTTs(count int) []float64 {
	if count <= 0 {
		return nil
	}
	out := make([]float64, count)
	for i := range out {
		out[i] = mockPathProbeRTTPattern[i%len(mockPathProbeRTTPattern)]
	}
	return out
}

func (m *MockPathProbe) ProbeICMP(ctx context.Context, ifaceName string, target net.IP, count int, timeout time.Duration) (model.WanProbeSample, error) {
	m.mu.Lock()
	m.ICMPCalls[ifaceName]++
	dead := m.icmpDead[ifaceName] || m.allDead[ifaceName]
	err := m.probeErr[ifaceName]
	m.mu.Unlock()
	if err != nil {
		return model.WanProbeSample{}, err
	}

	sample := model.WanProbeSample{
		TimestampUnix: time.Now().Unix(),
		Sent:          count,
		Method:        model.WanProbeMethodICMP,
		MetricQuality: model.WanMetricQualityFull,
	}
	if dead || count <= 0 {
		return sample, nil
	}
	sample.Received = count
	sample.RTTsMs = mockPathProbeRTTs(count)
	return sample, nil
}

func (m *MockPathProbe) ProbeTCP(ctx context.Context, ifaceName string, target net.IP, port, count int, timeout time.Duration) (model.WanProbeSample, error) {
	m.mu.Lock()
	m.TCPCalls[ifaceName]++
	dead := m.allDead[ifaceName]
	err := m.probeErr[ifaceName]
	m.mu.Unlock()
	if err != nil {
		return model.WanProbeSample{}, err
	}

	sample := model.WanProbeSample{
		TimestampUnix: time.Now().Unix(),
		Sent:          count,
		Method:        model.WanProbeMethodTCP,
		MetricQuality: model.WanMetricQualityConnectOnly,
	}
	if dead || count <= 0 {
		return sample, nil
	}
	sample.Received = count
	sample.RTTsMs = mockPathProbeRTTs(count)
	return sample, nil
}
