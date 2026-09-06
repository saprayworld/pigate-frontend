// Types for Dashboard
export interface FirewallLog {
  id: string
  time: string
  action: "PASS" | "DROP"
  src: string
  dest: string
  srcPort?: string
  port: string
  proto: string
  reason: string
  // Optional traffic-log enrichment fields (docs/ref/todo/
  // traffic-log-rule-name-and-domain-plan.md) — ruleId/ruleName are a
  // snapshot captured when the entry was logged, srcDomain/destDomain/
  // srcHostname/destHostname are resolved fresh on every read. All
  // optional: older/un-enriched entries simply omit them.
  ruleId?: string
  ruleName?: string
  srcDomain?: string
  destDomain?: string
  srcHostname?: string
  destHostname?: string
}

// Initial mockup logs for Dashboard
export const initialFirewallLogs: FirewallLog[] = [
  {
    id: "log-1",
    time: "14:31:02",
    action: "DROP",
    src: "185.220.101.4",
    dest: "10.0.0.45",
    port: "445",
    proto: "TCP",
    reason: "Blocked Port (SMB)"
  },
  {
    id: "log-2",
    time: "14:31:15",
    action: "PASS",
    src: "192.168.1.105",
    dest: "8.8.8.8",
    port: "53",
    proto: "UDP",
    reason: "DNS request"
  },
  {
    id: "log-3",
    time: "14:31:22",
    action: "DROP",
    src: "192.168.1.132",
    dest: "203.0.113.5",
    port: "23",
    proto: "TCP",
    reason: "Blocked Telnet"
  },
  {
    id: "log-4",
    time: "14:31:30",
    action: "PASS",
    src: "192.168.1.100",
    dest: "142.250.196.46",
    port: "443",
    proto: "TCP",
    reason: "HTTPS traffic"
  },
  {
    id: "log-5",
    time: "14:31:40",
    action: "DROP",
    src: "45.143.203.14",
    dest: "10.0.0.45",
    port: "22",
    proto: "TCP",
    reason: "Brute-force SSH"
  }
]

// Mockup options for Dashboard log streaming generator
export const mockSources = [
  "192.168.1.104",
  "192.168.1.112",
  "192.168.1.188",
  "185.220.101.4",
  "45.143.203.18",
  "82.102.23.140",
  "192.168.1.101"
]

export const mockDestinations = [
  "8.8.8.8",
  "1.1.1.1",
  "10.0.0.45",
  "142.250.196.46",
  "151.101.1.140",
  "192.168.1.1"
]

export const mockLogServices = [
  { port: "53", proto: "UDP", reason: "DNS query", action: "PASS" },
  { port: "443", proto: "TCP", reason: "HTTPS secure", action: "PASS" },
  { port: "80", proto: "TCP", reason: "HTTP plain", action: "PASS" },
  { port: "22", proto: "TCP", reason: "Blocked SSH", action: "DROP" },
  { port: "23", proto: "TCP", reason: "Blocked Telnet", action: "DROP" },
  { port: "445", proto: "TCP", reason: "Blocked Port (SMB)", action: "DROP" },
  { port: "3389", proto: "TCP", reason: "RDP connection attempt", action: "DROP" }
]

// Which nftables base chain a PolicyRule targets. "forward" (default) is the
// traffic passing through the box (Firewall Policy page); "input" is traffic
// destined to the box itself (Local-In Policy); "output" is traffic
// originating from the box itself (Local-Out Policy). See
// docs/ref/todo/input-output-chain-firewall-plan.md.
export type PolicyChain = "forward" | "input" | "output"

// Types for Firewall Policy
export interface PolicyRule {
  id: string
  name: string
  chain: PolicyChain
  // Deprecated: compat mirror of inInterfaces[0]/outInterfaces[0] only,
  // kept for old localStorage data / API responses that predate
  // multi-interface support. Never read directly for rendering/logic —
  // use inInterfaces/outInterfaces (see policyService.normalizeInterfaces)
  // instead. docs/ref/todo/multi-interface-firewall-rule-plan.md.
  inInterface: string // e.g. "ALL", "eth0", "wlan0"
  outInterface: string // e.g. "ALL", "eth0", "wlan0"
  // inInterfaces/outInterfaces are the source of truth (multi-interface
  // support, docs/ref/todo/multi-interface-firewall-rule-plan.md).
  // Optional so old localStorage/backup data without these keys still
  // type-checks; policyService.normalizeInterfaces seeds them from the
  // legacy scalar fields above when missing.
  inInterfaces?: string[]
  outInterfaces?: string[]
  source: string[]
  destination: string[]
  service: string[]
  action: "ACCEPT" | "DROP"
  log: boolean
  nat: boolean // Source NAT (masquerade to outgoing interface address)
  status: boolean // true = Enabled, false = Disabled
  // monitored opts this rule into persisted traffic counters that accumulate
  // across Apply/restart instead of resetting on every apply (docs/ref/todo/
  // fqdn-retry-and-monitored-counters-plan.md D-6, issue #141).
  monitored: boolean
}

// Initial mockup rules for Firewall Policy
export const initialPolicyRules: PolicyRule[] = []

// Types for Port Forwarding (DNAT / Virtual IP)
export interface PortForward {
  id: string
  name: string
  inInterface: string // external (WAN) interface, e.g. "eth0"
  externalPort: string // single ("8080") or range ("8000-8010", keep-port only)
  protocol: "tcp" | "udp"
  internalIP: string // internal LAN target IPv4
  internalPort: string // translated port; empty = keep original port (required-empty for ranges)
  status: boolean // true = Enabled, false = Disabled
}

// Initial mockup data for Port Forwarding
export const initialPortForwards: PortForward[] = []

// A single address entry (see docs/ref/todo/
// multi-value-address-service-objects-plan.md). An AddressObject now holds
// one or more of these; the legacy top-level type/value fields on
// AddressObject are kept only as a compat mirror of entries[0].
export interface AddressEntry {
  type: "subnet" | "range" | "fqdn"
  value: string
}

// Types for Address Objects
export interface AddressObject {
  id: string
  name: string
  // deprecated: compat mirror of entries[0], kept for backward compatibility
  // with older clients/localStorage payloads. Will be removed in the next
  // major version — prefer `entries`.
  type: "subnet" | "range" | "fqdn"
  // deprecated: compat mirror of entries[0], see `type` above.
  value: string
  // Optional so callers that only supply the legacy type/value pair (e.g.
  // pages not yet migrated to the list-form editor — see T-12/T-13) keep
  // compiling; normalizeAddress()/normalizeService() below always fill it in
  // before persisting or sending to the API.
  entries?: AddressEntry[]
  system: boolean
  refPolicies: string[]
}

// Initial mockup data for Address Objects
export const initialAddressObjects: AddressObject[] = [
  {
    id: "addr-1",
    name: "ALL",
    type: "subnet",
    value: "0.0.0.0/0",
    entries: [{ type: "subnet", value: "0.0.0.0/0" }],
    system: true,
    refPolicies: []
  },
  {
    id: "addr-2",
    name: "LAN_Network",
    type: "subnet",
    value: "192.168.1.0/24",
    entries: [{ type: "subnet", value: "192.168.1.0/24" }],
    system: false,
    refPolicies: []
  },
  {
    id: "addr-3",
    name: "Admin_PC",
    type: "subnet",
    system: false,
    value: "192.168.1.10/32",
    entries: [{ type: "subnet", value: "192.168.1.10/32" }],
    refPolicies: []
  },
  {
    id: "addr-4",
    name: "DHCP_Pool_Zone",
    type: "range",
    system: false,
    value: "192.168.1.100 - 192.168.1.200",
    entries: [{ type: "range", value: "192.168.1.100 - 192.168.1.200" }],
    refPolicies: []
  },
  {
    id: "addr-5",
    name: "Update_Server",
    type: "fqdn",
    system: false,
    value: "pigate-update.com",
    entries: [{ type: "fqdn", value: "pigate-update.com" }],
    refPolicies: []
  },
  {
    id: "addr-6",
    name: "Malicious_IP_List",
    type: "subnet",
    system: false,
    value: "198.51.100.0/22",
    // Seed demonstrating a multi-entry object (subnet + range + fqdn mixed).
    entries: [
      { type: "subnet", value: "198.51.100.0/22" },
      { type: "range", value: "203.0.113.10 - 203.0.113.20" },
      { type: "fqdn", value: "known-bad.example.com" }
    ],
    refPolicies: []
  }
]

// A single service entry (see docs/ref/todo/
// multi-value-address-service-objects-plan.md). A ServiceObject now holds
// one or more of these; the legacy top-level protocol/port fields on
// ServiceObject are kept only as a compat mirror of entries[0].
export interface ServiceEntry {
  protocol: "TCP" | "UDP" | "TCP/UDP" | "ICMP"
  port: string
}

// Types for Service Objects
export interface ServiceObject {
  id: string
  name: string
  // deprecated: compat mirror of entries[0], kept for backward compatibility
  // with older clients/localStorage payloads. Will be removed in the next
  // major version — prefer `entries`.
  protocol: "TCP" | "UDP" | "TCP/UDP" | "ICMP"
  // deprecated: compat mirror of entries[0], see `protocol` above.
  port: string
  // Optional so callers that only supply the legacy protocol/port pair (e.g.
  // pages not yet migrated to the list-form editor — see T-12/T-13) keep
  // compiling; normalizeAddress()/normalizeService() below always fill it in
  // before persisting or sending to the API.
  entries?: ServiceEntry[]
  type: "system" | "custom"
  refPolicies: string[]
}

// Initial mockup data for Service Objects
export const initialServiceObjects: ServiceObject[] = [
  {
    id: "svc-1",
    name: "ALL",
    protocol: "TCP/UDP",
    port: "1-65535",
    entries: [{ protocol: "TCP/UDP", port: "1-65535" }],
    type: "system",
    refPolicies: []
  },
  {
    id: "svc-2",
    name: "HTTP",
    protocol: "TCP",
    port: "80",
    entries: [{ protocol: "TCP", port: "80" }],
    type: "system",
    refPolicies: []
  },
  {
    id: "svc-3",
    name: "HTTPS",
    protocol: "TCP",
    port: "443",
    entries: [{ protocol: "TCP", port: "443" }],
    type: "system",
    refPolicies: []
  },
  {
    id: "svc-4",
    name: "SSH",
    protocol: "TCP",
    port: "22",
    entries: [{ protocol: "TCP", port: "22" }],
    type: "system",
    refPolicies: []
  },
  {
    id: "svc-5",
    name: "DNS",
    protocol: "UDP",
    port: "53",
    entries: [{ protocol: "UDP", port: "53" }],
    type: "system",
    refPolicies: []
  },
  {
    id: "svc-6",
    name: "ICMP",
    protocol: "ICMP",
    port: "-",
    entries: [{ protocol: "ICMP", port: "-" }],
    type: "system",
    refPolicies: []
  },
  {
    id: "svc-7",
    name: "Web_Ports",
    protocol: "TCP",
    port: "80",
    // Seed demonstrating a multi-entry service object.
    entries: [
      { protocol: "TCP", port: "80" },
      { protocol: "TCP", port: "443" },
      { protocol: "UDP", port: "443" }
    ],
    type: "custom",
    refPolicies: []
  }
]

// Types for Network Interfaces
export type AdminAccess = "HTTPS" | "HTTP" | "PING" | "SSH"
export type AddressingMode = "dhcp" | "static"
export type InterfaceType = "ethernet" | "wireless"

export interface WifiScanResult {
  ssid: string
  signal: number       // 0-100 percent
  security: string     // e.g. "WPA2-PSK", "WPA3", "Open"
  channel: number
  frequency: string    // "2.4 GHz" or "5 GHz"
}

export interface NetworkInterface {
  id: string
  name: string                // e.g. "eth0", "wlan0"
  alias: string               // e.g. "LAN_Internal", "WAN_WiFi"
  role: "LAN" | "WAN"
  type: InterfaceType
  subtype?: string            // e.g. "device", "veth", "bridge", "vlan"
  addressingMode: AddressingMode
  ip: string                  // e.g. "192.168.1.1"
  netmask: string             // e.g. "24"
  gateway: string             // e.g. "192.168.1.254" (used for static)
  metric?: number | null      // default-gateway route priority (lower = preferred, WAN failover); null/undefined = auto
  macAddress: string          // Effective MAC address currently active
  adminAccess: AdminAccess[]
  status: "up" | "down" | "offline"
  managed?: boolean           // computed: false = exists in kernel but has no config row (unmanaged); undefined = treat as managed
  speed: string               // e.g. "1000 Mbps", "72 Mbps"
  // VLAN (802.1Q) sub-interface fields — present only when subtype === "vlan"
  vlanParent?: string         // parent interface name, e.g. "eth0"
  vlanId?: number             // 802.1Q VLAN ID, 1–4094
  // Wi-Fi specific
  wifiSSID?: string
  wifiPassword?: string       // masked
  wifiSecurity?: string       // e.g. "WPA2-PSK"
  // MAC Address Randomization & LAA support
  macMode?: "hardware" | "randomized" | "laa"
  realMacAddress?: string
  randomizedMac?: string
  laaMacAddress?: string
  randomizeOnReconnect?: boolean
  prefer5GHz?: boolean       // lock Wi-Fi scanning to 5GHz channels only (freq_list) for maximum speed
  // Wi-Fi Backup & Failover Settings
  failoverEnabled?: boolean
  backupSsid?: string
  backupWifiPassword?: string
  backupWifiSecurity?: string
  ipCheckTimeout?: number
  primaryMaxRetries?: number
  failoverCooldown?: number
}

// Initial mockup data for Network Interfaces
export const initialNetworkInterfaces: NetworkInterface[] = [
  {
    id: "iface-1",
    name: "eth0",
    alias: "LAN_Internal",
    role: "LAN",
    type: "ethernet",
    subtype: "device",
    addressingMode: "static",
    ip: "192.168.1.1",
    netmask: "24",
    gateway: "",
    macAddress: "DC:A6:32:AA:BB:C1",
    realMacAddress: "DC:A6:32:AA:BB:C1",
    macMode: "hardware",
    adminAccess: ["PING", "HTTP", "SSH"],
    status: "up",
    managed: true,
    speed: "1000 Mbps"
  },
  {
    id: "iface-2",
    name: "wlan0",
    alias: "WAN_WiFi",
    role: "WAN",
    type: "wireless",
    subtype: "device",
    addressingMode: "dhcp",
    ip: "10.0.0.45",
    netmask: "24",
    gateway: "10.0.0.1",
    metric: 100, // primary WAN priority
    macAddress: "4E:88:2F:BC:A1:90", // effective MAC
    realMacAddress: "DC:A6:32:AA:BB:C2", // hardware MAC
    macMode: "randomized",
    randomizedMac: "4E:88:2F:BC:A1:90",
    laaMacAddress: "9A:11:22:33:44:55",
    randomizeOnReconnect: true,
    adminAccess: ["PING"],
    status: "up",
    managed: false, // demo: interface present in kernel but not configured by pigate (shows UNMANAGED badge)
    speed: "72 Mbps",
    wifiSSID: "MyHome_5G",
    wifiPassword: "••••••••",
    wifiSecurity: "WPA2",
    failoverEnabled: false,
    backupSsid: "MyHome_2G",
    backupWifiPassword: "backupPassword123",
    backupWifiSecurity: "WPA2",
    ipCheckTimeout: 15,
    primaryMaxRetries: 3,
    failoverCooldown: 60
  }
]

// Mock Wi-Fi Scan results
export const mockWifiScanResults: WifiScanResult[] = [
  { ssid: "MyHome_5G", signal: 85, security: "WPA2-PSK", channel: 36, frequency: "5 GHz" },
  { ssid: "MyHome_2G", signal: 72, security: "WPA2-PSK", channel: 6, frequency: "2.4 GHz" },
  { ssid: "Neighbor_AP", signal: 45, security: "WPA3", channel: 11, frequency: "2.4 GHz" },
  { ssid: "Cafe_Free_WiFi", signal: 30, security: "Open", channel: 1, frequency: "2.4 GHz" },
  { ssid: "Office_5G_Secured", signal: 62, security: "WPA2-Enterprise", channel: 149, frequency: "5 GHz" }
]

// Wi-Fi Saved-Networks (Preset) library — see docs/ref/todo/wifi-presets-plan.md.
// Password is intentionally never part of this type: the backend never returns
// it (only `hasPassword`), so the mock layer mirrors that shape exactly.
export type WifiPresetSecurity = "Open" | "WPA2" | "WPA2-PSK" | "WPA3" | "WPA2/WPA3"
export type WifiPresetMacMode = "" | "hardware" | "randomized" | "laa"

export interface WifiPreset {
  id: string
  name: string
  ssid: string
  security: WifiPresetSecurity
  macMode?: WifiPresetMacMode
  hasPassword: boolean
}

// Mock seed presets — no real plaintext passwords, only the hasPassword flag.
export const initialWifiPresets: WifiPreset[] = [
  {
    id: "wifi-preset-home5g",
    name: "Home 5G",
    ssid: "MyHome_5G",
    security: "WPA2",
    macMode: "hardware",
    hasPassword: true,
  },
  {
    id: "wifi-preset-office",
    name: "Office",
    ssid: "Office_5G_Secured",
    security: "WPA2/WPA3",
    macMode: "randomized",
    hasPassword: true,
  },
  {
    id: "wifi-preset-guest",
    name: "Guest Open",
    ssid: "Cafe_Free_WiFi",
    security: "Open",
    macMode: "",
    hasPassword: false,
  },
]

// Types for Static Routing
export interface StaticRoute {
  id: string
  destination: string     // e.g. "192.168.10.0/24"
  gateway: string         // e.g. "192.168.1.250" or "" for direct
  interface: string       // e.g. "eth0", "wlan0", "auto"
  metric: number          // priority (default 0 or 100)
  description: string
  status: boolean         // true = Active, false = Disabled
  type: "system" | "custom" | "defaultgateway" | "customgateway"
  scope: string
  src: string
  proto: string
  kernelOnly?: boolean
}

// Initial mockup data for Static Routes
export const initialStaticRoutes: StaticRoute[] = [
  {
    id: "route-1",
    destination: "0.0.0.0/0",
    gateway: "10.0.0.1",
    interface: "wlan0",
    metric: 100,
    description: "Default gateway route (WAN)",
    status: true,
    type: "system",
    scope: "global",
    src: "",
    proto: "boot"
  },
  {
    id: "route-2",
    destination: "192.168.1.0/24",
    gateway: "",
    interface: "eth0",
    metric: 0,
    description: "Direct subnet route for LAN",
    status: true,
    type: "system",
    scope: "link",
    src: "",
    proto: "kernel"
  },
  {
    id: "route-3",
    destination: "10.0.0.0/24",
    gateway: "",
    interface: "wlan0",
    metric: 0,
    description: "Direct subnet route for WAN",
    status: true,
    type: "system",
    scope: "link",
    src: "",
    proto: "kernel"
  }
]

// Types for DHCP Server
export interface DhcpConfig {
  id?: string
  enabled: boolean
  interface: string
  startIp: string
  endIp: string
  gateway: string
  netmask: string
  dns1: string
  dns2: string
  leaseTime: number // in seconds
  domain: string // DHCP option 15, empty = not advertised
}

export interface DhcpReservation {
  id: string
  deviceName: string
  macAddress: string
  ipAddress: string
}

export interface ActiveDhcpLease {
  id: string
  ipAddress: string
  macAddress: string
  hostname: string
  interface?: string
  expiresIn: string
  expiresAt?: string
}

// Initial mockup data for DHCP Server
export const initialDhcpConfigs: DhcpConfig[] = [
  {
    id: "dhcp-cfg-default",
    enabled: true,
    interface: "eth0",
    startIp: "192.168.1.100",
    endIp: "192.168.1.200",
    gateway: "192.168.1.1",
    netmask: "255.255.255.0",
    dns1: "8.8.8.8",
    dns2: "1.1.1.1",
    leaseTime: 86400, // 24 hours
    domain: ""
  }
]

export const initialDhcpConfig: DhcpConfig = initialDhcpConfigs[0]

export const initialDhcpReservations: DhcpReservation[] = [
  {
    id: "res-1",
    deviceName: "CEO_Laptop",
    macAddress: "A1:B2:C3:D4:E5:F6",
    ipAddress: "192.168.1.10"
  },
  {
    id: "res-2",
    deviceName: "Network_Printer",
    macAddress: "11:22:33:44:55:66",
    ipAddress: "192.168.1.50"
  }
]

export const initialActiveDhcpLeases: ActiveDhcpLease[] = [
  {
    id: "lease-1",
    ipAddress: "192.168.1.101",
    macAddress: "99:88:77:66:55:44",
    hostname: "iPhone-13",
    interface: "eth0",
    expiresIn: "11 hours, 45 mins"
  },
  {
    id: "lease-2",
    ipAddress: "192.168.1.102",
    macAddress: "AA:BB:CC:DD:EE:FF",
    hostname: "Android-SmartTV",
    interface: "eth0",
    expiresIn: "23 hours, 10 mins"
  },
  {
    id: "lease-3",
    ipAddress: "192.168.1.105",
    macAddress: "B4:F1:DA:C8:E2:10",
    hostname: "iPad-Pro",
    interface: "eth0",
    expiresIn: "2 hours, 15 mins"
  }
]

// Types for Settings & Maintenance
export interface TimeStatus {
  currentTime: string // RFC3339, device local time
  ntpSynchronized: boolean
}

export interface SystemTimeSettings {
  timezone: string // bare IANA name, e.g. "Asia/Bangkok"
  ntpSync: boolean
  ntpServer: string
  status?: TimeStatus // live kernel state, present on GET only
}

export interface NetworkServiceStatus {
  id: string
  name: string
  serviceName: string
  status: "running" | "stopped" | "failed" | "unavailable"
  restartAllowed: boolean
}

// Initial mockup data for Settings & Maintenance
export const initialSystemTimeSettings: SystemTimeSettings = {
  timezone: "Asia/Bangkok",
  ntpSync: true,
  ntpServer: "pool.ntp.org"
}

// Real identifiers matching the backend catalog (see
// backend/internal/service/system_service.go). Per-interface rows
// (wpa_supplicant@<if>, dhcpcd@<if>) aren't meaningful in this static
// standalone-mock seed, so only the fixed singleton units are listed here.
export const initialNetworkServices: NetworkServiceStatus[] = [
  {
    id: "dnsmasq",
    name: "DHCP/DNS Forwarder (dnsmasq)",
    serviceName: "dnsmasq.service",
    status: "running",
    restartAllowed: true
  },
  {
    id: "resolved",
    name: "DNS Resolver (systemd-resolved)",
    serviceName: "systemd-resolved.service",
    status: "running",
    restartAllowed: true
  },
  {
    id: "timesyncd",
    name: "Time Sync (systemd-timesyncd)",
    serviceName: "systemd-timesyncd.service",
    status: "running",
    restartAllowed: true
  },
  {
    id: "ssh",
    name: "SSH Daemon (ssh)",
    serviceName: "ssh.service",
    status: "running",
    restartAllowed: true
  },
  {
    id: "pigate",
    name: "PiGate Controller (pigate)",
    serviceName: "pigate.service",
    status: "running",
    restartAllowed: false
  }
]

export interface DNSRecord {
  id: string
  zoneId: string
  name: string
  type: string
  value: string
  ttl: number
  // NS-delegation glue IPs (NS records only, max 4). Optional so existing
  // mock data / older records without this field keep working unchanged
  // (docs/ref/todo/dns-ns-delegation-plan.md).
  glueIps?: string[]
  // NS-delegation mode (NS records only). "glue" (default) forwards to
  // glueIps; "upstream" hands the subtree to the box's normal upstream
  // resolvers instead, needed when the delegated nameserver answers with a
  // CNAME pointing outside its own zone (docs/ref/todo/
  // dns-ns-delegation-cname-fix-plan.md). Optional so existing mock data /
  // older records without this field keep working unchanged.
  delegationMode?: "glue" | "upstream"
}

export interface DNSZone {
  id: string
  zoneName: string
  forwardTo: string
  allowedIps: string
  isAuthoritative: boolean
  enabled: boolean
  records: DNSRecord[]
}

export const initialDNSZones: DNSZone[] = [
  {
    id: "zone-default-1",
    zoneName: "pigate.local",
    forwardTo: "",
    allowedIps: "any",
    isAuthoritative: true,
    enabled: true,
    records: [
      {
        id: "rec-default-1",
        zoneId: "zone-default-1",
        name: "@",
        type: "A",
        value: "192.168.1.1",
        ttl: 300
      },
      {
        id: "rec-default-2",
        zoneId: "zone-default-1",
        name: "router",
        type: "CNAME",
        value: "pigate.local",
        ttl: 300
      }
    ]
  },
  {
    id: "zone-default-2",
    zoneName: "home.sapray.net",
    forwardTo: "8.8.8.8",
    allowedIps: "any",
    isAuthoritative: false,
    enabled: true,
    records: []
  }
]

// DNS Server listen interfaces (which real LAN interfaces auth-server binds to)
// plus the DNS Statistics fields (docs/ref/todo/statistics-dns-top-domain-plan.md):
// queryLogging (opt-in switch, restarts dnsmasq) and the reverse-cache
// TTL/cap (live-tunable, no restart). Kept independent from DHCP Server
// configuration — sourced from the Interface Service.
export interface DNSServerSettings {
  interfaces: string[]
  queryLogging: boolean
  dnsCacheTtlMinutes: number
  dnsCacheMaxEntries: number
  // Upstream resolver source for the DNS Server itself (docs/ref/todo/
  // dns-server-settings-tab-and-upstream-plan.md). "system" (default) reads
  // System DNS (/dns page) at generate-time; "custom" forwards only to
  // upstreamServers. Changing either field restarts dnsmasq.
  upstreamMode: "system" | "custom"
  upstreamServers: string[]
}

export const DNS_CACHE_TTL_MIN = 1
export const DNS_CACHE_TTL_MAX = 1440
export const DNS_CACHE_TTL_DEFAULT = 60
export const DNS_CACHE_ENTRIES_MIN = 128
export const DNS_CACHE_ENTRIES_MAX = 65536
export const DNS_CACHE_ENTRIES_DEFAULT = 4096
// Must match backend model.DNSUpstreamMaxServers.
export const DNS_UPSTREAM_MAX_SERVERS = 4

export const initialDNSServerSettings: DNSServerSettings = {
  interfaces: ["eth0"],
  queryLogging: false,
  dnsCacheTtlMinutes: DNS_CACHE_TTL_DEFAULT,
  dnsCacheMaxEntries: DNS_CACHE_ENTRIES_DEFAULT,
  upstreamMode: "system",
  upstreamServers: [],
}

// DNS Server deny-list (docs/ref/todo/dns-blocked-domains-plan.md). A domain
// entry also blocks every subdomain of it — there is no exact-only mode.
export interface BlockedDomain {
  id: string
  domain: string
  mode: "nxdomain" | "sinkhole"
  enabled: boolean
  comment: string
  createdAt?: string
}

// Must match backend model.DNSBlockedDomainsMax.
export const DNS_BLOCKED_DOMAINS_MAX = 1000

export const initialBlockedDomains: BlockedDomain[] = []

// DNS blocklist import — bulk subscribe-URL/upload hosts-format blocklists
// (docs/ref/todo/dns-blocklist-import-plan.md). Deliberately mirrors backend
// model.DNSBlocklist 1:1 (its metadata lives in a JSON manifest on the
// backend, NOT SQLite/the DB used by the rest of this file — see the plan's
// §2.3 for why). Distinct from BlockedDomain above (the small, ≤1000-entry
// deny-list): this is for large public/personal hosts files (tens of
// thousands of domains) rendered into their own dnsmasq files.
export interface DNSBlocklist {
  id: string
  name: string
  sourceType: "url" | "upload"
  url?: string
  // blockMode selects which dnsmasq mechanism this list is rendered with —
  // "sinkhole" (addn-hosts, exact-match, DEFAULT for blocklists) or
  // "nxdomain" (conf-file with address=/d/, suffix-match — covers
  // subdomains too). Same union shape as BlockedDomain.mode above, but note
  // the *default* is the opposite of the deny-list's ("sinkhole" here vs.
  // "nxdomain" there) — see backend model.NormalizeBlocklistBlockMode's doc
  // comment for why.
  blockMode: "nxdomain" | "sinkhole"
  enabled: boolean
  domainCount: number
  fileBytes: number
  sha256: string
  lastFetchedAt?: string
  lastError?: string
  createdAt: string
}

// Must match backend model.DNSBlocklistsMax / DNSBlocklistMaxFileBytes (in
// MiB) / DNSBlocklistMaxNXDomainDomains.
export const DNS_BLOCKLISTS_MAX = 8
export const DNS_BLOCKLIST_MAX_FILE_MB = 16
export const DNS_BLOCKLIST_NXDOMAIN_MAX_DOMAINS = 150000

// Two entries on purpose — one of each sourceType AND one of each blockMode
// — so the Blocklists tab has a non-empty example of both mechanisms
// (addn-hosts sinkhole / conf-file nxdomain) visible in mock mode without
// the user having to add anything first.
export const initialDNSBlocklists: DNSBlocklist[] = [
  {
    id: "bl-stevenblack",
    name: "StevenBlack unified",
    sourceType: "url",
    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    blockMode: "sinkhole",
    enabled: true,
    domainCount: 93412,
    fileBytes: 1902344,
    sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0",
    lastFetchedAt: "2026-08-20T08:11:00Z",
    lastError: "",
    createdAt: "2026-08-20T08:10:00Z",
  },
  {
    id: "bl-manualupload",
    name: "Personal upload",
    sourceType: "upload",
    blockMode: "nxdomain",
    enabled: true,
    domainCount: 1240,
    fileBytes: 40920,
    sha256: "1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d835670",
    lastFetchedAt: "2026-08-21T09:00:00Z",
    lastError: "",
    createdAt: "2026-08-21T08:55:00Z",
  },
]

// --- Multi-WAN Failover (docs/ref/todo/multi-wan-failover-plan.md) -------
// Phase 1 only: uplink health-check config + read-only live status/metrics.
// probeMethod/state/effectiveMethod/metricQuality are plain strings (not
// literal unions) to mirror the backend's JSON contract exactly and avoid
// the mock/service layer needing its own separate narrowing.

export interface WanUplink {
  id: string
  name: string
  interface: string
  priority: number
  probeTargets: string[]
  probeMethod: string // "icmp" | "tcp" | "auto"
  probeTcpPort: number
  probeIntervalSeconds: number
  probeCount: number
  probeTimeoutMs: number
  lossThresholdPct: number
  latencyThresholdMs: number
  failStrikes: number
  recoverStrikes: number
  status: boolean
  description: string
}

export interface WanUplinkState {
  uplinkId: string
  interface: string
  state: string // "unknown" | "up" | "degraded" | "down"
  active: boolean
  lastLatencyMs: number
  // jitterMs is only meaningful when metricQuality === "full" — a
  // connect-only (TCP) round reports 0, callers must check metricQuality
  // before displaying it (D-6).
  jitterMs: number
  lossPct: number
  effectiveMethod: string // "icmp" | "tcp"
  metricQuality: string // "full" | "connect-only"
  strikes: number
  lastChangeAt: string
  reason: string
}

// WanStatusEntry mirrors the backend's flattened WanUplinkState + name +
// priority (Go struct embedding), so a single object carries everything a
// status card needs.
export interface WanStatusEntry extends WanUplinkState {
  name: string
  priority: number
}

export interface WanStatusResponse {
  uplinks: WanStatusEntry[]
  // Phase 2 (not-yet-built failover controller) fields — always the zero
  // value in Phase 1.
  bypassedByStaticRoute: boolean
  activeUplinkId: string
  lastSwitchAt: string
  lastSwitchReason: string
}

export interface WanMetricPoint {
  timestamp: string
  avgLatencyMs: number
  maxLatencyMs: number
  // null when the bucket has no full-quality (ICMP) sample — never treat a
  // missing value as zero jitter (D-6).
  jitterMs: number | null
  lossPct: number
}

// WanFailoverSettings is reserved for the Phase 2 kill switch/mode
// (docs/ref/todo/multi-wan-failover-plan.md Task 16-18) — defined now so
// wanService.ts's shape matches the eventual backend contract, even though
// no endpoint returns it yet in Phase 1. There is intentionally no field
// here that would let a "degraded" reading drive a failover decision (D-7).
export interface WanFailoverSettings {
  enabled: boolean
  mode: string // "auto" | "manual"
  manualUplinkId: string
  minHoldSeconds: number
  revertDelaySeconds: number
}

// Two example uplinks: primary wired connection healthy, backup Wi-Fi/4G
// uplink degraded (latency over threshold, no loss) — enough for the UI to
// exercise every visual state (Badge colors, effective-method label,
// connect-only jitter graying) without a real board.
export const initialWanUplinks: WanUplink[] = [
  {
    id: "wan-primary",
    name: "Primary Fiber",
    interface: "eth0",
    priority: 1,
    probeTargets: ["1.1.1.1", "8.8.8.8"],
    probeMethod: "auto",
    probeTcpPort: 443,
    probeIntervalSeconds: 5,
    probeCount: 3,
    probeTimeoutMs: 1000,
    lossThresholdPct: 50,
    latencyThresholdMs: 200,
    failStrikes: 3,
    recoverStrikes: 3,
    status: true,
    description: "Main fiber uplink",
  },
  {
    id: "wan-backup",
    name: "Backup 4G",
    interface: "wlan0",
    priority: 2,
    probeTargets: ["1.1.1.1"],
    probeMethod: "auto",
    probeTcpPort: 443,
    probeIntervalSeconds: 5,
    probeCount: 3,
    probeTimeoutMs: 1500,
    lossThresholdPct: 50,
    latencyThresholdMs: 150,
    failStrikes: 3,
    recoverStrikes: 3,
    status: true,
    description: "Backup 4G/Wi-Fi uplink",
  },
]

export const initialWanUplinkStates: Record<string, WanUplinkState> = {
  "wan-primary": {
    uplinkId: "wan-primary",
    interface: "eth0",
    state: "up",
    active: true,
    lastLatencyMs: 12.4,
    jitterMs: 2.1,
    lossPct: 0,
    effectiveMethod: "icmp",
    metricQuality: "full",
    strikes: 0,
    lastChangeAt: "2026-09-06T09:00:00Z",
    reason: "healthy",
  },
  "wan-backup": {
    uplinkId: "wan-backup",
    interface: "wlan0",
    state: "degraded",
    active: false,
    lastLatencyMs: 210.5,
    jitterMs: 18.7,
    lossPct: 0,
    effectiveMethod: "icmp",
    metricQuality: "full",
    strikes: 0,
    lastChangeAt: "2026-09-06T09:05:00Z",
    reason: "latency 210.5ms exceeds threshold 150.0ms",
  },
}

export const initialWanFailoverSettings: WanFailoverSettings = {
  enabled: false,
  mode: "auto",
  manualUplinkId: "",
  minHoldSeconds: 60,
  revertDelaySeconds: 120,
}




