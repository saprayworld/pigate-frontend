# Multi-WAN Failover — สลับ WAN อัตโนมัติเมื่อเน็ตหลักมีปัญหา (single-site)

> เอกสารแผนงานสำหรับฟีเจอร์: ตรวจสุขภาพ WAN uplink หลายเส้นด้วย ICMP/TCP probe
> (bind-to-device) แบบ Go-native แล้วสลับ default route อัตโนมัติเมื่อเส้นหลักมีปัญหา
> จริง (ไม่ใช่แค่สายหลุด) โดยไม่แตะ nftables/fwmark/policy routing เลย
>
> วันที่เขียน: 2026-09-06 · Branch อ้างอิง: `main` (จะแยก `feat/multi-wan-failover` ก่อนเริ่มโค้ด)
> สถานะใน README Feature Status: ไม่มีแถวนี้ → เป้าหมายคือเพิ่มแถวใหม่ "Multi-WAN Failover: Completed"
> **หมายเหตุการตั้งชื่อ:** ตั้งใจไม่ใช้คำว่า "SD-WAN" ในโค้ด/UI/เอกสาร เพราะขอบเขต
> นี้ไม่มี overlay tunnel หรือ controller ข้าม site — ใช้ "Multi-WAN Failover" ให้ตรง
> กับสิ่งที่ส่งมอบจริงเท่านั้น

## 0. เป้าหมายและขอบเขต

- **เป้าหมาย:** รองรับ WAN 2 เส้น (เช่น เน็ตบ้านหลัก + 4G สำรอง) ตรวจสุขภาพแต่ละเส้น
  ด้วย ICMP/TCP probe จริง (ไม่ใช่แค่ "มี default route หรือเปล่า") แสดงผล
  latency/jitter/loss สดในหน้า UI แล้วสลับ default route อัตโนมัติเมื่อเส้นหลัก
  ตรวจพบว่า "ตาย" จริง (รวมเคส link-up แต่อินเทอร์เน็ตใช้ไม่ได้ / brownout) พร้อม
  manual override และ kill switch ปิดฟีเจอร์ทั้งหมด
- **ยอมรับได้:** ตอนสลับ WAN แล้ว session ที่ค้างอยู่ (วิดีโอคอล/ดาวน์โหลด) จะขาด —
  ตัดสินใจโดยเจ้าของโปรเจกต์ 2026-09-06 เพราะไม่ต้องการทำ overlay tunnel เพื่อคง IP
- **นอกขอบเขต (ชัดเจน):**
  - **Policy-based routing / load balancing ตาม traffic class** (เดินหลาย WAN
    พร้อมกัน) — ต้องใช้ policy routing table + fwmark ใหม่ทั้งชุด เป็นงานคนละ
    ขนาด ถ้าต้องการในอนาคตให้วางแผนแยกเป็นฟีเจอร์ใหม่
  - **Multi-site overlay VPN (WireGuard) + centralized controller** — ติดปัญหา
    NAT traversal ที่แก้ด้วยโค้ดไม่ได้ (ต้องมี VPS/relay) และซ้อนทับกับแผน
    `cloudflare-tunnel-plan.md` / `cloudflare-mesh-plan.md` ที่มีอยู่แล้ว
  - **IPv6** — routing layer ปัจจุบันเป็น IPv4 ล้วน ระบุข้อจำกัดนี้ใน UI ตรงๆ
  - **ECMP/multipath** — ไม่ทำ
  - **DPI/per-application routing** — ต้องพึ่ง DNS/DPI ซึ่ง `tech_stack_design.md`
    §8 ห้ามใช้ DNS statistics ตัดสิน routing/firewall (poison ได้จาก LAN client)

## 1. สถานะปัจจุบัน (สำรวจโค้ดแล้ว ณ วันที่เขียน)

| ความสามารถ | สถานะ | ไฟล์:บรรทัด |
|---|---|---|
| Static route CRUD + reconcile ลง kernel ผ่าน netlink | ครบ | `backend/internal/service/routing.go`, `backend/internal/kernel/real_routing.go` |
| Marker route ของ PiGate = proto 120 (แยก route ของเราออกจาก route ระบบ) | มี | `real_routing.go:88` |
| ฟิลด์ `Metric *int` ต่อ interface + `EnforceDefaultRouteMetric()` | มี | `model/types.go:467`, `real_routing.go:321`, `routing.go:445` |
| NetlinkMonitor + NetEventBus (reconcile บน link/addr/route event, กัน event storm) | มี ออกแบบดี | `service/netlink_monitor.go`, `event_bus.go` |
| Health-check loop แบบ periodic + RAM state + settings ใน DB (แม่แบบที่ตรงที่สุดสำหรับ WAN probe) | มี | `service/dhcp_health_checker.go` |
| Firewall generator + policy-SNAT ผ่าน **fwmark 0x1 → masquerade** | มี | `kernel/real_firewall.go:795-822` |
| QoS ต่อ interface (HTB egress + IFB ingress) | มี | `kernel/real_qos.go`, `model/types.go:1267` |
| `rp_filter=2` (loose) — จำเป็นกับ asymmetric routing ของ multi-WAN | มีอยู่แล้ว | `install.sh:446-514` |
| Capability probe framework | มี | `service/system_capability.go` |
| Wi-Fi backup SSID failover (L2 เท่านั้น ไม่ใช่ path selection) | มี | `kernel/real_network.go`, `wpa.go` |
| Policy routing / multiple routing tables (`ip rule`, `Route.Table`) | **ไม่มีเลย** ทั้งโปรเจกต์ | — |
| WAN path health monitoring (latency/jitter/loss) | **ไม่มีเลย** | — |
| Dynamic failover ตามคุณภาพเส้นทาง (ปัจจุบันสลับเฉพาะตอน route หายจาก kernel) | **ไม่มี** | — |
| Tunnel/overlay ใดๆ (WireGuard/IPsec/GRE) | **ไม่มี** | — |
| `NetworkInterface.Role="WAN"` เป็น first-class object | เป็นแค่ label ให้ DHCP server ข้าม | `service/dhcp_server.go:44` |

สรุป: มีฐาน "multi-WAN ระดับพื้นฐาน" (metric ordering + failover เมื่อสายหลุดจริง)
แต่ยังไม่มีชิ้นส่วนหลักของ failover-แบบ-ตรวจสุขภาพเลย งานจริงคือสร้าง subsystem
ใหม่ (WAN uplink + prober + monitor + failover controller) แล้ว "เสียบ" เข้ากับ
กลไก `EnforceDefaultRouteMetric` เดิมที่มีอยู่แล้ว ไม่ใช่คิดกลไก routing ใหม่

## 2. แนวทางเทคนิค

**การตัดสินใจเชิงสถาปัตยกรรมที่บังคับใช้ทุก Task (D-1 ถึง D-8)**

- **D-1 — ไม่แตะ nftables/fwmark เลย** ขอบเขตนี้คือ failover ล้วน (ไม่มี policy
  routing/load balance) จึงไม่ต้องใช้ fwmark หรือ routing table เพิ่ม ความเสี่ยง
  ชนกับ fwmark 0x1 ของ policy-SNAT เดิมถูกกำจัดด้วยการออกแบบ ไม่ใช่ด้วยความระวัง
  กลไก failover = ปรับ priority ของ default route ต่อ interface เท่านั้น (ใช้
  `EnforceDefaultRouteMetric` ที่มีอยู่แล้ว) NAT เดิมทำงานต่อได้เองเพราะ
  masquerade อ้างอิง outgoing interface address อยู่แล้ว
- **D-2 — เจ้าของเดียวของ default-route metric (กัน route flapping)**
  `RoutingService.enforceInterfaceMetrics()` (`routing.go:445`) เป็นจุดเดียวที่
  เรียก `EnforceDefaultRouteMetric` ห้าม failover controller เรียก kernel เอง
  เด็ดขาด — เขียนค่า override ลงแมพ RAM แล้วสั่ง reconcile ผ่าน service เดียวกัน
  precedence บังคับ:
  ```
  1. static_routes ที่ active สำหรับ 0.0.0.0/0 บน iface นั้น → ชนะทุกอย่าง
     (failover ต้อง "ยอมแพ้" + ขึ้น warning ใน UI + event log ว่าถูก bypass)
  2. Failover override (RAM, จาก controller)               → ชนะ interface.Metric
  3. interface.Metric จาก DB                                → พฤติกรรมเดิม
  4. ไม่มีอะไรเลย                                            → ตาม dhcpcd/static เดิม
  ```
- **D-3 — metric time-series อยู่ใน RAM เท่านั้น** ตาม `tech_stack_design.md` §8
  ใช้แม่แบบเดียวกับ `logs/ringbuffer.go` / `traffic_stats.go` SQLite เก็บเฉพาะ
  config + event log ของการ failover (เหตุการณ์นานๆครั้ง ไม่ใช่ time-series)
- **D-4 — probe เป็น Go-native เท่านั้น ห้าม `exec.Command("ping")` ทุกกรณี**
- **D-5 — probe รองรับ 2 วิธี พร้อม auto-fallback ภายในรอบเดียว** `ProbeMethod`
  ต่อ uplink มี 3 ค่า: `icmp` | `tcp` | `auto`
  - `auto` = ยิง ICMP ก่อน **ถ้ารอบนั้นไม่ได้ reply เลย ให้ยิง TCP-connect ต่อ
    ทันทีในรอบเดียวกัน** แล้วใช้ผล TCP เป็นผลของรอบนั้น (ต้อง fallback ในรอบ
    เดียวกัน ไม่ใช่ "หลังประกาศ down แล้วค่อยลอง" — ไม่งั้น ICMP ที่ถูก ISP บล็อก
    จะถูกตีความเป็น outage จริงและสั่ง failover ผิดพลาด)
  - **Sticky:** ICMP ล้มเหลวติดกันครบ `stickyThreshold=3` รอบ แต่ TCP สำเร็จ →
    pin เป็น TCP กันยิง probe ซ้ำซ้อน แล้วลอง ICMP ใหม่ทุก 10 นาที (re-test)
  - **TCP ไม่ต้องใช้ `cap_net_raw`** (`net.Dialer{Control: SO_BINDTODEVICE}`)
    เครื่องที่ไม่มี `cap_net_raw` ยังใช้ฟีเจอร์ได้ด้วย method `tcp`
- **D-6 — TCP-connect วัดคุณภาพได้ไม่เท่า ICMP ต้องบอกผู้ใช้ตรงๆ** TCP ให้แค่
  connect-time (latency proxy) + สำเร็จ/ล้มเหลว (loss proxy) — **jitter ไม่มี
  ความหมาย** ต้องมีฟิลด์ `MetricQuality` (`full`|`connect-only`) ไหลถึง UI แล้ว
  เทา/ซ่อนค่า jitter เมื่อ connect-only ห้ามแสดงตัวเลขที่ตีความผิดได้
- **D-7 — ตัดแนวคิด "degraded trigger failover" ออกทั้งระบบ** `degraded` เป็น
  สถานะแสดงผลอย่างเดียว ไม่มีฟิลด์ `FailoverOnDegraded` เลย (ตัดทิ้ง ไม่ใช่ตั้ง
  default false) failover เกิดเฉพาะ `down` เท่านั้น — ตัดสินใจโดยเจ้าของโปรเจกต์
  2026-09-06 เพราะสลับ WAN = session ขาด ไม่อยากสลับโดยไม่จำเป็น
- **D-8 — สิทธิ์ API แยกสองระดับ** ดู/ตั้งค่า uplink = `authRoute` (เท่า Static
  Routes/QoS) ส่วน **kill switch + manual override เท่านั้น** = `superAdminRoute`
  (คุมทั้งเครือข่ายทันทีที่กดปุ่ม) — ตัดสินใจโดยเจ้าของโปรเจกต์ 2026-09-06

**pattern/ไฟล์แม่แบบที่ให้ทำตาม:** `dhcp_health_checker.go` (periodic monitor +
RAM state + settings), `routing.go`/`real_routing.go` (จุดแก้ precedence),
`logs/ringbuffer.go`/`traffic_stats.go` (RAM ring buffer 5 นาที×288), `router.go`
(authRoute/superAdminRoute split), `interface-metric-design.md` (Cautions เรื่อง
ping-pong ที่ห้ามทำซ้ำ)

## 3. ขั้นตอนการทำ (เรียงลำดับ dependency)

**Task 0 — Spike Kit สำหรับทดสอบบนบอร์ดจริง (blocking, ไม่ commit เข้า repo)**
ai-developer เตรียม แต่**เจ้าของโปรเจกต์เป็นคนรันจริง** เพราะทีม AI ไม่มีสิทธิ์
เข้าถึงบอร์ดที่มี WAN 2 เส้น:
- snippet Go ไฟล์เดียว (วางใน scratchpad เท่านั้น) ทดสอบ raw ICMP +
  `SO_BINDTODEVICE` **และ** TCP-connect bind ทั้งสองวิธี + วัด CPU/เวลา
- checklist คำสั่ง shell copy-paste ได้ ระบุผลลัพธ์ที่ต้องแปะกลับมา ครอบคลุม
  8 ข้อที่ต้องพิสูจน์:
  1. raw ICMP + bind ทำงานภายใต้ user `pigate`+`cap_net_raw` และ RTT ต่างกันจริง
     ตามเส้นทาง (ถ้า bind ไม่ได้ผล → ต้องกลับมาคุยใหม่ ขยายขอบเขตนอกแผนนี้)
  2. default route 2 เส้นต่างเมตริกอยู่ร่วมกันได้ สลับ metric แล้ว public IP
     เปลี่ยนภายใน <5 วินาที
  3. รัน pigate โหมด real สลับ metric ด้วยมือ → log `[Routing]` ไม่เกิด
     ping-pong (del/add วนเกิน 2 รอบ)
  4. ถอด/เสียบสาย WAN → NetlinkMonitor คืน metric ที่ต้องการภายใน ~2 วินาที
  5. หลังสลับ WAN แล้ว NAT ยังทำงาน (client ใน LAN ออกเน็ตได้)
  6. **เคส brownout** (link-up แต่ไม่มีเน็ต จริง — ถอดสาย uplink ของ modem)
     probe ต้องตรวจจับได้ (loss 100%) แม้ `ip route` ยังมี default route — นี่คือ
     เหตุผลหลักทั้งหมดของฟีเจอร์นี้
  7. ภาระ CPU ของ probe ที่ interval จริง (เช่น 5s×3 packet×2 uplink) ไม่เกิน ~1%
  8. `net.ipv4.conf.all.rp_filter=2` ยังเป็น loose บนเครื่องจริง
- โครงไฟล์ `docs/ref/wan-failover-findings.md` (หัวข้อ 1-8 เว้นช่องว่างรอเติมผล)
- **acceptance:** เจ้าของโปรเจกต์รันตามได้จนจบโดยไม่ต้องถามอะไรเพิ่ม snippet
  compile ผ่านด้วย `go run` บนบอร์ด **ต้องผ่านข้อ 1, 2, 6 อย่างน้อย** และบันทึกผล
  ลง findings doc ก่อนเริ่ม Task 1 ได้

### Phase 1 — WAN Uplink + Health Monitoring (read-only, ไม่แตะ routing เลย)

**Task 1 — model**
**ไฟล์:** `backend/internal/model/wan_uplink.go` (ใหม่),
`backend/internal/model/wan_validate.go` (ใหม่), `backend/internal/model/wan_validate_test.go` (ใหม่)
- `WanUplink{ID, Name, Interface, Priority int, ProbeTargets []string,
  ProbeMethod string /*icmp|tcp|auto*/, ProbeTCPPort int, ProbeIntervalSeconds,
  ProbeCount, ProbeTimeoutMs, LossThresholdPct, LatencyThresholdMs,
  FailStrikes, RecoverStrikes int, Status bool, Description}`,
  `WanUplinkInput`, `WanUplinkState{UplinkID, Interface, State string
  /*unknown|up|degraded|down*/, Active bool, LastLatencyMs, JitterMs, LossPct
  float64, EffectiveMethod, MetricQuality string, Strikes int, LastChangeAt,
  Reason string}`, `WanProbeSample{TimestampUnix int64, Sent, Received int,
  RTTsMs []float64, Method, MetricQuality string}`,
  `WanFailoverSettings{Enabled bool, Mode string /*auto|manual*/,
  ManualUplinkID string, MinHoldSeconds, RevertDelaySeconds int}`
  (**ไม่มี** `FailoverOnDegraded` — D-7)
- `ValidateWanUplink(input)` / `ValidateWanFailoverSettings(s)` เป็นฟังก์ชัน
  บริสุทธิ์: probe target เป็น **IPv4 literal เท่านั้น ห้าม hostname**
  (กัน DNS dependency loop ตอนเน็ตล่ม + กัน DNS poisoning เปลี่ยนพฤติกรรม
  routing ตาม §8) ปฏิเสธ multicast/broadcast/loopback/0.0.0.0; **ไม่มี default
  target ต้องกรอกเอง** (D-8 เรื่อง privacy); `ProbeMethod` ต้องเป็น 1 ใน 3 ค่า;
  ถ้า `tcp`/`auto` → `ProbeTCPPort` ต้อง 1-65535 (บังคับกรอก) ถ้า `icmp` → port
  ต้องเป็น 0; interval 2-300s; count 1-10; timeout 100-5000ms; loss 1-100%;
  latency 1-10000ms; strikes 1-20; priority 1-16
- **acceptance:** `go build ./...` ผ่าน; unit test ครอบ hostname ถูกปฏิเสธ,
  ค่านอกช่วงทุกฟิลด์ถูกปฏิเสธพร้อมข้อความอธิบายฟิลด์, method ทั้ง 3×port
  valid/invalid/ขาด, ค่า valid ผ่าน; struct ไม่มีคำว่า `Degraded` ในบริบท
  failover setting; ทุกฟิลด์ใหม่มี `omitempty`
- **depends_on:** Task 0

**Task 2 — db (migration + repository, ทำครบ Phase 1+2 ทีเดียว)**
**ไฟล์:** `backend/internal/db/connection.go` (แก้ ต่อท้ายกลุ่มใกล้
`dhcp_health_settings`), `backend/internal/db/wan_repo.go` (ใหม่),
`backend/internal/db/wan_migration_test.go` (ใหม่)
- ตาราง `wan_uplinks` (id, interface UNIQUE, ฟิลด์ตาม Task 1 รวม
  `probe_method TEXT NOT NULL DEFAULT 'auto'`, `probe_tcp_port INTEGER NOT
  NULL DEFAULT 0`) และ single-row `wan_failover_settings` (`id INTEGER
  PRIMARY KEY CHECK(id=1)`, `enabled INTEGER DEFAULT 0` — **default ปิด**,
  `mode DEFAULT 'auto'`, `manual_uplink_id DEFAULT ''`, `min_hold_seconds
  DEFAULT 60`, `revert_delay_seconds DEFAULT 120`, **ไม่มีคอลัมน์
  `failover_on_degraded`**) + seed `INSERT OR IGNORE`
- repo CRUD ตาม pattern `wifi_preset_repo.go`; `CREATE TABLE IF NOT EXISTS`
  เท่านั้น ห้าม ALTER ที่มี NOT NULL ไม่มี DEFAULT
- **acceptance:** `go test ./internal/db/...` ผ่าน; migration test เปิด DB เก่า
  migrate ขึ้นได้ + มีแถว id=1 + คอลัมน์ probe_method/probe_tcp_port มี default
  ถูกต้อง + CRUD ครบวงจร; `enabled` เริ่มต้นเป็น 0 จริง
- **depends_on:** Task 1

**Task 3 — kernel interface**
**ไฟล์:** `backend/internal/kernel/interfaces.go` (แก้ ต่อท้าย)
- `PathProbeManager` สองเมธอด:
  ```go
  ProbeICMP(ctx, ifaceName string, target net.IP, count int, timeout time.Duration) (model.WanProbeSample, error)
  ProbeTCP(ctx, ifaceName string, target net.IP, port, count int, timeout time.Duration) (model.WanProbeSample, error)
  ```
- doc comment: (1) read-only ไม่แก้ state ระบบใดๆ (2) ต้อง bind ออก
  `ifaceName` จริงผ่าน `SO_BINDTODEVICE` (3) ต้องเคารพ ctx คืนภายใน
  `count×timeout` เสมอ (4) ปลายทางไม่ตอบ **ไม่ใช่ error** คืน sample
  `Received=0` (error สงวนไว้สำหรับ "probe ระบบพัง" เช่นสร้าง socket ไม่ได้)
  (5) ต้องเซ็ต `Sample.Method`+`Sample.MetricQuality` เสมอ (`ProbeTCP` →
  `connect-only` เสมอ) **kernel layer ห้ามตัดสินใจเรื่อง fallback** เป็นหน้าที่
  service layer ทั้งหมด
- **acceptance:** `go build ./...` ผ่าน (จะผ่านเต็มหลัง Task 4/5); doc comment
  ครบ 5 ข้อ
- **depends_on:** Task 1

**Task 4 — kernel real implementation (SENSITIVE — raw socket, review เข้มพิเศษ)**
**ไฟล์:** `backend/internal/kernel/real_path_probe.go` (ใหม่, `//go:build
linux`), `backend/internal/kernel/real_path_probe_test.go` (ใหม่)
- `ProbeICMP`: `net.ListenConfig{Control:...}` setsockopt `SO_BINDTODEVICE` →
  `ListenPacket(ctx,"ip4:icmp","0.0.0.0")` encode/decode ด้วย
  `golang.org/x/net/icmp`+`ipv4` (เพิ่มเป็น direct dep — ปัจจุบันเป็น indirect
  อยู่แล้ว ไม่ใช่ dep ใหม่ต่อ supply chain); ICMP ID จาก PID, Sequence เดินหน้า
  ต่อ probe ต้องทิ้ง reply ที่ไม่ตรง ID/Seq; `defer conn.Close()` ทุกเส้นทางออก;
  ตรวจ `ifaceName` มีจริงจาก netlink ก่อนใช้; ห้าม log ทุกรอบ probe (เฉพาะ
  error ที่เปลี่ยนสถานะ)
- `ProbeTCP`: `net.Dialer{Control: bindToDeviceControl(iface), Timeout:
  timeout}` (helper ใช้ร่วมกับ ProbeICMP กัน setsockopt ผิดสองที่) →
  `DialContext(ctx,"tcp4",ip:port)` วัดเวลาจนสำเร็จ → **ปิด conn ทันทีด้วย
  defer** (กัน fd leak); **connection refused = ปลายทางถึงได้** (นับสำเร็จ
  ในเชิง reachability ต้องมี comment อธิบายชัด เพราะเข้าใจผิดง่าย) timeout/
  unreachable = ล้มเหลว
- **acceptance:** `go build ./...` + `go vet ./...` ผ่าน; unit test: จับคู่
  ID/Seq, คำนวณ loss/jitter จาก RTT list, เคารพ ctx cancel; TCP: listener
  ภายในเครื่อง connect สำเร็จ→success, port ไม่มีคนฟัง (refused)→reachable,
  ctx cancel ระหว่างรอ→คืนทันที, เรียก 100 ครั้งไม่มี fd รั่ว; `grep -rn
  "exec.Command" backend/internal/kernel/real_path_probe.go` ไม่พบ; มี
  `//go:build linux`
- **depends_on:** Task 3

**Task 5 — kernel mock**
**ไฟล์:** `backend/internal/kernel/mock.go` (แก้ ต่อท้าย)
- `MockPathProbe` implement ทั้งสองเมธอด คืนค่าจำลอง deterministic-ish (RTT
  10-30ms, loss 0%) + setter ให้เทสต์บังคับเคส **"ICMP ตายแต่ TCP ปกติ"**
  (เหตุผลหลักของ D-5) และ "ตายทั้งคู่" **ห้ามเปิด socket จริง ห้าม sleep นาน
  ตาม timeout จริง**
- **acceptance:** `go build ./...` ผ่านทั้งโปรเจกต์; รัน `-mock=true` ไม่มี
  traffic ICMP ออกจากเครื่อง (ตรวจจากโค้ดว่าไม่เรียก net.ListenPacket จริง)
- **depends_on:** Task 3

**Task 6 — service: metric ring buffer (RAM-only)**
**ไฟล์:** `backend/internal/service/wan_metrics_ring.go` (ใหม่),
`backend/internal/service/wan_metrics_ring_test.go` (ใหม่)
- ต่อ uplัง: ring ของ raw sample ล่าสุด N รอบ (`maxRawSamplesPerUplink=360`)
  + bucket สรุป 5 นาที×288 (24ชม.) เก็บ avg/max latency, jitter, loss% — ตาม
  แม่แบบ `traffic_stats.go`; mutex ป้องกัน concurrent access; **ห้าม import
  `internal/db` ในไฟล์นี้เด็ดขาด**
- **acceptance:** unit test: เขียนเกิน capacity evict ตัวเก่าสุดถูกต้อง,
  bucket สรุปถูกต้อง, `go test -race` ผ่าน; `grep -n "db\.\|INSERT\|UPDATE"`
  ไม่พบในไฟล์นี้
- **depends_on:** Task 1

**Task 7 — service: WAN health monitor + state machine**
**ไฟล์:** `backend/internal/service/wan_monitor.go` (ใหม่),
`backend/internal/service/wan_monitor_test.go` (ใหม่)
- โครงตาม `dhcp_health_checker.go` ทุกประการ (periodic ticker, อ่าน settings
  สดจาก DB ทุก tick, RAM state, `bus.IsPaused()` guard, mock mode ทำงานต่อ
  ด้วย MockPathProbe เพื่อให้ dev เห็นข้อมูลใน UI)
- แยกฟังก์ชันบริสุทธิ์สองตัว: `decideState()` (sample+threshold+สถานะเดิม+
  strikes → สถานะใหม่+เหตุผล) และ `selectProbeMethod(cfg, prevEffective,
  icmpFailStreak, lastICMPRetryAt, now)` (method+alsoTryICMP) เพื่อทดสอบ
  sticky/re-test logic โดยไม่ต้องมี kernel
- orchestration ต่อรอบ: `auto`→ICMP; ถ้า `Received==0` ทุก target→ยิง TCP
  ต่อทันที ใช้ผล TCP; อัปเดต streak/sticky; บันทึก `EffectiveMethod`+
  `MetricQuality` ลง state+ring; เมื่อสถานะ**เปลี่ยน**เท่านั้นจึง log event
  (`network`/`wan-uplink-state`); เมื่อ effective method สลับ (icmp↔tcp)
  log ครั้งเดียวต่อการสลับ **ห้าม log ทุกรอบ**
- expose `GetStates() []model.WanUplinkState`, `GetMetrics(uplinkID, window)`
- **ไฟล์นี้ห้าม import kernel.RoutingManager หรือแตะ routing ใดๆ** (Phase 1
  = read-only ล้วน)
- **acceptance:** `go test -race ./internal/service/...` ผ่าน; test ครอบ:
  loss 100% ต่อเนื่องครบ FailStrikes→down (ไม่ก่อนหน้านั้น), ฟื้นครบ
  RecoverStrikes→up, latency เกิน threshold ไม่ loss→degraded, probe error
  (ระบบพัง)≠down เป็น unknown+log, สถานะไม่เปลี่ยน→ไม่มี log ซ้ำ, **ICMP ตาย+
  TCP ปกติ→up (ไม่ใช่ down) และ EffectiveMethod=tcp หลังครบ sticky threshold**,
  ตายทั้งคู่→down ตาม FailStrikes, ICMP กลับมาใช้ได้หลัง re-test interval→
  กลับเป็น icmp+MetricQuality=full, method=icmp ล้วน→ไม่มีการยิง TCP เลยแม้
  loss 100% (call counter บน mock); `grep -n
  "Routing\|EnforceDefaultRouteMetric\|netlink"` ไม่พบในไฟล์นี้
- **depends_on:** Task 2, Task 5, Task 6

**Task 8 — wiring (monitor เท่านั้น)**
**ไฟล์:** `backend/cmd/pigate/main.go` (แก้)
- ประกาศ `pathProbe kernel.PathProbeManager` กลุ่มเดียวกับ manager อื่น,
  assign mock/real ตาม flag, สร้าง `wanMonitor` ใกล้ `dhcpHealthChecker`,
  **Start หลัง `netlinkMonitor.Start()` และหลัง `dhcpHealthChecker.Start()`**
  พร้อม log บรรทัดเดียวตามสไตล์เดิม; ส่ง `wanMonitor` เข้า `api.NewServer`
- **acceptance:** `go build ./...` ผ่าน; รัน `-mock=true` log แสดง monitor
  start ไม่ panic ภายใน 60 วินาที; รันโดยยังไม่มี uplink ใน DB ไม่มี
  error/log spam
- **depends_on:** Task 7

**Task 9 — api (handlers + routes + openapi)**
**ไฟล์:** `backend/internal/api/wan_handlers.go` (ใหม่),
`backend/internal/api/handlers.go` (แก้), `backend/internal/api/router.go`
(แก้), `docs/openapi.yaml` + `frontend/public/openapi.yaml` (แก้ทั้งคู่),
`backend/internal/api/wan_handlers_test.go` (ใหม่)
- endpoints ทั้งหมดใช้ **`authRoute`** (ตาราง route แยกสิทธิ์เต็มอยู่ใน §4):
  `GET /api/wan/uplinks`, `POST/PUT/DELETE /api/wan/uplinks[/{id}]`,
  `GET /api/wan/status` (สถานะสด+metric ล่าสุด รวม `bypassedByStaticRoute`,
  `activeUplinkId`, `lastSwitchAt`, `lastSwitchReason`), `GET
  /api/wan/metrics?uplink=<id>&window=<1h|24h>`
- validation ทั้งหมดอยู่ใน model/service ไม่ใช่ handler; error→400
  (validation), 404 (id ไม่พบ), 500 (kernel/db)
- **acceptance:** `go test ./internal/api/...` ผ่าน; POST target เป็น
  hostname→400 พร้อมข้อความบอกฟิลด์; GET status คืน JSON มีทุก uplink แม้ยัง
  ไม่เคย probe (state=unknown); openapi ทั้งสองไฟล์เนื้อหาส่วนใหม่ตรงกันทุก
  ตัวอักษร
- **depends_on:** Task 8

**Task 10 — frontend: API client + mock data**
**ไฟล์:** `frontend/src/services/wanService.ts` (ใหม่),
`frontend/src/data-mockup/mockData.ts` (แก้), `frontend/src/services/mockSync.ts` (แก้ถ้าจำเป็น)
- ตาม pattern `qosService.ts`/`staticRouteService.ts`; export type
  `WanUplink`, `WanUplinkState`, `WanMetricPoint`, `WanFailoverSettings`
  (ไม่มี `failoverOnDegraded`) + ฟังก์ชันครบทุก endpoint ของ Task 9 (เผื่อ
  endpoint ของ Task 16 ไว้ด้วยได้); mock data มี 2 uplink ตัวอย่าง (primary
  eth0 up, backup wlan0/4G degraded)
- **acceptance:** `yarn build`+`yarn lint` ผ่าน; type ตรงกับ JSON จริง
  (รัน backend `-mock=true -allow-dev-cors` คู่ `yarn dev` ไม่มี type
  error/undefined ใน console)
- **depends_on:** Task 9

**Task 11 — frontend: หน้า Multi-WAN**
**ไฟล์:** `frontend/src/pages/WanFailover.tsx` (ใหม่),
`frontend/src/App.tsx` (แก้), `frontend/src/components/app-sidebar.tsx` (แก้ กลุ่ม "Network")
- route `/network/wan` label "Multi-WAN"; Card สรุปต่อ uplink (Badge สถานะ
  up/degraded/down/unknown สี semantic เท่านั้น, latency/jitter/loss ล่าสุด,
  ป้าย effective method, Active badge, เทา/ซ่อน jitter เมื่อ connect-only
  พร้อม tooltip); กราฟ latency+loss ย้อนหลัง (1h/24h) จาก
  `GET /api/wan/metrics`; ตาราง uplink + Dialog เพิ่ม/แก้ (probe targets,
  method+port, thresholds, strikes, priority — บอกชัดว่าไม่มี default
  target); Alert ถาวรเตือน IPv4-only; poll ทุก 5 วินาที (clear ตอน
  unmount); ตาม `docs/rules_of_work.md` ทุกข้อ (ui components เท่านั้น, ห้าม
  shadow-*/backdrop-blur-*, ห้าม hardcode สี, dark/light, router จาก
  `"react-router"`, `<Dialog modal={false}>` เฉพาะมี Combobox)
- **acceptance:** `yarn build`+`yarn lint` ผ่าน; mock mode เห็น 2 uplink+
  กราฟ; dark/light อ่านออกทั้งคู่; `grep -n
  "shadow-\|backdrop-blur\|react-router-dom"` ไม่พบ
- **depends_on:** Task 10

**Task 12 — backup/restore**
**ไฟล์:** `backend/internal/service/backup.go` (แก้),
`backend/internal/model/backup.go` (แก้), `backend/internal/db/backup_repo.go` (แก้)
- เพิ่ม `WanUplinks []model.WanUplink` + `WanFailoverSettings
  *model.WanFailoverSettings` (pointer+`omitempty` ให้ backup เก่า import
  ได้), restore แบบ nil-check ตาม pattern `DhcpHealthSettings`
- **acceptance:** `go test ./internal/service/... -run Backup` ผ่าน;
  export→import กลับได้ uplink ครบ; **import backup เก่า (ไม่มีสองฟิลด์นี้)
  ผ่าน checksum และ import สำเร็จ**
- **depends_on:** Task 2

**Task 13 — capability probe**
**ไฟล์:** `backend/internal/service/system_capability.go` (แก้),
`backend/internal/kernel/real_capability.go` (แก้)
- เพิ่ม capability id `icmp-probe` — probe read-only ว่าเปิด raw ICMP socket
  ได้ไหม (สร้างแล้วปิดทันที ห้ามส่ง packet) ไม่ได้ (ไม่มี `cap_net_raw`) →
  degraded พร้อมเหตุผล (D-5: เครื่องยังใช้ method `tcp` ได้ต่อ ไม่ตายทั้งฟีเจอร์)
- **acceptance:** `go test ./internal/service/... -run Capability` ผ่าน;
  เครื่องไม่มี cap→panel แสดง degraded ไม่ใช่ error ทั้งหน้า; probe ไม่ส่ง
  packet จริง
- **depends_on:** Task 4

### Phase 2 — Automatic Failover (เริ่มเปลี่ยน routing)

**Task 14 — service: routing precedence + override API (SENSITIVE — review เข้ม)**
**ไฟล์:** `backend/internal/service/routing.go` (แก้),
`backend/internal/service/routing_test.go` (แก้)
- แมพ RAM `failoverMetricOverrides map[string]int`+mutex ใน
  `RoutingService`: `SetFailoverMetricOverride(iface,metric)`,
  `ClearFailoverMetricOverride(iface)`, `ClearAllFailoverMetricOverrides()`,
  `FailoverOverrides() map[string]int` (copy); แก้
  `enforceInterfaceMetrics()` (`:445`) บังคับ precedence ตาม D-2 **โดยไม่
  เปลี่ยนพฤติกรรมเดิมเมื่อไม่มี override สักตัว** เมื่อ static route
  0.0.0.0/0 ชนะ ให้เก็บสถานะ "bypassed" ให้ service ชั้นบนอ่านได้; เมธอด
  ทั้งหมดต้อง idempotent (ตั้งค่าเดิมซ้ำต้องไม่ del/add)
- **acceptance:** `go test -race ./internal/service/... -run Routing`
  ผ่าน; test: ไม่มี override→เรียก enforce ด้วยค่า iface.Metric เหมือนเดิม
  เป๊ะ (regression guard), มี override→ใช้ค่า override, มี static route
  0.0.0.0/0 active→**ไม่เรียก enforce เลย**+รายงาน bypassed, ตั้ง override
  ค่าเดิมซ้ำ 3 ครั้ง→ไม่เพิ่มการเรียก kernel
- **depends_on:** Task 7

**Task 15 — service: failover controller (SENSITIVE — review เข้ม)**
**ไฟล์:** `backend/internal/service/wan_failover.go` (ใหม่),
`backend/internal/service/wan_failover_test.go` (ใหม่)
- อ่านสถานะจาก `WanMonitor.GetStates()`+settings จาก DB ทุก tick แยก
  ตัดสินใจเป็นฟังก์ชันบริสุทธิ์ `decideActiveUplink(states, settings,
  current, now) (targetUplinkID, reason string, changed bool)` กติกา:
  - kill switch (`Enabled=false`)→`ClearAllFailoverMetricOverrides()`+คืน
    routing เดิม+ไม่ตัดสินใจอะไรอีก
  - `Mode="manual"`→บังคับ `ManualUplinkID` ไม่ว่าสถานะอะไร (ยัง log
    สถานะจริง)
  - `Mode="auto"`→เลือก uplink `Status=true` และสถานะ `up` เท่านั้น
    (ไม่มี degraded — D-7) ที่ `Priority` ต่ำสุด
  - **ห้ามสลับ** ถ้ายังไม่ครบ `MinHoldSeconds` จากการสลับครั้งก่อน (dampening)
  - **ห้าม blackhole:** ไม่มี uplink ไหน healthy เลย→คงของเดิม+log severity
    สูง (ไม่ถอน route ทิ้ง)
  - กลับ primary ต้องรอครบ `RevertDelaySeconds` เพิ่มจาก RecoverStrikes
  - บังคับใช้ผ่าน `RoutingService.SetFailoverMetricOverride`+
    `ReconcileKernelRoutingTable()` **เท่านั้น** ห้ามเรียก
    `kernel.RoutingManager` ตรงๆ (D-2)
  - ทุกการสลับ+เปลี่ยน mode/kill switch→log event (`network`/
    `wan-failover`) ระบุ from→to+เหตุผล
- **acceptance:** `go test -race ./internal/service/... -run Failover`
  ผ่าน; test: primary down→สลับ backup, primary ฟื้นก่อนครบ
  RevertDelay→**ไม่**สลับกลับ, ครบแล้ว→สลับกลับ, สลับสองครั้งใน
  MinHold→ครั้งที่สองถูกปฏิเสธ, ทุก uplink down→ไม่เปลี่ยนอะไร+log critical,
  kill switch off→ล้าง override หมด, manual mode→ชนะสถานะ health; `grep -n
  "kernel\.\|netlink\|nftables\|fwmark"` ไม่พบในไฟล์นี้
- **depends_on:** Task 14

**Task 16 — api: settings / kill switch / manual override**
**ไฟล์:** `backend/internal/api/wan_handlers.go` (แก้),
`backend/internal/api/router.go` (แก้), `docs/openapi.yaml`+
`frontend/public/openapi.yaml` (แก้ทั้งคู่), `backend/internal/api/wan_handlers_test.go` (แก้)
- `GET /api/wan/failover` = `authRoute`; **`PUT /api/wan/failover`
  (kill switch+mode+dampening) และ `POST /api/wan/failover/override` =
  `superAdminRoute`** (ตาราง route เต็มอยู่ใน §4); payload ตัด
  `failoverOnDegraded` ออก เพิ่ม `probeMethod`/`probeTcpPort`/
  `metricQuality`/`effectiveMethod`
- **acceptance:** `go test ./internal/api/...` ผ่าน; role
  `admin_readonly` เรียก `PUT /api/wan/failover`→403 ขณะที่ `GET
  /api/wan/status`→200; PUT `mode="manual"` แต่ `manualUplinkId` ว่าง→400;
  PUT uplinkId ไม่มีจริง→400; `-disable-edit=true`→PUT ได้ 403; openapi
  ทั้งสองไฟล์ระบุระดับสิทธิ์ตรงกัน
- **depends_on:** Task 15

**Task 17 — wiring controller**
**ไฟล์:** `backend/cmd/pigate/main.go` (แก้)
- สร้าง `wanFailoverController` (รับ repo, wanMonitor, routingService,
  eventLogService, eventBus) **Start ต่อจาก `wanMonitor.Start()` เท่านั้น**;
  ตอน startup **ไม่สลับอะไรทันที** ต้องรอ monitor มีสถานะไม่ใช่ `unknown`
  อย่างน้อยหนึ่งรอบเต็มก่อนตัดสินใจครั้งแรก (กัน flap ตอน boot); ปิดตัวเอง
  เงียบๆ เมื่อ `wan_failover_settings.enabled=0`
- **acceptance:** `go build ./...` ผ่าน; `-mock=true` โดย `enabled=0`
  (default)→**ไม่มี log `[Routing]` เพิ่มขึ้นเลย** เทียบก่อนมีฟีเจอร์
  (พิสูจน์ default-off ไม่กระทบเครื่องที่ติดตั้งอยู่แล้ว); `enabled=1` ใน
  mock→เห็น log การตัดสินใจ
- **depends_on:** Task 16

**Task 18 — frontend: control card**
**ไฟล์:** `frontend/src/pages/WanFailover.tsx` (แก้),
`frontend/src/services/wanService.ts` (แก้)
- Card "Failover Control": Switch kill switch พร้อม `AlertDialog` อธิบาย
  ผลกระทบ; เลือกโหมด Auto/Manual+เลือก uplink; แสดง uplink active+เวลา/
  เหตุผลของการสลับล่าสุด; ตั้ง MinHold/RevertDelay (**ไม่มี**
  FailoverOnDegraded — D-7); Alert สีเตือนถาวร "การสลับ WAN จะทำให้ session
  ที่ค้างอยู่ขาด รวมถึงหน้าเว็บนี้ถ้าเข้าผ่าน WAN เส้นนั้น"; ถ้า backend
  รายงาน `bypassedByStaticRoute=true`→Alert เตือนชัดพร้อมลิงก์ไปหน้า Static
  Routes; ปุ่ม kill switch/manual override ต้องซ่อน/disable สำหรับ role
  ที่ไม่ใช่ super_admin (ตาม pattern `SuperAdminRoute`/`isSuperAdmin`)
- **acceptance:** `yarn build`+`yarn lint` ผ่าน; mock mode: เปิด/ปิด kill
  switch ได้, สลับ Auto/Manual ได้, ข้อความเตือน session ขาดแสดงตลอด;
  role `admin_readonly`→เห็นสถานะ/กราฟได้แต่ควบคุม failover ไม่ได้
- **depends_on:** Task 17

**Task 19 — docs**
**ไฟล์:** `README.md`, `docs/tech_stack_design.md`,
`docs/ref/complete/interface-metric-design.md`
- README เพิ่มแถว Feature Status + ระบุข้อจำกัด IPv4-only;
  `tech_stack_design.md` บันทึกตาราง precedence 4 ระดับตาม D-2 เป็นข้อตกลง
  ถาวรของโปรเจกต์ ระบุชัดว่า Phase นี้**ไม่ใช้ fwmark และไม่ใช้ routing
  table เพิ่ม**; `interface-metric-design.md` เติมอ้างอิงถึง override ใหม่
  ใน Caution ข้อ 1
- **acceptance:** เอกสารครบตามที่ระบุ ตรวจด้วยตา
- **depends_on:** Task 18

## 4. API ที่เกี่ยวข้อง

| Method | Path | Role | พฤติกรรม |
|---|---|---|---|
| GET | `/api/wan/uplinks` | authRoute | รายการ uplink config |
| POST/PUT/DELETE | `/api/wan/uplinks[/{id}]` | authRoute | จัดการ uplink |
| GET | `/api/wan/status` | authRoute | สถานะสด+metric ล่าสุด+`bypassedByStaticRoute`+`activeUplinkId`+`lastSwitchAt/Reason` |
| GET | `/api/wan/metrics?uplink=&window=` | authRoute | ข้อมูลกราฟจาก ring buffer |
| GET | `/api/wan/failover` | authRoute | อ่าน failover settings |
| PUT | `/api/wan/failover` | **superAdminRoute** | kill switch/mode/dampening — คุมทั้งเครือข่ายทันที |
| POST | `/api/wan/failover/override` | **superAdminRoute** | บังคับ uplink ที่ active ด้วยมือ |

ทุกเส้น mutation ถูก `DisableEditMiddleware` บล็อกในโหมด `-disable-edit=true`
เหมือน subsystem อื่น

## 5. ข้อควรระวัง

1. **fwmark 0x1 ถูกใช้ทำ policy-SNAT อยู่แล้ว** — ฟีเจอร์นี้แก้ด้วยการไม่แตะ
   fwmark/nftables เลย (D-1) ไม่ใช่ด้วยความระมัดระวัง หากในอนาคตทำ Phase 3
   (policy routing) ต้องออกแบบ mark-space ใหม่แยกเอกสารต่างหาก
2. **กลไก reconcile 3 ตัวเคยมีปัญหา ping-pong กันมาก่อน**
   (`interface-metric-design.md`) เพิ่มกลไกที่ 3 (failover) ต้องกำหนด
   precedence ชัดตั้งแต่วันแรก (D-2) ห้าม failover controller เรียก kernel
   routing โดยตรงเด็ดขาด
3. **Session ขาดตอนสลับ WAN เป็นข้อจำกัดเชิงฟิสิกส์** ไม่ใช่บั๊ก — ต้องมี
   Alert เตือนถาวรใน UI (ยอมรับแล้วโดยเจ้าของโปรเจกต์)
4. **ISP บล็อก ICMP ได้** — แก้ด้วย auto-fallback ในรอบเดียวกัน (D-5) ต้อง
   ทดสอบเคสนี้จริงก่อนปิดงาน (ดู Final Acceptance ข้อ 24)
5. **SD card wear** — metric time-series ต้องอยู่ RAM เท่านั้น (D-3) ห้าม
   `wan_metrics_ring.go` import `internal/db`
6. **Probe ต้อง bind ออก interface ที่ต้องการจริง** ผ่าน `SO_BINDTODEVICE`
   ไม่ใช่แค่ source IP เพราะมี default route 2 เส้นพร้อมกัน
7. **Raw ICMP socket ต้องปิดทุกเส้นทางออก** (`defer conn.Close()`) กัน fd
   leak ระยะยาว (รันทุก 5 วินาทีตลอดชีพของ process)
8. **`degraded` ไม่ trigger failover** (D-7) เป็นสถานะแสดงผลอย่างเดียว
9. **ฟีเจอร์ default ปิด** (`enabled=0`) ต้องพิสูจน์ว่าเครื่องที่ติดตั้งอยู่
   แล้วไม่ได้รับผลกระทบใดๆ จนกว่าจะเปิดใช้เอง
10. **IPv4 เท่านั้น** — ต้องระบุข้อจำกัดนี้ใน UI ตรงๆ ไม่ปล่อยให้เข้าใจผิด
11. **Phase 0 ต้องทำโดยเจ้าของโปรเจกต์บนบอร์ดจริง** ทีม AI ไม่มีสิทธิ์เข้าถึง
    ฮาร์ดแวร์ที่มี WAN 2 เส้น ห้ามเริ่ม Task 1 จนกว่า Task 0 ข้อ 1, 2, 6 จะ
    PASS และบันทึกผลลง `docs/ref/wan-failover-findings.md`

**การทดสอบ:**
- mock mode ครอบคลุมได้: UI ทั้งหมด, validation, state machine (fail/
  recover strikes, sticky/re-test), role 403, DB round-trip, ไม่มี side
  effect ต่อ OS
- ต้องทดสอบบนบอร์ดจริงเท่านั้น (2 uplink): ค่า latency/jitter/loss สมเหตุ
  สมผลเทียบ `ping` มือ (คลาดเคลื่อน ≤20%), monitor ทิ้งไว้ 10 นาทีโดย
  failover ปิด→`ip route` ไม่เปลี่ยนเลย, เคส brownout จริง→สลับอัตโนมัติ,
  เคสสายหลุดจริง→สลับได้เช่นกัน, ฟื้นตัวไม่สลับกลับทันที (รอ RevertDelay),
  anti-flap (เสียบ/ถอดถี่ๆ 1 นาที ไม่ flap รัว), kill switch ล้าง override
  สะอาด, manual override บังคับใช้ได้จริง, precedence กับ static route
  0.0.0.0/0 ทำงานถูก, NAT ยังทำงานหลังสลับทุกครั้ง, event log ไม่ spam,
  ISP บล็อก ICMP→auto fallback เป็น TCP ไม่ false-positive failover, CPU
  เพิ่มไม่เกิน ~2%
- `go build ./... && go vet ./... && go test -race ./...` และ `yarn
  build && yarn lint` ต้องผ่าน

## 6. Checklist สรุป (Definition of Done)

- [ ] Task 0: Spike kit ส่งมอบ + เจ้าของโปรเจกต์รันบนบอร์ดจริง S-1/S-2/S-6 PASS
      + บันทึก `docs/ref/wan-failover-findings.md`
- [ ] Task 1: `model/wan_uplink.go` + validation + test
- [ ] Task 2: DB migration + `wan_repo.go` + migration test
- [ ] Task 3: `PathProbeManager` interface (ICMP+TCP)
- [ ] Task 4: `real_path_probe.go` (raw ICMP + TCP-connect, bind-to-device)
- [ ] Task 5: `MockPathProbe`
- [ ] Task 6: `wan_metrics_ring.go` (RAM-only ring buffer)
- [ ] Task 7: `wan_monitor.go` (state machine + sticky fallback)
- [ ] Task 8: wiring monitor ใน `cmd/pigate/main.go`
- [ ] Task 9: API handlers + routes (authRoute) + openapi
- [ ] Task 10: `frontend/src/services/wanService.ts` + mock data
- [ ] Task 11: `frontend/src/pages/WanFailover.tsx` + route + sidebar
- [ ] Task 12: backup/restore
- [ ] Task 13: capability probe `icmp-probe`
- [ ] Task 14: `routing.go` precedence + override API
- [ ] Task 15: `wan_failover.go` controller (dampening, anti-blackhole)
- [ ] Task 16: API settings/kill switch/override (superAdminRoute)
- [ ] Task 17: wiring controller ใน `cmd/pigate/main.go`
- [ ] Task 18: frontend control card
- [ ] Task 19: เอกสาร (README, tech_stack_design, interface-metric-design)
- [ ] ทดสอบ mock mode ครบ flow
- [ ] ทดสอบบนบอร์ดจริง (brownout, สายหลุด, anti-flap, kill switch, manual
      override, precedence, ICMP block fallback)
- [ ] `go build ./... && go vet ./... && go test -race ./...` +
      `yarn build && yarn lint` ผ่านทั้งหมด
- [ ] `grep -rn "exec.Command"` ไม่มีรายการใหม่จากฟีเจอร์นี้
- [ ] `grep -rn "netlink.Rule\|RuleAdd\|Route.Table\|RT_TABLE"` ไม่พบ
      (ยืนยันไม่ได้แอบทำ policy routing)
- [ ] diff ของ `real_firewall.go` ว่างเปล่า (ไม่แตะ firewall เลย)
- [ ] `grep -rn "failoverOnDegraded\|FailoverOnDegraded"` ไม่พบเลย (ยืนยัน D-7)
- [ ] `wan_metrics_ring.go` ไม่ import `internal/db`; `wan_monitor.go` ไม่
      import kernel routing; `wan_failover.go` ไม่ import kernel เลย
