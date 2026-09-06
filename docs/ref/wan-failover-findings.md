# Multi-WAN Failover — Task 0 Spike Findings (บอร์ดจริง)

> บันทึกผลการรัน Task 0 "Spike Kit" ตามแผน
> `docs/ref/todo/multi-wan-failover-plan.md` (หัวข้อ 3 "Task 0", ข้อควรระวังข้อ 11)
> เจ้าของโปรเจกต์เป็นคนรันบนบอร์ดจริงที่มี WAN 2 เส้น แล้วกรอกผลไฟล์นี้ — ทีม AI
> ไม่มีสิทธิ์เข้าถึงฮาร์ดแวร์จึงตรวจได้แค่ระดับ compile ของ spike snippet เท่านั้น
>
> **กติกา:** ต้องผ่าน S-1, S-2, S-6 อย่างน้อยก่อนอนุญาตให้เริ่ม Task 1 ของแผน
> (Phase 1 — WAN Uplink + Health Monitoring) ถ้าข้อไหน FAIL ให้หยุดแล้วกลับมาคุยกับ
> ทีม AI ก่อน อย่าดันแก้ spike/checklist เองแล้วลองใหม่เงียบๆ

## Metadata

| field | value |
|---|---|
| วันที่ทดสอบ | |
| ผู้ทดสอบ | |
| รุ่นบอร์ด | (เช่น Raspberry Pi 5, RAM) |
| OS/kernel | (`uname -a`) |
| WAN หลัก (interface / ISP) | |
| WAN สำรอง (interface / ISP) | |
| PiGate build/commit ที่ใช้ทดสอบ | |
| โหมดรัน PiGate (`-mock=false`/systemd/manual) | |

---

## S-1: raw ICMP + `SO_BINDTODEVICE` ทำงานจริง, RTT ต่างกันตามเส้นทางจริง

**ผลลัพธ์:** [x] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s1_primary_rtt` / `s1_backup_rtt` / `s1_tcpdump`):**

```
s1_primary_rtt
[icmp] seq=1 rtt=6.059166ms
[icmp] seq=2 rtt=5.371809ms
[icmp] seq=3 rtt=4.818081ms
[icmp] seq=4 rtt=5.31427ms
[icmp] seq=5 rtt=4.529504ms

s1_backup_rtt
[icmp] seq=1 rtt=28.251758ms
[icmp] seq=2 rtt=37.243525ms
[icmp] seq=3 rtt=46.9823ms
[icmp] seq=4 rtt=42.227108ms
[icmp] seq=5 rtt=34.607038ms

s1_tcpdump
apray@Galaxy-A05:~/pigate/testfile$ sudo tcpdump -ni $WAN_PRIMARY icmp and host 1.1.1.1 -c 5
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on wlx0cef1548ff2b, link-type EN10MB (Ethernet), snapshot length 262144 bytes
16:46:17.956769 IP 192.168.1.128 > 1.1.1.1: ICMP echo request, id 9447, seq 1, length 30
16:46:17.962705 IP 1.1.1.1 > 192.168.1.128: ICMP echo reply, id 9447, seq 1, length 30
16:46:18.963058 IP 192.168.1.128 > 1.1.1.1: ICMP echo request, id 9447, seq 2, length 30
16:46:18.968355 IP 1.1.1.1 > 192.168.1.128: ICMP echo reply, id 9447, seq 2, length 30
16:46:19.968697 IP 192.168.1.128 > 1.1.1.1: ICMP echo request, id 9447, seq 3, length 30
5 packets captured
6 packets received by filter
0 packets dropped by kernel
sapray@Galaxy-A05:~/pigate/testfile$ sudo tcpdump -ni $WAN_BACKUP icmp and host 1.1.1.1 -c 5
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on wlan0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
16:46:40.001957 IP 10.80.18.173 > 1.1.1.1: ICMP echo request, id 9456, seq 1, length 30
16:46:40.030035 IP 1.1.1.1 > 10.80.18.173: ICMP echo reply, id 9456, seq 1, length 30
16:46:41.030369 IP 10.80.18.173 > 1.1.1.1: ICMP echo request, id 9456, seq 2, length 30
16:46:41.067534 IP 1.1.1.1 > 10.80.18.173: ICMP echo reply, id 9456, seq 2, length 30
16:46:42.067888 IP 10.80.18.173 > 1.1.1.1: ICMP echo request, id 9456, seq 3, length 30
5 packets captured
6 packets received by filter
0 packets dropped by kernel
sapray@Galaxy-A05:~/pigate/testfile$
```

**หมายเหตุ:**

---

## S-2: default route 2 เส้นอยู่ร่วมกันได้, สลับ metric แล้ว public IP เปลี่ยนภายใน <5 วินาที

**ผลลัพธ์:** [x] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s2_before_ip` / `s2_switch_log`):**

```
t=+.975770302s ip=180.183.62.184
t=+1.911039715s ip=49.230.57.43
SWITCHED after 1.911039715s
```

**หมายเหตุ:**
หลังจากสลับแล้วมี Auto healing มาปรับกลับเหมือนเดิม แต่ Script จับ Public IP ได้ทัน เนื่องจากรันด้วย cli เพราะถ้าตั้งที่ Pigate UI จะนานกว่า 5 วิแน่นอน เพราะเป็น Wifi ทั้งคู่

> **หมายเหตุจากทีม AI (แก้ไข):** ที่เคยเดาว่า auto-healing มาจาก static route
> `0.0.0.0/0 proto 120` ที่เห็นใน S-6 นั้น **ผิด** — เจ้าของโปรเจกต์ยืนยันแล้วว่า
> fake gateway route ของ S-6 สร้าง**หลัง**ทดสอบ S-2 เสร็จ ตอนทดสอบ S-2 ยังไม่มี
> route นี้อยู่
>
> คำอธิบายที่เป็นไปได้กว่า: ผู้ทดสอบสลับ metric ผ่าน **CLI โดยตรง** (ไม่ใช่ผ่าน
> PiGate UI ตามที่ checklist แนะนำ — เห็นได้จากโน้ตว่า "รันด้วย cli") ซึ่งแก้ค่า
> ใน kernel routing table ตรงๆ โดยไม่ได้อัปเดตค่า `interface.Metric` ใน DB —
> กลไก reconcile ที่มีอยู่แล้ว (`enforceInterfaceMetrics()`/`EnforceDefaultRouteMetric`
> ใน `routing.go`) จึงตรวจพบว่าค่าจริงใน kernel ไม่ตรงกับค่าที่ DB กำหนดไว้ แล้ว
> ปรับกลับให้ตรงตาม DB โดยอัตโนมัติ — **นี่คือพฤติกรรมที่ถูกต้องตามที่ออกแบบไว้
> อยู่แล้ว (D-2 ข้อ 3)** ไม่ใช่บั๊ก ยืนยันว่ากลไก reconcile เดิมยังทำงานอยู่จริง
> ถ้าต้องการทดสอบการสลับแบบที่ "ติดถาวร" ต้องเปลี่ยนค่าผ่านหน้า Interfaces ของ
> PiGate UI ให้ตรงตาม checklist แทนการยิง CLI ตรง

---

## S-3: สลับ metric ด้วยมือ → log `[Routing]` ไม่เกิด ping-pong (del/add ไม่เกิน 2 รอบ)

**ผลลัพธ์:** [ ] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s3_routing_log`):**

```
Sep 06 16:58:29 Galaxy-A05 pigate[948]: 2026/09/06 16:58:29 [Routing] ApplyRoutes called with 0 routes
Sep 06 16:58:29 Galaxy-A05 pigate[948]: 2026/09/06 16:58:29 [Routing] ApplyRoutes completed
Sep 06 16:58:29 Galaxy-A05 pigate[948]: 2026/09/06 16:58:29 [Routing] Enforcing default route metric on wlan0: 20 -> 75 (gw 10.80.18.97, proto 16)
Sep 06 16:58:30 Galaxy-A05 pigate[948]: 2026/09/06 16:58:30 [Routing] ApplyRoutes called with 0 routes
Sep 06 16:58:30 Galaxy-A05 pigate[948]: 2026/09/06 16:58:30 [Routing] ApplyRoutes completed
```

**หมายเหตุ:**

---

## S-4: ถอด/เสียบสาย WAN → NetlinkMonitor คืน metric ที่ต้องการภายใน ~2 วินาที

**ผลลัพธ์:** [ ] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s4_unplug_log` / `s4_route_table`):**

```
ทำงานได้ตามปกติ แบบ wifi ต้องรอนานหน่อย
```

**หมายเหตุ:**

---

## S-5: หลังสลับ WAN แล้ว NAT ยังทำงาน (client ใน LAN ออกเน็ตได้)

**ผลลัพธ์:** [ ] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s5_client_nat`):**

```
ออกได้ปกติ เพราะเคยใช้มานานแล้ว wifi ตัวหลักหายไป wifi ตัวรองยังทำงานได้อยู่
```

**หมายเหตุ:**

---

## S-6: เคส brownout (link-up แต่ไม่มีเน็ตจริง) — probe ต้องตรวจจับได้แม้ยังมี default route

**ผลลัพธ์:** [x] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s6_link_state` / `s6_probe_loss`):**

```
sapray@Galaxy-A05:~/pigate/testfile$ ip -o link show $WAN_PRIMARY
6: wlx0cef1548ff2b: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DORMANT group default qlen 1000\    link/ether 26:54:fc:be:18:aa brd ff:ff:ff:ff:ff:ff permaddr 0c:ef:15:48:ff:2b
sapray@Galaxy-A05:~/pigate/testfile$ ip route show default
default via 192.168.1.78 dev wlx0cef1548ff2b proto 120 metric 10
default via 192.168.1.1 dev wlx0cef1548ff2b proto dhcp src 192.168.1.128 metric 50
default via 10.80.18.97 dev wlan0 proto dhcp src 10.80.18.173 metric 75
sapray@Galaxy-A05:~/pigate/testfile$ ./wan_probe_spike -mode=both -iface=$WAN_PRIMARY -target=1.1.1.1 -count=5
wan_probe_spike: iface=wlx0cef1548ff2b target=1.1.1.1 mode=both port=443 count=5 timeout=1s interval=1s
[icmp] seq=1 timeout (no reply)
[tcp]  seq=1 FAIL: dial tcp4 1.1.1.1:443: i/o timeout (refused would still mean the path/host is reachable)
[icmp] seq=2 timeout (no reply)
[tcp]  seq=2 FAIL: dial tcp4 1.1.1.1:443: i/o timeout (refused would still mean the path/host is reachable)
[icmp] seq=3 timeout (no reply)
[tcp]  seq=3 FAIL: dial tcp4 1.1.1.1:443: i/o timeout (refused would still mean the path/host is reachable)
[icmp] seq=4 timeout (no reply)
[tcp]  seq=4 FAIL: dial tcp4 1.1.1.1:443: i/o timeout (refused would still mean the path/host is reachable)
[icmp] seq=5 timeout (no reply)
[tcp]  seq=5 FAIL: dial tcp4 1.1.1.1:443: i/o timeout (refused would still mean the path/host is reachable)

--- icmp summary: sent=5 recv=0 loss=100.0% ---
  no successful samples -> no latency/jitter to report

--- tcp summary: sent=5 recv=0 loss=100.0% ---
  no successful samples -> no latency/jitter to report
```

**หมายเหตุ:**

---

## S-7: ภาระ CPU ของ probe ที่ interval จริง (เช่น 5s × 3 packet × 2 uplink) ไม่เกิน ~1%

**ผลลัพธ์:** [x] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s7_cpu_burst` / `s7_pidstat`):**

```
[2] 10469
Linux 6.8.0-1041-raspi (Galaxy-A05)     09/06/26        _aarch64_       (4 CPU)
wan_probe_spike: iface=wlx0cef1548ff2b target=1.1.1.1 mode=both port=443 count=3 timeout=1s interval=5s
[icmp] seq=1 rtt=11.015918ms
[tcp]  seq=1 connect-rtt=7.291846ms

17:04:49      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
17:04:50     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:04:51     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:04:52     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:04:53     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:04:54     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
[icmp] seq=2 rtt=5.688239ms
[tcp]  seq=2 connect-rtt=4.820804ms
17:04:55     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:04:56     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:04:57     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:04:58     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:04:59     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
[icmp] seq=3 rtt=5.330438ms
[tcp]  seq=3 connect-rtt=5.339865ms

--- icmp summary: sent=3 recv=3 loss=0.0% ---
  min=5.330438ms avg=7.344865ms max=11.015918ms jitter~=2.84274ms

--- tcp summary: sent=3 recv=3 loss=0.0% ---
  min=4.820804ms avg=5.817505ms max=7.291846ms jitter~=1.495051ms

--- CPU burst pass: 100 rounds, mode=both, no inter-round sleep ---
17:05:00     1000     10469    0.00    0.00    0.00    0.00    0.00     3  wan_probe_spike
17:05:01     1000     10469    0.00    0.00    0.00    0.00    0.00     3  wan_probe_spike
17:05:02     1000     10469    0.00    0.00    0.00    0.00    0.00     3  wan_probe_spike
17:05:03     1000     10469    0.00    1.00    0.00    0.00    1.00     3  wan_probe_spike
17:05:04     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:05:05     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:05:06     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:05:07     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:05:08     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
17:05:09     1000     10469    0.00    0.00    0.00    0.00    0.00     1  wan_probe_spike
Average:     1000     10469    0.00    0.05    0.00    0.00    0.05     -  wan_probe_spike
```

**หมายเหตุ:**

---

## S-8: `net.ipv4.conf.all.rp_filter=2` ยังเป็น loose บนเครื่องจริง

**ผลลัพธ์:** [x] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s8_rp_filter`):**

```
net.ipv4.conf.all.rp_filter = 2
2
2
```

**หมายเหตุ:**

---

## สรุป

- [x] S-1 PASS
- [x] S-2 PASS
- [ ] S-3 PASS — log สั้นเกินไป (~1s แทน ~10s ตามที่ checklist ขอ) ไม่ได้บล็อกเกณฑ์ขั้นต่ำ แต่ควรทำซ้ำให้ครบก่อนเริ่ม Task 14
- [ ] S-4 PASS — กรอกเป็นข้อความสรุปแทน raw log/route table ตามที่ checklist ขอ ควรทำซ้ำก่อนเริ่ม Task 14
- [ ] S-5 PASS — กรอกเป็นข้อความสรุปแทน raw output ของ curl/ping ตามที่ checklist ขอ ควรทำซ้ำก่อนเริ่ม Task 14
- [x] S-6 PASS
- [x] S-7 PASS
- [x] S-8 PASS
- [x] เกณฑ์ขั้นต่ำผ่าน (S-1 + S-2 + S-6) → **อนุญาตให้เริ่ม Task 1 ของแผนได้**

**ข้อค้นพบ/ความเสี่ยงเพิ่มเติมที่พบระหว่างทดสอบ:**

1. **Fake gateway route (`0.0.0.0/0 proto 120 metric 10` ผ่าน `wlx0cef1548ff2b`
   gw `192.168.1.78`) ที่สร้างขึ้นเพื่อทดสอบ S-6 โดยเฉพาะ** (ยืนยันแล้วว่าสร้าง
   **หลัง** S-2 ไม่เกี่ยวกับ "auto healing" ที่เห็นใน S-2 — ดูคำอธิบายที่แก้ไข
   แล้วในหมายเหตุของ S-2 ด้านบน) **ต้องลบ route ปลอมนี้ออกจากหน้า Static Routes
   ก่อนเริ่มทดสอบ Phase 2 (Task 14-15)** เพราะถ้าทิ้งไว้ static route 0.0.0.0/0
   นี้จะชนะทุกอย่างตาม D-2 ข้อ 1 ทำให้ failover controller "ยอมแพ้" ไม่สลับ WAN
   ให้เลย (พฤติกรรมถูกต้องตามที่ออกแบบไว้ แต่จะทำให้ดูเหมือนฟีเจอร์ไม่ทำงาน)
2. **"Auto healing" ใน S-2 มาจากกลไก reconcile เดิมที่มีอยู่แล้ว** (ไม่ใช่ static
   route) — ผู้ทดสอบสลับ metric ผ่าน CLI ตรงๆ ไม่ผ่าน PiGate UI ทำให้ค่าใน DB
   ไม่ตรงกับ kernel แล้วถูก `enforceInterfaceMetrics()` ปรับกลับอัตโนมัติ ยืนยัน
   ว่ากลไก reconcile เดิมทำงานถูกต้องตามที่ควรจะเป็น (D-2 ข้อ 3) ไม่ใช่บั๊ก
3. **S-3/S-4/S-5 ยังไม่มีหลักฐานดิบครบตามที่ checklist ขอ** ไม่กระทบการเริ่ม
   Task 1 (Phase 1 ไม่แตะ routing) แต่ควรทำให้ครบก่อนเริ่ม Task 14-15 (Phase 2)
   เพราะ Task นั้นแตะ routing โดยตรงและต้องมั่นใจเรื่อง route flapping/NAT/
   NetlinkMonitor timing มากกว่า Phase 1

