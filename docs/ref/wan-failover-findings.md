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

**ผลลัพธ์:** [ ] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s1_primary_rtt` / `s1_backup_rtt` / `s1_tcpdump`):**

```

```

**หมายเหตุ:**

---

## S-2: default route 2 เส้นอยู่ร่วมกันได้, สลับ metric แล้ว public IP เปลี่ยนภายใน <5 วินาที

**ผลลัพธ์:** [ ] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s2_before_ip` / `s2_switch_log`):**

```

```

**หมายเหตุ:**

---

## S-3: สลับ metric ด้วยมือ → log `[Routing]` ไม่เกิด ping-pong (del/add ไม่เกิน 2 รอบ)

**ผลลัพธ์:** [ ] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s3_routing_log`):**

```

```

**หมายเหตุ:**

---

## S-4: ถอด/เสียบสาย WAN → NetlinkMonitor คืน metric ที่ต้องการภายใน ~2 วินาที

**ผลลัพธ์:** [ ] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s4_unplug_log` / `s4_route_table`):**

```

```

**หมายเหตุ:**

---

## S-5: หลังสลับ WAN แล้ว NAT ยังทำงาน (client ใน LAN ออกเน็ตได้)

**ผลลัพธ์:** [ ] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s5_client_nat`):**

```

```

**หมายเหตุ:**

---

## S-6: เคส brownout (link-up แต่ไม่มีเน็ตจริง) — probe ต้องตรวจจับได้แม้ยังมี default route

**ผลลัพธ์:** [ ] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s6_link_state` / `s6_probe_loss`):**

```

```

**หมายเหตุ:**

---

## S-7: ภาระ CPU ของ probe ที่ interval จริง (เช่น 5s × 3 packet × 2 uplink) ไม่เกิน ~1%

**ผลลัพธ์:** [ ] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s7_cpu_burst` / `s7_pidstat`):**

```

```

**หมายเหตุ:**

---

## S-8: `net.ipv4.conf.all.rp_filter=2` ยังเป็น loose บนเครื่องจริง

**ผลลัพธ์:** [ ] PASS  [ ] FAIL

**ค่าที่สังเกตได้ (`s8_rp_filter`):**

```

```

**หมายเหตุ:**

---

## สรุป

- [ ] S-1 PASS
- [ ] S-2 PASS
- [ ] S-3 PASS
- [ ] S-4 PASS
- [ ] S-5 PASS
- [ ] S-6 PASS
- [ ] S-7 PASS
- [ ] S-8 PASS
- [ ] เกณฑ์ขั้นต่ำผ่าน (S-1 + S-2 + S-6) → **อนุญาตให้เริ่ม Task 1 ของแผนได้**

**ข้อค้นพบ/ความเสี่ยงเพิ่มเติมที่พบระหว่างทดสอบ (ถ้ามี):**

