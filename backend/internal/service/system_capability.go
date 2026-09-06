package service

import (
	"sync"
	"time"

	"pigate/internal/kernel"
	"pigate/internal/model"
)

// capabilityCacheTTL bounds how often SystemCapabilityService actually probes
// the kernel/D-Bus: a probe hits netlink + D-Bus, which is unnecessary work
// on every Dashboard poll since capability rarely changes at runtime (docs
// plan §2.4). ?force=1 (the "ตรวจสอบใหม่" button) bypasses this cache.
const capabilityCacheTTL = 30 * time.Second

// capabilityCatalogEntry maps a probe id to its user-facing display name.
// Mirrors the id->DisplayName catalog pattern in system_service.go.
type capabilityCatalogEntry struct {
	ID   string
	Name string
}

var capabilityCatalog = []capabilityCatalogEntry{
	{ID: "firewall", Name: "Firewall (nftables)"},
	{ID: "dbus", Name: "D-Bus System Bus"},
	{ID: "dnsmasq", Name: "DHCP/DNS Forwarder (dnsmasq)"},
	{ID: "resolved", Name: "DNS Resolver (systemd-resolved)"},
	{ID: "conntrack", Name: "Traffic Accounting (conntrack)"},
	{ID: "conntrack-events", Name: "Conntrack Event Stream"},
	{ID: "icmp-probe", Name: "Raw ICMP Probe (Multi-WAN Failover)"},
}

// ApplyHealthReporter lets any subsystem service (FirewallService today;
// QoS/DNS could implement it later) report the outcome of its most recent
// real attempt to apply DB-configured state to the kernel. A probe alone
// cannot prove a full rule set applies cleanly (docs plan §2.2) — this is
// the second source of truth SystemCapabilityService merges in.
type ApplyHealthReporter interface {
	// ApplyHealth returns whether the last apply succeeded, a detail message
	// (only meaningful when ok is false), and when it happened. A zero time
	// means "never attempted yet" — callers must not treat that as a failure.
	ApplyHealth() (ok bool, detail string, at time.Time)
}

// SystemCapabilityService probes and caches whether the kernel subsystems
// PiGate depends on are actually usable in the current environment, merging
// in any registered ApplyHealthReporter's last-apply outcome. It is the
// service-layer home for the Thai-language catalog/explanations, mirroring
// how SystemServiceService keeps kernel.SystemServiceManager policy-free.
type SystemCapabilityService struct {
	prober kernel.CapabilityProber
	mock   bool
	// ttl is the cache freshness window (capabilityCacheTTL by default); a
	// struct field rather than only the package const so tests can inject a
	// tiny value instead of sleeping 30s (docs plan T-09).
	ttl time.Duration

	mu       sync.RWMutex
	cache    []model.CapabilityProbeResult
	cachedAt time.Time

	applyMu     sync.RWMutex
	applyHealth map[string]ApplyHealthReporter

	eventLog *EventLogService
}

func NewSystemCapabilityService(prober kernel.CapabilityProber, mock bool, eventLog *EventLogService) *SystemCapabilityService {
	return &SystemCapabilityService{
		prober:      prober,
		mock:        mock,
		ttl:         capabilityCacheTTL,
		applyHealth: make(map[string]ApplyHealthReporter),
		eventLog:    eventLog,
	}
}

// RegisterApplyHealth wires a subsystem's ApplyHealthReporter in under id
// (matching a capabilityCatalog id, e.g. "firewall"). Safe to call any number
// of times; the latest registration for a given id wins.
func (s *SystemCapabilityService) RegisterApplyHealth(id string, r ApplyHealthReporter) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.applyHealth[id] = r
}

// Get returns the current capability status of every subsystem, using the
// cached probe result if it is younger than capabilityCacheTTL, unless force
// is true (the "ตรวจสอบใหม่" button, or a caller that must not use stale data).
func (s *SystemCapabilityService) Get(force bool) model.SystemCapabilities {
	results := s.probeResults(force)
	return s.buildCapabilities(results)
}

// Refresh forces a fresh probe (bypassing the cache) and logs an event for
// every capability that came back unavailable. Intended to be called once at
// startup (after the firewall's own startup apply has run, so an apply
// failure is already reflected via ApplyHealth) so operators see capability
// problems in the Event Log from boot onward, not only when someone happens
// to open the relevant page.
func (s *SystemCapabilityService) Refresh() model.SystemCapabilities {
	caps := s.Get(true)
	for _, c := range caps.Capabilities {
		if c.Available {
			continue
		}
		if s.eventLog != nil {
			s.eventLog.Log(model.EventCategorySystem, "system.capability_unavailable",
				model.EventSeverityWarning, "", c.ID, c.Detail)
		}
	}
	return caps
}

// probeResults returns the raw probe results, using the cache when it is
// still fresh and force is false.
func (s *SystemCapabilityService) probeResults(force bool) []model.CapabilityProbeResult {
	if !force {
		s.mu.RLock()
		fresh := s.cache != nil && time.Since(s.cachedAt) < s.ttl
		cached := s.cache
		s.mu.RUnlock()
		if fresh {
			return cached
		}
	}

	results := s.prober.ProbeAll()

	s.mu.Lock()
	s.cache = results
	s.cachedAt = time.Now()
	s.mu.Unlock()

	return results
}

// buildCapabilities enriches raw probe results with display name, Thai
// detail text, and CheckedAt, merging in any registered apply-health
// override per the rule in docs plan §2.2: a probe failure always wins; a
// successful probe with a failed last-apply becomes degraded/apply_failed.
func (s *SystemCapabilityService) buildCapabilities(results []model.CapabilityProbeResult) model.SystemCapabilities {
	now := time.Now().UTC().Format(time.RFC3339)
	byID := make(map[string]model.CapabilityProbeResult, len(results))
	for _, r := range results {
		byID[r.ID] = r
	}

	out := make([]model.CapabilityStatus, 0, len(capabilityCatalog))
	for _, entry := range capabilityCatalog {
		r, ok := byID[entry.ID]
		if !ok {
			// Registry drift (a catalog entry with no matching probe result) —
			// still surface it rather than silently dropping it.
			r = model.CapabilityProbeResult{ID: entry.ID, Reason: model.CapabilityReasonProbeFailed}
		}

		r = s.mergeApplyHealth(entry.ID, r)

		out = append(out, model.CapabilityStatus{
			ID:        entry.ID,
			Name:      entry.Name,
			Available: r.Available,
			Degraded:  r.Degraded,
			Reason:    r.Reason,
			Detail:    detailFor(r.Reason, r.Err),
			CheckedAt: now,
		})
	}

	return model.SystemCapabilities{
		Mock:         s.mock,
		CheckedAt:    now,
		Capabilities: out,
	}
}

// mergeApplyHealth applies the second-source-of-truth rule from docs plan
// §2.2: a probe failure always wins over apply health; otherwise, if a
// reporter is registered for id and its last apply failed, the result
// becomes degraded with reason apply_failed carrying the real error text.
// A reporter that has never applied yet (zero time) is not merged in at all.
func (s *SystemCapabilityService) mergeApplyHealth(id string, r model.CapabilityProbeResult) model.CapabilityProbeResult {
	if !r.Available {
		return r
	}

	s.applyMu.RLock()
	reporter, ok := s.applyHealth[id]
	s.applyMu.RUnlock()
	if !ok {
		return r
	}

	ok2, detail, at := reporter.ApplyHealth()
	if ok2 || at.IsZero() {
		return r
	}

	r.Degraded = true
	r.Reason = model.CapabilityReasonApplyFailed
	r.Err = detail
	return r
}

// detailFor translates a reason code (+ optional raw error text) into a
// Thai-language explanation for the UI banner. Every reason declared in
// model/capability.go must have a non-empty case here — this is the
// service-layer localization point the kernel layer deliberately stays free
// of (mirrors system_service.go's slug/catalog pattern).
func detailFor(reason, errText string) string {
	switch reason {
	case model.CapabilityReasonOK:
		return "ทำงานได้ตามปกติ"
	case model.CapabilityReasonMock:
		return "กำลังรันในโหมดจำลอง (mock) — ไม่มีการเรียก kernel จริง"
	case model.CapabilityReasonNotSupported:
		return "เคอร์เนลของเครื่องนี้ไม่รองรับ nf_tables (พบบ่อยบน WSL/คอนเทนเนอร์)"
	case model.CapabilityReasonPermissionDenied:
		return "สิทธิ์ไม่พอ — ต้องรัน `sudo setcap cap_net_admin,cap_net_raw+ep` ให้กับโปรแกรมนี้"
	case model.CapabilityReasonNoDBus:
		return "ไม่สามารถเชื่อมต่อ D-Bus system bus ได้ (พบบ่อยบนเครื่องที่ไม่มี systemd เช่น WSL)"
	case model.CapabilityReasonServiceMissing:
		return "ไม่พบบริการนี้ติดตั้งอยู่บนเครื่อง (unit ไม่ถูกโหลด)"
	case model.CapabilityReasonServiceInactive:
		msg := "บริการนี้ติดตั้งอยู่แต่ไม่ได้ทำงานอยู่ในขณะนี้"
		if errText != "" {
			msg += " (" + errText + ")"
		}
		return msg
	case model.CapabilityReasonApplyFailed:
		msg := "ตรวจสอบเบื้องต้นผ่าน แต่การ apply ค่าคอนฟิกล่าสุดไปยัง kernel ล้มเหลว"
		if errText != "" {
			msg += ": " + errText
		}
		return msg
	case model.CapabilityReasonProbeFailed:
		msg := "ตรวจสอบสถานะไม่สำเร็จ"
		if errText != "" {
			msg += ": " + errText
		}
		return msg
	case model.CapabilityReasonAcctDisabled:
		return "ตรวจสอบ conntrack ได้ แต่ยังไม่ได้เปิดการนับ byte ต่อ flow — กรุณาตั้งค่า " +
			"`net.netfilter.nf_conntrack_acct=1` (รัน install.sh ใหม่ หรือ `sudo sysctl " +
			"net.netfilter.nf_conntrack_acct=1` ด้วยตัวเอง) การ์ดวิเคราะห์ traffic บน Dashboard " +
			"จะแสดงค่า 0 ไปเรื่อย ๆ จนกว่าจะเปิดค่านี้"
	case model.CapabilityReasonEventsUnavailable:
		return "ไม่สามารถติดตาม conntrack DESTROY event ได้ (ต้องการ `cap_net_admin` และเคอร์เนลที่เปิด " +
			"`net.netfilter.nf_conntrack_events=1`) — ระบบยัง poll ข้อมูล traffic ได้ตามปกติ " +
			"เพียงแต่ป้าย \"ความแม่นยำ\" บนการ์ด Dashboard จะค้างที่ \"ประมาณการ\" แทน \"ใกล้เคียงจริง\""
	case model.CapabilityReasonICMPUnavailable:
		return "เปิด raw ICMP socket ไม่ได้ (ต้องการ `sudo setcap cap_net_raw+ep` ให้กับโปรแกรมนี้) — " +
			"ฟีเจอร์ Multi-WAN Failover ยังใช้งานได้ปกติผ่านวิธี TCP-connect (probeMethod = tcp หรือ auto " +
			"จะสลับไปใช้ TCP ให้อัตโนมัติ) เพียงแต่จะวัดค่า jitter ไม่ได้และแม่นยำน้อยกว่า ICMP"
	default:
		msg := "สถานะไม่ทราบแน่ชัด"
		if errText != "" {
			msg += ": " + errText
		}
		return msg
	}
}
