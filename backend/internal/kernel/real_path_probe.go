//go:build linux

package kernel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"

	"pigate/internal/model"
)

// protocolICMP is IPPROTO_ICMP (1) — the standard value, not imported from
// golang.org/x/net's internal/iana package (unexported outside that module).
const protocolICMP = 1

// icmpReadBufferSize is 1500 bytes, comfortably larger than any ICMP echo
// reply this probe expects on an IPv4 path (no jumbo frames on a WAN uplink).
const icmpReadBufferSize = 1500

// RealPathProbe implements kernel.PathProbeManager with a raw ICMP socket
// (golang.org/x/net/icmp + ipv4) and a plain net.Dialer TCP-connect, both
// bound to the requested interface via SO_BINDTODEVICE (bindToDeviceControl
// below) — see docs/ref/todo/multi-wan-failover-plan.md Task 4 and the
// board-tested spike behind Task 0's findings (docs/ref/wan-failover-findings.md
// S-1/S-6/S-7), whose proven bind-to-device + read/parse loop this
// implementation follows closely. D-4: everything here is pure Go socket
// code — no subprocess/shell invocation of any kind anywhere in this file.
type RealPathProbe struct{}

func NewRealPathProbe() *RealPathProbe {
	return &RealPathProbe{}
}

// icmpSequence is a process-wide, monotonically increasing ICMP sequence
// counter shared across every ProbeICMP call/uplink, so two probe rounds
// running concurrently (one per configured uplink) never emit overlapping
// (id, seq) pairs that could cross-match each other's replies.
var icmpSequence uint32

// bindToDeviceControl returns a Control func usable with both
// net.ListenConfig and net.Dialer that sets SO_BINDTODEVICE on the raw fd
// before it binds/connects — the single shared implementation ProbeICMP and
// ProbeTCP both use, so this setsockopt is never done in two different
// places that could drift (plan Task 4: "helper ใช้ร่วมกับ ProbeICMP กัน
// setsockopt ผิดสองที่").
func bindToDeviceControl(ifaceName string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		ctrlErr := c.Control(func(fd uintptr) {
			sockErr = unix.BindToDevice(int(fd), ifaceName)
		})
		if ctrlErr != nil {
			return ctrlErr
		}
		return sockErr
	}
}

// millisFloat converts a duration to fractional milliseconds, the unit every
// model.WanProbeSample RTT/latency field uses.
func millisFloat(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

// ProbeICMP implements kernel.PathProbeManager. See the interface doc
// comment (interfaces.go) for the read-only/bind/ctx/error-vs-loss contract
// this must uphold.
func (p *RealPathProbe) ProbeICMP(ctx context.Context, ifaceName string, target net.IP, count int, timeout time.Duration) (model.WanProbeSample, error) {
	sample := model.WanProbeSample{
		TimestampUnix: time.Now().Unix(),
		Method:        model.WanProbeMethodICMP,
		MetricQuality: model.WanMetricQualityFull,
	}
	if count <= 0 {
		return sample, nil
	}
	if _, err := netlink.LinkByName(ifaceName); err != nil {
		return sample, fmt.Errorf("interface %q not found: %w", ifaceName, err)
	}
	ip4 := target.To4()
	if ip4 == nil {
		return sample, fmt.Errorf("probe target %s is not an IPv4 address", target)
	}

	lc := net.ListenConfig{Control: bindToDeviceControl(ifaceName)}
	conn, err := lc.ListenPacket(ctx, "ip4:icmp", "0.0.0.0")
	if err != nil {
		return sample, fmt.Errorf("listen icmp on %s: %w", ifaceName, err)
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	dst := &net.IPAddr{IP: ip4}

	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		sample.Sent++
		seq := int(atomic.AddUint32(&icmpSequence, 1) & 0xffff)
		rtt, ok, perr := icmpRoundOnce(ctx, conn, dst, id, seq, timeout)
		if perr != nil {
			return sample, perr
		}
		if ok {
			sample.Received++
			sample.RTTsMs = append(sample.RTTsMs, millisFloat(rtt))
		}
	}
	return sample, nil
}

// icmpRoundOnce sends one ICMP echo request over the already-open, already
// bound conn and waits for the matching (id, seq) reply until timeout (or
// ctx, whichever is sooner) elapses. A timeout/no-reply is reported as
// ok=false, err=nil — that is normal packet loss, not a probe failure; err
// is reserved for the probe mechanism itself failing (marshal/write/read
// errors other than a plain deadline timeout).
func icmpRoundOnce(ctx context.Context, conn net.PacketConn, dst net.Addr, id, seq int, timeout time.Duration) (time.Duration, bool, error) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("pigate-wan-probe")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return 0, false, fmt.Errorf("marshal icmp echo: %w", err)
	}

	start := time.Now()
	if _, err := conn.WriteTo(wb, dst); err != nil {
		return 0, false, fmt.Errorf("write icmp echo: %w", err)
	}

	deadline := start.Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return 0, false, fmt.Errorf("set read deadline: %w", err)
	}

	// Force the blocking ReadFrom below to return promptly if ctx is
	// cancelled before the deadline above is reached (plain SetReadDeadline
	// alone only unblocks it at the deadline, not on cancellation) — this is
	// what makes "ctx cancel while waiting -> returns immediately" true.
	roundDone := make(chan struct{})
	defer close(roundDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-roundDone:
		}
	}()

	rb := make([]byte, icmpReadBufferSize)
	for {
		n, _, err := conn.ReadFrom(rb)
		if err != nil {
			if ctx.Err() != nil {
				return 0, false, nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return 0, false, nil
			}
			return 0, false, fmt.Errorf("read icmp reply: %w", err)
		}
		if n < ipv4.HeaderLen {
			continue
		}
		// Raw "ip4:icmp" sockets deliver the IPv4 header on read; strip it
		// before handing the payload to icmp.ParseMessage.
		payload := rb[:n]
		if hdr, herr := ipv4.ParseHeader(rb[:n]); herr == nil && hdr.Len <= n {
			payload = rb[hdr.Len:n]
		}
		rm, perr := icmp.ParseMessage(protocolICMP, payload)
		if perr != nil {
			continue // not a parseable ICMP message, keep listening until deadline
		}
		echo, isEcho := rm.Body.(*icmp.Echo)
		if !isEcho {
			continue // e.g. destination-unreachable meant for a different packet
		}
		if rm.Type == ipv4.ICMPTypeEchoReply && echo.ID == id && echo.Seq == seq {
			return time.Since(start), true, nil
		}
		// Reply for a different id/seq (stray/previous round) — keep waiting.
	}
}

// ProbeTCP implements kernel.PathProbeManager. See the interface doc comment
// (interfaces.go) for the read-only/bind/ctx/error-vs-loss contract this
// must uphold, in particular that a refused connection counts as the
// destination being reachable.
func (p *RealPathProbe) ProbeTCP(ctx context.Context, ifaceName string, target net.IP, port, count int, timeout time.Duration) (model.WanProbeSample, error) {
	sample := model.WanProbeSample{
		TimestampUnix: time.Now().Unix(),
		Method:        model.WanProbeMethodTCP,
		MetricQuality: model.WanMetricQualityConnectOnly,
	}
	if count <= 0 {
		return sample, nil
	}
	if _, err := netlink.LinkByName(ifaceName); err != nil {
		return sample, fmt.Errorf("interface %q not found: %w", ifaceName, err)
	}
	ip4 := target.To4()
	if ip4 == nil {
		return sample, fmt.Errorf("probe target %s is not an IPv4 address", target)
	}
	if port < 1 || port > 65535 {
		return sample, fmt.Errorf("invalid tcp port %d", port)
	}

	addr := net.JoinHostPort(ip4.String(), strconv.Itoa(port))
	dialer := net.Dialer{Control: bindToDeviceControl(ifaceName), Timeout: timeout}

	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		sample.Sent++

		roundCtx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		conn, err := dialer.DialContext(roundCtx, "tcp4", addr)
		cancel()

		switch {
		case err == nil:
			sample.Received++
			sample.RTTsMs = append(sample.RTTsMs, millisFloat(time.Since(start)))
			conn.Close()
		case errors.Is(err, syscall.ECONNREFUSED):
			// A refused connection means the remote host answered at L3/L4 —
			// the path IS reachable, the port simply has nothing listening.
			// Counted as success for reachability purposes (see the
			// kernel.PathProbeManager doc comment on ProbeTCP).
			sample.Received++
			sample.RTTsMs = append(sample.RTTsMs, millisFloat(time.Since(start)))
		default:
			// Timeout, no route to host, network unreachable, or ctx
			// cancellation: all counted as loss, never a probe-system error.
		}
	}
	return sample, nil
}
