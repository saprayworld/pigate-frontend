//go:build linux

package kernel

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// buildFakeICMPReply wraps a marshalled ICMP message in a minimal valid
// IPv4 header, mimicking exactly what a real raw "ip4:icmp" socket delivers
// on read (see icmpRoundOnce's header-stripping comment) — this lets the
// test exercise the real header-stripping + ID/Seq matching code path
// without needing an actual raw socket (which requires CAP_NET_RAW and is
// not available in ordinary CI/dev sandboxes; see real hardware evidence in
// docs/ref/wan-failover-findings.md S-1 instead for the raw-socket behavior
// itself).
func buildFakeICMPReply(t *testing.T, icmpType ipv4.ICMPType, id, seq int) []byte {
	t.Helper()
	msg := icmp.Message{Type: icmpType, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("x")}}
	body, err := msg.Marshal(nil)
	if err != nil {
		t.Fatalf("marshal icmp message: %v", err)
	}
	hdr := &ipv4.Header{
		Version: 4, Len: ipv4.HeaderLen, TOS: 0,
		TotalLen: ipv4.HeaderLen + len(body), TTL: 64, Protocol: protocolICMP,
		Src: net.IPv4(127, 0, 0, 1), Dst: net.IPv4(127, 0, 0, 1),
	}
	hb, err := hdr.Marshal()
	if err != nil {
		t.Fatalf("marshal ipv4 header: %v", err)
	}
	return append(hb, body...)
}

// newFakeICMPPair returns two UDP4 loopback sockets standing in for (a) the
// probe's own conn and (b) the "remote target" a test can manually script
// replies from — icmpRoundOnce only depends on the net.PacketConn/net.Addr
// interfaces, so a UDP socket pair exercises its ID/Seq-matching and
// header-stripping logic identically to a real raw ICMP socket, without
// requiring CAP_NET_RAW.
func newFakeICMPPair(t *testing.T) (probe net.PacketConn, remote net.PacketConn) {
	t.Helper()
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen probe socket: %v", err)
	}
	remote, err = net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		probe.Close()
		t.Fatalf("listen remote socket: %v", err)
	}
	return probe, remote
}

func TestIcmpRoundOnce_MatchesIDAndSeq(t *testing.T) {
	probe, remote := newFakeICMPPair(t)
	defer probe.Close()
	defer remote.Close()

	const id, seq = 1234, 7
	resultCh := make(chan struct {
		rtt time.Duration
		ok  bool
		err error
	}, 1)
	go func() {
		rtt, ok, err := icmpRoundOnce(context.Background(), probe, remote.LocalAddr(), id, seq, 2*time.Second)
		resultCh <- struct {
			rtt time.Duration
			ok  bool
			err error
		}{rtt, ok, err}
	}()

	// Read the "echo request" the round sent us, then reply with a
	// non-matching seq first (must be ignored) and finally the correct one.
	buf := make([]byte, 1500)
	remote.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := remote.ReadFrom(buf)
	if err != nil {
		t.Fatalf("remote failed to read probe's echo request: %v", err)
	}
	_ = n
	if _, err := remote.WriteTo(buildFakeICMPReply(t, ipv4.ICMPTypeEchoReply, id, seq+1), from); err != nil {
		t.Fatalf("failed to send stray reply: %v", err)
	}
	if _, err := remote.WriteTo(buildFakeICMPReply(t, ipv4.ICMPTypeEchoReply, id, seq), from); err != nil {
		t.Fatalf("failed to send matching reply: %v", err)
	}

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("unexpected error: %v", res.err)
		}
		if !res.ok {
			t.Fatal("expected ok=true for a matching id/seq reply")
		}
		if res.rtt <= 0 {
			t.Errorf("expected a positive RTT, got %v", res.rtt)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("icmpRoundOnce did not return in time")
	}
}

func TestIcmpRoundOnce_TimeoutIsLossNotError(t *testing.T) {
	probe, remote := newFakeICMPPair(t)
	defer probe.Close()
	defer remote.Close()

	start := time.Now()
	rtt, ok, err := icmpRoundOnce(context.Background(), probe, remote.LocalAddr(), 1, 1, 100*time.Millisecond)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("a plain timeout must not be an error, got: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false when nothing replies")
	}
	if rtt != 0 {
		t.Errorf("expected rtt=0 on loss, got %v", rtt)
	}
	if elapsed > 2*time.Second {
		t.Errorf("took too long to time out: %v", elapsed)
	}
}

func TestIcmpRoundOnce_CtxCancelReturnsImmediately(t *testing.T) {
	probe, remote := newFakeICMPPair(t)
	defer probe.Close()
	defer remote.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, ok, err := icmpRoundOnce(ctx, probe, remote.LocalAddr(), 1, 1, 30*time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ctx cancellation must not be reported as an error, got: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false when cancelled before any reply arrives")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("ctx cancel did not return promptly: took %v against a 30s timeout", elapsed)
	}
}

func TestProbeICMP_ZeroCountReturnsImmediately(t *testing.T) {
	p := NewRealPathProbe()
	sample, err := p.ProbeICMP(context.Background(), "lo", net.ParseIP("127.0.0.1"), 0, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sample.Sent != 0 || sample.Received != 0 {
		t.Errorf("expected no packets sent/received for count=0, got %+v", sample)
	}
	if sample.Method != "icmp" || sample.MetricQuality != "full" {
		t.Errorf("expected Method/MetricQuality always set, got %+v", sample)
	}
}

func TestProbeICMP_UnknownInterfaceErrors(t *testing.T) {
	p := NewRealPathProbe()
	_, err := p.ProbeICMP(context.Background(), "pigate-test-nonexistent-iface", net.ParseIP("1.1.1.1"), 1, time.Second)
	if err == nil {
		t.Fatal("expected an error for a nonexistent interface")
	}
}

func TestProbeICMP_RejectsIPv6Target(t *testing.T) {
	p := NewRealPathProbe()
	// "lo" always exists, so this reaches the IPv4-literal check without
	// needing CAP_NET_RAW (the check happens before the socket is opened).
	_, err := p.ProbeICMP(context.Background(), "lo", net.ParseIP("2001:4860:4860::8888"), 1, time.Second)
	if err == nil {
		t.Fatal("expected an error for an IPv6 target")
	}
}

func TestProbeTCP_UnknownInterfaceErrors(t *testing.T) {
	p := NewRealPathProbe()
	_, err := p.ProbeTCP(context.Background(), "pigate-test-nonexistent-iface", net.ParseIP("127.0.0.1"), 443, 1, time.Second)
	if err == nil {
		t.Fatal("expected an error for a nonexistent interface")
	}
}

func TestProbeTCP_ConnectSuccess(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	p := NewRealPathProbe()
	sample, err := p.ProbeTCP(context.Background(), "lo", net.ParseIP("127.0.0.1"), port, 3, time.Second)
	if err != nil {
		t.Skipf("ProbeTCP requires SO_BINDTODEVICE permission not available in this sandbox: %v", err)
	}
	if sample.Sent != 3 {
		t.Errorf("expected 3 sent, got %d", sample.Sent)
	}
	if sample.Received != 3 {
		t.Errorf("expected 3 received (listener accepts every connection), got %d", sample.Received)
	}
	if sample.MetricQuality != "connect-only" {
		t.Errorf("expected MetricQuality=connect-only, got %q", sample.MetricQuality)
	}
	if len(sample.RTTsMs) != 3 {
		t.Errorf("expected 3 RTT samples, got %d", len(sample.RTTsMs))
	}
}

func TestProbeTCP_RefusedCountsAsReachable(t *testing.T) {
	// Bind a listener then close it immediately: the OS still owns the port
	// briefly, but more reliably we just pick a high port nothing listens on
	// by opening and closing a listener to get a free port number.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	p := NewRealPathProbe()
	sample, err := p.ProbeTCP(context.Background(), "lo", net.ParseIP("127.0.0.1"), port, 1, time.Second)
	if err != nil {
		t.Skipf("ProbeTCP requires SO_BINDTODEVICE permission not available in this sandbox: %v", err)
	}
	if sample.Received != 1 {
		t.Errorf("expected a refused connection to count as reachable (Received=1), got %+v", sample)
	}
}

func TestProbeTCP_CtxCancelReturnsPromptly(t *testing.T) {
	p := NewRealPathProbe()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	// 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — guaranteed non-routable, so
	// the connection attempt will hang until timeout/cancel rather than
	// immediately refuse or succeed.
	start := time.Now()
	_, err := p.ProbeTCP(ctx, "lo", net.ParseIP("203.0.113.1"), 81, 1, 30*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Skipf("ProbeTCP requires SO_BINDTODEVICE permission not available in this sandbox: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("ctx cancel did not return promptly: took %v against a 30s timeout", elapsed)
	}
}

func TestProbeTCP_NoFdLeakOver100Calls(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	p := NewRealPathProbe()
	if _, err := p.ProbeTCP(context.Background(), "lo", net.ParseIP("127.0.0.1"), port, 1, time.Second); err != nil {
		t.Skipf("ProbeTCP requires SO_BINDTODEVICE permission not available in this sandbox: %v", err)
	}

	before := countOpenFds(t)
	for i := 0; i < 100; i++ {
		if _, err := p.ProbeTCP(context.Background(), "lo", net.ParseIP("127.0.0.1"), port, 1, time.Second); err != nil {
			t.Fatalf("ProbeTCP call %d failed: %v", i, err)
		}
	}
	after := countOpenFds(t)
	// Allow a small margin for GC/runtime-internal fd churn (timers, etc.)
	// rather than asserting an exact count.
	if after > before+5 {
		t.Errorf("possible fd leak: had %d fds open before, %d after 100 ProbeTCP calls", before, after)
	}
}

func countOpenFds(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot read /proc/self/fd on this platform: %v", err)
	}
	return len(entries)
}
