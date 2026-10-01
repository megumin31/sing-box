package queqiao

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func resumeTestOutbound(t *testing.T, profile, transport string) *Outbound {
	t.Helper()
	a, err := NewOutbound(context.Background(), nil, nil, "udp-resume", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: transport, UDPResume: true})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	t.Cleanup(func() { o.Close() })
	return o
}

type udpEchoProbe struct {
	conn    *net.UDPConn
	mu      sync.Mutex
	sources map[string]int
}

func newUDPProbe(t *testing.T) *udpEchoProbe {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &udpEchoProbe{conn: c, sources: make(map[string]int)}
	t.Cleanup(func() { c.Close() })
	go func() {
		b := make([]byte, maxUDPDatagram)
		for {
			n, source, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			p.mu.Lock()
			p.sources[source.String()]++
			p.mu.Unlock()
			c.WriteToUDP(b[:n], source)
		}
	}()
	return p
}
func (p *udpEchoProbe) onlySource(t *testing.T) string {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.sources) != 1 {
		t.Fatalf("destination observed %d relay endpoints: %v", len(p.sources), p.sources)
	}
	for s := range p.sources {
		return s
	}
	return ""
}
func waitUDPReplacement(t *testing.T, p *packetConn, before int) {
	t.Helper()
	c := p.wire
	deadline := time.Now().Add(8 * time.Second)
	for {
		c.mu.Lock()
		ready, closed, err := c.recoveryAttempts > before && !c.recovering, c.closed, c.err
		c.mu.Unlock()
		if closed {
			t.Fatalf("UDP resume failed: %v", err)
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("UDP replacement did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}
func exchangeUDPProbe(t *testing.T, p *packetConn, probe *udpEchoProbe, payload []byte) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	// UDP handover may lose datagrams. Each timeout starts a new application
	// probe; the implementation must never replay one on its own.
	for {
		p.SetWriteDeadline(deadline)
		if n, err := p.WriteTo(payload, probe.conn.LocalAddr()); err != nil || n != len(payload) {
			t.Fatalf("UDP write size=%d: %d %v", len(payload), n, err)
		}
		p.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		b := make([]byte, maxUDPDatagram)
		n, source, err := p.ReadFrom(b)
		if errors.Is(err, os.ErrDeadlineExceeded) && time.Now().Before(deadline) {
			continue
		}
		if err != nil || !bytes.Equal(b[:n], payload) || source.String() != probe.conn.LocalAddr().String() {
			t.Fatalf("UDP echo: %d %v %v", n, source, err)
		}
		return
	}
}
func testOfficialUDPResume(t *testing.T, profile, transport string) {
	o := resumeTestOutbound(t, profile, transport)
	first, second := newUDPProbe(t), newUDPProbe(t)
	raw, err := o.ListenPacket(context.Background(), M.ParseSocksaddr(first.conn.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*packetConn)
	defer p.Close()
	exchangeUDPProbe(t, p, first, []byte("before"))
	endpoint := first.onlySource(t)
	for attempt := 0; attempt < 3; attempt++ {
		p.wire.mu.Lock()
		token, session, flow := p.token, p.wire.session, p.wire.flow
		p.wire.mu.Unlock()
		abortCarrier(p.wire.currentCarrier())
		waitUDPReplacement(t, p, attempt)
		p.wire.mu.Lock()
		newToken, newSession, newFlow := p.token, p.wire.session, p.wire.flow
		p.wire.mu.Unlock()
		if newToken == token || newSession == session || newFlow == flow {
			t.Fatal("token/association IDs not rotated")
		}
		for i, size := range []int{0, 1, 1200, 65000, maxUDPDatagram} {
			probe := first
			if i%2 == 1 {
				probe = second
			}
			exchangeUDPProbe(t, p, probe, bytes.Repeat([]byte{byte(attempt + 1)}, size))
		}
		if first.onlySource(t) != endpoint || second.onlySource(t) != endpoint {
			t.Fatal("resumption changed remote relay endpoint")
		}
	}
	abortCarrier(p.wire.currentCarrier())
	select {
	case <-p.wire.done:
	case <-time.After(time.Second):
		t.Fatal("resume lifetime budget not enforced")
	}
	p.wire.mu.Lock()
	attempts := p.wire.recoveryAttempts
	p.wire.mu.Unlock()
	if attempts != 3 {
		t.Fatalf("attempts=%d", attempts)
	}
}
func testOfficialUDPResumePrincipal(t *testing.T, profile, otherProfile, transport string) {
	original, other := resumeTestOutbound(t, profile, transport), resumeTestOutbound(t, otherProfile, transport)
	probe := newUDPProbe(t)
	dest := M.ParseSocksaddr(probe.conn.LocalAddr().String())
	raw, err := original.ListenPacket(context.Background(), dest)
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*packetConn)
	exchangeUDPProbe(t, p, probe, []byte("original"))
	p.wire.mu.Lock()
	token := p.token
	p.resume = nil
	p.wire.mu.Unlock()
	abortCarrier(p.wire.currentCarrier())
	<-p.wire.done
	time.Sleep(1100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = other.resumeUDP(ctx, dest, other.generation, token)
	var invalid protocolError
	if !errors.As(err, &invalid) {
		t.Fatalf("wrong principal reclaimed relay: %v", err)
	}
	_, err = original.resumeUDP(ctx, dest, original.generation, token)
	if !errors.As(err, &invalid) {
		t.Fatalf("spent token accepted: %v", err)
	}
}
func testOfficialSharedUDPResume(t *testing.T, profile string) {
	o := resumeTestOutbound(t, profile, "quic")
	probe := newUDPProbe(t)
	var packets []*packetConn
	var wires []*Conn
	for i := 0; i < 8; i++ {
		raw, err := o.ListenPacket(context.Background(), M.ParseSocksaddr(probe.conn.LocalAddr().String()))
		if err != nil {
			t.Fatal(err)
		}
		p := raw.(*packetConn)
		packets = append(packets, p)
		wires = append(wires, p.wire)
		exchangeUDPProbe(t, p, probe, []byte{byte(i)})
	}
	assertTestSharedCarrier(t, wires)
	probe.mu.Lock()
	old := make(map[string]bool)
	for address := range probe.sources {
		old[address] = true
	}
	probe.mu.Unlock()
	if len(old) != 8 {
		t.Fatalf("relay count=%d", len(old))
	}
	breakTestCarrier(wires[0], true)
	for i, p := range packets {
		waitUDPReplacement(t, p, 0)
		exchangeUDPProbe(t, p, probe, []byte{byte(i + 10)})
	}
	assertTestSharedCarrier(t, wires)
	probe.mu.Lock()
	for address := range probe.sources {
		if !old[address] {
			t.Errorf("relay endpoint changed to %s", address)
		}
	}
	probe.mu.Unlock()
	packets[0].Close()
	for i, p := range packets[1:] {
		exchangeUDPProbe(t, p, probe, []byte{byte(i + 20)})
		p.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		o.mu.Lock()
		empty := len(o.active) == 0 && len(o.slots) == 0
		o.mu.Unlock()
		if empty {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("resumed UDP leaked logical slots")
		}
		time.Sleep(time.Millisecond)
	}
}

func testOfficialUDPResumePacketWindow(t *testing.T, profile, transport string) {
	o := resumeTestOutbound(t, profile, transport)
	probe := newUDPProbe(t)
	raw, err := o.ListenPacket(context.Background(), M.ParseSocksaddr(probe.conn.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*packetConn)
	defer p.Close()
	for generation := 0; generation < 2; generation++ {
		if generation > 0 {
			abortCarrier(p.wire.currentCarrier())
			waitUDPReplacement(t, p, 0)
			time.Sleep(1100 * time.Millisecond)
		}
		c := p.wire
		c.mu.Lock()
		carrier, session, flow := c.carrier, c.session, c.flow
		c.mu.Unlock()
		for _, seq := range []uint64{2, 0, 1, 1, 70, 0} {
			payload, _ := encodePacket(probe.conn.LocalAddr().String(), []byte{byte(seq)})
			if err := writeFrame(carrier, frame{typ: typePacket, session: session, flow: flow, sequence: seq, payload: payload}); err != nil {
				t.Fatal(err)
			}
		}
		p.SetReadDeadline(time.Now().Add(time.Second))
		got := make(map[byte]int)
		for i := 0; i < 4; i++ {
			var b [1]byte
			if _, _, err := p.ReadFrom(b[:]); err != nil {
				t.Fatal(err)
			}
			got[b[0]]++
		}
		for _, seq := range []byte{2, 0, 1, 70} {
			if got[seq] != 1 {
				t.Fatalf("gateway delivered wrong packet count: %v", got)
			}
		}
		p.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		if _, _, err := p.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("gateway replayed duplicate: %v", err)
		}
	}
	probe.onlySource(t)
}

func testOfficialUDPResumeLostGrant(t *testing.T, profile, transport string) {
	o := resumeTestOutbound(t, profile, transport)
	probe := newUDPProbe(t)
	raw, err := o.ListenPacket(context.Background(), M.ParseSocksaddr(probe.conn.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*packetConn)
	defer p.Close()
	exchangeUDPProbe(t, p, probe, []byte("before-lost-grant"))
	p.wire.mu.Lock()
	resume := p.resume
	first := true
	p.resume = func(ctx context.Context, token [16]byte) (*udpReplacement, error) {
		r, e := resume(ctx, token)
		if e == nil && first {
			first = false
			abortCarrier(r.conn)
			return nil, io.ErrUnexpectedEOF
		}
		return r, e
	}
	p.wire.mu.Unlock()
	abortCarrier(p.wire.currentCarrier())
	select {
	case <-p.wire.done:
	case <-time.After(5 * time.Second):
		t.Fatal("lost grant looped indefinitely")
	}
	p.wire.mu.Lock()
	attempts, failure := p.wire.recoveryAttempts, p.wire.err
	p.wire.mu.Unlock()
	var invalid protocolError
	if attempts != 2 || !errors.As(failure, &invalid) {
		t.Fatalf("ambiguous token use did not stop on fresh relay: attempts=%d %v", attempts, failure)
	}
	probe.onlySource(t)
}

func testOfficialUDPResumeWriteFault(t *testing.T, profile, transport string) {
	o := resumeTestOutbound(t, profile, transport)
	probe := newUDPProbe(t)
	raw, err := o.ListenPacket(context.Background(), M.ParseSocksaddr(probe.conn.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*packetConn)
	defer p.Close()
	exchangeUDPProbe(t, p, probe, []byte("before-write-fault"))
	endpoint := probe.onlySource(t)
	c := p.wire
	c.mu.Lock()
	c.carrier = acceptedErrorConn{c.carrier}
	c.mu.Unlock()
	// The wrapper transmits exactly one complete real authenticated PACKET, then
	// reports an I/O error. Recovery must consume it without replay or CopyPacket
	// teardown. Its reply may legitimately be lost at the old generation boundary.
	p.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if n, err := p.WriteTo([]byte("ambiguous-one"), probe.conn.LocalAddr()); err != nil || n != len("ambiguous-one") {
		t.Fatalf("send-side recovery failed: %d %v", n, err)
	}
	exchangeUDPProbe(t, p, probe, []byte("after-write-fault"))
	if probe.onlySource(t) != endpoint {
		t.Fatal("send-side recovery changed source endpoint")
	}
	c.mu.Lock()
	attempts := c.recoveryAttempts
	c.mu.Unlock()
	if attempts != 1 {
		t.Fatalf("send-side recovery attempts=%d", attempts)
	}
}

func testOfficialUDPResumeInterfaceUpdate(t *testing.T, profile, transport string) {
	o := resumeTestOutbound(t, profile, transport)
	probe := newUDPProbe(t)
	raw, err := o.ListenPacket(context.Background(), M.ParseSocksaddr(probe.conn.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*packetConn)
	defer p.Close()
	exchangeUDPProbe(t, p, probe, []byte("before-interface-update"))
	entered, cancelled := make(chan struct{}), make(chan struct{})
	p.wire.mu.Lock()
	p.resume = func(ctx context.Context, _ [16]byte) (*udpReplacement, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}
	p.wire.mu.Unlock()
	abortCarrier(p.wire.currentCarrier())
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("resume did not start")
	}
	o.InterfaceUpdated(context.Background())
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("interface update did not cancel pending resume")
	}
	select {
	case <-p.wire.done:
	default:
		t.Fatal("old association survived interface update")
	}
	o.mu.Lock()
	empty := len(o.active) == 0 && len(o.slots) == 0
	o.mu.Unlock()
	if !empty {
		t.Fatal("interface update leaked association slot")
	}
}

func testOfficialUDPResumeExpiredToken(t *testing.T, profile, transport string) {
	if os.Getenv("QUEQIAO_TEST_SLOW_UDP_RESUME") != "1" {
		t.Skip("set QUEQIAO_TEST_SLOW_UDP_RESUME=1 to wait through the official 30-second relay grace")
	}
	o := resumeTestOutbound(t, profile, transport)
	probe := newUDPProbe(t)
	raw, err := o.ListenPacket(context.Background(), M.ParseSocksaddr(probe.conn.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*packetConn)
	defer p.Close()
	exchangeUDPProbe(t, p, probe, []byte("before-expiry"))
	p.wire.mu.Lock()
	token := p.token
	p.resume = nil
	p.wire.mu.Unlock()
	abortCarrier(p.wire.currentCarrier())
	<-p.wire.done
	time.Sleep(31 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := o.resumeUDP(ctx, M.ParseSocksaddr(probe.conn.LocalAddr().String()), o.generation, token)
	var invalid protocolError
	if r != nil || !errors.As(err, &invalid) {
		t.Fatalf("expired token silently changed relay: %v", err)
	}
}
