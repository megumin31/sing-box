//go:build with_quic

package queqiao

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func eventually(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

func poolTestOutbound(t *testing.T) *Outbound {
	t.Helper()
	profile, certificate, _ := testIdentity(t)
	return poolTestOutboundIdentity(t, profile, certificate)
}

func poolTestOutboundIdentity(t *testing.T, profile clientProfile, certificate tls.Certificate) *Outbound {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{dataALPN}}, &quic.Config{MaxIncomingStreams: 1024, EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); listener.Close() })
	go func() {
		for {
			c, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				defer c.CloseWithError(0, "")
				for {
					s, err := c.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func() { io.Copy(s, s); s.Close() }()
				}
			}()
		}
	}()
	profile.Endpoint = listener.Addr().String()
	raw, _ := json.Marshal(profile)
	path := filepath.Join(t.TempDir(), "profile.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := NewOutbound(context.Background(), nil, nil, "pool-test", option.QueqiaoOutboundOptions{ProfilePath: path, Transport: "quic"})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	t.Cleanup(func() { o.Close() })
	return o
}

func TestQUICPoolCapacityIdleAndIsolation(t *testing.T) {
	o := poolTestOutbound(t)
	p := o.pool.(*quicPool)
	p.idleTimeout = 20 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	carriers := make([]*quicCarrier, 0, 256)
	connections := make(map[*quic.Conn]int)
	for i := 0; i < maxQUICConnections*maxQUICStreams; i++ {
		raw, err := p.Open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c := raw.(*quicCarrier)
		carriers = append(carriers, c)
		connections[c.connection]++
	}
	if len(connections) != 4 {
		t.Fatalf("connections=%d", len(connections))
	}
	for _, n := range connections {
		if n != 64 {
			t.Fatalf("streams per connection=%d", n)
		}
	}
	if _, err := p.Open(ctx); err == nil {
		t.Fatal("pool capacity ignored")
	}
	first, second := carriers[0], carriers[1]
	if first.connection != second.connection {
		t.Fatal("flows were not pooled")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second.SetDeadline(time.Now().Add(time.Second))
	if _, err := second.Write([]byte("survivor")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 8)
	if _, err := io.ReadFull(second, data); err != nil || string(data) != "survivor" {
		t.Fatalf("surviving flow %q: %v", data, err)
	}
	replacement, err := p.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.(*quicCarrier).connection != first.connection {
		t.Fatal("available stream capacity was not reused")
	}
	replacement.Close()
	for _, c := range carriers {
		c.Close()
	}
	eventually(t, func() bool { p.mu.Lock(); defer p.mu.Unlock(); return len(p.entries) == 0 })
	for c := range connections {
		select {
		case <-c.Context().Done():
		case <-ctx.Done():
			t.Fatal("idle connection/socket not closed")
		}
	}
	fresh, err := p.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if connections[fresh.(*quicCarrier).connection] != 0 {
		t.Fatal("reused expired connection")
	}
	fresh.Close()
}

func TestQUICPoolSharedHandshakeCancellation(t *testing.T) {
	o := poolTestOutbound(t)
	p := o.pool.(*quicPool)
	original := o.dialer
	gate := make(chan struct{})
	entered := make(chan struct{})
	var calls atomic.Int32
	type key struct{}
	o.dialer = testDialer{dial: func(ctx context.Context, n string, d M.Socksaddr) (net.Conn, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		if ctx.Value(key{}) != "metadata" {
			t.Error("caller dial metadata lost")
		}
		select {
		case <-gate:
			return original.DialContext(ctx, n, d)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	ctx1, cancel1 := context.WithCancel(context.WithValue(context.Background(), key{}, "metadata"))
	result1 := make(chan error, 1)
	go func() {
		c, e := p.Open(ctx1)
		if c != nil {
			c.Close()
		}
		result1 <- e
	}()
	<-entered
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	result2 := make(chan net.Conn, 1)
	err2 := make(chan error, 1)
	go func() { c, e := p.Open(ctx2); result2 <- c; err2 <- e }()
	eventually(t, func() bool { p.mu.Lock(); defer p.mu.Unlock(); return len(p.entries) == 1 && p.entries[0].users == 2 })
	cancel1()
	if err := <-result1; !errors.Is(err, context.Canceled) {
		t.Fatalf("first cancellation: %v", err)
	}
	close(gate)
	c := <-result2
	if err := <-err2; err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if calls.Load() != 1 {
		t.Fatalf("shared handshake dialed %d sockets", calls.Load())
	}
}

func TestQUICPoolResetDuringHandshake(t *testing.T) {
	o := poolTestOutbound(t)
	p := o.pool.(*quicPool)
	entered := make(chan struct{})
	finished := make(chan struct{})
	o.dialer = testDialer{dial: func(ctx context.Context, n string, d M.Socksaddr) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		close(finished)
		return nil, ctx.Err()
	}}
	result := make(chan error, 1)
	go func() { _, err := p.Open(context.Background()); result <- err }()
	<-entered
	p.Reset(false)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("reset handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("reset did not unblock acquire")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("reset did not cancel socket dial")
	}
	p.Reset(true)
	if _, err := p.Open(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed pool: %v", err)
	}
}

// Called by the opt-in official gateway suite. Keep the TCP and UDP flows live
// together, prove their actual carriers share a connection, and exercise
// stream-local cancellation, outbound network reset and re-dial.
func testOfficialQUICPool(t *testing.T, profile string, destination M.Socksaddr) {
	t.Helper()
	a, err := NewOutbound(context.Background(), nil, nil, "pooled-interop", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: "quic"})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		b := make([]byte, maxUDPDatagram)
		for {
			n, src, e := target.ReadFromUDP(b)
			if e != nil {
				return
			}
			target.WriteToUDP(b[:n], src)
		}
	}()
	var tcp []*Conn
	var udp []*packetConn
	for i := 0; i < 8; i++ {
		c, e := o.DialContext(ctx, "tcp", destination)
		if e != nil {
			t.Fatal(e)
		}
		tcp = append(tcp, c.(*Conn))
		u, e := o.ListenPacket(ctx, destination)
		if e != nil {
			t.Fatal(e)
		}
		udp = append(udp, u.(*packetConn))
	}
	connection := tcp[0].currentCarrier().(*quicCarrier).connection
	for _, c := range tcp {
		if c.currentCarrier().(*quicCarrier).connection != connection {
			t.Fatal("TCP flows did not share connection")
		}
	}
	for _, c := range udp {
		if c.wire.currentCarrier().(*quicCarrier).connection != connection {
			t.Fatal("UDP/TCP did not share connection")
		}
	}
	tcp[0].Close()
	udp[0].Close()
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err = o.DialContext(canceled, "tcp", destination); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled pooled flow: %v", err)
	}
	var wg sync.WaitGroup
	for i := 1; i < 8; i++ {
		i := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			c := tcp[i]
			c.SetDeadline(time.Now().Add(3 * time.Second))
			payload := []byte("pooled-tcp-survivor")
			_, e := c.Write(payload)
			if e == nil {
				b := make([]byte, len(payload))
				_, e = io.ReadFull(c, b)
				if string(b) != string(payload) {
					e = errors.New("TCP payload mismatch")
				}
			}
			if e != nil {
				t.Error(e)
			}
		}()
		go func() {
			defer wg.Done()
			c := udp[i]
			c.SetDeadline(time.Now().Add(3 * time.Second))
			payload := []byte("pooled-udp-survivor")
			_, e := c.WriteTo(payload, target.LocalAddr())
			if e == nil {
				b := make([]byte, 128)
				n, _, readErr := c.ReadFrom(b)
				e = readErr
				if string(b[:n]) != string(payload) {
					e = errors.New("UDP payload mismatch")
				}
			}
			if e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	o.InterfaceUpdated(ctx)
	select {
	case <-connection.Context().Done():
	case <-ctx.Done():
		t.Fatal("network change retained QUIC connection")
	}
	eventually(t, func() bool { o.mu.Lock(); defer o.mu.Unlock(); return len(o.active) == 0 && len(o.slots) == 0 })
	c, err := o.DialContext(ctx, "tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.(*Conn).currentCarrier().(*quicCarrier).connection == connection {
		t.Fatal("network change reused old connection")
	}
}

func TestQUICPoolIdentityExpiry(t *testing.T) {
	profile, _, peer := testIdentity(t)
	config, err := profile.tlsConfig(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	expires, err := quicIdentityExpiry(config, peer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = quicIdentityExpiry(config, peer, expires); err == nil {
		t.Fatal("pool accepted expired identity")
	}
	// A short-lived gateway issuer must cap a long-lived leaf and device.
	issuer := *peer[1]
	issuer.NotAfter = time.Now().Add(time.Minute)
	peers := append([]*x509.Certificate(nil), peer...)
	peers[1] = &issuer
	limit, err := quicIdentityExpiry(config, peers, time.Now())
	if err != nil || !limit.Equal(issuer.NotAfter) {
		t.Fatalf("issuer expiry ignored: %v %v", limit, err)
	}
	if _, err = quicIdentityExpiry(config, nil, time.Now()); err == nil {
		t.Fatal("missing peer accepted")
	}
}

func TestQUICPoolClosesAtCertificateExpiry(t *testing.T) {
	profile, certificate, _ := testIdentityExpires(t, time.Now().Add(2*time.Second))
	o := poolTestOutboundIdentity(t, profile, certificate)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, err := o.pool.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-c.(*quicCarrier).connection.Context().Done():
	case <-ctx.Done():
		t.Fatal("pool retained expired authenticated connection")
	}
	eventually(t, func() bool { p := o.pool.(*quicPool); p.mu.Lock(); defer p.mu.Unlock(); return len(p.entries) == 0 })
	if next, err := o.pool.Open(ctx); err == nil {
		next.Close()
		t.Fatal("expired credentials opened a replacement connection")
	}
}

func TestQUICPoolConcurrentOpenCloseAndReset(t *testing.T) {
	o := poolTestOutbound(t)
	p := o.pool.(*quicPool)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				c, err := p.Open(ctx)
				if err == nil {
					c.Close()
				}
				if i%5 == 0 {
					p.Reset(false)
				}
			}
		}()
	}
	wg.Wait()
	p.Reset(true)
	eventually(t, func() bool { p.mu.Lock(); defer p.mu.Unlock(); return len(p.entries) == 0 })
	if _, err := p.Open(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("permanent pool close: %v", err)
	}
}

func TestQUICPoolRetiresFailedDrain(t *testing.T) {
	o := poolTestOutbound(t)
	p := o.pool.(*quicPool)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, err := p.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	old := first.(*quicCarrier)
	old.drain.mu.Lock()
	old.drain.fail()
	old.drain.mu.Unlock()
	next, err := p.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next.(*quicCarrier).connection == old.connection {
		t.Fatal("failed ACK tracker reused")
	}
	first.Close()
	select {
	case <-old.connection.Context().Done():
	case <-ctx.Done():
		t.Fatal("failed drain retained idle connection")
	}
}
