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
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestQUICNoDatagramsAndFinalACK(t *testing.T) {
	profile, certificate, chain := testIdentity(t)
	roots := x509.NewCertPool()
	roots.AddCert(chain[2])
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{dataALPN}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	profile.Endpoint = listener.Addr().String()
	raw, _ := json.Marshal(profile)
	path := filepath.Join(t.TempDir(), "profile.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: path, Transport: "quic"})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		defer connection.CloseWithError(0, "")
		state := connection.ConnectionState()
		if state.SupportsDatagrams.Remote || state.Used0RTT {
			done <- errors.New("client enabled DATAGRAM or 0-RTT")
			return
		}
		// Retire stream 0 first: final-frame draining must use the actual
		// pooled stream ID instead of accidentally tracking only the first.
		warm, err := connection.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		data, err := io.ReadAll(warm)
		if err != nil || string(data) != "warm" {
			done <- errors.New("warm stream failed")
			return
		}
		warm.Close()
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		open, err := readFrame(stream)
		if err != nil {
			done <- err
			return
		}
		send := func(f frame) error { f.session, f.flow = open.session, open.flow; return writeFrame(stream, f) }
		if err = send(frame{typ: typeOpenOK}); err != nil {
			done <- err
			return
		}
		// ACK the client's FIN before sending our final data. This makes the
		// client's downstream ACK_FINAL its last frame and catches an early
		// QUIC connection close that discards that queued control frame.
		first, err := readFrame(stream)
		if err != nil || first.typ != typeClose || first.flags != flagFIN || first.sequence != 0 {
			if err == nil {
				err = errors.New("missing initial upstream FIN")
			}
			done <- err
			return
		}
		if err = send(frame{typ: typeACK, flags: flagACKUp | flagACKFinal}); err != nil {
			done <- err
			return
		}
		if err = send(frame{typ: typeData, payload: []byte("reply")}); err != nil {
			done <- err
			return
		}
		if err = send(frame{typ: typeClose, flags: flagFIN, sequence: 5}); err != nil {
			done <- err
			return
		}
		fin, finalACK := true, false
		for !fin || !finalACK {
			f, err := readFrame(stream)
			if err != nil {
				done <- err
				return
			}
			if f.typ == typeClose {
				fin = f.flags == flagFIN && f.sequence == 0
				if err = send(frame{typ: typeACK, flags: flagACKUp | flagACKFinal}); err != nil {
					done <- err
					return
				}
			}
			if f.typ == typeACK && f.flags == flagACKDown|flagACKFinal && f.sequence == 5 {
				finalACK = true
			}
		}
		done <- nil
	}()
	warm, err := o.pool.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = warm.Write([]byte("warm")); err != nil {
		t.Fatal(err)
	}
	if err = warm.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.(*Conn).currentCarrier().(*quicCarrier).StreamID() == 0 {
		t.Fatal("final ACK test did not use a pooled stream")
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if err = c.(*Conn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(c)
	if err != nil || string(received) != "reply" {
		t.Fatalf("reply %q: %v", received, err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("gateway did not receive final ACK")
	}
}

func TestQUICHandshakeCancellationUsesDialer(t *testing.T) {
	profile, _, _ := testIdentity(t)
	raw, _ := json.Marshal(profile)
	path := filepath.Join(t.TempDir(), "profile.json")
	os.WriteFile(path, raw, 0600)
	a, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: path, Transport: "quic"})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
	// A local UDP sink makes handshake cancellation deterministic and proves
	// that the common dialer route receives the outer UDP request.
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	called := false
	o.dialer = testDialer{dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		called = true
		if network != "udp" || destination.String() != profile.Endpoint {
			t.Errorf("wrong QUIC dialer request %s %s", network, destination)
		}
		return net.DialUDP("udp4", nil, sink.LocalAddr().(*net.UDPAddr))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err = o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("QUIC cancellation: %v", err)
	}
	if !called || len(o.slots) != 0 || len(o.active) != 0 {
		t.Fatal("QUIC dialer or cleanup failed")
	}
}

func TestQUICRejectsGatewayIdentityAndALPN(t *testing.T) {
	for _, kind := range []string{"gateway-URI", "ALPN"} {
		t.Run(kind, func(t *testing.T) {
			profile, certificate, _ := testIdentity(t)
			alpn := dataALPN
			if kind == "ALPN" {
				alpn = "queqiao-enroll/1"
			} else {
				profile.GatewayID = profile.DeviceID
			}
			listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{alpn}}, &quic.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			profile.Endpoint = listener.Addr().String()
			raw, _ := json.Marshal(profile)
			path := filepath.Join(t.TempDir(), "profile.json")
			os.WriteFile(path, raw, 0600)
			a, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: path, Transport: "quic"})
			if err != nil {
				t.Fatal(err)
			}
			o := a.(*Outbound)
			defer o.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if c, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443")); err == nil {
				c.Close()
				t.Fatal("unauthenticated QUIC gateway accepted")
			}
			if len(o.slots) != 0 || len(o.active) != 0 {
				t.Fatal("rejected QUIC handshake leaked resources")
			}
		})
	}
}

func TestQUICCloseInterruptsBlockedStreamWrite(t *testing.T) {
	profile, certificate, _ := testIdentity(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{dataALPN}}, &quic.Config{InitialStreamReceiveWindow: 16 << 10, MaxStreamReceiveWindow: 16 << 10, InitialConnectionReceiveWindow: 32 << 10, MaxConnectionReceiveWindow: 32 << 10})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	profile.Endpoint = listener.Addr().String()
	raw, _ := json.Marshal(profile)
	path := filepath.Join(t.TempDir(), "profile.json")
	os.WriteFile(path, raw, 0600)
	a, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: path, Transport: "quic"})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		defer connection.CloseWithError(0, "")
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			return
		}
		open, err := readFrame(stream)
		if err != nil {
			return
		}
		writeFrame(stream, frame{typ: typeOpenOK, session: open.session, flow: open.flow})
		<-ctx.Done()
	}()
	conn, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	c := conn.(*Conn)
	written := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 2<<20)); written <- err }()
	time.Sleep(20 * time.Millisecond)
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("blocked stream write unexpectedly completed")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt QUIC write")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("QUIC close exceeded its drain bound")
	}
	cancel()
	<-serverDone
}

func breakTestCarrier(c *Conn, shared bool) {
	raw := c.currentCarrier()
	if carrier, ok := raw.(*quicCarrier); ok && shared {
		carrier.connection.CloseWithError(0, "local test fault")
	} else {
		abortCarrier(raw)
	}
}

func assertTestSharedCarrier(t *testing.T, conns []*Conn) {
	t.Helper()
	first := conns[0].currentCarrier().(*quicCarrier).connection
	for _, c := range conns {
		if c.currentCarrier().(*quicCarrier).connection != first {
			t.Fatal("fault test flows do not share one connection")
		}
	}
}

func TestRecoveryRejectsExpiredQUICIdentity(t *testing.T) {
	profile, certificate, _ := testIdentityExpires(t, time.Now().Add(2*time.Second))
	o := poolTestOutboundIdentity(t, profile, certificate)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := o.pool.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := newRecoverableConn(raw, [16]byte{1}, 2, nil, context.Background(), func(ctx context.Context, s [16]byte, f, lane uint64) (net.Conn, error) {
		return o.joinFlow(ctx, M.ParseSocksaddr("example.com:443"), 0, s, f, lane)
	})
	defer c.Close()
	select {
	case <-c.done:
	case <-ctx.Done():
		t.Fatal("QUIC credential expiry did not terminate recovery")
	}
	c.mu.Lock()
	attempts, failure := c.recoveryAttempts, c.err
	c.mu.Unlock()
	var invalid identityError
	if !errors.As(failure, &invalid) || attempts != 1 {
		t.Fatalf("QUIC expiry attempts=%d error=%v", attempts, failure)
	}
}

func TestUDPResumeRejectsExpiredQUICIdentity(t *testing.T) {
	profile, certificate, _ := testIdentityExpires(t, time.Now().Add(2*time.Second))
	o := poolTestOutboundIdentity(t, profile, certificate)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := o.pool.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := newResumablePacketConn(raw, [16]byte{1}, 2, nil, context.Background(), [16]byte{1}, func(ctx context.Context, token [16]byte) (*udpReplacement, error) {
		return o.resumeUDP(ctx, M.ParseSocksaddr("example.com:53"), 0, token)
	})
	defer p.Close()
	c := p.wire
	select {
	case <-c.done:
	case <-ctx.Done():
		t.Fatal("QUIC credential expiry did not terminate recovery")
	}
	c.mu.Lock()
	attempts, failure := c.recoveryAttempts, c.err
	c.mu.Unlock()
	var invalid identityError
	if !errors.As(failure, &invalid) || attempts != 1 {
		t.Fatalf("QUIC expiry attempts=%d error=%v", attempts, failure)
	}
}
