//go:build with_quic

package queqiao

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
)

// These are localhost protocol peers, not official-gateway interoperability
// tests. Identities live only in memory. No profile or key is written to disk.
func fallbackLoopbackConfigs(t *testing.T) (*tls.Config, *tls.Config, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	profile, certificate, chain := testIdentity(t)
	client, err := profile.tlsConfig(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cv, sv := new(atomic.Int32), new(atomic.Int32)
	verify := client.VerifyConnection
	client.VerifyConnection = func(s tls.ConnectionState) error {
		if err := verify(s); err != nil {
			return err
		}
		cv.Add(1)
		return nil
	}
	roots := x509.NewCertPool()
	roots.AddCert(chain[2])
	server := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{dataALPN}, Certificates: []tls.Certificate{certificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
		VerifyConnection: func(s tls.ConnectionState) error {
			want := "queqiao://" + profile.ProviderID + "/account/" + profile.AccountID + "/device/" + profile.DeviceID
			if s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != dataALPN || len(s.PeerCertificates) == 0 || len(s.PeerCertificates[0].URIs) != 1 || s.PeerCertificates[0].URIs[0].String() != want {
				return errors.New("loopback peer rejected device identity or TLS negotiation")
			}
			sv.Add(1)
			return nil
		}}
	return client, server, cv, sv
}

func fallbackLoopbackOutbound(ctx context.Context, client *tls.Config, address string, udpCalls, tcpCalls *atomic.Int32) *Outbound {
	o := fallbackTestOutbound()
	o.ctx, o.cancel = context.WithCancel(ctx)
	o.tlsConfig, o.server = client, M.ParseSocksaddr(address)
	o.Adapter = outbound.NewAdapter("queqiao", "loopback", []string{"tcp", "udp"}, nil)
	o.dialer = testDialer{dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if destination != o.server {
			return nil, errors.New("unexpected loopback destination")
		}
		switch network {
		case "udp":
			udpCalls.Add(1)
		case "tcp":
			tcpCalls.Add(1)
		default:
			return nil, errors.New("unexpected network")
		}
		return (&net.Dialer{}).DialContext(ctx, network+"4", address)
	}}
	o.pool = newQUICPool(o)
	return o
}

func fallbackWaitPeer(t *testing.T, ctx context.Context, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("loopback peer did not finish:", ctx.Err())
	}
}

func TestInitialFallbackLoopbackRecovery(t *testing.T) {
	for _, udp := range []bool{false, true} {
		name := "TCP-JOIN"
		if udp {
			name = "UDP-resume"
		}
		t.Run(name, func(t *testing.T) {
			clientConfig, serverConfig, cv, sv := fallbackLoopbackConfigs(t)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			// Keep the same numeric UDP port bound while consuming (and dropping) QUIC
			// Initial packets. This exercises the real QUIC dial/timeout path, without
			// relying on an OS-specific ICMP error or changing the production timeout.
			sink, err := net.ListenPacket("udp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			var packets, udpCalls, tcpCalls atomic.Int32
			sinkDone := make(chan struct{})
			go func() {
				defer close(sinkDone)
				b := make([]byte, 2048)
				for {
					if _, _, err := sink.ReadFrom(b); err != nil {
						return
					}
					packets.Add(1)
				}
			}()
			t.Cleanup(func() { sink.Close(); <-sinkDone })
			stopListener := context.AfterFunc(ctx, func() { listener.Close() })
			defer stopListener()
			o := fallbackLoopbackOutbound(ctx, clientConfig, listener.Addr().String(), &udpCalls, &tcpCalls)
			defer o.Close()
			o.tcpRecovery, o.udpResume = !udp, udp
			cut, resumed := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			before, after := []byte("before interruption"), []byte("after automatic recovery")
			peerExited := make(chan struct{})
			go func() {
				defer close(peerExited)
				done <- fallbackRecoveryPeer(ctx, listener, serverConfig, udp, before, after, cut, resumed)
			}()
			t.Cleanup(func() { cancel(); listener.Close(); <-peerExited })
			deadline, _ := ctx.Deadline()
			destination := M.ParseSocksaddr("127.0.0.1:53")
			if udp {
				raw, err := o.ListenPacket(ctx, destination)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				raw.SetDeadline(deadline)
				addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
				if _, err = raw.WriteTo(before, addr); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 128)
				n, source, err := raw.ReadFrom(b)
				if err != nil || !bytes.Equal(b[:n], before) || source.String() != addr.String() {
					t.Fatalf("initial packet: %q %v %v", b[:n], source, err)
				}
				close(cut)
				select {
				case <-resumed:
				case <-ctx.Done():
					t.Fatal("automatic UDP resume did not arrive")
				}
				if _, err = raw.WriteTo(after, addr); err != nil {
					t.Fatal(err)
				}
				n, source, err = raw.ReadFrom(b)
				if err != nil || !bytes.Equal(b[:n], after) || source.String() != addr.String() {
					t.Fatalf("resumed packet: %q %v %v", b[:n], source, err)
				}
				p := raw.(*packetConn)
				p.wire.mu.Lock()
				attempts, token := p.wire.recoveryAttempts, p.token
				p.wire.mu.Unlock()
				if attempts != 1 || token != ([16]byte{2}) {
					t.Fatalf("resume state: attempts=%d token=%x", attempts, token)
				}
				if err = raw.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				raw, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				raw.SetDeadline(deadline)
				c := raw.(*Conn)
				if _, ok := c.currentCarrier().(*tls.Conn); !ok {
					t.Fatal("initial carrier is not TLS")
				}
				if _, err = c.Write(before); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, len(before))
				if _, err = io.ReadFull(c, b); err != nil || !bytes.Equal(b, before) {
					t.Fatalf("initial data: %q %v", b, err)
				}
				close(cut)
				select {
				case <-resumed:
				case <-ctx.Done():
					t.Fatal("automatic JOIN did not arrive")
				}
				if _, err = c.Write(after); err != nil {
					t.Fatal(err)
				}
				b = make([]byte, len(after))
				if _, err = io.ReadFull(c, b); err != nil || !bytes.Equal(b, after) {
					t.Fatalf("recovered data duplicated or corrupt: %q %v", b, err)
				}
				if err = c.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				rest, err := io.ReadAll(c)
				if err != nil || len(rest) != 0 {
					t.Fatalf("recovered FIN or duplicate delivery: %q %v", rest, err)
				}
				select {
				case <-c.done:
				case <-ctx.Done():
					t.Fatal("final ACK did not complete")
				}
				c.mu.Lock()
				attempts, retained := c.recoveryAttempts, len(c.replay)
				c.mu.Unlock()
				if attempts != 1 || retained != 0 {
					t.Fatalf("JOIN state: attempts=%d replay=%d", attempts, retained)
				}
			}
			fallbackWaitPeer(t, ctx, done)
			if udpCalls.Load() != 1 || tcpCalls.Load() != 2 || cv.Load() != 2 || sv.Load() != 2 || packets.Load() == 0 {
				t.Fatalf("actual handshakes/dials: UDP=%d TCP=%d verified=%d/%d QUIC packets=%d", udpCalls.Load(), tcpCalls.Load(), cv.Load(), sv.Load(), packets.Load())
			}
			// terminate closes the flow's done channel before its raw-socket close
			// and onClose resource release. Wait for that normal release, before
			// forcing outbound shutdown; an actual leak must still fail boundedly.
			quiescence := time.NewTimer(time.Second)
			defer quiescence.Stop()
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				o.mu.Lock()
				active := len(o.active)
				o.mu.Unlock()
				if active == 0 && len(o.slots) == 0 {
					break
				}
				select {
				case <-tick.C:
				case <-quiescence.C:
					t.Fatalf("normal flow cleanup did not finish: active=%d slots=%d", active, len(o.slots))
				}
			}
			o.Close()
			o.mu.Lock()
			active := len(o.active)
			o.mu.Unlock()
			pool := o.pool.(*quicPool)
			pool.mu.Lock()
			entries := len(pool.entries)
			pool.mu.Unlock()
			if active != 0 || len(o.slots) != 0 || entries != 0 {
				t.Fatalf("cleanup: active=%d slots=%d entries=%d", active, len(o.slots), entries)
			}
		})
	}
}

func fallbackRecoveryPeer(ctx context.Context, listener net.Listener, config *tls.Config, udp bool, before, after []byte, cut <-chan struct{}, resumed chan<- struct{}) error {
	var first frame
	for attempt := 0; attempt < 2; attempt++ {
		raw, err := listener.Accept()
		if err != nil {
			return err
		}
		defer raw.Close()
		stopRaw := context.AfterFunc(ctx, func() { raw.Close() })
		defer stopRaw()
		deadline, _ := ctx.Deadline()
		raw.SetDeadline(deadline)
		secure := tls.Server(raw, config)
		if err = secure.HandshakeContext(ctx); err != nil {
			return err
		}
		request, err := readFrame(secure)
		if err != nil {
			return err
		}
		ack := frame{typ: typeOpenOK, session: request.session, flow: request.flow}
		if attempt == 0 {
			if request.typ != typeOpen {
				return errors.New("initial request not OPEN")
			}
			if udp {
				if !bytes.Equal(request.payload, []byte("WOUD\x02")) {
					return errors.New("wrong UDP OPEN")
				}
				ack.payload = append([]byte{0}, make([]byte, 16)...)
				ack.payload[1] = 1
			} else if string(request.payload) != "example.com:443" {
				return errors.New("wrong TCP target")
			}
			first = request
		} else if udp {
			want := append([]byte("WOUD\x02"), make([]byte, 16)...)
			want[5] = 1
			if request.typ != typeOpen || !bytes.Equal(request.payload, want) || request.session == first.session || request.flow == first.flow {
				return errors.New("resume lost token or reused IDs")
			}
			ack.payload = append([]byte{1}, make([]byte, 16)...)
			ack.payload[1] = 2
		} else if request.typ != typeJoin || request.session != first.session || request.flow != first.flow || len(request.payload) != 8 || binary.BigEndian.Uint64(request.payload) == 0 {
			return errors.New("automatic JOIN lost identity or lane")
		}
		if err = writeFrame(secure, ack); err != nil {
			return err
		}
		send := func(f frame) error { f.session, f.flow = request.session, request.flow; return writeFrame(secure, f) }
		if attempt == 0 {
			f, err := readFrame(secure)
			if err != nil {
				return err
			}
			expectedType := typeData
			if udp {
				expectedType = typePacket
			}
			if f.typ != expectedType || f.sequence != 0 || f.session != request.session || f.flow != request.flow {
				return errors.New("bad initial application frame")
			}
			payload := f.payload
			if udp {
				var address string
				address, payload, err = decodePacket(payload)
				if err != nil || address != "127.0.0.1:53" {
					return errors.New("bad initial packet address")
				}
			}
			if !bytes.Equal(payload, before) {
				return errors.New("bad initial application bytes")
			}
			if err = send(f); err != nil {
				return err
			}
			select {
			case <-cut:
			case <-ctx.Done():
				return ctx.Err()
			}
			// Do not acknowledge TCP DATA: the automatic JOIN must replay it. Drop the
			// physical socket, without invoking any client recovery callback directly.
			raw.Close()
			continue
		}
		if !udp {
			down, err := readFrame(secure)
			if err != nil {
				return err
			}
			if down.typ != typeACK || down.flags != flagACKDown || down.sequence != uint64(len(before)) || down.session != request.session || down.flow != request.flow {
				return fmt.Errorf("missing automatic downstream progress: %+v", down)
			}
			replay, err := readFrame(secure)
			if err != nil {
				return err
			}
			if replay.typ != typeData || replay.flags != 0 || replay.sequence != 0 || replay.session != request.session || replay.flow != request.flow || !bytes.Equal(replay.payload, before) {
				return errors.New("unacknowledged DATA not replayed correctly")
			}
			if err = send(frame{typ: typeACK, flags: flagACKUp, sequence: uint64(len(before))}); err != nil {
				return err
			}
			// Replay downstream too. The application must see no duplicated bytes.
			if err = send(replay); err != nil {
				return err
			}
		}
		close(resumed)
		sawAfter := false
		for {
			f, err := readFrame(secure)
			if err != nil {
				return err
			}
			if f.session != request.session || f.flow != request.flow {
				return errors.New("replacement frame identity mismatch")
			}
			switch f.typ {
			case typeACK:
				if udp || f.flags&flagACKDown == 0 {
					return errors.New("unexpected acknowledgement")
				}
				if f.flags&flagACKFinal != 0 {
					if !sawAfter || f.sequence != uint64(len(before)+len(after)) {
						return errors.New("wrong final acknowledgement")
					}
					return nil
				}
			case typeData, typePacket:
				if sawAfter {
					return errors.New("application data unexpectedly replayed twice")
				}
				payload := f.payload
				if udp {
					address, b, err := decodePacket(payload)
					if err != nil || address != "127.0.0.1:53" || f.typ != typePacket || f.sequence != 0 {
						return errors.New("bad resumed packet/address/sequence")
					}
					payload = b
				} else if f.typ != typeData || f.sequence != uint64(len(before)) {
					return errors.New("bad post-JOIN data offset")
				}
				if !bytes.Equal(payload, after) {
					return errors.New("old payload duplicated on replacement")
				}
				sawAfter = true
				if !udp {
					if err = send(frame{typ: typeACK, flags: flagACKUp, sequence: uint64(len(before) + len(after))}); err != nil {
						return err
					}
				}
				if err = send(f); err != nil {
					return err
				}
			case typeClose:
				if !sawAfter || f.flags != flagFIN {
					return errors.New("unexpected close before post-recovery data")
				}
				if udp {
					return send(frame{typ: typeACK, flags: flagACKFinal})
				}
				final := uint64(len(before) + len(after))
				if f.sequence != final {
					return errors.New("wrong client final offset")
				}
				if err = send(frame{typ: typeACK, flags: flagACKUp | flagACKFinal, sequence: final}); err != nil {
					return err
				}
				if err = send(frame{typ: typeClose, flags: flagFIN, sequence: final}); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unexpected replacement frame %d", f.typ)
			}
		}
	}
	return errors.New("replacement did not complete")
}

func TestInitialFallbackLoopbackQUICRefusal(t *testing.T) {
	for _, mode := range []string{"identity", "ALPN"} {
		t.Run(mode, func(t *testing.T) {
			client, server, _, _ := fallbackLoopbackConfigs(t)
			if mode == "identity" {
				_, other, _, _ := fallbackLoopbackConfigs(t)
				server.Certificates = other.Certificates
			} else {
				server.NextProtos = []string{"different-protocol/1"}
			}
			listener, err := quic.ListenAddr("127.0.0.1:0", server, &quic.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var udpCalls, tcpCalls atomic.Int32
			o := fallbackLoopbackOutbound(ctx, client, listener.Addr().String(), &udpCalls, &tcpCalls)
			defer o.Close()
			raw, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
			if raw != nil {
				raw.Close()
				t.Fatal("invalid QUIC peer accepted")
			}
			if err == nil || errors.Is(err, context.DeadlineExceeded) || initialFallbackAllowed(err) {
				t.Fatalf("refusal not preserved: %v", err)
			}
			if udpCalls.Load() != 1 || tcpCalls.Load() != 0 {
				t.Fatalf("refusal triggered fallback: UDP=%d TCP=%d", udpCalls.Load(), tcpCalls.Load())
			}
		})
	}
}
