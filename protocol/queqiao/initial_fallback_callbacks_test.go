package queqiao

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
)

// Exercise callbacks captured by the actual public outbound entry points. The
// callbacks are invoked directly while the initial flow stays live, so this
// tests their transport/identity wiring, not the automatic outage replay loop.
func TestInitialFallbackSelectedTLSCallbacks(t *testing.T) {
	for _, udp := range []bool{false, true} {
		name := "JOIN"
		if udp {
			name = "UDP-resume"
		}
		t.Run(name, func(t *testing.T) {
			profile, certificate, chain := testIdentity(t)
			config, err := profile.tlsConfig(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			var verifiedClient, verifiedServer atomic.Int32
			verify := config.VerifyConnection
			config.VerifyConnection = func(s tls.ConnectionState) error {
				if err := verify(s); err != nil {
					return err
				}
				verifiedClient.Add(1)
				return nil
			}
			roots := x509.NewCertPool()
			roots.AddCert(chain[2])
			serverConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{dataALPN}, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
				VerifyConnection: func(s tls.ConnectionState) error {
					want := "queqiao://" + profile.ProviderID + "/account/" + profile.AccountID + "/device/" + profile.DeviceID
					if s.NegotiatedProtocol != dataALPN || len(s.PeerCertificates) == 0 || len(s.PeerCertificates[0].URIs) != 1 || s.PeerCertificates[0].URIs[0].String() != want {
						return errors.New("wrong recovery device")
					}
					verifiedServer.Add(1)
					return nil
				}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			o := fallbackTestOutbound()
			o.ctx = ctx
			o.tlsConfig = config
			o.server = M.ParseSocksaddr(profile.Endpoint)
			o.Adapter = outbound.NewAdapter("queqiao", "test", []string{"tcp", "udp"}, nil)
			o.tcpRecovery = !udp
			o.udpResume = udp
			var quicCalls, tcpCalls atomic.Int32
			o.pool = fallbackPoolFunc(func(context.Context) (net.Conn, error) { quicCalls.Add(1); return nil, syscall.ECONNREFUSED })
			initialFrames := make(chan frame, 1)
			serverDone := make(chan error, 2)
			var initial frame
			token1, token2 := [16]byte{1}, [16]byte{2}
			payload := []byte("selected TLS callback data")
			if udp {
				payload, err = encodePacket("127.0.0.1:53", payload)
				if err != nil {
					t.Fatal(err)
				}
			}
			o.dialer = testDialer{dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
				attempt := tcpCalls.Add(1)
				if attempt > 2 || network != "tcp" || destination != o.server {
					return nil, errors.New("unexpected replacement dial")
				}
				client, peer := net.Pipe()
				t.Cleanup(func() { client.Close(); peer.Close() })
				deadline, _ := ctx.Deadline()
				client.SetDeadline(deadline)
				peer.SetDeadline(deadline)
				go func() {
					defer peer.Close()
					secure := tls.Server(peer, serverConfig)
					if err := secure.HandshakeContext(ctx); err != nil {
						serverDone <- err
						return
					}
					f, err := readFrame(secure)
					if err != nil {
						serverDone <- err
						return
					}
					ack := frame{typ: typeOpenOK, session: f.session, flow: f.flow}
					if attempt == 1 {
						if f.typ != typeOpen {
							serverDone <- errors.New("initial request was not OPEN")
							return
						}
						if udp {
							if !bytes.Equal(f.payload, []byte("WOUD\x02")) {
								serverDone <- errors.New("initial UDP version mismatch")
								return
							}
							ack.payload = append([]byte{0}, token1[:]...)
						} else if string(f.payload) != "example.com:443" {
							serverDone <- errors.New("initial destination mismatch")
							return
						}
						initialFrames <- f
					} else if udp {
						want := append([]byte("WOUD\x02"), token1[:]...)
						if f.typ != typeOpen || !bytes.Equal(f.payload, want) || f.session == initial.session || f.flow == initial.flow {
							serverDone <- errors.New("resume token or fresh identity mismatch")
							return
						}
						ack.payload = append([]byte{1}, token2[:]...)
					} else if f.typ != typeJoin || f.session != initial.session || f.flow != initial.flow || len(f.payload) != 8 || binary.BigEndian.Uint64(f.payload) != 9 {
						serverDone <- errors.New("JOIN changed logical identity or lane")
						return
					}
					if err := writeFrame(secure, ack); err != nil {
						serverDone <- err
						return
					}
					if attempt == 1 {
						for {
							closing, err := readFrame(secure)
							if err != nil {
								serverDone <- err
								return
							}
							if closing.typ == typeClose {
								if udp {
									err = writeFrame(secure, frame{typ: typeACK, flags: flagACKFinal, session: f.session, flow: f.flow})
								}
								serverDone <- err
								return
							}
						}
					}
					data, err := readFrame(secure)
					if err != nil {
						serverDone <- err
						return
					}
					wantType := typeData
					if udp {
						wantType = typePacket
					}
					if data.typ != wantType || data.session != f.session || data.flow != f.flow || !bytes.Equal(data.payload, payload) {
						serverDone <- errors.New("replacement payload or identity mismatch")
						return
					}
					serverDone <- writeFrame(secure, data)
				}()
				return client, nil
			}}
			var replacement net.Conn
			var session [16]byte
			var flow uint64
			var closeOriginal func() error
			if udp {
				raw, err := o.ListenPacket(ctx, M.ParseSocksaddr("127.0.0.1:53"))
				if err != nil {
					t.Fatal(err)
				}
				p := raw.(*packetConn)
				closeOriginal = p.Close
				defer p.Close()
				initial = <-initialFrames
				p.wire.mu.Lock()
				token := p.token
				p.wire.mu.Unlock()
				r, err := p.resume(ctx, token)
				if err != nil {
					t.Fatal(err)
				}
				if r.token != token2 {
					t.Fatal("resume did not rotate token")
				}
				replacement, session, flow = r.conn, r.session, r.flow
			} else {
				raw, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
				if err != nil {
					t.Fatal(err)
				}
				c := raw.(*Conn)
				closeOriginal = c.Close
				defer c.Close()
				initial = <-initialFrames
				replacement, err = c.join(ctx, c.session, c.flow, 9)
				if err != nil {
					t.Fatal(err)
				}
				session, flow = c.session, c.flow
			}
			defer closeCarrier(replacement)
			if _, ok := replacement.(*tls.Conn); !ok {
				t.Fatal("captured callback lost the selected TLS carrier")
			}
			typ := typeData
			if udp {
				typ = typePacket
			}
			if err := writeFrame(replacement, frame{typ: typ, session: session, flow: flow, payload: payload}); err != nil {
				t.Fatal(err)
			}
			echo, err := readFrame(replacement)
			if err != nil || echo.typ != typ || echo.session != session || echo.flow != flow || !bytes.Equal(echo.payload, payload) {
				t.Fatalf("callback carrier echo: %v", err)
			}
			closeCarrier(replacement)
			if err := closeOriginal(); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				select {
				case err := <-serverDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("in-memory callback peer did not finish")
				}
			}
			if quicCalls.Load() != 1 || tcpCalls.Load() != 2 || verifiedClient.Load() != 2 || verifiedServer.Load() != 2 {
				t.Fatal("callback retried QUIC or skipped mutual authentication")
			}
			// done precedes onClose's resource release. Observe normal
			// quiescence without clearing state or forcing outbound cleanup.
			deadline := time.Now().Add(time.Second)
			for {
				o.mu.Lock()
				active := len(o.active)
				o.mu.Unlock()
				if active == 0 && len(o.slots) == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("callback test left an initial flow resource")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
