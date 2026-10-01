package queqiao

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type roleAdmissionPool struct {
	shared, exclusive func(context.Context) (net.Conn, error)
}

func (p *roleAdmissionPool) Open(ctx context.Context) (net.Conn, error) { return p.shared(ctx) }
func (p *roleAdmissionPool) OpenExclusive(ctx context.Context) (net.Conn, error) {
	return p.exclusive(ctx)
}
func (p *roleAdmissionPool) Reset(bool) {}
func roleAdmissionOutbound(t *testing.T) (*Outbound, tls.Certificate) {
	t.Helper()
	profile, certificate, _ := testIdentity(t)
	encoded, _ := json.Marshal(profile)
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := NewOutbound(context.Background(), nil, nil, "roles", option.QueqiaoOutboundOptions{ProfilePath: path, Transport: "tcp", TCPRecovery: true})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	// The fake pool stands in for already authenticated QUIC streams. Actual
	// configuration/build-tag and TLS verification have separate tests.
	o.transport = "quic"
	o.dataIsolation = true
	o.initialFallback = true
	t.Cleanup(func() { o.Close() })
	return o, certificate
}
func TestQUICRolesWireAdmissionAndReplacement(t *testing.T) {
	o, _ := roleAdmissionOutbound(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	frames := make(chan frame, 8)
	controlPeer := make(chan net.Conn, 1)
	var sharedCalls atomic.Int32
	var peers sync.WaitGroup
	accept := func(ctx context.Context, shared bool) (net.Conn, error) {
		raw, peer := net.Pipe()
		call := int32(0)
		if shared {
			call = sharedCalls.Add(1)
		}
		peers.Add(1)
		go func() {
			defer peers.Done()
			defer peer.Close()
			f, err := readFrame(peer)
			if err != nil {
				return
			}
			frames <- f
			if writeFrame(peer, frame{typ: typeOpenOK, session: f.session, flow: f.flow}) != nil {
				return
			}
			if shared && call == 1 {
				controlPeer <- peer
			}
			io.Copy(io.Discard, peer)
		}()
		return raw, nil
	}
	o.pool = &roleAdmissionPool{shared: func(c context.Context) (net.Conn, error) { return accept(c, true) }, exclusive: func(c context.Context) (net.Conn, error) { return accept(c, false) }}
	var tcpCalls atomic.Int32
	o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		tcpCalls.Add(1)
		return nil, errors.New("unexpected TLS fallback")
	}}
	raw, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	opened, joined := <-frames, <-frames
	if opened.typ != typeOpen || opened.flags != flagReserve {
		t.Fatalf("reserved OPEN=%+v", opened)
	}
	if joined.typ != typeJoin || joined.flags != 0 || joined.sequence != 0 || len(joined.payload) != 8 || binary.BigEndian.Uint64(joined.payload) == 0 || joined.session != opened.session || joined.flow != opened.flow {
		t.Fatalf("data JOIN=%+v", joined)
	}
	(<-controlPeer).Close()
	var replacement frame
	select {
	case replacement = <-frames:
	case <-ctx.Done():
		t.Fatal("control role not restored")
	}
	if replacement.typ != typeJoin || replacement.flags != flagReserve || replacement.session != opened.session || replacement.flow != opened.flow || len(replacement.payload) != 8 || binary.BigEndian.Uint64(replacement.payload) == 0 {
		t.Fatalf("control JOIN=%+v", replacement)
	}
	raw.Close()
	o.Close()
	peers.Wait()
	if tcpCalls.Load() != 0 {
		t.Fatal("post-OPEN isolation selected TCP")
	}
}
func TestQUICRolesOptionalAdmissionAndUDP(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		udp, ok bool
	}{
		{"capacity", errQUICConnectionCapacity, false, true}, {"timeout", context.DeadlineExceeded, false, true},
		{"identity", identityError{errors.New("refused")}, false, false},
		{"masked-identity", errors.Join(errQUICConnectionCapacity, identityError{errors.New("refused")}), false, false},
		{"udp", nil, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			o, _ := roleAdmissionOutbound(t)
			var exclusive, tcp atomic.Int32
			received := make(chan frame, 1)
			done := make(chan struct{})
			o.pool = &roleAdmissionPool{shared: func(context.Context) (net.Conn, error) {
				raw, peer := net.Pipe()
				go func() {
					defer close(done)
					defer peer.Close()
					f, err := readFrame(peer)
					if err != nil {
						return
					}
					received <- f
					if writeFrame(peer, frame{typ: typeOpenOK, session: f.session, flow: f.flow}) != nil {
						return
					}
					io.Copy(io.Discard, peer)
				}()
				return raw, nil
			}, exclusive: func(context.Context) (net.Conn, error) { exclusive.Add(1); return nil, test.err }}
			o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
				tcp.Add(1)
				return nil, errors.New("unexpected fallback")
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var closer io.Closer
			var err error
			if test.udp {
				closer, err = o.ListenPacket(ctx, M.ParseSocksaddr("example.com:53"))
			} else {
				closer, err = o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
			}
			if (err == nil) != test.ok {
				t.Fatalf("admission result=%v", err)
			}
			f := <-received
			if test.udp {
				if f.flags != 0 || exclusive.Load() != 0 {
					t.Fatal("UDP acquired isolation role")
				}
			} else {
				if f.flags != flagReserve || exclusive.Load() != 1 {
					t.Fatal("TCP role admission missing")
				}
			}
			if closer != nil && err == nil {
				closer.Close()
			}
			o.Close()
			<-done
			if tcp.Load() != 0 {
				t.Fatal("isolation error selected TCP")
			}
		})
	}
}
func TestQUICRolesInitialTLSFallbackHasNoReservation(t *testing.T) {
	o, certificate := roleAdmissionOutbound(t)
	var exclusive atomic.Int32
	o.pool = &roleAdmissionPool{shared: func(context.Context) (net.Conn, error) { return nil, context.DeadlineExceeded }, exclusive: func(context.Context) (net.Conn, error) {
		exclusive.Add(1)
		return nil, errors.New("unexpected isolation")
	}}
	received := make(chan frame, 1)
	done := make(chan struct{})
	o.dialer = testDialer{dial: func(ctx context.Context, n string, _ M.Socksaddr) (net.Conn, error) {
		if n != "tcp" {
			return nil, errors.New("unexpected transport")
		}
		raw, peer := net.Pipe()
		go func() {
			defer close(done)
			defer peer.Close()
			server := tls.Server(peer, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{dataALPN}})
			f, err := readFrame(server)
			if err != nil {
				return
			}
			received <- f
			if writeFrame(server, frame{typ: typeOpenOK, session: f.session, flow: f.flow}) != nil {
				return
			}
			io.Copy(io.Discard, server)
		}()
		return raw, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	f := <-received
	if f.flags != 0 || raw.(*Conn).bundle != nil || exclusive.Load() != 0 {
		t.Fatal("initial TLS fallback retained QUIC roles")
	}
	raw.Close()
	o.Close()
	<-done
}

type roleDeadlineResponse struct {
	reader    *bytes.Reader
	deadline  time.Time
	afterRead func()
}

func (c *roleDeadlineResponse) Read(p []byte) (int, error) {
	n, e := c.reader.Read(p)
	if n > 0 && c.reader.Len() == 0 {
		if c.afterRead != nil {
			c.afterRead()
		} else {
			time.Sleep(time.Until(c.deadline))
			synctest.Wait()
		}
	}
	return n, e
}
func (c *roleDeadlineResponse) Write(p []byte) (int, error)      { return len(p), nil }
func (c *roleDeadlineResponse) Close() error                     { return nil }
func (c *roleDeadlineResponse) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *roleDeadlineResponse) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *roleDeadlineResponse) SetDeadline(time.Time) error      { return nil }
func (c *roleDeadlineResponse) SetReadDeadline(time.Time) error  { return nil }
func (c *roleDeadlineResponse) SetWriteDeadline(time.Time) error { return nil }
func TestQUICRolesParsedRefusalSurvivesDeadline(t *testing.T) {
	for _, exclusive := range []bool{false, true} {
		t.Run(map[bool]string{false: "control", true: "data"}[exclusive], func(t *testing.T) {
			for _, cancelCaller := range []bool{false, true} {
				t.Run(map[bool]string{false: "deadline", true: "cancel"}[cancelCaller], func(t *testing.T) {
					for _, code := range []byte{1, 2, 4} {
						t.Run(map[byte]string{1: "protocol", 2: "identity", 4: "capacity"}[code], func(t *testing.T) {
							synctest.Test(t, func(t *testing.T) {
								o, _ := roleAdmissionOutbound(t)
								ctx, cancel := context.WithTimeout(context.Background(), time.Second)
								defer cancel()
								var wire bytes.Buffer
								_ = writeFrame(&wire, frame{typ: typeReset, session: [16]byte{1}, flow: 2, payload: []byte{code}})
								deadline, _ := ctx.Deadline()
								poolOpen := func(context.Context) (net.Conn, error) {
									c := &roleDeadlineResponse{reader: bytes.NewReader(wire.Bytes()), deadline: deadline}
									if cancelCaller {
										c.afterRead = func() { cancel(); synctest.Wait() }
									}
									return c, nil
								}
								o.pool = &roleAdmissionPool{shared: poolOpen, exclusive: poolOpen}
								flags := flagReserve
								if exclusive {
									flags = 0
								}
								_, err := o.joinLaneOnTransport(ctx, M.ParseSocksaddr("example.com:443"), 0, [16]byte{1}, 2, 3, false, flags, exclusive)
								if cancelCaller {
									if !errors.Is(err, context.Canceled) || isolationMayDegrade(err) {
										t.Fatalf("explicit cancellation was not terminal: %v", err)
									}
								} else if code == 4 {
									if !errors.Is(err, context.DeadlineExceeded) {
										t.Fatalf("capacity deadline=%v", err)
									}
								} else {
									var refusal gatewayResetError
									if !errors.As(err, &refusal) || refusal.code != code || isolationMayDegrade(err) {
										t.Fatalf("parsed terminal refusal masked by deadline: %v", err)
									}
								}
							})
						})
					}
				})
			}
		})
	}
}
