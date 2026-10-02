package queqiao

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type fallbackPoolFunc func(context.Context) (net.Conn, error)

func (f fallbackPoolFunc) Open(ctx context.Context) (net.Conn, error) { return f(ctx) }
func (fallbackPoolFunc) Reset(bool)                                   {}

// A byte sink with no sockets, listeners, certificates or credentials.
type fallbackMemoryConn struct {
	mu         sync.Mutex
	written    bytes.Buffer
	closed     bool
	writeError error
}

func (c *fallbackMemoryConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *fallbackMemoryConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written.Write(p)
	if c.writeError != nil {
		return 0, c.writeError
	}
	return len(p), nil
}
func (c *fallbackMemoryConn) Close() error                   { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (*fallbackMemoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*fallbackMemoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*fallbackMemoryConn) SetDeadline(time.Time) error      { return nil }
func (*fallbackMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*fallbackMemoryConn) SetWriteDeadline(time.Time) error { return nil }

func fallbackTestOutbound() *Outbound {
	return &Outbound{ctx: context.Background(), initialFallback: true,
		server: M.ParseSocksaddr("127.0.0.1:443"), active: make(map[net.Conn]io.Closer), slots: make(chan struct{}, 256)}
}

func TestInitialFallbackErrorAdmission(t *testing.T) {
	for _, v := range []struct {
		name    string
		err     error
		allowed bool
	}{
		{"timeout", context.DeadlineExceeded, true},
		{"refused", &net.OpError{Op: "dial", Net: "udp", Err: syscall.ECONNREFUSED}, true},
		{"unreachable", syscall.ENETUNREACH, true},
		{"reset", syscall.ECONNRESET, true},
		{"unknown", errors.New("unknown failure"), false},
		{"pool-capacity", errors.New("queqiao: QUIC pool capacity reached"), false},
		{"stream-credit-timeout", quicStreamOpenError{context.DeadlineExceeded}, false},
		{"closed", net.ErrClosed, false},
		{"canceled", context.Canceled, false},
		{"permissions", syscall.EACCES, false},
		{"identity", identityError{context.DeadlineExceeded}, false},
		{"protocol", protocolError{context.DeadlineExceeded}, false},
		{"gateway-capacity", errors.Join(gatewayResetError{code: 4}, context.DeadlineExceeded), false},
		{"certificate", errors.Join(&tls.CertificateVerificationError{}, context.DeadlineExceeded), false},
		{"invalid-certificate", errors.Join(x509.CertificateInvalidError{}, context.DeadlineExceeded), false},
		{"unknown-root", errors.Join(x509.UnknownAuthorityError{}, context.DeadlineExceeded), false},
		{"hostname", errors.Join(x509.HostnameError{}, context.DeadlineExceeded), false},
		{"permission-and-timeout", errors.Join(syscall.EPERM, context.DeadlineExceeded), false},
	} {
		t.Run(v.name, func(t *testing.T) {
			if got := initialFallbackAllowed(v.err); got != v.allowed {
				t.Fatalf("allowed=%v, want %v", got, v.allowed)
			}
		})
	}
}

func TestInitialFallbackSelection(t *testing.T) {
	for _, v := range []struct {
		name    string
		enabled bool
		quicErr error
		wantTCP bool
	}{
		{"QUIC-success", true, nil, false},
		{"enabled-refused", true, syscall.ECONNREFUSED, true},
		{"disabled-refused", false, syscall.ECONNREFUSED, false},
		{"identity-rejected", true, identityError{errors.New("identity")}, false},
		{"pool-full", true, errors.New("capacity"), false},
	} {
		t.Run(v.name, func(t *testing.T) {
			o := fallbackTestOutbound()
			o.initialFallback = v.enabled
			quicCalls, tcpCalls := 0, 0
			qc, tc := new(fallbackMemoryConn), new(fallbackMemoryConn)
			o.pool = fallbackPoolFunc(func(context.Context) (net.Conn, error) {
				quicCalls++
				if v.quicErr != nil {
					return nil, v.quicErr
				}
				return qc, nil
			})
			o.dialer = testDialer{dial: func(ctx context.Context, n string, d M.Socksaddr) (net.Conn, error) {
				tcpCalls++
				if n != "tcp" || d != o.server {
					t.Fatal("wrong fallback endpoint/network")
				}
				return tc, nil
			}}
			raw, tcp, err := o.dialInitialCarrier(context.Background(), 0)
			if quicCalls != 1 || (tcpCalls == 1) != v.wantTCP || tcp != v.wantTCP {
				t.Fatalf("selection: QUIC=%d TCP=%d tcp=%v", quicCalls, tcpCalls, tcp)
			}
			if v.wantTCP {
				if err != nil || raw != tc {
					t.Fatalf("fallback result: %v", err)
				}
			} else if v.quicErr == nil {
				if err != nil || raw != qc {
					t.Fatal("QUIC result")
				}
			} else if !errors.Is(err, v.quicErr) || raw != nil {
				t.Fatal("original refusal lost")
			}
		})
	}
}

func TestInitialFallbackBudgets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o := fallbackTestOutbound()
		start := time.Now()
		calls := 0
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		o.pool = fallbackPoolFunc(func(ctx context.Context) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() })
		o.dialer = testDialer{dial: func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
			calls++
			if time.Since(start) != 5*time.Second {
				t.Fatal("QUIC attempt did not end at 5s")
			}
			d, _ := ctx.Deadline()
			if d.Sub(time.Now()) != 10*time.Second {
				t.Fatal("total deadline changed")
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		_, _, err := o.dialInitialCarrier(ctx, 0)
		if !errors.Is(err, context.DeadlineExceeded) || calls != 1 || time.Since(start) != 15*time.Second {
			t.Fatalf("budget: calls=%d elapsed=%v err=%v", calls, time.Since(start), err)
		}
	})
	for _, budget := range []time.Duration{time.Second, 5 * time.Second} {
		synctest.Test(t, func(t *testing.T) {
			o := fallbackTestOutbound()
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			o.pool = fallbackPoolFunc(func(ctx context.Context) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() })
			o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
				t.Fatal("fallback after caller deadline")
				return nil, nil
			}}
			_, _, err := o.dialInitialCarrier(ctx, 0)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
		})
	}
}

func TestInitialFallbackCancellationAndGeneration(t *testing.T) {
	for _, mode := range []string{"caller", "owner", "interface", "closed"} {
		t.Run(mode, func(t *testing.T) {
			o := fallbackTestOutbound()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owner, stop := context.WithCancel(context.Background())
			defer stop()
			o.ctx = owner
			o.pool = fallbackPoolFunc(func(context.Context) (net.Conn, error) {
				switch mode {
				case "caller":
					cancel()
				case "owner":
					stop()
				case "interface":
					o.generation++
				case "closed":
					o.closed = true
				}
				return nil, syscall.ECONNREFUSED
			})
			o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
				t.Fatal("fallback after cancellation/change")
				return nil, nil
			}}
			if _, _, err := o.dialInitialCarrier(ctx, 0); err == nil {
				t.Fatal("missing cancellation error")
			}
		})
	}
}

func TestInitialFallbackNoRetryAfterOPEN(t *testing.T) {
	o := fallbackTestOutbound()
	raw := new(fallbackMemoryConn)
	calls := 0
	o.pool = fallbackPoolFunc(func(context.Context) (net.Conn, error) { calls++; return raw, nil })
	o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		t.Fatal("fallback after OPEN")
		return nil, nil
	}}
	if _, err := o.openFlow(context.Background(), []byte("example.com:443"), M.ParseSocksaddr("example.com:443")); err == nil {
		t.Fatal("EOF must fail OPEN")
	}
	if calls != 1 || !raw.closed || len(o.active) != 0 || len(o.slots) != 0 {
		t.Fatal("failed OPEN leaked resources")
	}
	f, err := readFrame(bytes.NewReader(raw.written.Bytes()))
	if err != nil || f.typ != typeOpen {
		t.Fatal("expected one OPEN")
	}
}

func TestInitialFallbackStillRequiresTLS(t *testing.T) {
	o := fallbackTestOutbound()
	raw := &fallbackMemoryConn{writeError: errors.New("stop after ClientHello")}
	calls := 0
	o.tlsConfig = &tls.Config{ServerName: "example.invalid", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{dataALPN}}
	o.pool = fallbackPoolFunc(func(context.Context) (net.Conn, error) { return nil, syscall.ECONNREFUSED })
	o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { calls++; return raw, nil }}
	if _, err := o.openFlow(context.Background(), []byte("example.com:443"), M.ParseSocksaddr("example.com:443")); err == nil {
		t.Fatal("failed TLS must fail OPEN")
	}
	b := raw.written.Bytes()
	if len(b) < 5 || b[0] != 22 {
		t.Fatal("fallback did not start TLS handshake")
	}
	if calls != 1 || !raw.closed || len(o.active) != 0 || len(o.slots) != 0 {
		t.Fatal("TLS failure leaked resources or retried")
	}
}

func TestInitialFallbackConfigRequiresQUIC(t *testing.T) {
	for _, transport := range []string{"", "tcp", "invalid"} {
		_, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: "unused", Transport: transport, QUICInitialFallback: true})
		if err == nil || err.Error() != "queqiao: quic_initial_fallback requires transport quic" {
			t.Fatalf("transport %q: %v", transport, err)
		}
	}
}

func TestInitialFallbackRecoveryRetainsTransport(t *testing.T) {
	for _, useTCP := range []bool{false, true} {
		o := fallbackTestOutbound()
		quicCalls, tcpCalls := 0, 0
		o.pool = fallbackPoolFunc(func(context.Context) (net.Conn, error) { quicCalls++; return nil, syscall.ECONNREFUSED })
		o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			tcpCalls++
			return nil, syscall.ECONNREFUSED
		}}
		_, err := o.dialFixedCarrier(context.Background(), useTCP)
		if !errors.Is(err, syscall.ECONNREFUSED) || (tcpCalls == 1) != useTCP || (quicCalls == 1) == useTCP {
			t.Fatalf("recovery changed transport: tcp=%d quic=%d", tcpCalls, quicCalls)
		}
	}
}

func TestRecoveryCanceledContextDoesNotDial(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		o := fallbackTestOutbound()
		o.pool = fallbackPoolFunc(func(context.Context) (net.Conn, error) {
			t.Fatal("canceled recovery opened QUIC")
			return nil, nil
		})
		o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			t.Fatal("canceled recovery opened TCP")
			return nil, nil
		}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if raw, err := o.dialFixedCarrier(ctx, tcp); raw != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled recovery result: %v", err)
		}
	}
}

func TestInitialFallbackBothErrors(t *testing.T) {
	o := fallbackTestOutbound()
	quicErr, tcpErr := syscall.ECONNREFUSED, syscall.EHOSTUNREACH
	calls := 0
	o.pool = fallbackPoolFunc(func(context.Context) (net.Conn, error) { return nil, quicErr })
	o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { calls++; return nil, tcpErr }}
	raw, _, err := o.dialInitialCarrier(context.Background(), 0)
	if raw != nil || calls != 1 || !errors.Is(err, quicErr) || !errors.Is(err, tcpErr) {
		t.Fatal("lost either cause or retried TCP")
	}
}

func TestInitialFallbackDisabledPreservesQUICBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o := fallbackTestOutbound()
		o.initialFallback = false
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		o.pool = fallbackPoolFunc(func(ctx context.Context) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() })
		o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			t.Fatal("fallback disabled")
			return nil, nil
		}}
		_, _, err := o.dialInitialCarrier(ctx, 0)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 15*time.Second {
			t.Fatalf("disabled budget: %v %v", time.Since(start), err)
		}
	})
}

func TestInitialFallbackExplicitTCP(t *testing.T) {
	o := fallbackTestOutbound()
	o.initialFallback = false
	raw := new(fallbackMemoryConn)
	calls := 0
	o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) { calls++; return raw, nil }}
	got, tcp, err := o.dialInitialCarrier(context.Background(), 0)
	if got != raw || !tcp || err != nil || calls != 1 {
		t.Fatal("explicit TCP behavior changed")
	}
}
