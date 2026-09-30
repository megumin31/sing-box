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

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type testDialer struct {
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (d testDialer) DialContext(ctx context.Context, n string, dst M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx, n, dst)
}
func (d testDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("UDP dialer must not be called")
}

func TestDialCancellationAndCapacity(t *testing.T) {
	for _, phase := range []string{"TLS", "OPEN", "outbound-close"} {
		t.Run(phase, func(t *testing.T) {
			profile, certificate, chain := testIdentity(t)
			raw, _ := json.Marshal(profile)
			path := filepath.Join(t.TempDir(), "profile.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			a, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: path})
			if err != nil {
				t.Fatal(err)
			}
			o := a.(*Outbound)
			defer o.Close()
			o.slots = make(chan struct{}, 1)
			ready := make(chan struct{})
			peerDone := make(chan struct{})
			o.dialer = testDialer{dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
				if network != "tcp" || destination.String() != profile.Endpoint {
					t.Errorf("outer dial mismatch: %s %s", network, destination)
				}
				client, server := net.Pipe()
				go func() {
					defer close(peerDone)
					defer server.Close()
					if phase == "TLS" {
						close(ready)
						io.Copy(io.Discard, server)
						return
					}
					roots := x509.NewCertPool()
					roots.AddCert(chain[2])
					secure := tls.Server(server, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{dataALPN}, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots})
					if err := secure.Handshake(); err != nil {
						return
					}
					f, err := readFrame(secure)
					if err != nil || f.typ != typeOpen {
						return
					}
					close(ready)
					io.Copy(io.Discard, secure)
				}()
				return client, nil
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443")); result <- err }()
			select {
			case <-ready:
			case <-time.After(2 * time.Second):
				t.Fatal("dial did not reach test phase")
			}
			if _, err = o.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.com:443")); err == nil {
				t.Fatal("connection cap was ignored")
			}
			if phase == "outbound-close" {
				o.Close()
			} else {
				cancel()
			}
			select {
			case err = <-result:
				if phase != "outbound-close" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation error = %v", err)
				}
				if err == nil {
					t.Fatal("canceled dial succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt dial")
			}
			select {
			case <-peerDone:
			case <-time.After(time.Second):
				t.Fatal("carrier leaked")
			}
			o.mu.Lock()
			active := len(o.active)
			o.mu.Unlock()
			if active != 0 || len(o.slots) != 0 {
				t.Fatalf("resource leak: %d active, %d slots", active, len(o.slots))
			}
		})
	}
}

func TestCloseDoesNotWaitForTLSCloseNotify(t *testing.T) {
	profile, certificate, _ := testIdentity(t)
	config, err := profile.tlsConfig(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ready := make(chan error, 1)
	go func() {
		server := tls.Server(b, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{dataALPN}, Certificates: []tls.Certificate{certificate}})
		if err := server.Handshake(); err != nil {
			ready <- err
			return
		}
		f, err := readFrame(server)
		if err == nil && (f.typ != typeClose || f.flags != flagFIN|flagAbort) {
			err = io.ErrUnexpectedEOF
		}
		ready <- err
		// Intentionally leave the TLS close_notify unread.
	}()
	client := tls.Client(a, config)
	if err = client.Handshake(); err != nil {
		t.Fatal(err)
	}
	c := newConn(client, [16]byte{1}, 1, nil)
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close waited for TLS close_notify")
	}
	if err = <-ready; err != nil {
		t.Fatal(err)
	}
}
