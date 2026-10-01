package queqiao

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// TCP permits both TLS peers to write at once. Give net.Pipe a bounded client
// write queue for the negative TLS 1.3 case where the peer sends an alert while
// the client sends Finished. No operating-system socket is created.
type fallbackBufferedPipe struct {
	net.Conn
	queue      chan []byte
	done       chan struct{}
	writerDone chan struct{}
	once       sync.Once
}

func newFallbackBufferedPipe(raw net.Conn) *fallbackBufferedPipe {
	c := &fallbackBufferedPipe{Conn: raw, queue: make(chan []byte, 8), done: make(chan struct{}), writerDone: make(chan struct{})}
	go func() {
		defer close(c.writerDone)
		for {
			select {
			case <-c.done:
				return
			case p := <-c.queue:
				if _, err := raw.Write(p); err != nil {
					c.Close()
					return
				}
			}
		}
	}()
	return c
}

func (c *fallbackBufferedPipe) Write(p []byte) (int, error) {
	if len(p) > 64<<10 {
		return 0, errors.New("test write queue record exceeds 64 KiB")
	}
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	copyOfP := append([]byte(nil), p...)
	select {
	case <-c.done:
		return 0, net.ErrClosed
	case c.queue <- copyOfP:
		return len(p), nil
	}
}

func (c *fallbackBufferedPipe) Close() error {
	c.once.Do(func() { close(c.done); c.Conn.Close() })
	return nil
}

// Reuse the repository's existing in-memory identity fixture. Nothing is
// enrolled, saved to disk or sent over a socket: both peers use net.Pipe.
func TestInitialFallbackAuthenticatedPipe(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-gateway", "wrong-root", "wrong-ALPN", "missing-client-certificate"} {
		t.Run(mode, func(t *testing.T) {
			profile, certificate, chain := testIdentity(t)
			clientProfile := profile
			if mode == "wrong-gateway" {
				clientProfile.GatewayID = "44444444444444444444444444444444"
			}
			config, err := clientProfile.tlsConfig(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing-client-certificate" {
				config.Certificates = nil
			}
			var clientVerified atomic.Int32
			verify := config.VerifyConnection
			config.VerifyConnection = func(state tls.ConnectionState) error {
				if err := verify(state); err != nil {
					return err
				}
				clientVerified.Add(1)
				return nil
			}
			if mode == "wrong-root" {
				_, certificate, _ = testIdentity(t)
			}
			roots := x509.NewCertPool()
			roots.AddCert(chain[2])
			var serverVerified atomic.Int32
			serverConfig := &tls.Config{
				MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
				NextProtos: []string{dataALPN}, Certificates: []tls.Certificate{certificate},
				ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
				VerifyConnection: func(state tls.ConnectionState) error {
					want := "queqiao://" + profile.ProviderID + "/account/" + profile.AccountID + "/device/" + profile.DeviceID
					if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != dataALPN ||
						len(state.PeerCertificates) == 0 || len(state.PeerCertificates[0].URIs) != 1 ||
						state.PeerCertificates[0].URIs[0].String() != want {
						return errors.New("test peer did not authenticate the expected device")
					}
					serverVerified.Add(1)
					return nil
				},
			}
			if mode == "wrong-ALPN" {
				serverConfig.NextProtos = []string{"different-protocol/1"}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			clientRaw, peer := net.Pipe()
			var client net.Conn = clientRaw
			if mode == "missing-client-certificate" {
				buffered := newFallbackBufferedPipe(clientRaw)
				client = buffered
				defer func() { buffered.Close(); <-buffered.writerDone }()
			}
			defer client.Close()
			defer peer.Close()
			deadline, _ := ctx.Deadline()
			client.SetDeadline(deadline)
			peer.SetDeadline(deadline)
			var opens atomic.Int32
			serverDone := make(chan error, 1)
			payload := []byte("authenticated fallback data")
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
				if f.typ != typeOpen || string(f.payload) != "example.com:443" {
					serverDone <- errors.New("expected exactly the destination OPEN")
					return
				}
				opens.Add(1)
				if err := writeFrame(secure, frame{typ: typeOpenOK, session: f.session, flow: f.flow}); err != nil {
					serverDone <- err
					return
				}
				data, err := readFrame(secure)
				if err != nil {
					serverDone <- err
					return
				}
				if data.typ != typeData || data.session != f.session || data.flow != f.flow || data.sequence != 0 || !bytes.Equal(data.payload, payload) {
					serverDone <- errors.New("DATA or logical identity mismatch after OPEN")
					return
				}
				serverDone <- writeFrame(secure, data)
			}()
			o := fallbackTestOutbound()
			o.ctx, o.tlsConfig, o.server = ctx, config, M.ParseSocksaddr(profile.Endpoint)
			quicCalls, tcpCalls := 0, 0
			o.pool = fallbackPoolFunc(func(context.Context) (net.Conn, error) {
				quicCalls++
				return nil, syscall.ECONNREFUSED
			})
			o.dialer = testDialer{dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
				tcpCalls++
				if network != "tcp" || destination != o.server {
					return nil, errors.New("fallback changed the configured endpoint")
				}
				return client, nil
			}}
			opened, openErr := o.openFlow(ctx, []byte("example.com:443"), M.ParseSocksaddr("example.com:443"))
			if mode == "valid" {
				if openErr != nil {
					t.Fatal(openErr)
				}
				if !opened.useTCP {
					t.Fatal("selected carrier was not retained as TCP")
				}
				secure, ok := opened.conn.(*tls.Conn)
				if !ok || !secure.ConnectionState().HandshakeComplete {
					t.Fatal("OPEN returned without an authenticated TLS carrier")
				}
				if err := writeFrame(opened.conn, frame{typ: typeData, session: opened.session, flow: opened.flow, payload: payload}); err != nil {
					t.Fatal(err)
				}
				reply, err := readFrame(opened.conn)
				if err != nil || reply.typ != typeData || reply.session != opened.session || reply.flow != opened.flow || !bytes.Equal(reply.payload, payload) {
					t.Fatalf("authenticated echo mismatch: %v", err)
				}
				client.Close()
				opened.remove()
			} else if openErr == nil {
				client.Close()
				opened.remove()
				t.Fatal("invalid peer was accepted")
			}
			if mode == "wrong-gateway" || mode == "wrong-root" {
				var identity identityError
				if !errors.As(openErr, &identity) {
					t.Fatalf("expected strict identity rejection, got %v", openErr)
				}
			}
			select {
			case serverErr := <-serverDone:
				if mode == "valid" && serverErr != nil {
					t.Fatal(serverErr)
				}
				if mode == "missing-client-certificate" && (serverErr == nil || !strings.Contains(serverErr.Error(), "client didn't provide a certificate")) {
					t.Fatalf("expected explicit missing-client-certificate rejection, got %v", serverErr)
				}
			case <-ctx.Done():
				t.Fatal("in-memory peer did not finish")
			}
			if quicCalls != 1 || tcpCalls != 1 || len(o.active) != 0 || len(o.slots) != 0 {
				t.Fatal("unexpected retry or retained initial-flow resources")
			}
			if mode == "valid" {
				if opens.Load() != 1 || clientVerified.Load() != 1 || serverVerified.Load() != 1 {
					t.Fatal("OPEN count or mutual identity verification count mismatch")
				}
			} else {
				if opens.Load() != 0 {
					t.Fatal("failed mutual authentication reached OPEN")
				}
				if mode == "missing-client-certificate" {
					if serverVerified.Load() != 0 {
						t.Fatal("peer accepted a missing client certificate")
					}
				} else if clientVerified.Load() != 0 {
					t.Fatal("invalid peer passed client identity verification")
				}
			}
		})
	}
}

func TestInitialFallbackRejectsInvalidProfilePin(t *testing.T) {
	profile, _, _ := testIdentity(t)
	profile.RootPin = "invalid-pin"
	if _, err := profile.tlsConfig(time.Now()); err == nil {
		t.Fatal("invalid profile root pin was accepted before fallback")
	}
}
