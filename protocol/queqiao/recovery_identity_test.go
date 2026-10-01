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

func TestRecoveryRejectsExpiredTLSIdentity(t *testing.T) {
	profile, certificate, chain := testIdentityExpires(t, time.Now().Add(2*time.Second))
	roots := x509.NewCertPool()
	roots.AddCert(chain[2])
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			raw, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				secure := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{dataALPN}, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots})
				if secure.Handshake() != nil {
					return
				}
				f, e := readFrame(secure)
				if e != nil {
					return
				}
				if writeFrame(secure, frame{typ: typeOpenOK, session: f.session, flow: f.flow}) != nil {
					return
				}
				io.Copy(io.Discard, secure)
			}()
		}
	}()
	profile.Endpoint = listener.Addr().String()
	data, _ := json.Marshal(profile)
	path := filepath.Join(t.TempDir(), "profile.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := NewOutbound(context.Background(), nil, nil, "expiry-recovery", option.QueqiaoOutboundOptions{ProfilePath: path, TCPRecovery: true})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
	raw, err := o.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*Conn)
	defer c.Close()
	time.Sleep(time.Until(chain[0].NotAfter) + 10*time.Millisecond)
	abortCarrier(c.currentCarrier())
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		t.Fatal("expired credentials were retried without bound")
	}
	c.mu.Lock()
	failure, attempts := c.err, c.recoveryAttempts
	c.mu.Unlock()
	var invalid identityError
	if !errors.As(failure, &invalid) || attempts != 1 {
		t.Fatalf("expired identity result: attempts=%d %v", attempts, failure)
	}
}

func TestUDPResumeRejectsExpiredTLSIdentity(t *testing.T) {
	profile, certificate, chain := testIdentityExpires(t, time.Now().Add(2*time.Second))
	roots := x509.NewCertPool()
	roots.AddCert(chain[2])
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			raw, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				secure := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{dataALPN}, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots})
				if secure.Handshake() != nil {
					return
				}
				f, e := readFrame(secure)
				if e != nil {
					return
				}
				if writeFrame(secure, frame{typ: typeOpenOK, session: f.session, flow: f.flow, payload: append([]byte{0}, make([]byte, 16)...)}) != nil {
					return
				}
				io.Copy(io.Discard, secure)
			}()
		}
	}()
	profile.Endpoint = listener.Addr().String()
	data, _ := json.Marshal(profile)
	path := filepath.Join(t.TempDir(), "profile.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := NewOutbound(context.Background(), nil, nil, "expiry-recovery", option.QueqiaoOutboundOptions{ProfilePath: path, UDPResume: true})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
	raw, err := o.ListenPacket(context.Background(), M.ParseSocksaddr("example.com:53"))
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*packetConn).wire
	defer raw.Close()
	time.Sleep(time.Until(chain[0].NotAfter) + 10*time.Millisecond)
	abortCarrier(c.currentCarrier())
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		t.Fatal("expired credentials were retried without bound")
	}
	c.mu.Lock()
	failure, attempts := c.err, c.recoveryAttempts
	c.mu.Unlock()
	var invalid identityError
	if !errors.As(failure, &invalid) || attempts != 1 {
		t.Fatalf("expired identity result: attempts=%d %v", attempts, failure)
	}
}
