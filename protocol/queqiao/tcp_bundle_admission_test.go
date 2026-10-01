package queqiao

import (
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
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestTCPBundleInitialJOINAdmission(t *testing.T) {
	for _, mode := range []string{"accept", "refuse", "wrong-identity", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			profile, certificate, _ := testIdentity(t)
			data, _ := json.Marshal(profile)
			path := filepath.Join(t.TempDir(), "profile.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			a, err := NewOutbound(context.Background(), nil, nil, "bundle", option.QueqiaoOutboundOptions{ProfilePath: path, Transport: "tcp", TCPRecovery: true, TCPLanes: 2})
			if err != nil {
				t.Fatal(err)
			}
			o := a.(*Outbound)
			defer o.Close()
			var calls atomic.Int32
			var wg sync.WaitGroup
			var identity frame
			joined := make(chan struct{})
			aborted := make(chan bool, 1)
			admit := make(chan struct{})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			o.dialer = testDialer{dial: func(ctx context.Context, n string, d M.Socksaddr) (net.Conn, error) {
				call := calls.Add(1)
				client, peer := net.Pipe()
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer peer.Close()
					server := tls.Server(peer, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{dataALPN}})
					f, e := readFrame(server)
					if e != nil {
						return
					}
					if call == 1 {
						if f.typ != typeOpen || f.flags != 0 {
							t.Error("initial lane did not use ordinary OPEN")
							return
						}
						identity = f
					} else {
						if call != 2 || f.typ != typeJoin || f.flags != 0 || f.sequence != 0 || len(f.payload) != 8 || binary.BigEndian.Uint64(f.payload) == 0 || f.session != identity.session || f.flow != identity.flow {
							t.Error("second lane did not preserve JOIN identity")
							return
						}
						close(joined)
						select {
						case <-admit:
						case <-ctx.Done():
							return
						}
					}
					response := frame{typ: typeOpenOK, session: f.session, flow: f.flow}
					if call == 2 && mode == "refuse" {
						response.typ = typeReset
						response.payload = []byte{4}
					}
					if call == 2 && mode == "wrong-identity" {
						response.flow++
					}
					if writeFrame(server, response) != nil {
						return
					}
					if call == 1 {
						next, readErr := readFrame(server)
						aborted <- readErr == nil && next.typ == typeClose && next.flags == flagFIN|flagAbort && next.session == f.session && next.flow == f.flow
					} else {
						io.Copy(io.Discard, server)
					}
				}()
				return client, nil
			}}
			type outcome struct {
				conn net.Conn
				err  error
			}
			result := make(chan outcome, 1)
			go func() {
				c, e := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
				result <- outcome{c, e}
			}()
			select {
			case <-joined:
			case <-ctx.Done():
				t.Fatal("JOIN not reached")
			}
			select {
			case v := <-result:
				if v.conn != nil {
					v.conn.Close()
				}
				t.Fatalf("Dial returned before JOIN OPEN_OK: %v", v.err)
			default:
			}
			if mode == "cancel" {
				cancel()
			} else {
				close(admit)
			}
			v := <-result
			if mode == "accept" {
				if v.err != nil {
					t.Fatal(v.err)
				}
				v.conn.Close()
			} else {
				if v.conn != nil || v.err == nil {
					t.Fatalf("bad JOIN admitted: %+v", v)
				}
				if mode == "cancel" && !errors.Is(v.err, context.Canceled) {
					t.Fatalf("cancellation=%v", v.err)
				}
			}
			cancel()
			o.Close()
			wg.Wait()
			if mode == "refuse" || mode == "wrong-identity" {
				if !<-aborted {
					t.Fatal("failed JOIN did not abort the existing destination")
				}
			}
			o.mu.Lock()
			active := len(o.active)
			o.mu.Unlock()
			if calls.Load() != 2 || active != 0 || len(o.slots) != 0 {
				t.Fatalf("dial/cleanup calls=%d active=%d slots=%d", calls.Load(), active, len(o.slots))
			}
		})
	}
}
