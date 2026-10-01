package queqiao

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

// A control frame may hold writeGate until after the application's deadline.
// No application state can be committed until the application owns that gate.
func TestSendAdmissionGateDeadline(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		name := "plain"
		if recovery {
			name = "recovery"
		}
		t.Run(name, func(t *testing.T) {
			for _, fin := range []bool{false, true} {
				operation := "data"
				if fin {
					operation = "fin"
				}
				t.Run(operation, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						raw, peer := net.Pipe()
						defer peer.Close()
						c := newConnState(raw, [16]byte{1}, 1, nil)
						defer c.terminate(net.ErrClosed)
						if recovery {
							c.join = func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) {
								t.Error("local gate timeout must not start JOIN")
								return nil, net.ErrClosed
							}
						}
						<-c.writeGate
						c.SetWriteDeadline(time.Now().Add(time.Second))
						var err error
						if fin {
							err = c.CloseWrite()
						} else {
							var n int
							n, err = c.Write([]byte("abc"))
							if n != 0 {
								t.Fatalf("unsent bytes reported accepted: %d", n)
							}
						}
						if !errors.Is(err, os.ErrDeadlineExceeded) {
							t.Fatalf("gate timeout: %v", err)
						}
						if c.sendNext != 0 || len(c.replay) != 0 || c.localFIN || c.recovering || c.closed {
							t.Fatalf("pre-send timeout changed state: next=%d replay=%d fin=%v recovering=%v closed=%v", c.sendNext, len(c.replay), c.localFIN, c.recovering, c.closed)
						}
						c.SetWriteDeadline(time.Now().Add(time.Second))
						c.writeGate <- struct{}{}
						done := make(chan error, 1)
						go func() {
							if fin {
								done <- c.CloseWrite()
							} else {
								_, e := c.Write([]byte("abc"))
								done <- e
							}
						}()
						peer.SetReadDeadline(time.Now().Add(time.Second))
						f, err := readFrame(peer)
						if err != nil {
							t.Fatal(err)
						}
						if err = <-done; err != nil {
							t.Fatal(err)
						}
						if f.sequence != 0 {
							t.Fatalf("offset gap after retry: %d", f.sequence)
						}
						if fin {
							if f.typ != typeClose || f.flags != flagFIN {
								t.Fatalf("missing FIN: %+v", f)
							}
							if err = c.CloseWrite(); err != nil {
								t.Fatal(err)
							}
						} else {
							if f.typ != typeData || string(f.payload) != "abc" {
								t.Fatalf("wrong DATA: %+v", f)
							}
							if err = c.handleFrame(frame{typ: typeACK, flags: flagACKUp, sequence: 3}); err != nil {
								t.Fatal(err)
							}
							go func() { done <- c.CloseWrite() }()
							f, err = readFrame(peer)
							if err != nil {
								t.Fatal(err)
							}
							if err = <-done; err != nil {
								t.Fatal(err)
							}
							if f.typ != typeClose || f.flags != flagFIN || f.sequence != 3 {
								t.Fatalf("bad final offset: %+v", f)
							}
						}
						if err = c.handleFrame(frame{typ: typeACK, flags: flagACKUp | flagACKFinal, sequence: c.sendNext}); err != nil {
							t.Fatal(err)
						}
						if !c.localFinalACK || len(c.replay) != 0 {
							t.Fatal("final ACK/replay did not settle")
						}
					})
				})
			}
		})
	}
}

// The same admission timeouts must remain retryable through an actual gateway,
// without an outage/JOIN to fill an accidentally skipped byte range.
func testOfficialSendAdmissionDeadline(t *testing.T, profile, transport string) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			raw, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(raw, raw)
				raw.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	for _, recovery := range []bool{false, true} {
		name := "plain"
		if recovery {
			name = "recovery"
		}
		t.Run(name, func(t *testing.T) {
			a, err := NewOutbound(context.Background(), nil, nil, "admission", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: transport, TCPRecovery: recovery})
			if err != nil {
				t.Fatal(err)
			}
			defer a.(*Outbound).Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			raw, err := a.DialContext(ctx, "tcp", M.ParseSocksaddr(target.Addr().String()))
			if err != nil {
				t.Fatal(err)
			}
			c := raw.(*Conn)
			defer c.Close()
			c.SetDeadline(time.Now().Add(4 * time.Second))
			if err = c.acquire(c.writeGate, true); err != nil {
				t.Fatal(err)
			}
			c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
			n, err := c.Write([]byte("abc"))
			c.writeGate <- struct{}{}
			if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("unadmitted DATA: %d %v", n, err)
			}
			c.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if n, err = c.Write([]byte("abc")); n != 3 || err != nil {
				t.Fatalf("retry DATA: %d %v", n, err)
			}
			got := make([]byte, 3)
			if _, err = io.ReadFull(c, got); err != nil || string(got) != "abc" {
				t.Fatalf("contiguous echo: %q %v", got, err)
			}
			if err = c.acquire(c.writeGate, true); err != nil {
				t.Fatal(err)
			}
			c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
			err = c.CloseWrite()
			c.writeGate <- struct{}{}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("unadmitted FIN: %v", err)
			}
			c.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if err = c.CloseWrite(); err != nil {
				t.Fatalf("retry FIN: %v", err)
			}
			tail, err := io.ReadAll(c)
			if err != nil || len(tail) != 0 {
				t.Fatalf("half-close: %q %v", tail, err)
			}
			c.mu.Lock()
			attempts, next, acked := c.recoveryAttempts, c.sendNext, c.acked
			c.mu.Unlock()
			if attempts != 0 || next != 3 || acked != 3 {
				t.Fatalf("unnecessary recovery/gap: attempts=%d next=%d acked=%d", attempts, next, acked)
			}
		})
	}
}
