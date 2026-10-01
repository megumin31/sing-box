package queqiao

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestPathProbeFrozenHeader(t *testing.T) {
	session := [16]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	var b bytes.Buffer
	if err := writeFrame(&b, frame{typ: typeProbe, session: session, sequence: 99, payload: make([]byte, 1200)}); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(b.Bytes()[:headerSize]) != "574f01090000101112131415161718191a1b1c1d1e1f00000000000000000000000000000063000004b000000000" {
		t.Fatal("PROBE frozen header mismatch")
	}
}

func TestPathProbeRequestBounds(t *testing.T) {
	for _, v := range []struct {
		size, count int
		zero        bool
	}{{0, 1, false}, {1201, 1, false}, {1, 0, false}, {1, 129, false}, {1200, 110, false}, {1, 1, true}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		session := [16]byte{1}
		if v.zero {
			session = [16]byte{}
		}
		called := false
		r, err := exchangePathProbe(ctx, new(fallbackMemoryConn), func() error { called = true; return nil }, func() { called = true }, session, make([]byte, v.size), v.count)
		cancel()
		if err == nil || called || r.status != "invalid_request" {
			t.Fatalf("invalid probe admitted: %+v", v)
		}
	}
	for _, transport := range []string{"", "tcp"} {
		_, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: "not-opened", Transport: transport, QUICPathProbe: true})
		if err == nil || err.Error() != "queqiao: quic_path_probe requires transport quic" {
			t.Fatalf("config validation: %v", err)
		}
	}
}

func TestPathProbeEchoContract(t *testing.T) {
	for _, mode := range []string{"valid", "128-frame-bound", "byte-bound", "type", "flags", "class", "session", "flow", "sequence", "payload", "length", "early-EOF", "trailing-echo", "complete-no-EOF"} {
		t.Run(mode, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			timeout := 2 * time.Second
			if mode == "complete-no-EOF" {
				timeout = 200 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			payload, count := []byte("bounded echo"), 2
			if mode == "128-frame-bound" {
				count = 128
			}
			if mode == "byte-bound" {
				count = 128
				payload = make([]byte, 1024)
			}
			halfClosed := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				defer b.Close()
				for i := 0; i < count; i++ {
					f, err := readFrame(b)
					if err != nil {
						done <- err
						return
					}
					if mode == "early-EOF" {
						continue
					}
					if i == 0 {
						switch mode {
						case "type":
							f.typ = typeOpenOK
						case "flags":
							f.flags = flagFIN
						case "class":
							f.class = 1
						case "session":
							f.session[0]++
						case "flow":
							f.flow = 1
						case "sequence":
							f.sequence = 1
						case "payload":
							f.payload[0] ^= 1
						case "length":
							f.payload = f.payload[:len(f.payload)-1]
						}
					}
					if err = writeFrame(b, f); err != nil {
						done <- err
						return
					}
					if mode != "valid" && mode != "128-frame-bound" && mode != "byte-bound" && mode != "trailing-echo" && mode != "complete-no-EOF" {
						done <- nil
						return
					}
				}
				if mode == "complete-no-EOF" {
					<-ctx.Done()
					done <- nil
					return
				}
				if mode == "trailing-echo" {
					writeFrame(b, frame{typ: typeProbe, session: [16]byte{1}, payload: payload})
				}
				select {
				case <-halfClosed:
					done <- nil
				case <-ctx.Done():
					done <- ctx.Err()
				}
			}()
			r, err := exchangePathProbe(ctx, a, func() error { close(halfClosed); return nil }, func() { a.Close() }, [16]byte{1}, payload, count)
			if mode == "valid" || mode == "128-frame-bound" || mode == "byte-bound" || mode == "complete-no-EOF" {
				if err != nil || r.status != "conformant" || r.sent != count || r.received != count {
					t.Fatalf("complete: %+v %v", r, err)
				}
				select {
				case <-halfClosed:
				default:
					t.Fatal("missing half-close")
				}
			} else {
				var p protocolError
				if !errors.As(err, &p) || r.status != "protocol_error" {
					t.Fatalf("violation classified as %+v %v", r, err)
				}
			}
			a.Close()
			b.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("peer not reaped")
			}
		})
	}
}

func TestPathProbeTimeoutAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			half := make(chan struct{})
			peerDone := make(chan struct{})
			go func() {
				defer close(peerDone)
				for i := 0; i < 2; i++ {
					if _, err := readFrame(b); err != nil {
						return
					}
				}
				<-half
				if canceled {
					cancel()
				}
				<-ctx.Done()
			}()
			r, err := exchangePathProbe(ctx, a, func() error { close(half); return nil }, func() { a.Close() }, [16]byte{1}, []byte{1}, 2)
			if canceled {
				if !errors.Is(err, context.Canceled) || r.status != "canceled" {
					t.Fatalf("cancel: %+v %v", r, err)
				}
			} else if err != nil || r.status != "incomplete" || r.received != 0 {
				t.Fatalf("timeout: %+v %v", r, err)
			}
			<-peerDone
		})
	}
}

func TestPathProbeErrorsNeverFallback(t *testing.T) {
	for _, err := range []error{context.DeadlineExceeded, io.EOF, protocolError{errors.New("mismatch")}} {
		if initialFallbackAllowed(quicProbeError{err}) {
			t.Fatalf("probe error caused fallback: %v", err)
		}
	}
}

func TestPathProbePartialEchoKnownViolation(t *testing.T) {
	for _, mode := range []string{"wrong-header", "wrong-length", "wrong-prefix", "partial-wrong-header"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				done := make(chan struct{})
				go func() {
					defer close(done)
					f, err := readFrame(b)
					if err != nil {
						return
					}
					if mode == "wrong-header" || mode == "partial-wrong-header" {
						f.flow = 1
					}
					if mode == "wrong-length" {
						f.payload = append(f.payload, 1)
					}
					var encoded bytes.Buffer
					writeFrame(&encoded, f)
					n := headerSize
					if mode == "partial-wrong-header" {
						n = 30
					}
					if mode == "wrong-prefix" {
						n++
						encoded.Bytes()[headerSize] ^= 1
					}
					b.Write(encoded.Bytes()[:n])
					<-ctx.Done()
				}()
				r, err := exchangePathProbe(ctx, a, func() error { return nil }, func() { a.Close() }, [16]byte{1}, []byte("echo"), 1)
				var violation protocolError
				if !errors.As(err, &violation) || r.status != "protocol_error" {
					t.Errorf("known partial echo violation was hidden: %+v %v", r, err)
				}
				cancel()
				<-done
			})
		})
	}
}

type probeEOFWithSlowWriter struct {
	fallbackMemoryConn
	ctx     context.Context
	stopped <-chan struct{}
}

func (s *probeEOFWithSlowWriter) Read([]byte) (int, error) { return 0, io.EOF }
func (s *probeEOFWithSlowWriter) Write([]byte) (int, error) {
	<-s.stopped
	<-s.ctx.Done()
	return 0, net.ErrClosed
}

func TestPathProbeObservedEOFWinsOverWriterTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		stopped := make(chan struct{})
		var once sync.Once
		s := &probeEOFWithSlowWriter{ctx: ctx, stopped: stopped}
		r, err := exchangePathProbe(ctx, s, func() error { return nil }, func() { once.Do(func() { close(stopped) }) }, [16]byte{1}, []byte{1}, 1)
		var violation protocolError
		if !errors.As(err, &violation) || r.status != "protocol_error" {
			t.Fatalf("observed EOF hidden by writer timeout: %+v %v", r, err)
		}
	})
}
