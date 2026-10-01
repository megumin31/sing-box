//go:build with_quic

package queqiao

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	M "github.com/sagernet/sing/common/metadata"
)

func TestPathProbeQUICPoolGate(t *testing.T) {
	for _, mode := range []string{"conformant", "incomplete", "mismatch", "header-stall", "early-EOF", "transport-close"} {
		t.Run(mode, func(t *testing.T) {
			client, server, _, _ := fallbackLoopbackConfigs(t)
			listener, err := quic.ListenAddr("127.0.0.1:0", server, &quic.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			var udpCalls, tcpCalls, applicationOpens atomic.Int32
			o := fallbackLoopbackOutbound(ctx, client, listener.Addr().String(), &udpCalls, &tcpCalls)
			o.pathProbe = true
			defer o.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept(ctx)
				if err != nil {
					done <- err
					return
				}
				defer conn.CloseWithError(0, "")
				stream, err := conn.AcceptStream(ctx)
				if err != nil {
					done <- err
					return
				}
				frames := make([]frame, 0, pathProbeFrames)
				for i := 0; i < pathProbeFrames; i++ {
					f, err := readFrame(stream)
					if err != nil {
						done <- err
						return
					}
					if f.typ != typeProbe || f.flow != 0 || f.flags != 0 || f.class != 0 || f.sequence != uint64(i) || f.session == ([16]byte{}) || len(f.payload) != maxProbePayload {
						done <- errors.New("bad probe request")
						return
					}
					if i > 0 && f.session != frames[0].session {
						done <- errors.New("probe session changed")
						return
					}
					frames = append(frames, f)
				}
				if _, err := readFrame(stream); !errors.Is(err, io.EOF) {
					done <- errors.New("probe request did not half-close")
					return
				}
				switch mode {
				case "mismatch":
					frames[0].payload[0] = 1
					err = writeFrame(stream, frames[0])
				case "header-stall":
					frames[0].flow = 1
					var encoded bytes.Buffer
					err = writeFrame(&encoded, frames[0])
					if err == nil {
						_, err = stream.Write(encoded.Bytes()[:headerSize])
					}
				case "early-EOF":
					err = stream.Close()
				case "transport-close":
					err = conn.CloseWithError(42, "test disconnect")
				case "conformant":
					for _, f := range frames {
						if err = writeFrame(stream, f); err != nil {
							break
						}
					}
					if err == nil {
						err = stream.Close()
					}
				}
				if err != nil {
					done <- err
					return
				}
				if mode != "conformant" && mode != "incomplete" {
					<-conn.Context().Done()
					done <- nil
					return
				}
				application, err := conn.AcceptStream(ctx)
				if err != nil {
					done <- err
					return
				}
				f, err := readFrame(application)
				if err != nil {
					done <- err
					return
				}
				if f.typ != typeOpen {
					done <- errors.New("first application frame is not OPEN")
					return
				}
				applicationOpens.Add(1)
				if err = writeFrame(application, frame{typ: typeOpenOK, session: f.session, flow: f.flow}); err != nil {
					done <- err
					return
				}
				// Keep the connection alive until the outbound is closed by the test.
				<-conn.Context().Done()
				done <- nil
			}()
			c, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
			if mode == "conformant" || mode == "incomplete" {
				if err != nil {
					t.Fatal(err)
				}
				pool := o.pool.(*quicPool)
				pool.mu.Lock()
				if len(pool.entries) != 1 {
					pool.mu.Unlock()
					t.Fatal("probe did not retain live pool connection")
				}
				entry := pool.entries[0]
				pool.mu.Unlock()
				<-entry.ready
				if entry.probe.status != mode || entry.probe.sent != pathProbeFrames {
					t.Fatalf("probe result: %+v", entry.probe)
				}
				if mode == "conformant" && entry.probe.received != pathProbeFrames {
					t.Fatal("missing conformant echoes")
				}
				c.Close()
			} else {
				if c != nil {
					c.Close()
					t.Fatal("application flow escaped invalid probe")
				}
				if err == nil || initialFallbackAllowed(err) {
					t.Fatalf("probe failure eligible for fallback: %v", err)
				}
				if applicationOpens.Load() != 0 {
					t.Fatal("OPEN was sent before probe acceptance")
				}
			}
			if udpCalls.Load() != 1 || tcpCalls.Load() != 0 {
				t.Fatalf("probe reselected carrier: UDP=%d TCP=%d", udpCalls.Load(), tcpCalls.Load())
			}
			o.Close()
			fallbackWaitPeer(t, ctx, done)
		})
	}
}

func TestPathProbeDeadlineAfterAuthenticationCannotFallback(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	entry := &quicPoolEntry{ctx: context.Background(), ready: make(chan struct{}), probeStarted: make(chan struct{})}
	close(entry.probeStarted)
	err := waitQUICEntry(ctx, entry)
	var probe quicProbeError
	if !errors.As(err, &probe) || !errors.Is(err, context.DeadlineExceeded) || initialFallbackAllowed(err) {
		t.Fatalf("authenticated probe timeout selected fallback: %v", err)
	}
}

func TestPathProbeQUICSharedCallerCancellation(t *testing.T) {
	client, server, _, _ := fallbackLoopbackConfigs(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", server, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var udpCalls, tcpCalls atomic.Int32
	o := fallbackLoopbackOutbound(ctx, client, listener.Addr().String(), &udpCalls, &tcpCalls)
	o.pathProbe = true
	defer o.Close()
	seen, release, peerDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			peerDone <- err
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			peerDone <- err
			return
		}
		var frames []frame
		for i := 0; i < pathProbeFrames; i++ {
			f, err := readFrame(stream)
			if err != nil {
				peerDone <- err
				return
			}
			frames = append(frames, f)
		}
		close(seen)
		select {
		case <-release:
		case <-ctx.Done():
			peerDone <- ctx.Err()
			return
		}
		for _, f := range frames {
			if err = writeFrame(stream, f); err != nil {
				peerDone <- err
				return
			}
		}
		stream.Close()
		<-conn.Context().Done()
		peerDone <- nil
	}()
	firstCtx, cancelFirst := context.WithCancel(ctx)
	defer cancelFirst()
	first := make(chan error, 1)
	go func() {
		c, err := o.pool.Open(firstCtx)
		if c != nil {
			c.Close()
		}
		first <- err
	}()
	select {
	case <-seen:
	case <-ctx.Done():
		t.Fatal("probe did not start")
	}
	type opened struct {
		conn net.Conn
		err  error
	}
	second := make(chan opened, 1)
	go func() { c, err := o.pool.Open(ctx); second <- opened{c, err} }()
	pool := o.pool.(*quicPool)
	for {
		pool.mu.Lock()
		shared := len(pool.entries) == 1 && pool.entries[0].users == 2
		pool.mu.Unlock()
		if shared {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("second caller did not share probe")
		case <-time.After(time.Millisecond):
		}
	}
	cancelFirst()
	if err = <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter: %v", err)
	}
	close(release)
	var r opened
	select {
	case r = <-second:
	case <-ctx.Done():
		t.Fatal("surviving caller stalled")
	}
	if r.err != nil || r.conn == nil {
		t.Fatalf("surviving caller: %v", r.err)
	}
	r.conn.Close()
	o.Close()
	fallbackWaitPeer(t, ctx, peerDone)
	if udpCalls.Load() != 1 || tcpCalls.Load() != 0 {
		t.Fatal("shared probe created extra connection")
	}
}

func TestPathProbeInterfaceUpdateCancelsGate(t *testing.T) {
	client, server, _, _ := fallbackLoopbackConfigs(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", server, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var udpCalls, tcpCalls atomic.Int32
	o := fallbackLoopbackOutbound(ctx, client, listener.Addr().String(), &udpCalls, &tcpCalls)
	o.pathProbe = true
	defer o.Close()
	seen := make(chan struct{})
	peerDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			peerDone <- err
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			peerDone <- err
			return
		}
		if _, err = readFrame(stream); err != nil {
			peerDone <- err
			return
		}
		close(seen)
		<-conn.Context().Done()
		peerDone <- nil
	}()
	done := make(chan error, 1)
	go func() {
		raw, _, err := o.dialInitialCarrier(ctx, 0)
		if raw != nil {
			raw.Close()
		}
		done <- err
	}()
	select {
	case <-seen:
	case <-ctx.Done():
		t.Fatal("probe not started")
	}
	o.InterfaceUpdated(ctx)
	select {
	case err := <-done:
		if err == nil || initialFallbackAllowed(err) {
			t.Fatalf("old generation retained: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("interface update did not interrupt probe")
	}
	fallbackWaitPeer(t, ctx, peerDone)
	if tcpCalls.Load() != 0 {
		t.Fatal("canceled probe opened fallback TCP")
	}
	pool := o.pool.(*quicPool)
	pool.mu.Lock()
	entries := len(pool.entries)
	pool.mu.Unlock()
	if entries != 0 {
		t.Fatal("old generation left pool entry")
	}
}
