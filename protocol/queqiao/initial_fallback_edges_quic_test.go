//go:build with_quic

package queqiao

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/quic-go"
)

func TestInitialFallbackInstalledQUICErrors(t *testing.T) {
	for _, v := range []struct {
		name    string
		err     error
		allowed bool
	}{
		{"handshake-timeout", &quic.HandshakeTimeoutError{}, true},
		{"idle-timeout", &quic.IdleTimeoutError{}, true},
		{"crypto-refusal", &quic.TransportError{Remote: true, ErrorCode: quic.TransportErrorCode(0x12a)}, false},
		{"protocol-refusal", &quic.TransportError{Remote: true, ErrorCode: quic.ProtocolViolation}, false},
		{"transport-refusal", &quic.TransportError{Remote: true, ErrorCode: quic.ConnectionRefused}, false},
		{"application-refusal", &quic.ApplicationError{Remote: true, ErrorCode: 1}, false},
		{"version-negotiation", &quic.VersionNegotiationError{}, false},
		{"stateless-reset", &quic.StatelessResetError{}, false},
		{"stream-refusal", &quic.StreamError{Remote: true, ErrorCode: 1}, false},
	} {
		t.Run(v.name, func(t *testing.T) {
			variants := []error{v.err, fmt.Errorf("wrapped: %w", v.err), &net.OpError{Op: "dial", Net: "udp", Err: v.err}}
			if !v.allowed {
				variants = append(variants, errors.Join(&quic.HandshakeTimeoutError{}, v.err), errors.Join(v.err, &quic.HandshakeTimeoutError{}))
			}
			for i, err := range variants {
				if got := initialFallbackAllowed(err); got != v.allowed {
					t.Errorf("variant %d: allowed=%v, want %v", i, got, v.allowed)
				}
			}
		})
	}
}

// Use the real shared-entry wait/release lifecycle, with readiness published by
// the test rather than a network handshake. No quic.Conn or socket is created.
func TestInitialFallbackStaggeredSharedEntry(t *testing.T) {
	for _, explicitCancel := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			entryCtx, stopEntry := context.WithCancel(context.Background())
			defer stopEntry()
			e := &quicPoolEntry{ctx: entryCtx, cancel: stopEntry, ready: make(chan struct{}), drain: newQUICDrain(), users: 1}
			p := &quicPool{owner: fallbackTestOutbound(), entries: []*quicPoolEntry{e}, idleTimeout: 30 * time.Second}
			defer p.Reset(true)
			first, cancelFirst := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelFirst()
			firstDone := make(chan error, 1)
			go func() { err := waitQUICEntry(first, e); p.release(e); firstDone <- err }()
			time.Sleep(time.Second)
			p.mu.Lock()
			e.users++
			p.mu.Unlock()
			second, cancelSecond := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancelSecond()
			secondDone := make(chan error, 1)
			go func() { secondDone <- waitQUICEntry(second, e) }()
			synctest.Wait()
			if explicitCancel {
				cancelFirst()
			}
			err := <-firstDone
			want := context.DeadlineExceeded
			if explicitCancel {
				want = context.Canceled
			}
			if !errors.Is(err, want) || initialFallbackAllowed(err) == explicitCancel {
				t.Fatalf("wrong first waiter outcome: %v", err)
			}
			p.mu.Lock()
			users, count := e.users, len(p.entries)
			p.mu.Unlock()
			if users != 1 || count != 1 || entryCtx.Err() != nil {
				t.Fatal("first waiter canceled the viable shared entry")
			}
			select {
			case <-secondDone:
				t.Fatal("second waiter finished before readiness")
			default:
			}
			close(e.ready)
			if err := <-secondDone; err != nil {
				t.Fatalf("second waiter lost the shared entry: %v", err)
			}
			p.release(e)
			p.mu.Lock()
			users = e.users
			idle := e.idle != nil
			p.mu.Unlock()
			if users != 0 || !idle {
				t.Fatal("final shared reservation did not enter bounded idle cleanup")
			}
		})
	}
}
