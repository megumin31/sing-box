package queqiao

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// Models the distinction important to QUIC: Write accepts bytes into a stream
// buffer; graceful Close drains them, while Abort discards the queued bytes.
// No sockets, clocks, credentials, or actual transport are needed here.
type queuedAbortCarrier struct {
	mu                sync.Mutex
	queued, delivered []byte
	closes, aborts    int
	writeErr          error
}

func (c *queuedAbortCarrier) Read([]byte) (int, error) { return 0, io.EOF }
func (c *queuedAbortCarrier) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	if c.writeErr != nil {
		n /= 2
	}
	c.queued = append(c.queued, p[:n]...)
	return n, c.writeErr
}
func (c *queuedAbortCarrier) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	c.delivered = append(c.delivered, c.queued...)
	c.queued = nil
	return nil
}
func (c *queuedAbortCarrier) Abort() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.aborts++
	c.queued = nil
	return nil
}
func (c *queuedAbortCarrier) LocalAddr() net.Addr              { return nil }
func (c *queuedAbortCarrier) RemoteAddr() net.Addr             { return nil }
func (c *queuedAbortCarrier) SetDeadline(time.Time) error      { return nil }
func (c *queuedAbortCarrier) SetReadDeadline(time.Time) error  { return nil }
func (c *queuedAbortCarrier) SetWriteDeadline(time.Time) error { return nil }

func TestQUICRolesExplicitClosePreservesQueuedAbort(t *testing.T) {
	for _, tc := range []struct {
		name                                               string
		busyFirst, busyBoth, writeFailure, protocolFailure bool
	}{
		{name: "control-abort"},
		{name: "data-abort", busyFirst: true},
		{name: "no-idle-lane", busyFirst: true, busyBoth: true},
		{name: "partial-abort-write", writeFailure: true},
		{name: "protocol-failure", protocolFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := &queuedAbortCarrier{}, &queuedAbortCarrier{}
			if tc.writeFailure {
				a.writeErr = io.ErrUnexpectedEOF
			}
			c := newConnState(a, [16]byte{7}, 11, nil)
			cancelled := false
			c.recoveryCancel = func() { cancelled = true }
			bundle := &tcpBundle{c: c, lanes: [2]*tcpBundleLane{{raw: a, busy: tc.busyFirst}, {raw: b, busy: tc.busyBoth}}}
			bundle.roles = &quicRoleLanes{b: bundle}
			c.bundle = bundle
			if tc.protocolFailure {
				c.terminate(protocolError{errors.New("known refusal")})
			} else if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if !cancelled {
				t.Fatal("local shutdown did not cancel recovery")
			}
			wantDrain := !tc.busyBoth && !tc.writeFailure && !tc.protocolFailure
			var chosen, other *queuedAbortCarrier
			if tc.busyFirst {
				chosen, other = b, a
			} else {
				chosen, other = a, b
			}
			if wantDrain {
				if chosen.closes != 1 || chosen.aborts != 0 || other.closes != 0 || other.aborts != 1 {
					t.Fatalf("queued ABORT discarded: chosen close/abort=%d/%d, other=%d/%d", chosen.closes, chosen.aborts, other.closes, other.aborts)
				}
				f, err := readFrame(bytes.NewReader(chosen.delivered))
				if err != nil || f.typ != typeClose || f.flags != flagFIN|flagAbort || f.session != c.session || f.flow != c.flow || f.sequence != 0 {
					t.Fatalf("delivered close=%+v err=%v", f, err)
				}
				if c.err != net.ErrClosed {
					t.Fatalf("explicit Close became normal EOF: %v", c.err)
				}
			} else if a.closes+b.closes != 0 || a.aborts+b.aborts != 2 {
				t.Fatalf("failed/absent abort was drained: closes=%d aborts=%d", a.closes+b.closes, a.aborts+b.aborts)
			}
			before := a.closes + a.aborts + b.closes + b.aborts
			c.Close()
			if a.closes+a.aborts+b.closes+b.aborts != before {
				t.Fatal("repeated Close repeated shutdown")
			}
		})
	}
}

// A successful local ABORT uses the existing bounded carrier drain. Its pool
// ownership must not be released early; the unrelated lane aborts promptly.
type heldQueuedAbortCarrier struct {
	*queuedAbortCarrier
	started chan struct{}
	release <-chan struct{}
}

func (c *heldQueuedAbortCarrier) Close() error {
	close(c.started)
	<-c.release
	return c.queuedAbortCarrier.Close()
}
func TestQUICRolesExplicitCloseHoldsDrainOwnership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(release) })
		a := &heldQueuedAbortCarrier{&queuedAbortCarrier{}, make(chan struct{}), release}
		b := &queuedAbortCarrier{}
		removed := make(chan struct{})
		c := newConnState(a, [16]byte{7}, 11, func() { close(removed) })
		c.recoveryCancel = func() {}
		bundle := &tcpBundle{c: c, lanes: [2]*tcpBundleLane{{raw: a}, {raw: b}}}
		bundle.roles = &quicRoleLanes{b: bundle}
		c.bundle = bundle
		finished := make(chan struct{})
		go func() { c.Close(); close(finished) }()
		<-a.started
		synctest.Wait()
		select {
		case <-c.done:
		default:
			t.Fatal("application shutdown did not precede drain")
		}
		select {
		case <-removed:
			t.Fatal("pool ownership released before ABORT drain")
		default:
		}
		b.mu.Lock()
		aborts := b.aborts
		b.mu.Unlock()
		if aborts != 1 {
			t.Fatal("unrelated carrier was not promptly aborted")
		}
		once.Do(func() { close(release) })
		<-finished
		<-removed
		if c.err != net.ErrClosed {
			t.Fatalf("Close error=%v", c.err)
		}
	})
}
func TestQUICRolesAbortDrainRequiresCurrentLaneAndLocalClose(t *testing.T) {
	for _, err := range []error{net.ErrClosed, protocolError{errors.New("known refusal")}} {
		for _, stale := range []bool{false, true} {
			a, b := &queuedAbortCarrier{}, &queuedAbortCarrier{}
			c := newConnState(a, [16]byte{7}, 11, nil)
			c.recoveryCancel = func() {}
			selected := &tcpBundleLane{raw: a}
			bundle := &tcpBundle{c: c, lanes: [2]*tcpBundleLane{selected, {raw: b}}}
			bundle.roles = &quicRoleLanes{b: bundle}
			c.bundle = bundle
			marker := selected
			if stale {
				marker = &tcpBundleLane{raw: a}
			}
			c.terminateWithQueuedAbort(err, marker)
			want := 0
			if err == net.ErrClosed && !stale {
				want = 1
			}
			if a.closes != want || b.closes != 0 {
				t.Fatalf("stale=%v error=%v unexpectedly drained %d/%d", stale, err, a.closes, b.closes)
			}
		}
	}
}
