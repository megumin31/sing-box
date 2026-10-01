package queqiao

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestTCPBundleConfiguration(t *testing.T) {
	for _, opts := range []option.QueqiaoOutboundOptions{
		{TCPLanes: -1}, {TCPLanes: 3}, {TCPLanes: 2, TCPRecovery: true},
		{TCPLanes: 2, Transport: "quic", TCPRecovery: true}, {TCPLanes: 2, Transport: "tcp"},
	} {
		opts.ProfilePath = "unused"
		if _, err := NewOutbound(context.Background(), nil, nil, "bundle", opts); err == nil {
			t.Fatalf("accepted invalid options: %+v", opts)
		}
	}
}
func bundleTestConn(t *testing.T, join joinLaneFunc) (*Conn, [2]net.Conn) {
	t.Helper()
	a, p := net.Pipe()
	b, q := net.Pipe()
	if join == nil {
		join = func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) {
			return nil, protocolError{errors.New("unexpected JOIN")}
		}
	}
	c := newBundleConn(a, b, [16]byte{1}, 2, nil, context.Background(), join)
	t.Cleanup(func() { c.terminate(net.ErrClosed); p.Close(); q.Close() })
	return c, [2]net.Conn{p, q}
}
func bundleFrame(typ byte, sequence uint64, payload string) frame {
	return frame{typ: typ, session: [16]byte{1}, flow: 2, sequence: sequence, payload: []byte(payload)}
}
func bundleWrite(t *testing.T, p net.Conn, f frame) {
	t.Helper()
	p.SetWriteDeadline(time.Now().Add(time.Second))
	if err := writeFrame(p, f); err != nil {
		t.Fatal(err)
	}
}
func bundleRead(t *testing.T, p net.Conn) frame {
	t.Helper()
	p.SetReadDeadline(time.Now().Add(time.Second))
	f, err := readFrame(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.session != ([16]byte{1}) || f.flow != 2 {
		t.Fatalf("changed logical IDs: %+v", f)
	}
	return f
}
func TestTCPBundleControlProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peers := bundleTestConn(t, nil)
		result := make(chan error, 1)
		go func() { _, err := c.Write([]byte("blocked")); result <- err }()
		synctest.Wait()
		c.mu.Lock()
		busy := c.bundle.lanes[0].busy
		c.mu.Unlock()
		if !busy {
			t.Fatal("first DATA did not enter blocked lane")
		}
		bundleWrite(t, peers[1], bundleFrame(typeData, 0, "reply"))
		ack := bundleRead(t, peers[1])
		if ack.typ != typeACK || ack.sequence != 5 {
			t.Fatalf("control did not bypass blocked DATA: %+v", ack)
		}
		c.Close()
		if <-result == nil {
			t.Fatal("blocked application write survived close")
		}
	})
}
func TestTCPBundleReassemblyAndFinal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peers := bundleTestConn(t, nil)
		// Keep both peer receive sides running so ACKs cannot occupy both lanes.
		for _, p := range peers {
			go io.Copy(io.Discard, p)
		}
		bundleWrite(t, peers[1], bundleFrame(typeData, 3, "def"))
		bundleWrite(t, peers[0], bundleFrame(typeData, 0, "abc"))
		bundleWrite(t, peers[1], bundleFrame(typeData, 0, "abcdef"))
		fin := bundleFrame(typeClose, 6, "")
		fin.flags = flagFIN
		bundleWrite(t, peers[0], fin)
		c.SetReadDeadline(time.Now().Add(time.Second))
		all, err := io.ReadAll(c)
		if err != nil || string(all) != "abcdef" {
			t.Fatalf("reassembly=%q err=%v", all, err)
		}
		synctest.Wait()
		c.mu.Lock()
		next, pending := c.recvNext, len(c.pending)
		c.mu.Unlock()
		if next != 6 || pending != 0 {
			t.Fatalf("duplicate delivery/buffer: %d %d", next, pending)
		}
	})
}
func TestTCPBundleAdmissionDeadline(t *testing.T) {
	for _, fin := range []bool{false, true} {
		t.Run(map[bool]string{false: "DATA", true: "FIN"}[fin], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, _ := bundleTestConn(t, nil)
				c.mu.Lock()
				for _, lane := range c.bundle.lanes {
					lane.busy = true
				}
				c.mu.Unlock()
				c.SetWriteDeadline(time.Now().Add(time.Second))
				var err error
				if fin {
					err = c.CloseWrite()
				} else {
					var n int
					n, err = c.Write([]byte("abc"))
					if n != 0 {
						t.Fatalf("accepted unsent bytes=%d", n)
					}
				}
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("deadline=%v", err)
				}
				c.mu.Lock()
				defer c.mu.Unlock()
				if c.sendNext != 0 || c.localFIN || len(c.replay) != 0 || c.recovering {
					t.Fatal("pre-admission timeout committed state")
				}
			})
		})
	}
}
func TestTCPBundleSurvivingLaneReplay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peers := bundleTestConn(t, nil)
		wrote := make(chan error, 1)
		go func() { _, err := c.Write([]byte("abc")); wrote <- err }()
		first := bundleRead(t, peers[0])
		if first.typ != typeData || first.sequence != 0 || string(first.payload) != "abc" {
			t.Fatalf("first=%+v", first)
		}
		if err := <-wrote; err != nil {
			t.Fatal(err)
		}
		peers[0].Close()
		ack := bundleRead(t, peers[1])
		if ack.typ != typeACK {
			t.Fatalf("recovery ACK=%+v", ack)
		}
		replay := bundleRead(t, peers[1])
		if replay.typ != typeData || replay.sequence != 0 || string(replay.payload) != "abc" {
			t.Fatalf("replay=%+v", replay)
		}
		up := bundleFrame(typeACK, 3, "")
		up.flags = flagACKUp
		bundleWrite(t, peers[1], up)
		synctest.Wait()
		c.mu.Lock()
		recovering, attempts := c.recovering, c.recoveryAttempts
		c.mu.Unlock()
		if recovering || attempts != 0 {
			t.Fatalf("survivor recovery=%v JOINs=%d", recovering, attempts)
		}
		go func() { _, err := c.Write([]byte("def")); wrote <- err }()
		second := bundleRead(t, peers[1])
		if second.sequence != 3 || string(second.payload) != "def" {
			t.Fatalf("after replay=%+v", second)
		}
		if err := <-wrote; err != nil {
			t.Fatal(err)
		}
	})
}
func TestTCPBundleAllLanesJoin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		replacement, peer := net.Pipe()
		defer peer.Close()
		calls := 0
		c, peers := bundleTestConn(t, func(ctx context.Context, s [16]byte, f, l uint64) (net.Conn, error) {
			calls++
			if s != ([16]byte{1}) || f != 2 || l == 0 {
				t.Error("JOIN identity changed")
			}
			if calls > 1 {
				return nil, protocolError{errors.New("unexpected second JOIN")}
			}
			return replacement, nil
		})
		peers[0].Close()
		peers[1].Close()
		ack := bundleRead(t, peer)
		if ack.typ != typeACK {
			t.Fatalf("new lane=%+v", ack)
		}
		synctest.Wait()
		c.mu.Lock()
		recovering := c.recovering
		c.mu.Unlock()
		if calls != 1 || recovering {
			t.Fatalf("JOIN calls=%d recovering=%v", calls, recovering)
		}
		result := make(chan error, 1)
		go func() { _, err := c.Write([]byte("joined")); result <- err }()
		f := bundleRead(t, peer)
		if f.typ != typeData || f.sequence != 0 {
			t.Fatalf("joined data=%+v", f)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
}

func TestTCPBundleHalfCloseWaitsForACK(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peers := bundleTestConn(t, nil)
		result := make(chan error, 1)
		go func() { _, err := c.Write([]byte("abc")); result <- err }()
		_ = bundleRead(t, peers[0])
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		go func() { result <- c.CloseWrite() }()
		synctest.Wait()
		c.mu.Lock()
		fin := c.localFIN
		c.mu.Unlock()
		if fin {
			t.Fatal("FIN before cumulative ACK")
		}
		up := bundleFrame(typeACK, 3, "")
		up.flags = flagACKUp
		bundleWrite(t, peers[1], up)
		f := bundleRead(t, peers[1])
		if f.typ != typeClose || f.flags != flagFIN || f.sequence != 3 {
			t.Fatalf("FIN=%+v", f)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		up.flags |= flagACKFinal
		bundleWrite(t, peers[1], up)
		down := bundleFrame(typeClose, 0, "")
		down.flags = flagFIN
		bundleWrite(t, peers[0], down)
		final := bundleRead(t, peers[0])
		if final.typ != typeACK || final.flags != flagACKDown|flagACKFinal || final.sequence != 0 {
			t.Fatalf("final ACK=%+v", final)
		}
		select {
		case <-c.done:
		case <-time.After(time.Second):
			t.Fatal("logical close did not complete")
		}
		if !errors.Is(c.err, io.EOF) {
			t.Fatalf("logical final error=%v", c.err)
		}
	})
}
func TestTCPBundleRecoveryBudget(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{"protocol", gatewayResetError{1}, 1}, {"identity", identityError{errors.New("expired")}, 1},
		{"capacity", gatewayResetError{4}, 3}, {"transport", io.ErrUnexpectedEOF, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				c, peers := bundleTestConn(t, func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) { calls++; return nil, test.err })
				peers[0].Close()
				peers[1].Close()
				select {
				case <-c.done:
				case <-time.After(41 * time.Second):
					t.Fatal("unbounded recovery")
				}
				if calls != test.want {
					t.Fatalf("JOIN attempts=%d want=%d", calls, test.want)
				}
			})
		})
	}
}
func TestTCPBundleRejectsFrameIdentityAndConflictingData(t *testing.T) {
	for _, kind := range []string{"identity", "overlap", "flags", "window"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, peers := bundleTestConn(t, nil)
				for _, p := range peers {
					go io.Copy(io.Discard, p)
				}
				f := bundleFrame(typeData, 3, "def")
				bundleWrite(t, peers[0], f)
				switch kind {
				case "identity":
					f.flow++
				case "overlap":
					f.payload = []byte("xyz")
				case "flags":
					f.flags = flagFIN
				case "window":
					f.sequence = receiveLimit + 1
				}
				// Receiver may close immediately after consuming this complete frame.
				_ = writeFrame(peers[1], f)
				select {
				case <-c.done:
				case <-time.After(time.Second):
					t.Fatal("invalid logical frame accepted")
				}
			})
		})
	}
}

func TestTCPBundleRetiredLaneCannotCompleteFlow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _ := bundleTestConn(t, nil)
		c.mu.Lock()
		old := c.bundle.lanes[1]
		old.finalACK, old.fin = true, true
		c.bundle.lanes[1] = nil
		c.localFinalACK, c.remoteFIN = true, true
		c.recovering = true
		c.mu.Unlock()
		c.bundle.failLane(old, io.ErrUnexpectedEOF)
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		abortCarrier(old.raw)
		if closed {
			t.Fatal("stale retired generation completed active flow")
		}
	})
}

func TestTCPBundleUnreadOverlap(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "partial"}[partial], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, peers := bundleTestConn(t, nil)
				for _, p := range peers {
					go io.Copy(io.Discard, p)
				}
				bundleWrite(t, peers[0], bundleFrame(typeData, 0, "abcdef"))
				synctest.Wait()
				bundleWrite(t, peers[1], bundleFrame(typeData, 2, "cdef"))
				synctest.Wait()
				c.mu.Lock()
				closed := c.closed
				size := c.queue.Len()
				c.mu.Unlock()
				if closed || size != 6 {
					t.Fatalf("matching unread duplicate: closed=%v bytes=%d", closed, size)
				}
				offset, payload := uint64(0), "xbcdef"
				if partial {
					offset, payload = 4, "xfg"
				}
				_ = writeFrame(peers[1], bundleFrame(typeData, offset, payload))
				select {
				case <-c.done:
				case <-time.After(time.Second):
					t.Fatal("conflicting unread overlap accepted")
				}
			})
		})
	}
}

func TestTCPBundleACKWaitsForRecoveryAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		replacement, peer := net.Pipe()
		defer peer.Close()
		calls := 0
		c, peers := bundleTestConn(t, func(ctx context.Context, _ [16]byte, _, _ uint64) (net.Conn, error) {
			calls++
			if calls < 3 {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			time.Sleep(4900 * time.Millisecond)
			return replacement, nil
		})
		peers[0].Close()
		peers[1].Close()
		synctest.Wait()
		// One pending normal ACK must survive the 5+5+4.9 second handshakes and
		// 0.1+0.2 second retry backoff, which exceed a 15-second write budget.
		c.queueACK(0, false)
		go io.Copy(io.Discard, peer)
		time.Sleep(16 * time.Second)
		synctest.Wait()
		c.mu.Lock()
		closed, recovering, err := c.closed, c.recovering, c.err
		c.mu.Unlock()
		if closed || recovering || calls != 3 {
			t.Fatalf("control preempted admission: closed=%v recovering=%v calls=%d err=%v", closed, recovering, calls, err)
		}
	})
}

func TestTCPBundleACKWaitsForCapacityBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		replacement, peer := net.Pipe()
		defer peer.Close()
		calls := 0
		c, peers := bundleTestConn(t, func(ctx context.Context, _ [16]byte, _, _ uint64) (net.Conn, error) {
			calls++
			if calls < 3 {
				return nil, gatewayResetError{4}
			}
			return replacement, nil
		})
		peers[0].Close()
		peers[1].Close()
		synctest.Wait()
		// Capacity refusals delay the third JOIN by 0.1+15 seconds;
		// waiting for that admission must not consume a control write budget.
		c.queueACK(0, false)
		go io.Copy(io.Discard, peer)
		time.Sleep(16 * time.Second)
		synctest.Wait()
		c.mu.Lock()
		closed, recovering, err := c.closed, c.recovering, c.err
		c.mu.Unlock()
		if closed || recovering || calls != 3 {
			t.Fatalf("control preempted admission: closed=%v recovering=%v calls=%d err=%v", closed, recovering, calls, err)
		}
	})
}

type bundleWriteFailure struct {
	net.Conn
	once  sync.Once
	wrote chan struct{}
}

func (c *bundleWriteFailure) Write([]byte) (int, error) {
	c.once.Do(func() { close(c.wrote) })
	return 0, io.ErrClosedPipe
}

func TestTCPBundleTombstoneReadBeforeFailedWriteRetirement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		replacement, peer := net.Pipe()
		defer peer.Close()
		raw := &bundleWriteFailure{Conn: replacement, wrote: make(chan struct{})}
		calls := 0
		c, peers := bundleTestConn(t, func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) {
			calls++
			if calls > 1 {
				return nil, protocolError{errors.New("unexpected repeat JOIN")}
			}
			return raw, nil
		})
		closedWrite := make(chan error, 1)
		go func() { closedWrite <- c.CloseWrite() }()
		fin := bundleRead(t, peers[0])
		if fin.typ != typeClose || fin.flags != flagFIN {
			t.Fatalf("initial FIN=%+v", fin)
		}
		if err := <-closedWrite; err != nil {
			t.Fatal(err)
		}
		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			defer peer.Close()
			<-raw.wrote
			ack := bundleFrame(typeACK, 0, "")
			ack.flags = flagACKUp | flagACKFinal
			if writeFrame(peer, ack) != nil {
				return
			}
			fin := bundleFrame(typeClose, 0, "")
			fin.flags = flagFIN
			_ = writeFrame(peer, fin)
		}()
		peers[0].Close()
		peers[1].Close()
		select {
		case <-c.done:
		case <-time.After(10 * time.Second):
			t.Fatal("tombstone completion stalled")
		}
		<-peerDone
		c.mu.Lock()
		err := c.err
		c.mu.Unlock()
		if !errors.Is(err, io.EOF) || calls != 1 {
			t.Fatalf("discarded queued final frames: calls=%d error=%v", calls, err)
		}
	})
}

func TestTCPBundleCloseCancelsPendingJOIN(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		replacement, peer := net.Pipe()
		defer peer.Close()
		entered := make(chan struct{})
		returned := make(chan struct{})
		c, peers := bundleTestConn(t, func(ctx context.Context, _ [16]byte, _, _ uint64) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			close(returned)
			// A connector returning a late success cannot install it after close.
			return replacement, nil
		})
		peers[0].Close()
		peers[1].Close()
		<-entered
		c.Close()
		<-returned
		peer.SetReadDeadline(time.Now().Add(time.Second))
		var data [1]byte
		if _, err := peer.Read(data[:]); !errors.Is(err, io.EOF) {
			t.Fatalf("late JOIN carrier was not closed: %v", err)
		}
		c.mu.Lock()
		live := c.bundle.lanes[0] != nil || c.bundle.lanes[1] != nil
		c.mu.Unlock()
		if live {
			t.Fatal("late JOIN resurrected closed bundle")
		}
	})
}
