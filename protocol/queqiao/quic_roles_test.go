package queqiao

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestQUICRolesConfiguration(t *testing.T) {
	for _, opts := range []option.QueqiaoOutboundOptions{
		{QUICDataIsolation: true, TCPRecovery: true},
		{QUICDataIsolation: true, Transport: "tcp", TCPRecovery: true},
		{QUICDataIsolation: true, Transport: "quic"},
	} {
		opts.ProfilePath = "unused"
		if _, err := NewOutbound(context.Background(), nil, nil, "roles", opts); err == nil {
			t.Fatalf("invalid options accepted: %+v", opts)
		}
	}
}
func roleTestConn(t *testing.T, join joinLaneFunc) (*Conn, [2]net.Conn) {
	t.Helper()
	a, p := net.Pipe()
	b, q := net.Pipe()
	if join == nil {
		join = func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) {
			return nil, protocolError{errors.New("unexpected control JOIN")}
		}
	}
	c := newQUICRoleConn(a, b, [16]byte{1}, 2, nil, context.Background(), join)
	t.Cleanup(func() { c.terminate(net.ErrClosed); p.Close(); q.Close() })
	return c, [2]net.Conn{p, q}
}
func TestQUICRolesSingleDesignatedData(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, p := roleTestConn(t, nil)
		result := make(chan error, 1)
		go func() { _, err := c.Write([]byte("first")); result <- err }()
		synctest.Wait()
		p[0].SetReadDeadline(time.Now().Add(time.Millisecond))
		var one [1]byte
		if _, err := p[0].Read(one[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("DATA leaked onto control: %v", err)
		}
		bundleWrite(t, p[0], bundleFrame(typeData, 0, "ok"))
		ack := bundleRead(t, p[0])
		if ack.typ != typeACK || ack.sequence != 2 {
			t.Fatalf("control bypass=%+v", ack)
		}
		first := bundleRead(t, p[1])
		if first.typ != typeData || string(first.payload) != "first" {
			t.Fatalf("DATA=%+v", first)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		go func() { _, err := c.Write([]byte("second")); result <- err }()
		second := bundleRead(t, p[1])
		if second.typ != typeData || second.sequence != 5 {
			t.Fatalf("designated DATA=%+v", second)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
}
func TestQUICRolesDataFailureUsesControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, p := roleTestConn(t, nil)
		result := make(chan error, 1)
		go func() { _, err := c.Write([]byte("abc")); result <- err }()
		_ = bundleRead(t, p[1])
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		p[1].Close()
		ack := bundleRead(t, p[0])
		if ack.typ != typeACK {
			t.Fatalf("recovery ACK=%+v", ack)
		}
		replay := bundleRead(t, p[0])
		if replay.typ != typeData || replay.sequence != 0 || string(replay.payload) != "abc" {
			t.Fatalf("control replay=%+v", replay)
		}
		up := bundleFrame(typeACK, 3, "")
		up.flags = flagACKUp
		bundleWrite(t, p[0], up)
		synctest.Wait()
		c.mu.Lock()
		attempts := c.recoveryAttempts
		data := c.bundle.lanes[1]
		c.mu.Unlock()
		if attempts != 0 || data != nil {
			t.Fatal("data lane was refilled or not retired")
		}
		go func() { _, err := c.Write([]byte("def")); result <- err }()
		f := bundleRead(t, p[0])
		if f.sequence != 3 || string(f.payload) != "def" {
			t.Fatalf("control continuation=%+v", f)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
}
func TestQUICRolesControlReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		replacement, peer := net.Pipe()
		defer peer.Close()
		calls := 0
		c, p := roleTestConn(t, func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) { calls++; return replacement, nil })
		p[0].Close()
		ack := bundleRead(t, p[1])
		if ack.typ != typeACK {
			t.Fatalf("temporary control=%+v", ack)
		}
		restored := bundleRead(t, peer)
		if restored.typ != typeACK {
			t.Fatalf("new control=%+v", restored)
		}
		synctest.Wait()
		c.mu.Lock()
		sameData := c.bundle.lanes[1] != nil
		restoring := c.bundle.roles.restoring
		c.mu.Unlock()
		if calls != 1 || !sameData || restoring {
			t.Fatalf("role replacement: calls=%d data=%v restoring=%v", calls, sameData, restoring)
		}
		result := make(chan error, 1)
		go func() { _, err := c.Write([]byte("still-isolated")); result <- err }()
		f := bundleRead(t, p[1])
		if f.typ != typeData {
			t.Fatalf("data moved on control restoration: %+v", f)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
}
func TestQUICRolesAllFailureRestoresControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		replacement, peer := net.Pipe()
		defer peer.Close()
		calls := 0
		c, p := roleTestConn(t, func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) { calls++; return replacement, nil })
		p[0].Close()
		p[1].Close()
		ack := bundleRead(t, peer)
		if ack.typ != typeACK {
			t.Fatalf("recovery=%+v", ack)
		}
		synctest.Wait()
		c.mu.Lock()
		control, data := c.bundle.lanes[0], c.bundle.lanes[1]
		c.mu.Unlock()
		if calls != 1 || control == nil || data != nil {
			t.Fatalf("all failure roles: calls=%d control=%v data=%v", calls, control != nil, data != nil)
		}
	})
}
func TestQUICRolesLateControlJoinAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		replacement, peer := net.Pipe()
		defer peer.Close()
		entered := make(chan struct{})
		returned := make(chan struct{})
		c, p := roleTestConn(t, func(ctx context.Context, _ [16]byte, _, _ uint64) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			close(returned)
			return replacement, nil
		})
		p[0].Close()
		_ = bundleRead(t, p[1])
		<-entered
		c.Close()
		<-returned
		peer.SetReadDeadline(time.Now().Add(time.Second))
		var buf [1]byte
		if _, err := peer.Read(buf[:]); !errors.Is(err, io.EOF) {
			t.Fatalf("late control not closed: %v", err)
		}
		c.mu.Lock()
		live := c.bundle.lanes[0] != nil || c.bundle.lanes[1] != nil
		c.mu.Unlock()
		if live {
			t.Fatal("late result resurrected role")
		}
	})
}
func TestQUICRolesRefusalIsTerminal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, p := roleTestConn(t, func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) { return nil, gatewayResetError{2} })
		p[0].Close()
		_ = bundleRead(t, p[1])
		select {
		case <-c.done:
		case <-time.After(time.Second):
			t.Fatal("identity refusal hidden behind surviving data lane")
		}
	})
}

type roleDrainCarrier struct {
	net.Conn
	started chan struct{}
	release <-chan struct{}
	aborts  *atomic.Int32
}

func (c *roleDrainCarrier) Close() error { c.started <- struct{}{}; <-c.release; return c.Conn.Close() }
func (c *roleDrainCarrier) Abort() error { c.aborts.Add(1); return c.Conn.Close() }
func TestQUICRolesNormalDrainAndCancel(t *testing.T) {
	for _, normal := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "normal"}[normal], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, p := net.Pipe()
				b, q := net.Pipe()
				defer p.Close()
				defer q.Close()
				started := make(chan struct{}, 2)
				release := make(chan struct{})
				var releaseOnce sync.Once
				defer releaseOnce.Do(func() { close(release) })
				var aborts atomic.Int32
				first := &roleDrainCarrier{a, started, release, &aborts}
				second := &roleDrainCarrier{b, started, release, &aborts}
				removed := make(chan struct{})
				c := newQUICRoleConn(first, second, [16]byte{1}, 2, func() { close(removed) }, context.Background(), nil)
				ended := make(chan struct{})
				go func() {
					defer close(ended)
					if normal {
						c.terminate(io.EOF)
					} else {
						c.terminate(net.ErrClosed)
					}
				}()
				if normal {
					<-started
					<-started
					select {
					case <-removed:
						t.Fatal("resources released before both stream drains")
					default:
					}
					releaseOnce.Do(func() { close(release) })
				}
				<-ended
				<-removed
				if got := aborts.Load(); normal && got != 0 || !normal && got != 2 {
					t.Fatalf("normal=%v abort calls=%d", normal, got)
				}
			})
		})
	}
}

func TestQUICRolesCapacityCannotMaskRefusal(t *testing.T) {
	for _, terminal := range []error{identityError{errors.New("identity")}, protocolError{errors.New("protocol")}, gatewayResetError{2}, context.Canceled, quicProbeError{context.DeadlineExceeded}, quicStreamOpenError{context.DeadlineExceeded}} {
		for _, capacity := range []error{gatewayResetError{4}, errQUICConnectionCapacity} {
			for _, err := range []error{errors.Join(capacity, terminal), errors.Join(terminal, capacity)} {
				if isolationMayDegrade(err) {
					t.Errorf("capacity masked terminal failure: %v", err)
				}
			}
		}
	}
}
func TestQUICRolesOldRestoreCannotClearNewWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dead, peer := net.Pipe()
		peer.Close()
		enteredSecond := make(chan struct{})
		calls := 0
		c, p := roleTestConn(t, func(ctx context.Context, _ [16]byte, _, _ uint64) (net.Conn, error) {
			calls++
			if calls == 1 {
				return dead, nil
			}
			if calls == 2 {
				close(enteredSecond)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
		// All ACKs may use DATA while each control replacement is unavailable.
		go io.Copy(io.Discard, p[1])
		p[0].Close()
		<-enteredSecond
		synctest.Wait()
		c.mu.Lock()
		restoring := c.bundle.roles.restoring
		c.mu.Unlock()
		if !restoring {
			t.Error("old worker cleared the newer pending JOIN ownership")
		}
		c.bundle.roles.restoreControl()
		synctest.Wait()
		if calls != 2 {
			t.Errorf("concurrent replacement workers: calls=%d", calls)
		}
		c.Close()
	})
}

func TestQUICRolesAdmissionEOFIsNotApplicationEOF(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(map[bool]string{false: "control", true: "all"}[all], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, p := roleTestConn(t, func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) { return nil, io.EOF })
				p[0].Close()
				if all {
					p[1].Close()
				} else {
					_ = bundleRead(t, p[1])
				}
				select {
				case <-c.done:
				case <-time.After(time.Second):
					t.Fatal("refused role did not terminate")
				}
				var data [1]byte
				_, err := c.Read(data[:])
				if err == nil || errors.Is(err, io.EOF) {
					t.Fatalf("JOIN EOF became application completion without FIN: %v", err)
				}
			})
		})
	}
}

func TestQUICRolesKnownRefusalAtRestorationDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, p := roleTestConn(t, func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) {
			time.Sleep(recoveryTimeout)
			synctest.Wait()
			return nil, identityError{errors.New("known identity refusal")}
		})
		p[0].Close()
		_ = bundleRead(t, p[1])
		time.Sleep(recoveryTimeout + time.Second)
		synctest.Wait()
		c.mu.Lock()
		closed, err := c.closed, c.err
		c.mu.Unlock()
		var identity identityError
		if !closed || !errors.As(err, &identity) {
			t.Fatalf("restoration deadline hid known refusal: closed=%v error=%v", closed, err)
		}
	})
}

func TestQUICRolesAllLaneDeadlineIsNotEOF(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, p := roleTestConn(t, func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) {
			return nil, context.DeadlineExceeded
		})
		p[0].Close()
		p[1].Close()
		select {
		case <-c.done:
		case <-time.After(41 * time.Second):
			t.Fatal("unbounded deadline recovery")
		}
		var buf [1]byte
		_, err := c.Read(buf[:])
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) {
			t.Fatalf("transport deadline became application EOF: %v", err)
		}
	})
}
