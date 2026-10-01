package queqiao

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func testOfficialTCPRecovery(t *testing.T, profile, transport string) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var accepts atomic.Int32
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	destination := M.ParseSocksaddr(target.Addr().String())
	a, err := NewOutbound(context.Background(), nil, nil, "recovery", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: transport, TCPRecovery: true})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, err := o.DialContext(ctx, "tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*Conn)
	defer c.Close()
	c.SetDeadline(time.Now().Add(12 * time.Second))
	payload := bytes.Repeat([]byte("native-join-replay-0123456789"), 160000)
	wrote := make(chan error, 1)
	go func() {
		_, e := c.Write(payload)
		if e == nil {
			e = c.CloseWrite()
		}
		wrote <- e
	}()
	prefix := make([]byte, 256<<10)
	if _, err = io.ReadFull(c, prefix); err != nil {
		t.Fatal(err)
	}
	breakTestCarrier(c, true)
	rest, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("recovered read: %v", err)
	}
	if err = <-wrote; err != nil {
		t.Fatalf("recovered write: %v", err)
	}
	got := append(prefix, rest...)
	if !bytes.Equal(got, payload) {
		t.Fatalf("replay corrupted/duplicated bytes: got=%d want=%d", len(got), len(payload))
	}
	select {
	case <-c.done:
	case <-ctx.Done():
		t.Fatal("recovered FIN did not complete")
	}
	c.mu.Lock()
	attempts, retained, finalErr := c.recoveryAttempts, len(c.replay), c.err
	c.mu.Unlock()
	if attempts < 1 || attempts > maxRecoveryAttempts || retained != 0 || !errors.Is(finalErr, io.EOF) {
		t.Fatalf("recovery state attempts=%d replay=%d error=%v", attempts, retained, finalErr)
	}
	if accepts.Load() != 1 {
		t.Fatalf("recovery opened %d destination sockets", accepts.Load())
	}
}

func TestRecoveryRetryPolicyAndBudget(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{"protocol", gatewayResetError{1}, 1}, {"authentication", gatewayResetError{2}, 1}, {"destination", gatewayResetError{3}, 1}, {"capacity", gatewayResetError{4}, 3}, {"transport-mode", gatewayResetError{5}, 1},
		{"malformed", protocolError{errors.New("bad frame")}, 1}, {"identity", identityError{errors.New("expired")}, 1}, {"I/O", io.ErrUnexpectedEOF, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, peer := net.Pipe()
				var calls atomic.Int32
				c := newRecoverableConn(client, [16]byte{1}, 2, nil, context.Background(), func(ctx context.Context, s [16]byte, f, lane uint64) (net.Conn, error) {
					if s != ([16]byte{1}) || f != 2 || lane == 0 {
						t.Error("replacement identity changed")
					}
					calls.Add(1)
					return nil, test.err
				})
				defer c.Close()
				peer.Close()
				select {
				case <-c.done:
				case <-time.After(50 * time.Second):
					t.Fatal("recovery retry was unbounded")
				}
				if int(calls.Load()) != test.want {
					t.Fatalf("attempts=%d want=%d", calls.Load(), test.want)
				}
			})
		})
	}
}

func TestRecoveryCloseCancelsJoinAndReadDeadline(t *testing.T) {
	client, peer := net.Pipe()
	entered, exited := make(chan struct{}), make(chan struct{})
	c := newRecoverableConn(client, [16]byte{1}, 2, nil, context.Background(), func(ctx context.Context, _ [16]byte, _, _ uint64) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		close(exited)
		return nil, ctx.Err()
	})
	peer.Close()
	<-entered
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline during JOIN: %v", err)
	}
	c.SetReadDeadline(time.Time{})
	start := time.Now()
	c.Close()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel JOIN")
	}
	if time.Since(start) > time.Second {
		t.Fatal("Close waited for recovery budget")
	}
}

func TestRecoveryWindowAndSelectiveACK(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	c := newRecoverableConn(client, [16]byte{1}, 2, nil, context.Background(), func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) { return nil, gatewayResetError{1} })
	defer c.Close()
	go func() {
		for {
			if _, err := readFrame(peer); err != nil {
				return
			}
		}
	}()
	c.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if n, err := c.Write(make([]byte, sendWindow)); n != sendWindow || err != nil {
		t.Fatalf("fill replay window: %d %v", n, err)
	}
	c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	n, err := c.Write([]byte{1})
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("full-window backpressure: %d %v", n, err)
	}
	c.mu.Lock()
	retained := 0
	for _, s := range c.replay {
		retained += len(s.data)
	}
	c.mu.Unlock()
	if retained != sendWindow {
		t.Fatalf("retained payload=%d", retained)
	}
	ranges := make([]byte, 16)
	binary.BigEndian.PutUint64(ranges, 16)
	binary.BigEndian.PutUint64(ranges[8:], sendWindow)
	if err = c.handleFrame(frame{typ: typeACK, flags: flagACKUp | flagRanges, sequence: 8, payload: ranges}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	first := c.replay[0]
	retained = 0
	for _, s := range c.replay {
		retained += len(s.data)
	}
	c.mu.Unlock()
	if first.offset != 8 || retained != sendWindow-8 {
		t.Fatal("selective ACK released replay bytes before cumulative prefix")
	}
	if err = c.handleFrame(frame{typ: typeACK, flags: flagACKUp, sequence: sendWindow + 1}); err == nil {
		t.Fatal("ACK beyond accepted bytes admitted")
	}
	c.Close()
	c.mu.Lock()
	retained = len(c.replay)
	c.mu.Unlock()
	if retained != 0 {
		t.Fatal("Close retained replay payload")
	}
}

func TestRecoveryPartialReplayAndDownstreamDedup(t *testing.T) {
	client, peer := net.Pipe()
	session := [16]byte{1}
	flow := uint64(2)
	replayed := make(chan frame, 1)
	c := newRecoverableConn(client, session, flow, nil, context.Background(), func(ctx context.Context, s [16]byte, f, lane uint64) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			defer remote.Close()
			remote.SetDeadline(time.Now().Add(2 * time.Second))
			first, e := readFrame(remote)
			if e != nil || first.typ != typeACK || first.sequence != 4 {
				t.Errorf("replacement downstream prefix: %+v %v", first, e)
				return
			}
			data, e := readFrame(remote)
			if e != nil {
				t.Error(e)
				return
			}
			replayed <- data
			send := func(f frame) error { f.session, f.flow = session, flow; return writeFrame(remote, f) }
			if e = send(frame{typ: typeACK, flags: flagACKUp, sequence: 10}); e != nil {
				return
			}
			if e = send(frame{typ: typeData, sequence: 0, payload: []byte("abcdefgh")}); e != nil {
				return
			}
			if e = send(frame{typ: typeClose, flags: flagFIN, sequence: 8}); e != nil {
				return
			}
			upDone, downDone := false, false
			for !upDone || !downDone {
				f, e := readFrame(remote)
				if e != nil {
					return
				}
				if f.typ == typeClose {
					if e = send(frame{typ: typeACK, flags: flagACKUp | flagACKFinal, sequence: 10}); e != nil {
						return
					}
					upDone = true
				}
				if f.typ == typeACK && f.flags == flagACKDown|flagACKFinal {
					downDone = true
				}
			}
		}()
		return local, nil
	})
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	go func() {
		defer peer.Close()
		if _, err := readFrame(peer); err != nil {
			return
		}
		writeFrame(peer, frame{typ: typeACK, flags: flagACKUp, session: session, flow: flow, sequence: 4})
		writeFrame(peer, frame{typ: typeData, session: session, flow: flow, payload: []byte("abcd")})
	}()
	if n, err := c.Write([]byte("0123456789")); n != 10 || err != nil {
		t.Fatalf("initial write %d %v", n, err)
	}
	first := make([]byte, 4)
	if _, err := io.ReadFull(c, first); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(c)
	if err != nil || string(first)+string(rest) != "abcdefgh" {
		t.Fatalf("duplicate downstream %q %q: %v", first, rest, err)
	}
	if err = c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-replayed:
		if f.typ != typeData || f.sequence != 4 || string(f.payload) != "456789" {
			t.Fatalf("replay wrong offset/data: %+v", f)
		}
	case <-time.After(time.Second):
		t.Fatal("no replay")
	}
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("final state did not settle")
	}
}

// Fault injection sits above the authenticated carrier only in these tests.
// Every emitted ACK/DATA/FIN still comes from the unmodified official gateway.
type frameFaultState struct{ fired, heldFinal, cut atomic.Bool }
type frameFaultConn struct {
	net.Conn
	mode        string
	buffered    bytes.Buffer
	state       *frameFaultState
	finObserved bool
}

func (c *frameFaultConn) Read(p []byte) (int, error) {
	for c.buffered.Len() == 0 {
		if c.mode == "downstream-final-ACK-loss" && c.finObserved && c.state.fired.CompareAndSwap(false, true) {
			abortCarrier(c.Conn)
			return 0, io.ErrUnexpectedEOF
		}
		f, err := readFrame(c.Conn)
		if err != nil {
			return 0, err
		}
		if c.mode == "upstream-ACK-loss" && f.typ == typeACK && f.flags&flagACKUp != 0 && c.state.fired.CompareAndSwap(false, true) {
			abortCarrier(c.Conn)
			return 0, io.ErrUnexpectedEOF
		}
		if c.mode == "completed-tombstone" && f.typ == typeACK && f.flags == flagACKUp|flagACKFinal && !c.state.heldFinal.Swap(true) {
			c.state.fired.Store(true)
			continue
		}
		if f.typ == typeClose && f.flags == flagFIN {
			c.finObserved = true
		}
		if err = writeFrame(&c.buffered, f); err != nil {
			return 0, err
		}
	}
	return c.buffered.Read(p)
}
func (c *frameFaultConn) Write(p []byte) (int, error) {
	f, parseErr := readFrame(bytes.NewReader(p))
	final := parseErr == nil && f.typ == typeACK && f.flags == flagACKDown|flagACKFinal
	if c.mode == "downstream-final-ACK-loss" && final {
		// The reader may have published the cutoff before Abort finishes.
		// Never forward the very ACK under test in that interleaving.
		c.state.fired.Store(true)
		abortCarrier(c.Conn)
		return 0, io.ErrUnexpectedEOF
	}
	n, err := c.Conn.Write(p)
	if c.mode == "completed-tombstone" && final && c.state.heldFinal.Load() && n == len(p) && err == nil && c.state.cut.CompareAndSwap(false, true) {
		go closeCarrier(c.Conn)
	}
	return n, err
}
func (c *frameFaultConn) Close() error { closeCarrier(c.Conn); return nil }
func (c *frameFaultConn) Abort() error { abortCarrier(c.Conn); return nil }

func testOfficialRecoveryACKLoss(t *testing.T, profile, transport string) {
	for _, mode := range []string{"upstream-ACK-loss", "downstream-final-ACK-loss", "completed-tombstone"} {
		t.Run(mode, func(t *testing.T) {
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			var accepts atomic.Int32
			go func() {
				for {
					c, e := target.Accept()
					if e != nil {
						return
					}
					accepts.Add(1)
					go func() {
						defer c.Close()
						c.SetDeadline(time.Now().Add(15 * time.Second))
						io.Copy(c, c)
						c.(*net.TCPConn).CloseWrite()
					}()
				}
			}()
			destination := M.ParseSocksaddr(target.Addr().String())
			a, err := NewOutbound(context.Background(), nil, nil, "ACK-loss", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: transport, TCPRecovery: true})
			if err != nil {
				t.Fatal(err)
			}
			o := a.(*Outbound)
			defer o.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			opened, err := o.openFlow(ctx, []byte(destination.String()), destination)
			if err != nil {
				t.Fatal(err)
			}
			state := &frameFaultState{}
			fault := &frameFaultConn{Conn: opened.conn, mode: mode, state: state}
			c := newRecoverableConn(fault, opened.session, opened.flow, opened.remove, ctx, func(ctx context.Context, s [16]byte, f, lane uint64) (net.Conn, error) {
				raw, err := o.joinFlow(ctx, destination, opened.generation, s, f, lane)
				if err == nil && !state.fired.Load() {
					return &frameFaultConn{Conn: raw, mode: mode, state: state}, nil
				}
				return raw, err
			})
			if err = opened.install(c); err != nil {
				c.Close()
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(40 * time.Second))
			payload := bytes.Repeat([]byte("last-ACK-and-replay-"), 10000)
			wrote := make(chan error, 1)
			go func() {
				_, e := c.Write(payload)
				if e == nil {
					e = c.CloseWrite()
				}
				wrote <- e
			}()
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("read after ACK loss: %v", err)
			}
			if err = <-wrote; err != nil {
				t.Fatalf("write after ACK loss: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("ACK loss duplicated/truncated payload: %d/%d", len(got), len(payload))
			}
			select {
			case <-c.done:
			case <-ctx.Done():
				t.Fatal("ACK loss did not reach final state")
			}
			c.mu.Lock()
			attempts, finalErr := c.recoveryAttempts, c.err
			c.mu.Unlock()
			if !state.fired.Load() || attempts < 1 || attempts > 3 || !errors.Is(finalErr, io.EOF) {
				t.Fatalf("ACK-loss recovery fired=%v attempts=%d final=%v", state.fired.Load(), attempts, finalErr)
			}
			if accepts.Load() != 1 {
				t.Fatalf("ACK recovery reopened %d destination sockets", accepts.Load())
			}
		})
	}
}

func testOfficialSharedTCPRecovery(t *testing.T, profile string) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var accepts atomic.Int32
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	a, err := NewOutbound(context.Background(), nil, nil, "shared-recovery", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: "quic", TCPRecovery: true})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var conns []*Conn
	for i := 0; i < 8; i++ {
		raw, e := o.DialContext(ctx, "tcp", M.ParseSocksaddr(target.Addr().String()))
		if e != nil {
			t.Fatal(e)
		}
		conns = append(conns, raw.(*Conn))
	}
	assertTestSharedCarrier(t, conns)
	breakTestCarrier(conns[0], true)
	errs := make(chan error, len(conns))
	payload := bytes.Repeat([]byte("shared-pool-rescue"), 65536)
	for _, c := range conns {
		c := c
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			wrote := make(chan error, 1)
			go func() {
				_, e := c.Write(payload)
				if e == nil {
					e = c.CloseWrite()
				}
				wrote <- e
			}()
			got, e := io.ReadAll(c)
			if e == nil {
				e = <-wrote
			}
			if e == nil && !bytes.Equal(got, payload) {
				e = errors.New("shared recovery payload mismatch")
			}
			if e == nil {
				select {
				case <-c.done:
				case <-ctx.Done():
					e = ctx.Err()
				}
			}
			if e == nil {
				c.mu.Lock()
				attempts, finalErr := c.recoveryAttempts, c.err
				c.mu.Unlock()
				if attempts < 1 || attempts > 3 || !errors.Is(finalErr, io.EOF) {
					e = fmt.Errorf("shared recovery attempts=%d final=%v", attempts, finalErr)
				}
			}
			errs <- e
		}()
	}
	for range conns {
		if err = <-errs; err != nil {
			t.Error(err)
		}
	}
	if accepts.Load() != int32(len(conns)) {
		t.Fatalf("shared recovery changed destination count: %d", accepts.Load())
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		o.mu.Lock()
		empty := len(o.active) == 0 && len(o.slots) == 0
		o.mu.Unlock()
		if empty {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shared recovery leaked logical flow slots")
		}
		time.Sleep(time.Millisecond)
	}
}

func testOfficialJoinPrincipal(t *testing.T, profile, otherProfile, transport string, destination M.Socksaddr) {
	makeOutbound := func(path string) *Outbound {
		a, err := NewOutbound(context.Background(), nil, nil, "principal", option.QueqiaoOutboundOptions{ProfilePath: path, Transport: transport, TCPRecovery: true})
		if err != nil {
			t.Fatal(err)
		}
		o := a.(*Outbound)
		t.Cleanup(func() { o.Close() })
		return o
	}
	original, other := makeOutbound(profile), makeOutbound(otherProfile)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := original.DialContext(ctx, "tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*Conn)
	defer c.Close()
	for _, test := range []struct {
		name string
		o    *Outbound
		flow uint64
	}{{"other-device", other, c.flow}, {"other-flow", original, c.flow ^ 1}} {
		joined, e := test.o.joinFlow(ctx, destination, 0, c.session, test.flow, 42)
		if joined != nil {
			joined.Close()
			t.Fatalf("%s JOIN accepted", test.name)
		}
		var reset gatewayResetError
		if !errors.As(e, &reset) || reset.code != 1 {
			t.Fatalf("%s JOIN rejection: %v", test.name, e)
		}
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = c.Write([]byte("original survives")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len("original survives"))
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "original survives" {
		t.Fatalf("principal isolation damaged original flow: %q %v", b, err)
	}
}

func TestRecoveryCloseInterruptsReplayWrite(t *testing.T) {
	client, peer := net.Pipe()
	next, nextPeer := net.Pipe()
	defer nextPeer.Close()
	entered := make(chan struct{})
	c := newRecoverableConn(client, [16]byte{1}, 2, nil, context.Background(), func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) { close(entered); return next, nil })
	peer.Close()
	<-entered
	// The replacement peer never reads the initial ACK: Close must cancel the
	// replay write rather than waiting for its 40-second recovery deadline.
	start := time.Now()
	c.Close()
	if time.Since(start) > time.Second {
		t.Fatal("Close blocked behind replay write")
	}
	nextPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := nextPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("replacement remained open")
	}
}

func TestRecoveryLifetimeAttemptLimit(t *testing.T) {
	client, peer := net.Pipe()
	joined := make(chan net.Conn, 3)
	ready := make(chan struct{}, 3)
	var calls atomic.Int32
	c := newRecoverableConn(client, [16]byte{1}, 2, nil, context.Background(), func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) {
		local, remote := net.Pipe()
		calls.Add(1)
		joined <- remote
		go func() {
			defer remote.Close()
			if _, err := readFrame(remote); err != nil {
				return
			}
			ready <- struct{}{}
			for {
				if _, err := readFrame(remote); err != nil {
					return
				}
			}
		}()
		return local, nil
	})
	defer c.Close()
	for i := 0; i < maxRecoveryAttempts; i++ {
		peer.Close()
		select {
		case peer = <-joined:
		case <-time.After(time.Second):
			t.Fatal("no replacement")
		}
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("replacement did not become ready")
		}
		deadline := time.Now().Add(time.Second)
		for {
			c.mu.Lock()
			recovering := c.recovering
			c.mu.Unlock()
			if !recovering {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("recovery did not settle")
			}
			time.Sleep(time.Millisecond)
		}
	}
	peer.Close()
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("lifetime attempt cap was reset after each outage")
	}
	if calls.Load() != maxRecoveryAttempts {
		t.Fatalf("JOIN calls=%d", calls.Load())
	}
}

func TestRecoverySmallWriteSegmentBound(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	c := newRecoverableConn(client, [16]byte{1}, 2, nil, context.Background(), func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) { return nil, gatewayResetError{1} })
	defer c.Close()
	go func() {
		for {
			if _, err := readFrame(peer); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 1024; i++ {
		if _, err := c.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	if n, err := c.Write([]byte{1}); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("segment limit: %d %v", n, err)
	}
	c.mu.Lock()
	count := len(c.replay)
	c.mu.Unlock()
	if count != 1024 {
		t.Fatalf("segments=%d", count)
	}
}

func testOfficialHalfClosedRecovery(t *testing.T, profile, transport string) {
	if os.Getenv("QUEQIAO_TEST_SLOW_RECOVERY") != "1" {
		t.Skip("set QUEQIAO_TEST_SLOW_RECOVERY=1 for protected-lane admission timing")
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var accepts atomic.Int32
	go func() {
		for {
			raw, e := target.Accept()
			if e != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(35 * time.Second))
				request, e := io.ReadAll(raw)
				if e != nil {
					return
				}
				time.Sleep(2 * time.Second)
				raw.Write(append([]byte("response:"), request...))
				raw.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	a, err := NewOutbound(context.Background(), nil, nil, "half-close-recovery", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: transport, TCPRecovery: true})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
	raw, err := o.DialContext(context.Background(), "tcp", M.ParseSocksaddr(target.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*Conn)
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err = c.Write([]byte("half-closed request")); err != nil {
		t.Fatal(err)
	}
	if err = c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		c.mu.Lock()
		acked := c.localFinalACK
		c.mu.Unlock()
		if acked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial FIN was not acknowledged")
		}
		time.Sleep(time.Millisecond)
	}
	// Break only the terminal stream, leaving the pooled connection alive.
	// The official QUIC gateway protects its young lane for 15 seconds.
	breakTestCarrier(c, false)
	body, err := io.ReadAll(c)
	if err != nil || string(body) != "response:half-closed request" {
		t.Fatalf("half-close recovery %q: %v", body, err)
	}
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("half-close recovery did not complete")
	}
	c.mu.Lock()
	attempts, finalErr := c.recoveryAttempts, c.err
	c.mu.Unlock()
	if attempts < 1 || attempts > 3 || !errors.Is(finalErr, io.EOF) || accepts.Load() != 1 {
		t.Fatalf("half-close attempts=%d final=%v destinations=%d", attempts, finalErr, accepts.Load())
	}
}

func TestRecoveryWriteDeadlineReportsAcceptedBytes(t *testing.T) {
	client, peer := net.Pipe()
	entered := make(chan struct{})
	c := newRecoverableConn(client, [16]byte{1}, 2, nil, context.Background(), func(ctx context.Context, _ [16]byte, _, _ uint64) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	defer c.Close()
	go func() { peer.Read(make([]byte, 1)); peer.Close() }()
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	payload := []byte("retained despite a partial physical write")
	go func() { n, err := c.Write(payload); done <- result{n, err} }()
	<-entered
	c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case r := <-done:
		if r.n != len(payload) || !errors.Is(r.err, os.ErrDeadlineExceeded) {
			t.Fatalf("accepted prefix=%d %v", r.n, r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("write deadline did not interrupt recovery wait")
	}
	if n, err := c.Write([]byte("new")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired deadline accepted new bytes: %d %v", n, err)
	}
	c.mu.Lock()
	retained := 0
	for _, s := range c.replay {
		retained += len(s.data)
	}
	c.mu.Unlock()
	if retained != len(payload) {
		t.Fatalf("accepted bytes not retained: %d", retained)
	}
}

func TestFrameFaultFinalACKCannotRaceCutoff(t *testing.T) {
	for _, alreadyFired := range []bool{false, true} {
		local, remote := net.Pipe()
		state := &frameFaultState{}
		state.fired.Store(alreadyFired)
		c := &frameFaultConn{Conn: local, mode: "downstream-final-ACK-loss", state: state}
		var wire bytes.Buffer
		writeFrame(&wire, frame{typ: typeACK, flags: flagACKDown | flagACKFinal})
		if n, err := c.Write(wire.Bytes()); n != 0 || err == nil {
			t.Fatalf("fault forwarded final ACK: %d %v", n, err)
		}
		remote.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := remote.Read(make([]byte, headerSize)); n != 0 || err == nil {
			t.Fatalf("peer received dropped ACK: %d %v", n, err)
		}
		remote.Close()
	}
}

func TestRecoveryCompletionWaitsForReplacement(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	c := newConnState(client, [16]byte{1}, 2, nil)
	c.localFIN = true
	c.localFinalACK = true
	c.remoteFIN = true
	c.remoteFinalACKSent = true
	c.recovering = true
	c.finishIfComplete()
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		t.Fatal("queued old final ACK completed flow during carrier recovery")
	}
	c.mu.Lock()
	c.recovering = false
	c.mu.Unlock()
	c.finishIfComplete()
	select {
	case <-c.done:
	default:
		t.Fatal("settled completion did not close flow")
	}
}

func TestRecoveryCloseCancelsCapacityBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, peer := net.Pipe()
		calls := make(chan struct{}, 3)
		c := newRecoverableConn(local, [16]byte{1}, 2, nil, context.Background(), func(context.Context, [16]byte, uint64, uint64) (net.Conn, error) {
			calls <- struct{}{}
			return nil, gatewayResetError{4}
		})
		peer.Close()
		<-calls
		<-calls
		// The third attempt would wait for the gateway's 15-second protection.
		before := time.Now()
		c.Close()
		synctest.Wait()
		if time.Since(before) >= time.Second {
			t.Fatal("Close waited through capacity backoff")
		}
		select {
		case <-calls:
			t.Fatal("JOIN continued after Close")
		default:
		}
	})
}
