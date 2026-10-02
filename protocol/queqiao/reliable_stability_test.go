//go:build with_quic

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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

const stabilityRounds = 48
const stabilityPayload = 32 << 10

// This is a finite lifecycle exercise, not a throughput or WAN simulation.
// Two competing QUIC pools each retain two logical TCP flows; a separate TLS
// flow runs beside them. Three interruption events close four owned QUIC
// connections while a
// target reply is held. Short-flow churn and one read timeout test isolation.
func TestReliableCompetingConnections(t *testing.T) {
	bin := os.Getenv("QUEQIAO_GATEWAY_BINARY")
	if bin == "" {
		t.Skip("set QUEQIAO_GATEWAY_BINARY to the reviewed companion candidate")
	}
	for _, feedback := range []bool{false, true} {
		t.Run(fmt.Sprintf("feedback-%v", feedback), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			var exchanges sync.WaitGroup
			t.Cleanup(exchanges.Wait)
			profile := stabilityGateway(t, ctx, bin, feedback)
			target := newStabilityTarget(t, ctx)
			outs := make([]*Outbound, 3)
			meters := make([]*roleSocketMeter, 2)
			for i := range outs {
				transport := "quic"
				if i == 2 {
					transport = "tcp"
				}
				a, err := NewOutbound(ctx, nil, nil, "stability", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: transport, TCPRecovery: true, QUICDataIsolation: i < 2})
				if err != nil {
					t.Fatal(err)
				}
				outs[i] = a.(*Outbound)
				defer outs[i].Close()
				if i < 2 {
					meters[i] = newRoleSocketMeter(outs[i])
				}
			}
			flows := make([]*Conn, 5)
			for i := range flows {
				o := outs[i/2]
				if i == 4 {
					o = outs[2]
				}
				raw, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr(target.listener.Addr().String()))
				if err != nil {
					t.Fatal(err)
				}
				flows[i] = raw.(*Conn)
				defer flows[i].Close()
			}
			for i := 0; i < 4; i++ {
				flows[i].mu.Lock()
				complete := flows[i].bundle != nil && flows[i].bundle.lanes[0] != nil && flows[i].bundle.lanes[1] != nil
				flows[i].mu.Unlock()
				if !complete {
					t.Fatal("initial isolated role pair not admitted")
				}
			}
			started := time.Now()
			for seq := 0; seq < stabilityRounds; seq++ {
				results := make(chan error, len(flows))
				for id, c := range flows {
					exchanges.Add(1)
					go func(id int, c *Conn) {
						defer exchanges.Done()
						results <- stabilityExchange(c, uint32(id), uint32(seq), id == 0 && seq == 20, target)
					}(id, c)
				}
				if seq == 12 || seq == 28 || seq == 36 {
					select {
					case held := <-target.held:
						id := 0
						if seq != 12 {
							id = 2
						}
						if held.id != uint32(id) || held.seq != uint32(seq) {
							close(held.release)
							t.Fatalf("unexpected held frame %d/%d", held.id, held.seq)
						}
						c := flows[id]
						c.mu.Lock()
						control, data := c.bundle.lanes[0], c.bundle.lanes[1]
						c.mu.Unlock()
						if (seq == 12 || seq == 28) && control == nil || (seq == 12 || seq == 36) && data == nil {
							close(held.release)
							t.Fatal("fault role missing before planned interruption")
						}
						if seq == 12 || seq == 36 {
							stabilityInterrupt(t, ctx, data.raw.(*quicCarrier), "data")
						}
						if seq == 12 || seq == 28 {
							stabilityInterrupt(t, ctx, control.raw.(*quicCarrier), "control")
						}
						close(held.release)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				for range flows {
					select {
					case err := <-results:
						if err != nil {
							t.Fatalf("round %d: %v", seq, err)
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				if seq%8 == 7 {
					i := seq / 8
					owner := outs[i%2]
					raw, err := owner.DialContext(ctx, "tcp", M.ParseSocksaddr(target.listener.Addr().String()))
					if err != nil {
						t.Fatal(err)
					}
					churn := raw.(*Conn)
					if err = stabilityExchange(churn, uint32(100+i), 0, false, target); err != nil {
						churn.Close()
						t.Fatal(err)
					}
					if i%2 == 0 {
						churn.Close()
					} else {
						stabilityFinal(t, ctx, churn)
						churn.Close()
					}
					// Natural release, not forced map clearing or closing the pool.
					eventually(t, func() bool {
						owner.mu.Lock()
						n := len(owner.active)
						owner.mu.Unlock()
						return n == 2 && len(owner.slots) == 2
					})
				}
				select {
				case err := <-target.errors:
					t.Fatal(err)
				default:
				}
				// A fixed minimum duration lets each live flow cross the gateway's
				// age classifier while avoiding busy-loop stress or rate ranking.
				if wait := time.Until(started.Add(time.Duration(seq+1) * 250 * time.Millisecond)); wait > 0 {
					timer := time.NewTimer(wait)
					select {
					case <-timer.C:
					case <-ctx.Done():
						timer.Stop()
						t.Fatal(ctx.Err())
					}
				}
			}
			for _, c := range flows {
				stabilityFinal(t, ctx, c)
			}
			for _, o := range outs {
				eventually(t, func() bool { o.mu.Lock(); n := len(o.active); o.mu.Unlock(); return n == 0 && len(o.slots) == 0 })
				o.Close()
			}
			for i, m := range meters {
				eventually(t, func() bool { return m.active.Load() == 0 })
				if m.peak.Load() > 4 {
					t.Fatalf("pool%d exceeded four sockets: %d", i, m.peak.Load())
				}
			}
			until := time.Now().Add(3 * time.Second)
			for {
				target.mu.Lock()
				active := target.active
				ids := fmt.Sprint(target.activeIDs)
				target.mu.Unlock()
				if active == 0 {
					break
				}
				if time.Now().After(until) {
					t.Errorf("target release timeout: active=%d logicalIDs=%s", active, ids)
					break
				}
				time.Sleep(time.Millisecond)
			}
			target.mu.Lock()
			if target.accepted != 11 || len(target.counts) != 11 {
				t.Errorf("destination ownership changed: accepts=%d logical=%d", target.accepted, len(target.counts))
			}
			for id := uint32(0); id < 5; id++ {
				if target.counts[id] != stabilityRounds {
					t.Errorf("flow%d delivered%d requests", id, target.counts[id])
				}
			}
			for id := uint32(100); id < 106; id++ {
				if target.counts[id] != 1 {
					t.Errorf("churn%d delivered%d requests", id, target.counts[id])
				}
			}
			target.mu.Unlock()
			select {
			case err := <-target.errors:
				t.Fatal(err)
			default:
			}
			for i, c := range flows {
				c.mu.Lock()
				attempts := c.recoveryAttempts
				c.mu.Unlock()
				if attempts > maxRecoveryAttempts {
					t.Fatalf("flow%d JOIN budget=%d", i, attempts)
				}
				t.Logf("flow=%d JOINs=%d", i, attempts)
			}
			t.Logf("feedback=%v elapsed=%v verified_application_bytes=%d destinations=11 pool_peaks=%d/%d", feedback, time.Since(started), (5*stabilityRounds+6)*stabilityPayload, meters[0].peak.Load(), meters[1].peak.Load())
		})
	}
}

func stabilityExchange(c *Conn, id, seq uint32, readTimeout bool, target *stabilityTarget) error {
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	buf := make([]byte, 12+stabilityPayload)
	binary.BigEndian.PutUint32(buf, id)
	binary.BigEndian.PutUint32(buf[4:], seq)
	binary.BigEndian.PutUint32(buf[8:], stabilityPayload)
	for i := 12; i < len(buf); i++ {
		buf[i] = byte(id*17 + seq*31 + uint32(i))
	}
	if n, err := c.Write(buf); err != nil || n != len(buf) {
		return fmt.Errorf("flow%d seq%d write: %d/%d, %v", id, seq, n, len(buf), err)
	}
	if readTimeout {
		var held stabilityHeld
		select {
		case held = <-target.timeoutHeld:
		case <-time.After(5 * time.Second):
			return errors.New("target timeout hold not reached")
		}
		if held.id != id || held.seq != seq {
			close(held.release)
			return errors.New("wrong timeout hold")
		}
		if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
			close(held.release)
			return err
		}
		var one [1]byte
		n, err := c.Read(one[:])
		close(held.release)
		if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			return fmt.Errorf("expected bounded read timeout, n=%d err=%v", n, err)
		}
		if err := c.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
	}
	got := make([]byte, len(buf))
	if _, err := io.ReadFull(c, got); err != nil {
		return fmt.Errorf("flow%d seq%d read: %w", id, seq, err)
	}
	if !bytes.Equal(got, buf) {
		return fmt.Errorf("flow%d seq%d payload mismatch", id, seq)
	}
	return nil
}

func stabilityFinal(t *testing.T, ctx context.Context, c *Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := c.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("strict final read n=%d err=%v", n, err)
	}
	select {
	case <-c.done:
	case <-ctx.Done():
		t.Fatal("final ACK timeout")
	}
	c.mu.Lock()
	ok := c.err == io.EOF && c.localFinalACK && c.remoteFIN && c.recvNext == c.remoteFinal && len(c.replay) == 0
	c.mu.Unlock()
	if !ok {
		t.Fatal("logical EOF did not complete final ACK/replay state")
	}
}

type stabilityHeld struct {
	id, seq uint32
	release chan struct{}
}
type stabilityTarget struct {
	listener         net.Listener
	mu               sync.Mutex
	counts           map[uint32]int
	activeIDs        map[uint32]bool
	accepted, active int
	held             chan stabilityHeld
	timeoutHeld      chan stabilityHeld
	errors           chan error
}

func newStabilityTarget(t *testing.T, ctx context.Context) *stabilityTarget {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stabilityTarget{listener: l, counts: make(map[uint32]int), activeIDs: make(map[uint32]bool), held: make(chan stabilityHeld, 3), timeoutHeld: make(chan stabilityHeld, 1), errors: make(chan error, 32)}
	local, stop := context.WithCancel(ctx)
	var peers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.accepted++
			s.active++
			s.mu.Unlock()
			peers.Add(1)
			go func() {
				defer peers.Done()
				defer c.Close()
				defer func() { s.mu.Lock(); s.active--; s.mu.Unlock() }()
				cancelClose := context.AfterFunc(local, func() { c.Close() })
				defer cancelClose()
				if err := s.serve(local, c); err != nil {
					select {
					case s.errors <- err:
					default:
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { stop(); l.Close(); <-acceptDone; peers.Wait() })
	return s
}

func (s *stabilityTarget) serve(ctx context.Context, c net.Conn) error {
	var ownedID uint32
	hasID := false
	defer func() {
		if hasID {
			s.mu.Lock()
			delete(s.activeIDs, ownedID)
			s.mu.Unlock()
		}
	}()
	seq := uint32(0)
	for {
		var h [12]byte
		n, err := io.ReadFull(c, h[:])
		if err == io.EOF && n == 0 {
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		id, gotSeq, size := binary.BigEndian.Uint32(h[:]), binary.BigEndian.Uint32(h[4:]), binary.BigEndian.Uint32(h[8:])
		if size != stabilityPayload || gotSeq != seq || hasID && id != ownedID {
			return fmt.Errorf("target order/size: id%d sequence%d expected%d size%d", id, gotSeq, seq, size)
		}
		b := make([]byte, 12+stabilityPayload)
		copy(b, h[:])
		if _, err = io.ReadFull(c, b[12:]); err != nil {
			return err
		}
		for i := 12; i < len(b); i++ {
			if b[i] != byte(id*17+seq*31+uint32(i)) {
				return fmt.Errorf("target corrupt payload flow%d seq%d", id, seq)
			}
		}
		s.mu.Lock()
		if !hasID && s.counts[id] != 0 {
			s.mu.Unlock()
			return fmt.Errorf("target socket reopened for flow%d", id)
		}
		s.counts[id]++
		s.activeIDs[id] = true
		s.mu.Unlock()
		ownedID, hasID = id, true
		if id == 0 && seq == 12 || id == 2 && (seq == 28 || seq == 36) {
			e := stabilityHeld{id, seq, make(chan struct{})}
			select {
			case s.held <- e:
			case <-ctx.Done():
				return nil
			}
			select {
			case <-e.release:
			case <-ctx.Done():
				return nil
			}
		}
		delay := time.Duration(seq%3) * 15 * time.Millisecond
		if id == 0 && seq == 20 {
			e := stabilityHeld{id, seq, make(chan struct{})}
			select {
			case s.timeoutHeld <- e:
			case <-ctx.Done():
				return nil
			}
			select {
			case <-e.release:
			case <-ctx.Done():
				return nil
			}
		}
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil
			}
		}
		if _, err = c.Write(b); err != nil {
			return err
		}
		seq++
	}
}

func stabilityGateway(t *testing.T, ctx context.Context, bin string, feedback bool) string {
	t.Helper()
	dir := t.TempDir()
	state, profile := filepath.Join(dir, "provider"), filepath.Join(dir, "profile.json")
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := l.Addr().String()
	l.Close()
	run := func(args ...string) string {
		t.Helper()
		c, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		b, err := exec.CommandContext(c, bin, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture command %s: %v", args[0], err)
		}
		return strings.TrimSpace(string(b))
	}
	run("provider", "init", "--state", state, "--name", "stability-test", "--endpoint", endpoint)
	run("provider", "add-user", "--state", state, "--name", "test")
	invite := run("provider", "invite", "--state", state, "--user", "test")
	logPath := filepath.Join(dir, "gateway.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"server", "--state", state, "--listen", endpoint, "--transport", "auto", "--allow-private-destinations", "--log-file", "none", "--log-level", "error"}
	if feedback {
		args = append(args, "--reliable-idle-feedback")
	}
	gateway := exec.CommandContext(ctx, bin, args...)
	gateway.Stdout, gateway.Stderr = log, log
	if err = gateway.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		gateway.Process.Kill()
		gateway.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Logf("gateway log: %s", b)
		}
	})
	until := time.Now().Add(5 * time.Second)
	for {
		c, e := net.DialTimeout("tcp4", endpoint, 100*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(until) {
			t.Fatal("gateway startup timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	run("enroll", "--invite", invite, "--profile", profile, "--device-name", "stability-test", "--local-address", "127.0.0.1")
	return profile
}

func stabilityInterrupt(t *testing.T, ctx context.Context, c *quicCarrier, role string) {
	t.Helper()
	select {
	case <-c.connection.Context().Done():
		t.Fatalf("planned %s interruption selected an already closed connection", role)
	default:
	}
	if err := c.connection.CloseWithError(0, "owned stability "+role+" interruption"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.connection.Context().Done():
	case <-ctx.Done():
		t.Fatal("owned connection did not close")
	}
}
