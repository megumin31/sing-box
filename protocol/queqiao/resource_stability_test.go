//go:build with_quic && linux

package queqiao

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type resourceSnapshot struct {
	Elapsed                                  time.Duration
	Goroutines, ClientFD, GatewayFD          int
	ClientRSS, GatewayRSS, Available         uint64
	Active, Slots, PoolEntries, OwnedSockets []int
}

func resourceProc(pid int) (int, uint64, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return 0, 0, err
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			n, e := strconv.ParseUint(fields[1], 10, 64)
			return len(entries), n * 1024, e
		}
	}
	return 0, 0, fmt.Errorf("pid%d RSS unavailable", pid)
}

func resourceAvailable() (uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			n, e := strconv.ParseUint(strings.Fields(line)[1], 10, 64)
			return n * 1024, e
		}
	}
	return 0, fmt.Errorf("MemAvailable unavailable")
}

func resourceObserve(gateway int, started time.Time, outs []*Outbound, meters []*roleSocketMeter) (resourceSnapshot, error) {
	s := resourceSnapshot{Elapsed: time.Since(started), Goroutines: runtime.NumGoroutine()}
	var err error
	if s.ClientFD, s.ClientRSS, err = resourceProc(os.Getpid()); err != nil {
		return s, err
	}
	if s.GatewayFD, s.GatewayRSS, err = resourceProc(gateway); err != nil {
		return s, err
	}
	if s.Available, err = resourceAvailable(); err != nil {
		return s, err
	}
	for _, o := range outs {
		o.mu.Lock()
		s.Active = append(s.Active, len(o.active))
		o.mu.Unlock()
		s.Slots = append(s.Slots, len(o.slots))
		if p, ok := o.pool.(*quicPool); ok {
			p.mu.Lock()
			s.PoolEntries = append(s.PoolEntries, len(p.entries))
			p.mu.Unlock()
		}
	}
	for _, m := range meters {
		s.OwnedSockets = append(s.OwnedSockets, int(m.active.Load()))
	}
	if s.ClientRSS+s.GatewayRSS > 512<<20 {
		return s, fmt.Errorf("sampled client+gateway RSS exceeds512MiB: %+v", s)
	}
	if s.Available < 192<<20 {
		return s, fmt.Errorf("available memory below192MiB: %+v", s)
	}
	return s, nil
}

func resourceAwait(t *testing.T, ctx context.Context, limit time.Duration, label string, ready func() bool) {
	t.Helper()
	until := time.NewTimer(limit)
	defer until.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatalf("%s: %v", label, ctx.Err())
		case <-until.C:
			t.Fatalf("%s timed out after %v", label, limit)
		}
	}
}

// TestReliableResourceStability deliberately uses the production30s idle timer.
// It is a bounded minutes-scale lifecycle test, not an endurance/performance test.
func TestReliableResourceStability(t *testing.T) {
	if os.Getenv("QUEQIAO_RESOURCE_STABILITY") != "1" {
		t.Skip("set QUEQIAO_RESOURCE_STABILITY=1 for the explicit minutes-scale fixture")
	}
	bin := os.Getenv("QUEQIAO_GATEWAY_BINARY")
	if bin == "" {
		t.Skip("set QUEQIAO_GATEWAY_BINARY to the frozen v2 companion")
	}
	for _, feedback := range []bool{false, true} {
		t.Run(fmt.Sprintf("feedback-%v", feedback), func(t *testing.T) {
			defer resourceDump(t)
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()
			var exchanges sync.WaitGroup
			t.Cleanup(exchanges.Wait)
			gatewayPID := 0
			profile := stabilityGateway(t, ctx, bin, feedback, func(pid int) { gatewayPID = pid })
			defer func() {
				if t.Failed() {
					resourceDumpFD(t, gatewayPID)
				}
			}()
			target := newStabilityTarget(t, ctx)
			target.mu.Lock()
			target.holdPlan = map[uint64]bool{}
			for _, seq := range []uint32{40, 90, 140} {
				target.holdPlan[uint64(10)<<32|uint64(seq)] = true
			}
			target.mu.Unlock()
			makeOutbound := func(transport string, isolate bool) *Outbound {
				a, err := NewOutbound(ctx, nil, nil, "resource-stability", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: transport, TCPRecovery: true, QUICDataIsolation: isolate})
				if err != nil {
					t.Fatal(err)
				}
				o := a.(*Outbound)
				t.Cleanup(func() { o.Close() })
				return o
			}
			dial := func(o *Outbound) *Conn {
				raw, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr(target.listener.Addr().String()))
				if err != nil {
					t.Fatal(err)
				}
				c := raw.(*Conn)
				t.Cleanup(func() { c.Close() })
				return c
			}
			// Warm runtime/netpoll/QUIC initialization before comparing aggregate counts.
			warm := makeOutbound("quic", false)
			wc := dial(warm)
			if err := stabilityExchange(wc, 900, 0, false, target); err != nil {
				t.Fatal(err)
			}
			stabilityFinal(t, ctx, wc)
			wc.Close()
			warm.Close()
			resourceAwait(t, ctx, 5*time.Second, "warm target release", func() bool { target.mu.Lock(); defer target.mu.Unlock(); return target.active == 0 })
			// Collect a short quiescent range instead of mistaking one runtime sample for a leak.
			started := time.Now()
			baseline := resourceSnapshot{}
			for i := 0; i < 3; i++ {
				s, err := resourceObserve(gatewayPID, started, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("warm baseline%d %+v", i, s)
				if s.Goroutines > baseline.Goroutines {
					baseline.Goroutines = s.Goroutines
				}
				if s.ClientFD > baseline.ClientFD {
					baseline.ClientFD = s.ClientFD
				}
				if s.GatewayFD > baseline.GatewayFD {
					baseline.GatewayFD = s.GatewayFD
				}
				time.Sleep(100 * time.Millisecond)
			}
			outs := []*Outbound{makeOutbound("quic", true), makeOutbound("quic", false), makeOutbound("tcp", false)}
			meters := []*roleSocketMeter{newRoleSocketMeter(outs[0]), newRoleSocketMeter(outs[1])}
			flows := []*Conn{dial(outs[0]), dial(outs[0]), dial(outs[1]), dial(outs[2])}
			// Start the96s business window only after all admissions have succeeded.
			started = time.Now()
			var bytesVerified uint64
			for seq := 0; seq < 192; seq++ {
				results := make(chan error, len(flows))
				for i, c := range flows {
					exchanges.Add(1)
					go func(id int, c *Conn) {
						defer exchanges.Done()
						results <- stabilityExchange(c, uint32(10+id), uint32(seq), false, target)
					}(i, c)
				}
				if seq == 40 || seq == 90 || seq == 140 {
					var held stabilityHeld
					select {
					case held = <-target.held:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					if held.id != 10 || held.seq != uint32(seq) {
						close(held.release)
						t.Fatalf("wrong held request: %d/%d", held.id, held.seq)
					}
					unique := make(map[*quic.Conn]*quicCarrier)
					var controls, dataLanes []*quicCarrier
					for _, c := range flows[:2] {
						c.mu.Lock()
						control, data := c.bundle.lanes[0], c.bundle.lanes[1]
						valid := control != nil && data != nil && c.carrier == control.raw
						c.mu.Unlock()
						if !valid {
							close(held.release)
							t.Fatal("expected live control/data pair before interruption")
						}
						cq, dq := control.raw.(*quicCarrier), data.raw.(*quicCarrier)
						for _, q := range []*quicCarrier{cq, dq} {
							select {
							case <-q.connection.Context().Done():
								close(held.release)
								t.Fatal("role connection already closed before interruption")
							default:
							}
						}
						controls = append(controls, cq)
						dataLanes = append(dataLanes, dq)
					}
					if controls[0].connection != controls[1].connection || dataLanes[0].connection == dataLanes[1].connection || dataLanes[0].connection == controls[0].connection || dataLanes[1].connection == controls[0].connection {
						close(held.release)
						t.Fatal("expected one shared control and two exclusive data connections")
					}
					unique[controls[0].connection] = controls[0]
					if seq == 140 {
						for _, q := range dataLanes {
							unique[q.connection] = q
						}
					}
					wantPhysical := 1
					if seq == 140 {
						wantPhysical = 3
					}
					if len(unique) != wantPhysical {
						close(held.release)
						t.Fatal("physical close set mismatch")
					}

					for _, q := range unique {
						stabilityInterrupt(t, ctx, q, "resource-current-generation")
					}
					close(held.release)
					t.Logf("interruption seq=%d physical_closes=%d", seq, len(unique))
				}
				for range flows {
					select {
					case err := <-results:
						if err != nil {
							t.Fatalf("round%d: %v", seq, err)
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				bytesVerified += uint64(len(flows) * stabilityPayload * 2)
				if seq == 40 || seq == 90 || seq == 140 {
					want := 1
					if seq == 90 {
						want = 2
					}
					if seq == 140 {
						want = 3
					}
					for id, c := range flows[:2] {
						resourceAwait(t, ctx, 5*time.Second, "JOIN settles", func() bool {
							c.mu.Lock()
							defer c.mu.Unlock()
							return !c.closed && !c.recovering && !c.recoveryRunning && c.bundle.lanes[0] != nil && c.recoveryAttempts == want
						})
						t.Logf("flow%d settled lifetime JOINs=%d", 10+id, want)
					}
				}
				if seq%8 == 7 {
					i := seq / 8
					churn := dial(outs[0])
					if err := stabilityExchange(churn, uint32(100+i), 0, false, target); err != nil {
						t.Fatal(err)
					}
					bytesVerified += 2 * stabilityPayload
					if i%2 == 1 {
						stabilityFinal(t, ctx, churn)
					}
					churn.Close()
					resourceAwait(t, ctx, 5*time.Second, "short flow natural release", func() bool {
						outs[0].mu.Lock()
						defer outs[0].mu.Unlock()
						return len(outs[0].active) == 2 && len(outs[0].slots) == 2
					})
					resourceAwait(t, ctx, 3*time.Second, "short destination release", func() bool { target.mu.Lock(); defer target.mu.Unlock(); return target.active == 4 })
				}
				if bytesVerified > 64<<20 {
					t.Fatal("64MiB application byte budget exceeded")
				}
				if seq%10 == 0 {
					s, err := resourceObserve(gatewayPID, started, outs, meters)
					t.Logf("sample %+v", s)
					if err != nil {
						t.Fatal(err)
					}
					for _, m := range meters {
						if m.peak.Load() > 4 {
							t.Fatal("physical connection quota exceeded")
						}
					}
				}
				select {
				case err := <-target.errors:
					t.Fatal(err)
				default:
				}
				if wait := time.Until(started.Add(time.Duration(seq+1) * 500 * time.Millisecond)); wait > 0 {
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
				c.Close()
			}
			for _, o := range outs {
				resourceAwait(t, ctx, 5*time.Second, "logical natural release", func() bool { o.mu.Lock(); defer o.mu.Unlock(); return len(o.active) == 0 && len(o.slots) == 0 })
			}
			shared := outs[1].pool.(*quicPool)
			shared.mu.Lock()
			hasIdleEntry := len(shared.entries) > 0
			shared.mu.Unlock()
			if !hasIdleEntry {
				t.Fatal("no retained shared entry: real idle timer was not exercised")
			}
			idleStarted := time.Now()
			// No Outbound.Close/Reset and no shortened idle timeout before this assertion.
			for i, o := range outs[:2] {
				p := o.pool.(*quicPool)
				if p.idleTimeout != 30*time.Second {
					t.Fatal("production idle timer changed")
				}
				resourceAwait(t, ctx, 36*time.Second, "real idle pool reclamation", func() bool {
					p.mu.Lock()
					defer p.mu.Unlock()
					return len(p.entries) == 0 && meters[i].active.Load() == 0
				})
			}
			if time.Since(idleStarted) < 28*time.Second {
				t.Fatal("shared entry closed before expected real idle interval")
			}
			t.Logf("natural idle wait=%v before Outbound.Close", time.Since(idleStarted))
			for _, o := range outs {
				o.Close()
			}
			resourceAwait(t, ctx, 5*time.Second, "all target releases", func() bool { target.mu.Lock(); defer target.mu.Unlock(); return target.active == 0 })
			target.mu.Lock()
			accepted := target.accepted
			counts := make(map[uint32]int, len(target.counts))
			for k, v := range target.counts {
				counts[k] = v
			}
			target.mu.Unlock()
			if accepted != 29 || len(counts) != 29 {
				t.Fatalf("destination ownership: accepted=%d identities=%d", accepted, len(counts))
			}
			for id := uint32(10); id < 14; id++ {
				if counts[id] != 192 {
					t.Fatalf("long flow%d requests=%d", id, counts[id])
				}
			}
			for id := uint32(100); id < 124; id++ {
				if counts[id] != 1 {
					t.Fatalf("short flow%d requests=%d", id, counts[id])
				}
			}
			if counts[900] != 1 {
				t.Fatal("warm request count changed")
			}
			for i, c := range flows {
				c.mu.Lock()
				attempts := c.recoveryAttempts
				c.mu.Unlock()
				want := 0
				if i < 2 {
					want = 3
				}
				if attempts != want {
					t.Fatalf("flow%d lifetime JOIN=%d want%d", i, attempts, want)
				}
			}
			// Runtime timers/reapers may finish asynchronously; allow a small fixed
			// runtime range, while exact owned targets/tokens/sockets must already be0.
			var final resourceSnapshot
			resourceAwait(t, ctx, 8*time.Second, "aggregate resources return to warm range", func() bool {
				s, err := resourceObserve(gatewayPID, started, outs, meters)
				final = s
				if err != nil {
					t.Fatal(err)
				}
				return s.Goroutines <= baseline.Goroutines+4 && s.ClientFD <= baseline.ClientFD+2 && s.GatewayFD <= baseline.GatewayFD+2
			})
			t.Logf("final %+v baseline=%+v verified_bidirectional_bytes=%d destinations=%d lifetime_JOINs=3/3/0/0", final, baseline, bytesVerified, accepted)
			for _, m := range meters {
				if m.active.Load() != 0 || m.peak.Load() > 4 {
					t.Fatalf("socket final=%d peak=%d", m.active.Load(), m.peak.Load())
				}
			}
			select {
			case err := <-target.errors:
				t.Fatal(err)
			default:
			}
			// On failure keep stack/FD ownership evidence in the go test log, not secrets.
		})
	}
}

func resourceDump(t *testing.T) {
	if !t.Failed() {
		return
	}
	data := make([]byte, 2<<20)
	n := runtime.Stack(data, true)
	t.Logf("goroutine snapshot:\n%s", data[:n])
	resourceDumpFD(t, os.Getpid())
}

func resourceDumpFD(t *testing.T, pid int) {
	base := fmt.Sprintf("/proc/%d/fd", pid)
	files, _ := os.ReadDir(base)
	for _, f := range files {
		v, e := os.Readlink(filepath.Join(base, f.Name()))
		if e == nil {
			t.Logf("pid%d fd%s=%s", pid, f.Name(), v)
		}
	}
}
