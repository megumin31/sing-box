//go:build with_quic

package queqiao

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestQUICRolesQuotaIncludesCanceledDialOwners(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o := fallbackTestOutbound()
		o.dataIsolation = true
		entered := make(chan struct{}, 4)
		release := make(chan struct{})
		var calls atomic.Int32
		o.dialer = testDialer{dial: func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
			calls.Add(1)
			entered <- struct{}{}
			<-release
			return nil, context.Canceled
		}}
		p := newQUICPool(o).(*quicPool)
		defer p.Reset(true)
		var cancels []context.CancelFunc
		results := make(chan error, 4)
		for i := 0; i < 4; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			cancels = append(cancels, cancel)
			go func() { _, err := p.OpenExclusive(ctx); results <- err }()
		}
		for i := 0; i < 4; i++ {
			<-entered
		}
		for _, cancel := range cancels {
			cancel()
		}
		for i := 0; i < 4; i++ {
			if err := <-results; !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled caller=%v", err)
			}
		}
		p.mu.Lock()
		entries, inflight := len(p.entries), p.inflight
		p.mu.Unlock()
		if entries != 0 || inflight != 4 {
			t.Fatalf("retirement state entries=%d inflight=%d", entries, inflight)
		}
		if _, err := p.Open(context.Background()); !errors.Is(err, errQUICConnectionCapacity) {
			t.Fatalf("canceled owners did not retain hard quota: %v", err)
		}
		if calls.Load() != 4 {
			t.Fatal("opened fifth connection before old owners exited")
		}
		close(release)
		synctest.Wait()
		p.mu.Lock()
		inflight = p.inflight
		p.mu.Unlock()
		if inflight != 0 {
			t.Fatalf("quota leaked after all dial owners exited: %d", inflight)
		}
	})
}

func TestQUICRolesExclusivePoolAndDrainQuota(t *testing.T) {
	o := poolTestOutbound(t)
	o.dataIsolation = true
	p := o.pool.(*quicPool)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	control, err := p.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	var data []net.Conn
	defer func() {
		for _, c := range data {
			abortCarrier(c)
		}
	}()
	for i := 0; i < 3; i++ {
		c, e := p.OpenExclusive(ctx)
		if e != nil {
			t.Fatal(e)
		}
		data = append(data, c)
		if c.(*quicCarrier).connection == control.(*quicCarrier).connection {
			t.Fatal("exclusive DATA reused shared connection")
		}
	}
	again, err := p.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.(*quicCarrier).connection != control.(*quicCarrier).connection {
		t.Fatal("shared Open selected exclusive entry")
	}
	again.Close()
	if _, err = p.OpenExclusive(ctx); !errors.Is(err, errQUICConnectionCapacity) {
		t.Fatalf("fifth QUIC connection admitted: %v", err)
	}
	draining := data[0].(*quicCarrier)
	// A deliberately unacknowledged trace endpoint holds the existing bounded
	// drain wait, independently of localhost packet timing.
	draining.writeMu.Lock()
	draining.written = 1
	draining.writeMu.Unlock()
	drained := make(chan struct{})
	go func() { draining.Close(); close(drained) }()
	eventually(t, func() bool { draining.writeMu.Lock(); defer draining.writeMu.Unlock(); return draining.closing })
	if _, err = p.OpenExclusive(ctx); !errors.Is(err, errQUICConnectionCapacity) {
		t.Fatalf("draining connection released quota early: %v", err)
	}
	p.Reset(false)
	select {
	case <-drained:
	case <-ctx.Done():
		t.Fatal("reset did not release draining stream")
	}
	eventually(t, func() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.inflight == 0 })
	fresh, err := p.OpenExclusive(ctx)
	if err != nil {
		t.Fatalf("quota not reusable after retirement: %v", err)
	}
	fresh.Close()
}
