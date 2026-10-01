//go:build with_quic

package queqiao

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestInitialFallbackQUICEntryPreservesFailure(t *testing.T) {
	for _, original := range []error{syscall.ECONNREFUSED, identityError{errors.New("identity refused")}} {
		ctx, cancel := context.WithCancel(context.Background())
		e := &quicPoolEntry{ctx: ctx, ready: make(chan struct{}), err: original}
		close(e.ready)
		cancel()
		for i := 0; i < 100; i++ {
			if err := waitQUICEntry(context.Background(), e); !errors.Is(err, original) {
				t.Fatalf("published failure lost: %v", err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := &quicPoolEntry{ctx: ctx, ready: make(chan struct{})}
	if err := waitQUICEntry(context.Background(), e); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("unpublished canceled entry: %v", err)
	}
}

func TestInitialFallbackQUICRefusalAtDeadline(t *testing.T) {
	for _, refusal := range []error{identityError{errors.New("identity refused")}, protocolError{errors.New("protocol refused")}} {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		e := &quicPoolEntry{ctx: context.Background(), ready: make(chan struct{}), err: refusal}
		close(e.ready)
		// Both signals are already ready; no scheduling or wall-clock race is
		// needed. Repetition exercises either outcome of the old random select.
		for i := 0; i < 100; i++ {
			if err := waitQUICEntry(ctx, e); !errors.Is(err, refusal) {
				t.Fatalf("published refusal masked by deadline: %v", err)
			}
		}
	}
}

func TestInitialFallbackQUICWaitCancellationAndLateSuccess(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		var ctx context.Context
		var cancel context.CancelFunc
		want := context.Canceled
		if deadline {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		}
		defer cancel()
		e := &quicPoolEntry{ctx: context.Background(), ready: make(chan struct{})}
		close(e.ready)
		for i := 0; i < 100; i++ {
			if err := waitQUICEntry(ctx, e); !errors.Is(err, want) {
				t.Fatalf("late success escaped caller end: %v", err)
			}
		}
		if !deadline {
			e.err = identityError{errors.New("identity refused")}
			if err := waitQUICEntry(ctx, e); !errors.Is(err, context.Canceled) {
				t.Fatalf("explicit cancellation priority lost: %v", err)
			}
		}
	}
}

func TestInitialFallbackPublishedRefusalDoesNotSelectTCP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o := fallbackTestOutbound()
		refusal := identityError{errors.New("identity refused")}
		o.pool = fallbackPoolFunc(func(ctx context.Context) (net.Conn, error) {
			<-ctx.Done()
			e := &quicPoolEntry{ctx: context.Background(), ready: make(chan struct{}), err: refusal}
			close(e.ready)
			return nil, waitQUICEntry(ctx, e)
		})
		o.dialer = testDialer{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			t.Fatal("TCP attempted despite published identity refusal")
			return nil, nil
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _, err := o.dialInitialCarrier(ctx, 0)
		if !errors.Is(err, refusal) {
			t.Fatalf("exact identity refusal lost: %v", err)
		}
	})
}
