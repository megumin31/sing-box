package queqiao

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"

	"github.com/sagernet/sing-box/option"
)

func TestActiveFallbackErrorAdmission(t *testing.T) {
	for _, v := range []struct {
		name    string
		err     error
		allowed bool
	}{
		{"eof", io.EOF, true},
		{"partial-frame", io.ErrUnexpectedEOF, true},
		{"closed-pipe", io.ErrClosedPipe, true},
		{"closed-carrier", net.ErrClosed, true},
		{"path-reset", syscall.ECONNRESET, true},
		{"path-unreachable", syscall.ENETUNREACH, true},
		{"unknown", errors.New("unknown"), false},
		{"canceled", context.Canceled, false},
		{"caller-deadline", context.DeadlineExceeded, false},
		{"application-deadline", os.ErrDeadlineExceeded, false},
		{"identity", identityError{io.EOF}, false},
		{"protocol", protocolError{io.EOF}, false},
		{"certificate-with-path-loss", errors.Join(io.EOF, &tls.CertificateVerificationError{}), false},
		{"permission-with-path-loss", errors.Join(io.EOF, syscall.EACCES), false},
		{"capacity-hides-permission", errors.Join(gatewayResetError{code: 4}, syscall.EACCES, io.EOF), false},
		{"capacity-hides-refusal", errors.Join(gatewayResetError{code: 4}, gatewayResetError{code: 1}, io.EOF), false},
		{"stream-credit-with-path-loss", errors.Join(io.EOF, quicStreamOpenError{context.DeadlineExceeded}), false},
	} {
		t.Run(v.name, func(t *testing.T) {
			h := newCarrierHandoff(false, true)
			if got := h.prepare(v.err); got != v.allowed || h.tcp() != v.allowed {
				t.Fatalf("allowed=%v tcp=%v want=%v", got, h.tcp(), v.allowed)
			}
			if !v.allowed {
				err := h.replacementError(v.err)
				if !errors.Is(err, v.err) || carrierHandoffDenied(v.err) && !permanentRecoveryError(err) {
					t.Fatalf("replacement refusal lost or retriable: %v", err)
				}
			}
		})
	}
}

func TestActiveFallbackStickyAndPerFlow(t *testing.T) {
	h := newCarrierHandoff(false, true)
	other := newCarrierHandoff(false, true)
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if !h.prepare(io.EOF) || !h.tcp() {
				t.Error("TCP choice not published")
			}
		}()
	}
	workers.Wait()
	if other.tcp() {
		t.Fatal("one flow changed another flow's transport")
	}
	if !h.prepare(errors.New("ambiguous TCP JOIN response")) || !h.tcp() {
		t.Fatal("handoff returned to QUIC after uncertain JOIN")
	}
	for _, tcp := range []bool{false, true} {
		disabled := newCarrierHandoff(tcp, false)
		if !disabled.prepare(io.EOF) || disabled.tcp() != tcp {
			t.Fatal("default changed transport")
		}
	}
	if h.prepare(errors.Join(io.EOF, syscall.EPERM)) {
		t.Fatal("sticky TCP bypassed permission refusal")
	}
}

// Concurrent read/write failures must share one JOIN worker. Close must cancel
// its in-progress replacement attempt and prevent a late carrier from installing.
func TestActiveFallbackConcurrentFailureAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()
		h := newCarrierHandoff(false, true)
		var attempts atomic.Int32
		entered, canceled := make(chan struct{}), make(chan struct{})
		c := newRecoverableConnWithPolicy(client, [16]byte{1}, 2, nil, context.Background(), func(ctx context.Context, s [16]byte, f, lane uint64) (net.Conn, error) {
			if attempts.Add(1) != 1 {
				t.Error("duplicate JOIN worker")
			}
			if !h.tcp() || s != ([16]byte{1}) || f != 2 || lane == 0 {
				t.Error("wrong transport or logical identity")
			}
			close(entered)
			<-ctx.Done()
			close(canceled)
			return nil, ctx.Err()
		}, h.prepare)
		defer c.Close()
		var workers sync.WaitGroup
		for range 16 {
			workers.Add(1)
			go func() { defer workers.Done(); c.failCarrier(client, io.ErrUnexpectedEOF) }()
		}
		workers.Wait()
		<-entered
		c.Close()
		<-canceled
		synctest.Wait()
		if attempts.Load() != 1 || c.currentCarrier() != nil {
			t.Fatal("close retried JOIN or installed replacement")
		}
	})
}

func TestActiveFallbackConfigRequirements(t *testing.T) {
	for _, v := range []struct {
		name, transport, network string
		tcp, udp, isolation      bool
		want                     string
	}{
		{"default-transport", "", "", true, true, false, "requires transport quic"},
		{"tcp-transport", "tcp", "", true, true, false, "requires transport quic"},
		{"missing-tcp-recovery", "quic", "", false, true, false, "for TCP requires tcp_recovery"},
		{"missing-udp-resume", "quic", "", true, false, false, "for UDP requires udp_resume"},
		{"tcp-only-missing-recovery", "quic", "tcp", false, false, false, "for TCP requires tcp_recovery"},
		{"udp-only-missing-resume", "quic", "udp", false, false, false, "for UDP requires udp_resume"},
	} {
		t.Run(v.name, func(t *testing.T) {
			_, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{
				ProfilePath: "unused", Transport: v.transport, Network: option.NetworkList(v.network),
				TCPRecovery: v.tcp, UDPResume: v.udp, QUICActiveFallback: true, QUICDataIsolation: v.isolation,
			})
			if err == nil || !strings.Contains(err.Error(), v.want) {
				t.Fatalf("configuration: %v want %q", err, v.want)
			}
		})
	}
}
