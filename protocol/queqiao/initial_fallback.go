package queqiao

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

const initialQUICAttemptTimeout = 5 * time.Second

// Stream admission failures are not evidence that QUIC connection establishment
// failed. In particular a peer's stream-credit timeout must not select TCP.
type quicStreamOpenError struct{ error }

func (e quicStreamOpenError) Unwrap() error { return e.error }

// dialInitialCarrier runs before any Queqiao OPEN is written. A fallback TCP
// socket is still unauthenticated here; openFlow must run the same TLS profile
// handshake as explicit TCP before sending OPEN. Existing flows never use this
// selection again. Only the separate opt-in active carrier policy can hand off
// an already open logical flow through JOIN or token-bound UDP resume.
func (o *Outbound) dialInitialCarrier(ctx context.Context, generation uint64) (net.Conn, bool, error) {
	if err := o.initialDialState(ctx, generation); err != nil {
		return nil, false, err
	}
	if o.pool == nil {
		raw, err := o.dialer.DialContext(ctx, "tcp", o.server)
		return raw, true, err
	}
	quicCtx := ctx
	cancel := func() {}
	if o.initialFallback {
		quicCtx, cancel = context.WithTimeout(ctx, initialQUICAttemptTimeout)
	}
	raw, quicErr := o.pool.Open(quicCtx)
	cancel()
	if quicErr == nil {
		return raw, false, nil
	}
	if raw != nil {
		abortCarrier(raw)
	}
	if !o.initialFallback || !initialFallbackAllowed(quicErr) {
		return nil, false, quicErr
	}
	if err := o.initialDialState(ctx, generation); err != nil {
		return nil, false, err
	}
	// Reuse the caller's original bounded context, not the expired QUIC attempt.
	// There is exactly one TCP attempt and no persistent endpoint cooldown.
	raw, tcpErr := o.dialer.DialContext(ctx, "tcp", o.server)
	if tcpErr != nil {
		if raw != nil {
			abortCarrier(raw)
		}
		return nil, true, errors.Join(fmt.Errorf("queqiao: initial QUIC attempt: %w", quicErr), fmt.Errorf("queqiao: initial TCP fallback: %w", tcpErr))
	}
	return raw, true, nil
}

func (o *Outbound) initialDialState(ctx context.Context, generation uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// A child attempt and its parent can expire at the same instant before the
	// parent's cancellation callback has run. The timestamp is still binding.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	if err := o.ctx.Err(); err != nil {
		return err
	}
	o.mu.Lock()
	closed := o.closed || o.generation != generation
	o.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return nil
}

// dialFixedCarrier never reselects transport during logical-flow recovery.
func (o *Outbound) dialFixedCarrier(ctx context.Context, useTCP bool) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if useTCP {
		return o.dialer.DialContext(ctx, "tcp", o.server)
	}
	if o.pool == nil {
		return nil, protocolError{errors.New("queqiao: selected QUIC carrier is unavailable")}
	}
	return o.pool.Open(ctx)
}

func initialFallbackAllowed(err error) bool {
	// A multi-error wrapper can contain both a timeout and a known refusal.
	// Inspect terminal QUIC types before accepting any timeout in that tree.
	if initialQUICTerminalFailure(err) {
		return false
	}
	var identity identityError
	var protocol protocolError
	var reset gatewayResetError
	var certificate *tls.CertificateVerificationError
	var invalid x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var streamOpen quicStreamOpenError
	var probe quicProbeError
	if errors.As(err, &identity) || errors.As(err, &protocol) || errors.As(err, &reset) ||
		errors.As(err, &certificate) || errors.As(err, &invalid) || errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &streamOpen) || errors.As(err, &probe) ||
		errors.Is(err, context.Canceled) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return false
	}
	var timeout net.Error
	return errors.As(err, &timeout) && timeout.Timeout() ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ETIMEDOUT)
}
