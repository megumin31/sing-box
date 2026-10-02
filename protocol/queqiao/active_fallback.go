package queqiao

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
)

// carrierHandoff is per logical flow, never an outbound-wide endpoint cooldown.
// Called only after a current authenticated carrier has failed. The lane engine
// serializes recovery before invoking prepare; no application DATA is admitted
// while JOIN/replay or UDP relay reclaim is in progress. Once TCP is selected we
// never dial QUIC for this flow again, including an ambiguous lost JOIN reply.
type carrierHandoff struct {
	mu      sync.Mutex
	useTCP  bool
	enabled bool
}

func newCarrierHandoff(useTCP, enabled bool) *carrierHandoff {
	return &carrierHandoff{useTCP: useTCP, enabled: enabled}
}

func (h *carrierHandoff) tcp() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.useTCP
}

func (h *carrierHandoff) prepare(err error) bool {
	if h == nil || !h.enabled {
		return true
	}
	if carrierHandoffDenied(err) {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.useTCP {
		return true
	}
	if !activeQUICCarrierLoss(err) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) && !initialFallbackAllowed(err) {
		return false
	}
	h.useTCP = true
	return true
}

// Refusals in a joined error tree must not be hidden by an allowed I/O cause.
// An application deadline, identity/protocol refusal or OS permission failure is
// not evidence of QUIC path loss and must never trigger a TCP handoff.
func carrierHandoffDenied(err error) bool {
	if activeQUICTerminalFailure(err) {
		return true
	}
	return visitErrorTree(err, func(err error) bool {
		switch e := err.(type) {
		case identityError, protocolError, *tls.CertificateVerificationError,
			x509.CertificateInvalidError, x509.UnknownAuthorityError, x509.HostnameError,
			tls.RecordHeaderError, tls.AlertError, quicProbeError, quicStreamOpenError:
			return true
		case gatewayResetError:
			return e.code != 4
		}
		return err == context.Canceled || err == context.DeadlineExceeded || err == os.ErrDeadlineExceeded || err == syscall.EACCES || err == syscall.EPERM
	})
}

func visitErrorTree(err error, visit func(error) bool) bool {
	if err == nil {
		return false
	}
	if visit(err) {
		return true
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range e.Unwrap() {
			if visitErrorTree(child, visit) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return visitErrorTree(e.Unwrap(), visit)
	}
	return false
}

func (h *carrierHandoff) replacementError(err error) error {
	if h != nil && h.enabled && err != nil && carrierHandoffDenied(err) {
		// Reuse the existing terminal recovery classification, preserving the
		// original cause. Never retry an identity or authorization rejection.
		return identityError{err}
	}
	return err
}
