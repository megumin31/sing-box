package queqiao

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
)

var errQUICConnectionCapacity = errors.New("queqiao: QUIC pool capacity reached")

type exclusiveCarrierPool interface {
	OpenExclusive(context.Context) (net.Conn, error)
}

func (o *Outbound) dialExclusiveQUIC(ctx context.Context) (net.Conn, error) {
	pool, ok := o.pool.(exclusiveCarrierPool)
	if !ok {
		return nil, protocolError{errors.New("queqiao: isolated QUIC carrier unavailable")}
	}
	return pool.OpenExclusive(ctx)
}

// Optional isolation can decline a transient/capacity attempt, never a known
// authentication, protocol, stream-admission or PROBE refusal. This does not
// select another transport or change the existing authenticated logical flow.
func isolationMayDegrade(err error) bool {
	if initialQUICTerminalFailure(err) || terminalRoleReset(err) {
		return false
	}
	var identity identityError
	var protocol protocolError
	var certificate *tls.CertificateVerificationError
	var invalid x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var stream quicStreamOpenError
	var probe quicProbeError
	if errors.As(err, &identity) || errors.As(err, &protocol) || errors.As(err, &certificate) || errors.As(err, &invalid) || errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &stream) || errors.As(err, &probe) || errors.Is(err, context.Canceled) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return false
	}
	var reset gatewayResetError
	return errors.As(err, &reset) && reset.code == 4 || errors.Is(err, errQUICConnectionCapacity) || initialFallbackAllowed(err)
}
func terminalRoleReset(err error) bool {
	switch e := err.(type) {
	case gatewayResetError:
		return e.code != 4
	case *gatewayResetError:
		return e.code != 4
	case interface{ Unwrap() []error }:
		for _, child := range e.Unwrap() {
			if terminalRoleReset(child) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return terminalRoleReset(e.Unwrap())
	}
	return false
}

// A transport ending before JOIN admission is not a logical-flow FIN. Do
// not expose an EOF sentinel as application completion or graceful drain.
func normalizeRoleAdmissionError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return protocolError{errors.New("queqiao: incomplete QUIC role admission")}
	}
	return err
}

// The shared lane engine owns logical recovery. This policy owns QUIC roles:
// slot0 is reserved control, slot1 is the sole isolated DATA connection.
// It deliberately does not use the TCP bundle's available-lane round robin.
type quicRoleLanes struct {
	b          *tcpBundle
	restoring  bool
	generation uint64
}

func newQUICRoleConn(control, data net.Conn, session [16]byte, flow uint64, onClose func(), ctx context.Context, joinControl joinLaneFunc) *Conn {
	c := newConnState(control, session, flow, onClose)
	c.join = joinControl
	c.recoveryCtx, c.recoveryCancel = context.WithCancel(ctx)
	b := &tcpBundle{c: c}
	b.roles = &quicRoleLanes{b: b}
	b.lanes[0] = &tcpBundleLane{raw: control}
	if data != nil {
		b.lanes[1] = &tcpBundleLane{raw: data, joined: true}
	}
	c.bundle = b
	lanes := b.lanes
	go c.ackLoop()
	for _, lane := range lanes {
		if lane != nil {
			go b.readLoop(lane)
		}
	}
	return c
}
func (r *quicRoleLanes) selectLaneLocked(data bool) *tcpBundleLane {
	b := r.b
	if data {
		lane := b.lanes[1]
		if lane == nil {
			lane = b.lanes[0]
		}
		// Being busy is not a reason to schedule DATA on a second connection.
		if lane != nil && !lane.busy {
			return lane
		}
		return nil
	}
	for _, lane := range b.lanes {
		if lane != nil && !lane.busy {
			return lane
		}
	}
	return nil
}
func (r *quicRoleLanes) shutdown(err error) {
	c, b := r.b.c, r.b
	c.mu.Lock()
	lanes := b.lanes
	b.lanes = [2]*tcpBundleLane{}
	c.mu.Unlock()
	if err != io.EOF {
		for _, lane := range lanes {
			if lane != nil {
				abortCarrier(lane.raw)
			}
		}
		return
	}
	// Both streams may have carried final state during a role outage. Each
	// quicCarrier.Close drains its own stream; parallel waits stay bounded by
	// the existing two-second per-stream limit before releasing socket quota.
	var wg sync.WaitGroup
	for _, lane := range lanes {
		if lane != nil {
			wg.Add(1)
			go func(raw net.Conn) { defer wg.Done(); closeCarrier(raw) }(lane.raw)
		}
	}
	wg.Wait()
}
func (r *quicRoleLanes) restoreControl() {
	c, b := r.b.c, r.b
	c.mu.Lock()
	if c.closed || b.lanes[0] != nil || b.lanes[1] == nil || r.restoring || c.recoveryAttempts >= maxRecoveryAttempts {
		c.mu.Unlock()
		return
	}
	r.restoring = true
	r.generation++
	generation := r.generation
	c.mu.Unlock()
	go r.restoreLoop(generation)
}
func (r *quicRoleLanes) restoreLoop(generation uint64) {
	c, b := r.b.c, r.b
	ctx, cancel := context.WithTimeout(c.recoveryCtx, recoveryTimeout)
	defer cancel()
	defer func() {
		c.mu.Lock()
		if r.generation == generation {
			r.restoring = false
		}
		c.notifyLocked()
		c.mu.Unlock()
	}()
	var lastErr error
	for {
		c.mu.Lock()
		if c.closed || b.lanes[0] != nil || c.recoveryAttempts >= maxRecoveryAttempts {
			c.mu.Unlock()
			return
		}
		c.recoveryAttempts++
		attempt := c.recoveryAttempts
		c.mu.Unlock()
		if attempt > 1 {
			timer := time.NewTimer(recoveryBackoff(attempt-1, lastErr))
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return
			case <-c.done:
				timer.Stop()
				return
			}
		}
		raw, err := joinInitialBundleLane(ctx, c.join, c.session, c.flow)
		err = normalizeRoleAdmissionError(err)
		if err != nil {
			if !isolationMayDegrade(err) {
				c.terminate(err)
				return
			}
			if ctx.Err() != nil {
				return
			}
			lastErr = err
			continue
		}
		c.mu.Lock()
		if c.closed || ctx.Err() != nil || b.lanes[0] != nil || r.generation != generation {
			c.mu.Unlock()
			abortCarrier(raw)
			return
		}
		lane := &tcpBundleLane{raw: raw, joined: true}
		b.lanes[0] = lane
		c.carrier = raw
		b.epoch++
		r.restoring = false
		c.recovering = true
		start := !c.recoveryRunning
		c.recoveryRunning = true
		c.notifyLocked()
		c.mu.Unlock()
		go b.readLoop(lane)
		// Replay/ACK/FIN uses the remaining restoration budget, not a fresh40s.
		if start {
			b.recoverWithin(ctx)
		}
		return
	}
}
