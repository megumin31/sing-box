package queqiao

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const (
	maxRecoveryAttempts = 3 // lifetime JOIN budget per logical TCP flow
	recoveryTimeout     = 40 * time.Second
	joinTimeout         = 5 * time.Second
)

type joinLaneFunc func(context.Context, [16]byte, uint64, uint64) (net.Conn, error)
type identityError struct{ error }

func (e identityError) Unwrap() error { return e.error }

func abortCarrier(raw net.Conn) {
	if raw == nil {
		return
	}
	if a, ok := raw.(interface{ Abort() error }); ok {
		a.Abort()
	} else {
		closeCarrier(raw)
	}
}
func permanentRecoveryError(err error) bool {
	var reset gatewayResetError
	var protocol protocolError
	var identity identityError
	// A capacity marker in a joined error must not conceal a terminal
	// identity/protocol refusal (including an active handoff admission error).
	if errors.As(err, &protocol) || errors.As(err, &identity) {
		return true
	}
	if errors.As(err, &reset) {
		return reset.code != 4
	} // only capacity can heal
	return false
}

func (c *Conn) waitReady(application bool, controlDeadline time.Time) error {
	for {
		c.mu.Lock()
		if c.closed {
			err := c.err
			c.mu.Unlock()
			if err == nil {
				return net.ErrClosed
			}
			return err
		}
		d := controlDeadline
		if application {
			d = c.writeDeadline
		}
		if !d.IsZero() && !time.Now().Before(d) {
			c.mu.Unlock()
			return os.ErrDeadlineExceeded
		}
		if !c.recovering && c.carrier != nil {
			c.mu.Unlock()
			return nil
		}
		ch := c.changed
		c.mu.Unlock()
		if err := waitChange(ch, c.done, d); errors.Is(err, os.ErrDeadlineExceeded) {
			return err
		}
	}
}

// A failure invalidates one physical lane. Only one worker replaces it, even
// when DATA writer, ACK worker and reader discover the same failure together.
func (c *Conn) failCarrier(raw net.Conn, err error) bool {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false
	}
	if raw == c.carrier && c.onJoinedLane && c.joinedFinalACK && c.joinedFIN && c.localFinalACK && c.remoteFIN && c.recvNext == c.remoteFinal && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		c.mu.Unlock()
		c.terminate(io.EOF)
		return false
	}
	if raw != c.carrier {
		c.mu.Unlock()
		return true
	}
	if c.join == nil || c.remoteAbort || permanentRecoveryError(err) || c.beforeRecovery != nil && !c.beforeRecovery(err) {
		c.mu.Unlock()
		c.terminate(err)
		return false
	}
	c.carrier = nil
	c.recovering = true
	start := !c.recoveryRunning
	c.recoveryRunning = true
	c.notifyLocked()
	c.mu.Unlock()
	abortCarrier(raw)
	if start {
		go c.recoverLoop()
	}
	return true
}

func (c *Conn) trimReplayLocked() {
	for len(c.replay) > 0 {
		first := &c.replay[0]
		end := first.offset + uint64(len(first.data))
		if end <= c.acked {
			*first = segment{}
			c.replay = c.replay[1:]
			continue
		}
		if first.offset < c.acked {
			first.data = first.data[c.acked-first.offset:]
			first.offset = c.acked
		}
		break
	}
}

func (c *Conn) recoverLoop() {
	ctx, cancel := context.WithTimeout(c.recoveryCtx, recoveryTimeout)
	defer cancel()
	var lastErr error
	for outageAttempt := 0; outageAttempt < maxRecoveryAttempts; outageAttempt++ {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		if c.recoveryAttempts >= maxRecoveryAttempts {
			c.mu.Unlock()
			break
		}
		c.recoveryAttempts++
		attemptNumber := c.recoveryAttempts
		c.mu.Unlock()
		if outageAttempt > 0 {
			timer := time.NewTimer(recoveryBackoff(attemptNumber-1, lastErr))
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				c.terminate(ctx.Err())
				return
			}
		}
		var id [8]byte
		for id == ([8]byte{}) {
			if _, err := rand.Read(id[:]); err != nil {
				c.terminate(err)
				return
			}
		}
		attempt, cancelAttempt := context.WithTimeout(ctx, joinTimeout)
		raw, err := c.join(attempt, c.session, c.flow, binary.BigEndian.Uint64(id[:]))
		cancelAttempt()
		if err != nil {
			lastErr = err
			if permanentRecoveryError(err) {
				c.terminate(err)
				return
			}
			if ctx.Err() != nil {
				break
			}
			continue
		}
		stopReplay := context.AfterFunc(ctx, func() { abortCarrier(raw) })
		select {
		case <-c.writeGate:
		case <-ctx.Done():
			stopReplay()
			abortCarrier(raw)
			c.terminate(ctx.Err())
			return
		case <-c.done:
			stopReplay()
			abortCarrier(raw)
			return
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			c.writeGate <- struct{}{}
			stopReplay()
			abortCarrier(raw)
			return
		}
		// No application DATA may be appended while recovering. These immutable
		// slices stay valid even as the new reader trims acknowledged prefixes.
		replay := append([]segment(nil), c.replay...)
		received := c.recvNext
		downFinal := c.remoteFIN && received == c.remoteFinal
		upFinal, finalOffset := c.localFIN, c.sendNext
		c.carrier = raw
		c.onJoinedLane = true
		c.joinedFinalACK = false
		c.joinedFIN = false
		c.notifyLocked()
		c.mu.Unlock()
		deadline, _ := ctx.Deadline()
		raw.SetWriteDeadline(deadline)
		flags := flagACKDown
		if downFinal {
			flags |= flagACKFinal
		}
		// Read immediately after OPEN_OK. A completion tombstone can send its
		// final ACK/FIN and close its receive direction before our first write.
		err = writeFrame(raw, frame{typ: typeACK, flags: flags, session: c.session, flow: c.flow, sequence: received})
		if err == nil && downFinal {
			c.mu.Lock()
			c.remoteFinalACKSent = true
			c.mu.Unlock()
		}

		if err == nil {
			for _, s := range replay {
				c.mu.Lock()
				acked := c.acked
				c.mu.Unlock()
				end := s.offset + uint64(len(s.data))
				if end <= acked {
					continue
				}
				if s.offset < acked {
					s.data = s.data[acked-s.offset:]
					s.offset = acked
				}
				if err = writeFrame(raw, frame{typ: typeData, session: c.session, flow: c.flow, sequence: s.offset, payload: s.data}); err != nil {
					break
				}
			}
		}
		if err == nil && upFinal {
			err = writeFrame(raw, frame{typ: typeClose, flags: flagFIN, session: c.session, flow: c.flow, sequence: finalOffset})
		}
		if err != nil && upFinal {
			c.waitJoinedFinal(ctx, raw)
		}
		raw.SetWriteDeadline(time.Time{})
		if !stopReplay() && err == nil {
			err = ctx.Err()
			if err == nil {
				err = context.Canceled
			}
		}
		c.mu.Lock()
		if err == nil && (c.closed || c.carrier != raw) {
			err = net.ErrClosed
		}
		if err == nil {
			if downFinal {
				c.remoteFinalACKSent = true
			}
			c.recovering = false
			c.recoveryRunning = false
			c.notifyLocked()
		} else if c.carrier == raw {
			c.carrier = nil
			c.notifyLocked()
		}
		closed := c.closed
		next, final := c.recvNext, c.remoteFIN && c.recvNext == c.remoteFinal
		c.mu.Unlock()
		c.writeGate <- struct{}{}
		if err == nil {
			c.queueACK(next, final)
			c.finishIfComplete()
			return
		}
		abortCarrier(raw)
		if closed {
			return
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if ctx.Err() != nil {
		lastErr = ctx.Err()
	}
	if lastErr == nil {
		lastErr = io.ErrUnexpectedEOF
	}
	c.terminate(fmt.Errorf("queqiao: TCP recovery budget exhausted: %w", lastErr))
}

func recoveryBackoff(attempt int, err error) time.Duration {
	var reset gatewayResetError
	if errors.As(err, &reset) && reset.code == 4 && attempt >= 2 {
		return 15 * time.Second
	}
	return time.Duration(attempt) * 100 * time.Millisecond
}

// A tombstone closes its read side after publishing final state. Do not throw
// away its already queued ACK/FIN merely because the reciprocal write fails.
func (c *Conn) waitJoinedFinal(ctx context.Context, raw net.Conn) {
	timer := time.NewTimer(joinTimeout)
	defer timer.Stop()
	for {
		c.mu.Lock()
		closed, changed, current := c.closed, c.changed, c.carrier == raw
		c.mu.Unlock()
		if closed || !current {
			return
		}
		select {
		case <-changed:
		case <-c.done:
			return
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		}
	}
}
