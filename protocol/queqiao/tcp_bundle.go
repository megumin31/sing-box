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

// tcpBundle owns physical lanes only. Conn remains the sole owner of offsets,
// replay bytes, receive bounds and final state. All fields use Conn.mu.
// Two lanes are admitted initially; failures may reduce the bundle to one.
// There is no background replenishment or throughput/adaptive-path policy.
type tcpBundle struct {
	c     *Conn
	lanes [2]*tcpBundleLane
	next  int
	epoch uint64
	roles *quicRoleLanes
}
type tcpBundleLane struct {
	raw                   net.Conn
	busy, application     bool
	joined, finalACK, fin bool
}

func freshLaneID() (uint64, error) {
	var v [8]byte
	for v == ([8]byte{}) {
		if _, err := rand.Read(v[:]); err != nil {
			return 0, err
		}
	}
	return binary.BigEndian.Uint64(v[:]), nil
}
func joinInitialBundleLane(ctx context.Context, join joinLaneFunc, session [16]byte, flow uint64) (net.Conn, error) {
	id, err := freshLaneID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, joinTimeout)
	defer cancel()
	return join(ctx, session, flow, id)
}
func newBundleConn(first, second net.Conn, session [16]byte, flow uint64, onClose func(), ctx context.Context, join joinLaneFunc) *Conn {
	c := newConnState(first, session, flow, onClose)
	c.join = join
	c.recoveryCtx, c.recoveryCancel = context.WithCancel(ctx)
	b := &tcpBundle{c: c, lanes: [2]*tcpBundleLane{{raw: first}, {raw: second, joined: true}}}
	c.bundle = b
	go c.ackLoop()
	for _, lane := range b.lanes {
		go b.readLoop(lane)
	}
	return c
}
func (b *tcpBundle) containsLocked(lane *tcpBundleLane) bool {
	return b.lanes[0] == lane || b.lanes[1] == lane
}
func (b *tcpBundle) setApplicationDeadlineLocked(t time.Time) {
	for _, lane := range b.lanes {
		if lane != nil && lane.busy && lane.application {
			lane.raw.SetWriteDeadline(t)
		}
	}
}
func (b *tcpBundle) shutdown() {
	c := b.c
	c.mu.Lock()
	lanes := b.lanes
	b.lanes = [2]*tcpBundleLane{}
	c.mu.Unlock()
	for _, lane := range lanes {
		if lane != nil {
			abortCarrier(lane.raw)
		}
	}
}
func (b *tcpBundle) close() error {
	c := b.c
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.recoveryCancel()
	var lane *tcpBundleLane
	for _, candidate := range b.lanes {
		if candidate != nil && !candidate.busy {
			lane = candidate
			lane.busy = true
			break
		}
	}
	offset := c.sendNext
	c.mu.Unlock()
	var queuedAbort *tcpBundleLane
	if lane != nil {
		lane.raw.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		if err := writeFrame(lane.raw, frame{typ: typeClose, flags: flagFIN | flagAbort, session: c.session, flow: c.flow, sequence: offset}); err == nil {
			queuedAbort = lane
		}
	}
	c.terminateWithQueuedAbort(net.ErrClosed, queuedAbort)
	return nil
}

func (b *tcpBundle) send(f frame, application bool, commit func(), replay bool) error {
	c := b.c
	controlDeadline := time.Now().Add(controlTimeout)
	waitedForLane := false
	for {
		c.mu.Lock()
		if c.closed {
			err := c.err
			c.mu.Unlock()
			if err == nil {
				err = net.ErrClosed
			}
			return err
		}
		// A control write's budget starts when recovery can offer a lane.
		// Waiting for bounded JOIN admission must not consume that write budget.
		if !application && !replay && (c.recovering || waitedForLane) {
			controlDeadline = time.Now().Add(controlTimeout)
		}
		waitedForLane = !application && !replay && b.lanes[0] == nil && b.lanes[1] == nil
		deadline := controlDeadline
		if application {
			deadline = c.writeDeadline
		} else if !replay && b.lanes[0] == nil && b.lanes[1] == nil {
			deadline = time.Time{}
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			c.mu.Unlock()
			return os.ErrDeadlineExceeded
		}
		var lane *tcpBundleLane
		if !application || !c.recovering || replay {
			if b.roles != nil {
				lane = b.roles.selectLaneLocked(f.typ == typeData)
			} else {
				for k := 0; k < len(b.lanes); k++ {
					i := k
					if application {
						i = (b.next + k) % len(b.lanes)
					}
					candidate := b.lanes[i]
					if candidate != nil && !candidate.busy {
						lane = candidate
						if application {
							b.next = (i + 1) % len(b.lanes)
						}
						break
					}
				}
			}
		}
		if lane == nil {
			// A recovery worker must return to JOIN when no lane survives; waiting
			// here would make it wait for itself to admit that replacement.
			if replay && b.lanes[0] == nil && b.lanes[1] == nil {
				c.mu.Unlock()
				return io.ErrUnexpectedEOF
			}
			changed := c.changed
			c.mu.Unlock()
			if err := waitChange(changed, c.done, deadline); err != nil {
				return err
			}
			continue
		}
		lane.busy, lane.application = true, application
		if commit != nil {
			commit()
			commit = nil
		}
		lane.raw.SetWriteDeadline(deadline)
		c.mu.Unlock()
		f.session, f.flow = c.session, c.flow
		err := writeFrame(lane.raw, f)
		c.mu.Lock()
		lane.busy, lane.application = false, false
		lane.raw.SetWriteDeadline(time.Time{})
		c.notifyLocked()
		c.mu.Unlock()
		if err == nil {
			return nil
		}
		c.mu.Lock()
		awaitFinal := c.localFIN && lane.joined && !c.closed && b.containsLocked(lane)
		c.mu.Unlock()
		if awaitFinal {
			b.waitJoinedFinal(lane, deadline)
		}
		b.failLane(lane, err)
		if replay {
			return err
		}
	}
}

func (b *tcpBundle) failLane(lane *tcpBundleLane, err error) {
	c := b.c
	c.mu.Lock()
	if c.closed || !b.containsLocked(lane) {
		c.mu.Unlock()
		return
	}
	if permanentRecoveryError(err) {
		c.mu.Unlock()
		c.terminate(err)
		return
	}
	if lane.joined && lane.finalACK && lane.fin && c.localFinalACK && c.remoteFIN && c.recvNext == c.remoteFinal && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		c.mu.Unlock()
		c.terminate(io.EOF)
		return
	}
	if c.beforeRecovery != nil {
		if !c.beforeRecovery(err) {
			c.mu.Unlock()
			c.terminate(err)
			return
		}
		if b.roles != nil && !b.roles.tcpMode {
			// Ordinary TCP JOIN replaces the entire reserved-control QUIC
			// flow. Remove every schedulable QUIC lane under the same lock,
			// then abort all their writers before starting that JOIN. A
			// surviving DATA lane must not send concurrently with TLS DATA.
			retired := b.lanes
			b.lanes = [2]*tcpBundleLane{}
			b.roles.tcpMode = true
			b.roles.generation++
			b.roles.restoring = false
			c.carrier = nil
			b.epoch++
			c.recovering = true
			start := !c.recoveryRunning
			c.recoveryRunning = true
			c.notifyLocked()
			c.mu.Unlock()
			for _, old := range retired {
				if old != nil {
					abortCarrier(old.raw)
				}
			}
			if start {
				go b.recover()
			}
			return
		}
	}
	for i, current := range b.lanes {
		if current == lane {
			b.lanes[i] = nil
		}
	}
	b.epoch++
	c.recovering = true
	start := !c.recoveryRunning
	c.recoveryRunning = true
	c.notifyLocked()
	c.mu.Unlock()
	abortCarrier(lane.raw)
	if start {
		go b.recover()
	}
}
func (b *tcpBundle) readLoop(lane *tcpBundleLane) {
	c := b.c
	for {
		c.mu.Lock()
		for c.buffered > receiveLimit-maxPayload && c.queue.Len() > 0 && !c.closed && b.containsLocked(lane) {
			changed := c.changed
			c.mu.Unlock()
			<-changed
			c.mu.Lock()
		}
		alive := !c.closed && b.containsLocked(lane)
		c.mu.Unlock()
		if !alive {
			return
		}
		f, err := readFrame(lane.raw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			b.failLane(lane, err)
			return
		}
		// Even if a concurrent writer retired this lane, a completely received
		// authenticated frame still belongs to the logical flow and is idempotent.
		if f.session != c.session || f.flow != c.flow {
			c.terminate(protocolError{errors.New("queqiao: bundle frame belongs to another flow")})
			return
		}
		if err = c.handleFrame(f); err != nil {
			c.terminate(err)
			return
		}
		c.mu.Lock()
		if f.typ == typeACK && f.flags&flagACKFinal != 0 {
			lane.finalACK = true
		}
		if f.typ == typeClose && f.flags&flagAbort == 0 {
			lane.fin = true
		}
		c.notifyLocked()
		c.mu.Unlock()
	}
}

func (b *tcpBundle) recover() { b.recoverWithin(b.c.recoveryCtx) }
func (b *tcpBundle) quicRolesActive() bool {
	b.c.mu.Lock()
	defer b.c.mu.Unlock()
	return b.roles != nil && !b.roles.tcpMode
}
func (b *tcpBundle) recoverWithin(parent context.Context) {
	c := b.c
	ctx, cancel := context.WithTimeout(parent, recoveryTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { c.terminate(ctx.Err()) })
	defer stop()
	var lastErr error = io.ErrUnexpectedEOF
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		noLane := b.lanes[0] == nil && b.lanes[1] == nil
		if noLane {
			if b.roles != nil && b.roles.restoring {
				changed := c.changed
				c.mu.Unlock()
				deadline, _ := ctx.Deadline()
				if waitChange(changed, c.done, deadline) != nil {
					return
				}
				continue
			}
			if c.recoveryAttempts >= maxRecoveryAttempts {
				c.mu.Unlock()
				c.terminate(fmt.Errorf("queqiao: TCP bundle recovery budget exhausted: %w", lastErr))
				return
			}
			c.recoveryAttempts++
			attemptNumber := c.recoveryAttempts
			c.mu.Unlock()
			if attemptNumber > 1 {
				timer := time.NewTimer(recoveryBackoff(attemptNumber-1, lastErr))
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
			if b.quicRolesActive() {
				err = normalizeRoleAdmissionError(err)
			}
			if err != nil {
				lastErr = err
				if permanentRecoveryError(err) || b.quicRolesActive() && !isolationMayDegrade(err) {
					c.terminate(err)
					return
				}
				continue
			}
			c.mu.Lock()
			if c.closed || ctx.Err() != nil {
				c.mu.Unlock()
				abortCarrier(raw)
				return
			}
			lane := &tcpBundleLane{raw: raw, joined: true}
			b.lanes[0] = lane
			c.carrier = raw
			c.notifyLocked()
			c.mu.Unlock()
			go b.readLoop(lane)
			continue
		}
		epoch := b.epoch
		replay := append([]segment(nil), c.replay...)
		received, downFinal := c.recvNext, c.remoteFIN && c.recvNext == c.remoteFinal
		upFinal, finalOffset := c.localFIN, c.sendNext
		c.mu.Unlock()
		flags := flagACKDown
		if downFinal {
			flags |= flagACKFinal
		}
		err := b.send(frame{typ: typeACK, flags: flags, sequence: received}, false, nil, true)
		if err == nil && downFinal {
			c.mu.Lock()
			c.remoteFinalACKSent = true
			c.mu.Unlock()
		}
		for _, s := range replay {
			if err != nil {
				break
			}
			c.mu.Lock()
			acked := c.acked
			c.mu.Unlock()
			if s.offset+uint64(len(s.data)) <= acked {
				continue
			}
			if s.offset < acked {
				s.data = s.data[acked-s.offset:]
				s.offset = acked
			}
			err = b.send(frame{typ: typeData, sequence: s.offset, payload: s.data}, false, nil, true)
		}
		if err == nil && upFinal {
			err = b.send(frame{typ: typeClose, flags: flagFIN, sequence: finalOffset}, false, nil, true)
		}
		c.mu.Lock()
		stable := err == nil && epoch == b.epoch && !c.closed
		if stable {
			c.recovering = false
			c.recoveryRunning = false
			c.notifyLocked()
		}
		c.mu.Unlock()
		if stable {
			if b.roles != nil {
				b.roles.restoreControl()
			}
			c.finishIfComplete()
			return
		}
		lastErr = err
	}
}

// Admission failure must not leave the already OPENed destination waiting for
// recovery grace when we can still deliver a bounded authenticated abort.
func abortInitialBundleFlow(ctx context.Context, opened *openedFlow) {
	if ctx.Err() == nil {
		deadline := time.Now().Add(100 * time.Millisecond)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		opened.conn.SetWriteDeadline(deadline)
		_ = writeFrame(opened.conn, frame{typ: typeClose, flags: flagFIN | flagAbort, session: opened.session, flow: opened.flow})
	}
	abortCarrier(opened.conn)
	opened.remove()
}

// Completion tombstones can publish ACK/FIN and close before reading our ACK.
// Preserve their queued final evidence before retiring a write-failed lane.
// The lane reader alone establishes peer EOF; a failed write is never EOF proof.
func (b *tcpBundle) waitJoinedFinal(lane *tcpBundleLane, writeDeadline time.Time) {
	deadline := time.Now().Add(joinTimeout)
	if !writeDeadline.IsZero() && writeDeadline.Before(deadline) {
		deadline = writeDeadline
	}
	c := b.c
	for {
		c.mu.Lock()
		finished := c.closed || !b.containsLocked(lane)
		changed := c.changed
		c.mu.Unlock()
		if finished {
			return
		}
		if err := waitChange(changed, c.done, deadline); err != nil {
			return
		}
	}
}
