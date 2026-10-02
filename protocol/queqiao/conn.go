package queqiao

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	receiveLimit   = 4 << 20
	sendWindow     = 1 << 20
	chunkSize      = 32 << 10
	controlTimeout = 15 * time.Second
)

type segment struct {
	offset uint64
	data   []byte
}

// Conn is one flow on one reliable TLS/TCP or QUIC stream. Memory is bounded
// independently of peer claims. Optional recovery retains bounded upstream bytes
// and replaces only the reliable lane, preserving the logical offsets and FIN state.
type Conn struct {
	carrier                                   net.Conn
	bundle                                    *tcpBundle
	localAddr, remoteAddr                     net.Addr
	join                                      joinLaneFunc
	beforeRecovery                            func(error) bool
	recoveryCtx                               context.Context
	recoveryCancel                            context.CancelFunc
	recovering, recoveryRunning               bool
	recoveryAttempts                          int
	onJoinedLane, joinedFinalACK, joinedFIN   bool
	replay                                    []segment
	session                                   [16]byte
	flow                                      uint64
	mu                                        sync.Mutex
	changed                                   chan struct{}
	done                                      chan struct{}
	err                                       error
	closed                                    bool
	readDeadline, writeDeadline               time.Time
	writingApplication                        bool
	sendNext, acked                           uint64
	localFIN, localFinalACK                   bool
	recvNext                                  uint64
	remoteFIN                                 bool
	remoteFinal                               uint64
	pending                                   []segment
	queue                                     bytes.Buffer
	buffered                                  int
	writeGate                                 chan struct{}
	applicationGate                           chan struct{}
	onClose                                   func()
	ackReady                                  chan struct{}
	ackNext                                   uint64
	ackFinal, remoteFinalACKSent, remoteAbort bool
}

func newConnState(raw net.Conn, session [16]byte, flow uint64, onClose func()) *Conn {
	c := &Conn{carrier: raw, localAddr: raw.LocalAddr(), remoteAddr: raw.RemoteAddr(), session: session, flow: flow, changed: make(chan struct{}), done: make(chan struct{}), writeGate: make(chan struct{}, 1), applicationGate: make(chan struct{}, 1), onClose: onClose, ackReady: make(chan struct{}, 1)}
	c.writeGate <- struct{}{}
	c.applicationGate <- struct{}{}
	return c
}

func newConn(raw net.Conn, session [16]byte, flow uint64, onClose func()) *Conn {
	return newRecoverableConn(raw, session, flow, onClose, nil, nil)
}
func newRecoverableConn(raw net.Conn, session [16]byte, flow uint64, onClose func(), ctx context.Context, join joinLaneFunc) *Conn {
	return newRecoverableConnWithPolicy(raw, session, flow, onClose, ctx, join, nil)
}
func newRecoverableConnWithPolicy(raw net.Conn, session [16]byte, flow uint64, onClose func(), ctx context.Context, join joinLaneFunc, beforeRecovery func(error) bool) *Conn {
	c := newConnState(raw, session, flow, onClose)
	c.join = join
	c.beforeRecovery = beforeRecovery
	if join != nil {
		c.recoveryCtx, c.recoveryCancel = context.WithCancel(ctx)
	}
	go c.ackLoop()
	go c.readLoop()
	return c
}
func (c *Conn) LocalAddr() net.Addr      { return c.localAddr }
func (c *Conn) RemoteAddr() net.Addr     { return c.remoteAddr }
func (c *Conn) currentCarrier() net.Conn { c.mu.Lock(); defer c.mu.Unlock(); return c.carrier }

func closeCarrier(conn net.Conn) {
	if conn == nil {
		return
	}
	if secure, ok := conn.(*tls.Conn); ok {
		secure.NetConn().Close()
	} else {
		conn.Close()
	}
}

func (c *Conn) notifyLocked() { close(c.changed); c.changed = make(chan struct{}) }
func (c *Conn) terminate(err error) {
	c.terminateWithQueuedAbort(err, nil)
}

// A successful local Close may have queued its authenticated ABORT on one
// QUIC role stream. Preserve only that specific stream's bounded drain; errors
// and remote termination never obtain this exception to immediate abort.
func (c *Conn) terminateWithQueuedAbort(err error, queuedAbort *tcpBundleLane) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.err = err
	raw := c.carrier
	c.carrier = nil
	c.replay = nil
	if c.recoveryCancel != nil {
		c.recoveryCancel()
	}
	c.pending = nil
	c.buffered = c.queue.Len()
	close(c.done)
	c.notifyLocked()
	c.mu.Unlock()
	// TLS Close may wait up to five seconds to write close_notify. Protocol
	// FIN/ACK_FINAL supplies the authenticated completion signal, so terminate
	// the underlying carrier directly and promptly unblock both I/O workers.
	if c.bundle != nil && c.bundle.roles != nil {
		c.bundle.roles.shutdown(err, queuedAbort)
	} else {
		closeCarrier(raw)
		if c.bundle != nil {
			c.bundle.shutdown()
		}
	}
	if c.onClose != nil {
		c.onClose()
	}
}

func waitChange(ch, done <-chan struct{}, deadline time.Time) error {
	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		delay := time.Until(deadline)
		if delay <= 0 {
			return os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(delay)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-ch:
		return nil
	case <-done:
		return net.ErrClosed
	case <-timeout:
		return os.ErrDeadlineExceeded
	}
}

func (c *Conn) acquire(gate chan struct{}, application bool) error {
	controlDeadline := time.Now().Add(controlTimeout)
	for {
		c.mu.Lock()
		closed, err, changed, d := c.closed, c.err, c.changed, c.writeDeadline
		c.mu.Unlock()
		if closed {
			if err == nil {
				return net.ErrClosed
			}
			return err
		}
		if !application {
			d = controlDeadline
		}
		if !d.IsZero() && !time.Now().Before(d) {
			return os.ErrDeadlineExceeded
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !d.IsZero() {
			timer = time.NewTimer(time.Until(d))
			timeout = timer.C
		}
		select {
		case <-gate:
			if timer != nil {
				timer.Stop()
			}
			return nil
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return os.ErrDeadlineExceeded
		}
	}
}

func (c *Conn) send(f frame, application bool) error {
	return c.sendWithCommit(f, application, nil)
}

// commit runs once under mu, with the physical write gate held and a ready
// carrier. Before this point a deadline must not consume offsets or FIN state.
// After it, any write failure invalidates the carrier and recovery owns replay.
func (c *Conn) sendWithCommit(f frame, application bool, commit func()) error {
	if c.bundle != nil {
		return c.bundle.send(f, application, commit, false)
	}
	controlDeadline := time.Now().Add(controlTimeout)
	for {
		if err := c.waitReady(application, time.Time{}); err != nil {
			return err
		}
		if !application {
			controlDeadline = time.Now().Add(controlTimeout)
		}
		if err := c.acquire(c.writeGate, application); err != nil {
			return err
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			c.writeGate <- struct{}{}
			return net.ErrClosed
		}
		if c.recovering || c.carrier == nil {
			c.mu.Unlock()
			c.writeGate <- struct{}{}
			continue
		}
		raw := c.carrier
		d := controlDeadline
		if application {
			d = c.writeDeadline
		}
		if application && !d.IsZero() && !time.Now().Before(d) {
			c.mu.Unlock()
			c.writeGate <- struct{}{}
			return os.ErrDeadlineExceeded
		}
		if commit != nil {
			commit()
			commit = nil
		}
		c.writingApplication = application
		raw.SetWriteDeadline(d)
		c.mu.Unlock()
		f.session, f.flow = c.session, c.flow
		err := writeFrame(raw, f)
		c.mu.Lock()
		c.writingApplication = false
		raw.SetWriteDeadline(time.Time{})
		c.mu.Unlock()
		c.writeGate <- struct{}{}
		if err == nil {
			return nil
		}
		if !c.failCarrier(raw, err) {
			return err
		}
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if c.queue.Len() > 0 {
			n, _ := c.queue.Read(p)
			c.buffered -= n
			c.notifyLocked()
			c.mu.Unlock()
			return n, nil
		}
		if c.remoteFIN && c.recvNext == c.remoteFinal {
			c.mu.Unlock()
			return 0, io.EOF
		}
		if c.closed {
			err := c.err
			c.mu.Unlock()
			if err == nil {
				err = net.ErrClosed
			}
			return 0, err
		}
		changed, d := c.changed, c.readDeadline
		c.mu.Unlock()
		if err := waitChange(changed, c.done, d); errors.Is(err, os.ErrDeadlineExceeded) {
			return 0, err
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	if err := c.acquire(c.applicationGate, true); err != nil {
		return 0, err
	}
	defer func() { c.applicationGate <- struct{}{} }()
	written := 0
	for len(p) > 0 {
		c.mu.Lock()
		if c.closed || c.localFIN {
			err := c.err
			c.mu.Unlock()
			if err == nil {
				err = net.ErrClosed
			}
			return written, err
		}
		d := c.writeDeadline
		if c.recovering {
			changed := c.changed
			c.mu.Unlock()
			if err := waitChange(changed, c.done, d); err != nil {
				return written, err
			}
			continue
		}
		if !d.IsZero() && !time.Now().Before(d) {
			c.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		}
		n := min(len(p), chunkSize)
		if c.sendNext-c.acked+uint64(n) > sendWindow || c.join != nil && len(c.replay) >= 1024 {
			changed := c.changed
			c.mu.Unlock()
			if err := waitChange(changed, c.done, d); err != nil {
				return written, err
			}
			continue
		}
		offset := c.sendNext
		if uint64(n) > math.MaxUint64-offset {
			c.mu.Unlock()
			c.terminate(errors.New("queqiao: send offset overflow"))
			return written, errors.New("queqiao: send offset overflow")
		}
		c.mu.Unlock()
		accepted := false
		err := c.sendWithCommit(frame{typ: typeData, sequence: offset, payload: p[:n]}, true, func() {
			c.sendNext += uint64(n)
			if c.join != nil {
				c.replay = append(c.replay, segment{offset, append([]byte(nil), p[:n]...)})
			}
			accepted = true
		})
		// With recovery enabled, these bytes were accepted into the replay
		// buffer even if the caller's deadline expires during the outage.
		if err == nil || c.join != nil && accepted {
			written += n
			p = p[n:]
		}
		if err != nil {
			if c.join == nil && accepted {
				c.terminate(err)
			}
			return written, err
		}
	}
	return written, nil
}

func (c *Conn) CloseWrite() error {
	if err := c.acquire(c.applicationGate, true); err != nil {
		return err
	}
	defer func() { c.applicationGate <- struct{}{} }()
	c.mu.Lock()
	if c.localFIN {
		c.mu.Unlock()
		return nil
	}
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	// Do not announce a recoverable FIN until every prior byte is cumulatively
	// acknowledged. Otherwise a lost final ACK can make replay DATA arrive at
	// the official gateway after it has irrevocably half-closed the destination.
	for c.join != nil && c.acked < c.sendNext && !c.closed {
		ch, d := c.changed, c.writeDeadline
		c.mu.Unlock()
		if err := waitChange(ch, c.done, d); err != nil {
			return err
		}
		c.mu.Lock()
	}
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	offset := c.sendNext
	c.mu.Unlock()
	accepted := false
	if err := c.sendWithCommit(frame{typ: typeClose, flags: flagFIN, sequence: offset}, true, func() {
		c.localFIN = true
		accepted = true
	}); err != nil {
		if c.join == nil && accepted {
			c.terminate(err)
		}
		return err
	}
	return nil
}

func (c *Conn) Close() error {
	if c.bundle != nil {
		return c.bundle.close()
	}
	c.mu.Lock()
	if c.recoveryCancel != nil {
		c.recoveryCancel()
	}
	c.mu.Unlock()
	// Best-effort ABORT releases the gateway destination without its recovery
	// grace. Never queue behind a blocked writer; closing the carrier must
	// still interrupt all local operations within a bounded time.
	select {
	case <-c.writeGate:
		c.mu.Lock()
		closed, offset, raw := c.closed, c.sendNext, c.carrier
		if !closed && raw != nil {
			raw.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		}
		c.mu.Unlock()
		if !closed && raw != nil {
			_ = writeFrame(raw, frame{typ: typeClose, flags: flagFIN | flagAbort, session: c.session, flow: c.flow, sequence: offset})
		}
		c.writeGate <- struct{}{}
	default:
	}
	c.terminate(net.ErrClosed)
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readDeadline, c.writeDeadline = t, t
	if c.bundle != nil {
		c.bundle.setApplicationDeadlineLocked(t)
	}
	if c.writingApplication && c.carrier != nil {
		c.carrier.SetWriteDeadline(t)
	}
	c.notifyLocked()
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readDeadline = t
	c.notifyLocked()
	return nil
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.writeDeadline = t
	if c.bundle != nil {
		c.bundle.setApplicationDeadlineLocked(t)
	}
	if c.writingApplication && c.carrier != nil {
		c.carrier.SetWriteDeadline(t)
	}
	c.notifyLocked()
	return nil
}

func (c *Conn) readLoop() {
	for {
		// Bound delivered-but-unread storage while retaining space for a full frame.
		c.mu.Lock()
		for c.buffered > receiveLimit-maxPayload && c.queue.Len() > 0 && !c.closed {
			ch := c.changed
			c.mu.Unlock()
			<-ch
			c.mu.Lock()
		}
		for c.carrier == nil && !c.closed {
			ch := c.changed
			c.mu.Unlock()
			<-ch
			c.mu.Lock()
		}
		closed, raw := c.closed, c.carrier
		c.mu.Unlock()
		if closed {
			return
		}
		f, err := readFrame(raw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			if c.failCarrier(raw, err) {
				continue
			}
			return
		}
		c.mu.Lock()
		current := c.carrier == raw && !c.closed
		c.mu.Unlock()
		if !current {
			continue
		}
		if f.session != c.session || f.flow != c.flow {
			c.terminate(errors.New("queqiao: frame belongs to another flow"))
			return
		}
		if err = c.handleFrame(f); err != nil {
			c.terminate(err)
			return
		}
	}
}

func (c *Conn) handleFrame(f frame) error {
	switch f.typ {
	case typeData:
		if f.flags != 0 {
			return errors.New("queqiao: invalid DATA flags")
		}
		c.mu.Lock()
		err := c.insertLocked(f.sequence, f.payload)
		next, final := c.recvNext, c.remoteFIN && c.recvNext == c.remoteFinal
		c.notifyLocked()
		c.mu.Unlock()
		if err != nil {
			return err
		}
		c.queueACK(next, final)
	case typeACK:
		c.mu.Lock()
		err := validateACK(f, c.sendNext, c.localFIN)
		if err == nil {
			if f.sequence > c.acked {
				c.acked = f.sequence
				c.trimReplayLocked()
			}
			if f.flags&flagACKFinal != 0 {
				c.localFinalACK = true
				if c.onJoinedLane {
					c.joinedFinalACK = true
				}
			}
			c.notifyLocked()
		}
		c.mu.Unlock()
		if err != nil {
			return err
		}
	case typeClose:
		if f.flags&flagFIN == 0 || f.flags&^uint16(flagFIN|flagAbort) != 0 || len(f.payload) != 0 {
			return errors.New("queqiao: invalid CLOSE")
		}
		c.mu.Lock()
		if f.flags&flagAbort != 0 {
			c.remoteAbort = true
			c.mu.Unlock()
			c.queueACK(f.sequence, true)
			return nil
		}
		if f.sequence < c.recvNext || c.remoteFIN && c.remoteFinal != f.sequence || f.sequence-c.recvNext > receiveLimit {
			c.mu.Unlock()
			return errors.New("queqiao: invalid final offset")
		}
		for _, s := range c.pending {
			if s.offset+uint64(len(s.data)) > f.sequence {
				c.mu.Unlock()
				return errors.New("queqiao: FIN precedes received data")
			}
		}
		c.remoteFIN = true
		if c.onJoinedLane {
			c.joinedFIN = true
		}
		c.remoteFinal = f.sequence
		final := c.recvNext == f.sequence
		c.notifyLocked()
		c.mu.Unlock()
		if final {
			c.queueACK(f.sequence, true)
		}
	case typeReset:
		return resetError(f)
	default:
		return errors.New("queqiao: unexpected frame in TCP flow")
	}
	c.finishIfComplete()
	return nil
}

func (c *Conn) queueACK(next uint64, final bool) {
	c.mu.Lock()
	if next > c.ackNext {
		c.ackNext = next
	}
	c.ackFinal = c.ackFinal || final
	c.mu.Unlock()
	select {
	case c.ackReady <- struct{}{}:
	default:
	}
}

// The frame reader must never wait for a control write. In full-duplex traffic
// both peers may be writing DATA; synchronous ACK writes would deadlock them.
// A single coalescing worker keeps the control queue bounded to one ACK.
func (c *Conn) ackLoop() {
	for {
		select {
		case <-c.done:
			return
		case <-c.ackReady:
		}
		c.mu.Lock()
		next, final, abort := c.ackNext, c.ackFinal, c.remoteAbort
		c.mu.Unlock()
		flags := flagACKDown
		if final {
			flags |= flagACKFinal
		}
		if err := c.send(frame{typ: typeACK, flags: flags, sequence: next}, false); err != nil {
			c.terminate(err)
			return
		}
		if final {
			c.mu.Lock()
			c.remoteFinalACKSent = true
			c.mu.Unlock()
		}
		if abort {
			c.terminate(errors.New("queqiao: gateway aborted flow"))
			return
		}
		c.finishIfComplete()
	}
}

func (c *Conn) finishIfComplete() {
	c.mu.Lock()
	finished := !c.recovering && c.remoteFIN && c.recvNext == c.remoteFinal && c.remoteFinalACKSent && c.localFinalACK
	c.mu.Unlock()
	if finished {
		c.terminate(io.EOF)
	}
}

func (c *Conn) insertLocked(offset uint64, data []byte) error {
	if uint64(len(data)) > math.MaxUint64-offset {
		return errors.New("queqiao: DATA offset overflow")
	}
	end := offset + uint64(len(data))
	if c.remoteFIN && end > c.remoteFinal {
		return errors.New("queqiao: DATA beyond FIN")
	}
	if c.bundle != nil && c.queue.Len() > 0 {
		queuedStart := c.recvNext - uint64(c.queue.Len())
		start, stop := max(offset, queuedStart), min(end, c.recvNext)
		if start < stop && !bytes.Equal(data[start-offset:stop-offset], c.queue.Bytes()[start-queuedStart:stop-queuedStart]) {
			return errors.New("queqiao: conflicting unread DATA across lanes")
		}
	}
	if end <= c.recvNext {
		return nil
	} // Retransmitted prefix, already delivered.
	if offset < c.recvNext {
		data = data[c.recvNext-offset:]
		offset = c.recvNext
	}
	if end-c.recvNext > receiveLimit {
		return errors.New("queqiao: receive gap exceeds bound")
	}
	// Trim duplicate overlap against each retained segment. At most one frame's
	// bytes are copied into new segments and the total retained span is bounded.
	additions := []segment{{offset, data}}
	for _, old := range c.pending {
		var next []segment
		oldEnd := old.offset + uint64(len(old.data))
		for _, s := range additions {
			sEnd := s.offset + uint64(len(s.data))
			if sEnd <= old.offset || s.offset >= oldEnd {
				next = append(next, s)
				continue
			}
			if c.bundle != nil {
				start, end := max(s.offset, old.offset), min(sEnd, oldEnd)
				if !bytes.Equal(s.data[start-s.offset:end-s.offset], old.data[start-old.offset:end-old.offset]) {
					return errors.New("queqiao: conflicting buffered DATA across lanes")
				}
			}
			if s.offset < old.offset {
				next = append(next, segment{s.offset, s.data[:old.offset-s.offset]})
			}
			if sEnd > oldEnd {
				next = append(next, segment{oldEnd, s.data[oldEnd-s.offset:]})
			}
		}
		additions = next
	}
	for _, s := range additions {
		c.buffered += len(s.data)
		s.data = append([]byte(nil), s.data...)
		c.pending = append(c.pending, s)
	}
	if c.buffered > receiveLimit || len(c.pending) > 1024 {
		return errors.New("queqiao: receive buffer limit exceeded")
	}
	sort.Slice(c.pending, func(i, j int) bool { return c.pending[i].offset < c.pending[j].offset })
	for len(c.pending) > 0 && c.pending[0].offset == c.recvNext {
		s := c.pending[0]
		c.pending[0] = segment{}
		c.pending = c.pending[1:]
		c.queue.Write(s.data)
		c.recvNext += uint64(len(s.data))
	}
	return nil
}
