package queqiao

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"time"
)

type inboundFlowKey struct {
	session [16]byte
	flow    uint64
}

type inboundLane struct {
	raw          net.Conn
	tcp, control bool
}

// inboundWire keeps a passive, bounded logical carrier alive across physical
// JOINs. The existing Conn owns byte offsets, deduplication and FIN state. Its
// client-oriented ACK flags are mirrored here for the server endpoint. Only
// admitted, authenticated lanes enter this object; routing IDs confer no trust.
type inboundWire struct {
	mu                                 sync.Mutex
	readMu, sendMu                     sync.Mutex
	key                                inboundFlowKey
	lanes                              []*inboundLane
	reserved, tcpMode, packets, closed bool
	changed                            chan struct{}
	queue                              []frame
	queued                             int
	readBuffer                         bytes.Buffer
	replay                             []frame
	replayBytes                        int
	sent                               uint64
	fin, ack                           *frame
	finalACK, packetFinal              bool
	readDeadline, writeDeadline        time.Time
	outage                             uint64
	outageStop                         chan struct{}
	grace                              time.Duration
	local, remote                      net.Addr
	err                                error
	onRetire                           func(net.Conn)
}

func newInboundWire(key inboundFlowKey, packets, reserved bool) *inboundWire {
	grace := recoveryTimeout
	if packets {
		grace = udpResumeTimeout
	}
	return &inboundWire{key: key, packets: packets, reserved: reserved, changed: make(chan struct{}), grace: grace}
}

func mirrorACK(f frame) frame {
	if f.typ == typeACK {
		up, down := f.flags&flagACKUp != 0, f.flags&flagACKDown != 0
		f.flags &^= flagACKUp | flagACKDown
		if up {
			f.flags |= flagACKDown
		}
		if down {
			f.flags |= flagACKUp
		}
	}
	return f
}

func (w *inboundWire) notifyLocked() { close(w.changed); w.changed = make(chan struct{}) }
func (w *inboundWire) hasLaneLocked(lane *inboundLane) bool {
	for _, current := range w.lanes {
		if current == lane {
			return true
		}
	}
	return false
}
func (w *inboundWire) chooseLocked(data bool) *inboundLane {
	if data && w.reserved && !w.tcpMode {
		for _, lane := range w.lanes {
			if !lane.control {
				return lane
			}
		}
	}
	if len(w.lanes) > 0 {
		return w.lanes[0]
	}
	return nil
}

// Admission is serialized with frame writes. First TCP JOIN freezes and aborts
// all QUIC lanes before OPEN_OK and replay; it never creates a mixed bundle.
func (w *inboundWire) admit(raw net.Conn, tcp, control bool, response frame) error {
	w.mu.Lock()
	if w.closed || w.tcpMode && !tcp || control && (tcp || !w.reserved) {
		w.mu.Unlock()
		return protocolError{errors.New("queqiao: inadmissible server lane")}
	}
	var retired []*inboundLane
	if tcp && !w.tcpMode {
		retired = w.lanes
		w.lanes = nil
		w.tcpMode = true
		w.armOutageLocked()
		w.notifyLocked()
	}
	if len(w.lanes) >= 2 {
		w.mu.Unlock()
		return gatewayResetError{4}
	}
	w.mu.Unlock()
	for _, old := range retired {
		abortCarrier(old.raw)
		if w.onRetire != nil {
			w.onRetire(old.raw)
		}
	}
	w.sendMu.Lock()
	defer w.sendMu.Unlock()
	w.mu.Lock()
	if w.closed || w.tcpMode && !tcp {
		w.mu.Unlock()
		return net.ErrClosed
	}
	if len(w.lanes) >= 2 {
		w.mu.Unlock()
		return gatewayResetError{4}
	}
	replay := append([]frame(nil), w.replay...)
	var ack, fin *frame
	if w.ack != nil {
		x := *w.ack
		ack = &x
	}
	if w.fin != nil {
		x := *w.fin
		fin = &x
	}
	w.mu.Unlock()
	raw.SetWriteDeadline(time.Now().Add(joinTimeout))
	if err := writeFrame(raw, response); err != nil {
		return err
	}
	if ack != nil {
		if err := writeFrame(raw, *ack); err != nil {
			return err
		}
	}
	for _, f := range replay {
		if err := writeFrame(raw, f); err != nil {
			return err
		}
	}
	if fin != nil {
		if err := writeFrame(raw, *fin); err != nil {
			return err
		}
	}
	raw.SetWriteDeadline(time.Time{})
	lane := &inboundLane{raw: raw, tcp: tcp, control: control}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return net.ErrClosed
	}
	w.lanes = append(w.lanes, lane)
	w.local, w.remote = raw.LocalAddr(), raw.RemoteAddr()
	w.outage++
	if w.outageStop != nil {
		close(w.outageStop)
		w.outageStop = nil
	}
	w.notifyLocked()
	w.mu.Unlock()
	go w.readLane(lane)
	return nil
}

func (w *inboundWire) failLane(lane *inboundLane) {
	w.mu.Lock()
	if w.closed || !w.hasLaneLocked(lane) {
		w.mu.Unlock()
		return
	}
	for i, current := range w.lanes {
		if current == lane {
			w.lanes = append(w.lanes[:i], w.lanes[i+1:]...)
			break
		}
	}
	if len(w.lanes) == 0 {
		w.armOutageLocked()
	}
	w.notifyLocked()
	w.mu.Unlock()
	abortCarrier(lane.raw)
	if w.onRetire != nil {
		w.onRetire(lane.raw)
	}
}

// A failed first TCP admission must still expire after retiring the QUIC
// lanes. Check the epoch and close under one lock so a successful replacement
// cannot be closed by a stale timer.
func (w *inboundWire) armOutageLocked() {
	w.outage++
	epoch := w.outage
	if w.outageStop != nil {
		close(w.outageStop)
	}
	stop := make(chan struct{})
	w.outageStop = stop
	go func() {
		timer := time.NewTimer(w.grace)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-stop:
			return
		}
		w.mu.Lock()
		var retired []*inboundLane
		if !w.closed && len(w.lanes) == 0 && w.outage == epoch {
			retired = w.closeLocked(errors.New("queqiao: passive carrier replacement grace exhausted"))
		}
		w.mu.Unlock()
		w.retire(retired)
	}()
}

func (w *inboundWire) readLane(lane *inboundLane) {
	for {
		f, err := readFrame(lane.raw)
		if err != nil {
			w.failLane(lane)
			return
		}
		w.mu.Lock()
		if w.closed || !w.hasLaneLocked(lane) {
			w.mu.Unlock()
			return
		}
		if f.session != w.key.session || f.flow != w.key.flow {
			w.mu.Unlock()
			w.closeWithError(protocolError{errors.New("queqiao: server lane frame identity mismatch")})
			return
		}
		if f.typ == typeACK && !w.packets {
			if err = validateACK(mirrorACK(f), w.sent, w.fin != nil); err != nil {
				w.mu.Unlock()
				w.closeWithError(protocolError{err})
				return
			}
			if f.flags&flagACKFinal != 0 {
				w.finalACK = true
			}
			for len(w.replay) > 0 {
				first := &w.replay[0]
				end := first.sequence + uint64(len(first.payload))
				if end <= f.sequence {
					w.replayBytes -= len(first.payload)
					w.replay[0] = frame{}
					w.replay = w.replay[1:]
					continue
				}
				if first.sequence < f.sequence {
					trimmed := int(f.sequence - first.sequence)
					first.payload = first.payload[trimmed:]
					first.sequence = f.sequence
					w.replayBytes -= trimmed
				}
				break
			}
		}
		for !w.closed && w.hasLaneLocked(lane) && w.queued+headerSize+len(f.payload) > receiveLimit {
			changed := w.changed
			w.mu.Unlock()
			<-changed
			w.mu.Lock()
		}
		if w.closed || !w.hasLaneLocked(lane) {
			w.mu.Unlock()
			return
		}
		w.queue = append(w.queue, f)
		w.queued += headerSize + len(f.payload)
		w.notifyLocked()
		w.mu.Unlock()
	}
}

func (w *inboundWire) Read(p []byte) (int, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()
	if w.readBuffer.Len() > 0 {
		return w.readBuffer.Read(p)
	}
	for {
		w.mu.Lock()
		if len(w.queue) > 0 {
			f := w.queue[0]
			w.queue[0] = frame{}
			w.queue = w.queue[1:]
			w.queued -= headerSize + len(f.payload)
			w.notifyLocked()
			w.mu.Unlock()
			if err := writeFrame(&w.readBuffer, mirrorACK(f)); err != nil {
				return 0, err
			}
			return w.readBuffer.Read(p)
		}
		if w.closed {
			err := w.err
			w.mu.Unlock()
			if err == nil {
				err = net.ErrClosed
			}
			return 0, err
		}
		changed, deadline := w.changed, w.readDeadline
		w.mu.Unlock()
		if err := waitChange(changed, nil, deadline); err != nil {
			return 0, err
		}
	}
}

func (w *inboundWire) Write(p []byte) (int, error) {
	f, err := readFrame(bytes.NewReader(p))
	if err != nil {
		return 0, err
	}
	f = mirrorACK(f)
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return 0, net.ErrClosed
	}
	if f.session != w.key.session || f.flow != w.key.flow {
		w.mu.Unlock()
		return 0, protocolError{errors.New("queqiao: server write identity mismatch")}
	}
	if f.typ == typeData {
		if f.sequence != w.sent || w.replayBytes+len(f.payload) > sendWindow {
			w.mu.Unlock()
			return 0, protocolError{errors.New("queqiao: server replay bound or offset mismatch")}
		}
		w.sent += uint64(len(f.payload))
		w.replay = append(w.replay, f)
		w.replayBytes += len(f.payload)
	} else if f.typ == typeClose && !w.packets {
		copy := f
		w.fin = &copy
	} else if f.typ == typeACK && f.flags&flagACKUp != 0 {
		copy := f
		w.ack = &copy
	} else if w.packets && f.typ == typeACK && f.flags == flagACKFinal {
		w.packetFinal = true
	}
	w.mu.Unlock()
	blocked := false
	for {
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return 0, net.ErrClosed
		}
		lane := w.chooseLocked(f.typ == typeData)
		if lane == nil {
			if w.packets && f.typ == typePacket {
				w.mu.Unlock()
				return len(p), nil
			} // possibly lost, never replayed
			changed := w.changed
			w.mu.Unlock()
			blocked = true
			<-changed
			continue
		}
		w.mu.Unlock()
		w.sendMu.Lock()
		w.mu.Lock()
		if w.closed || !w.hasLaneLocked(lane) {
			w.mu.Unlock()
			w.sendMu.Unlock()
			continue
		}
		deadline := w.writeDeadline
		if w.packets && deadline.IsZero() {
			deadline = time.Now().Add(controlTimeout)
		}
		if blocked && !deadline.IsZero() {
			deadline = time.Now().Add(controlTimeout)
		}
		lane.raw.SetWriteDeadline(deadline)
		w.mu.Unlock()
		err = writeFrame(lane.raw, f)
		lane.raw.SetWriteDeadline(time.Time{})
		w.sendMu.Unlock()
		if err == nil {
			return len(p), nil
		}
		w.failLane(lane)
		if w.packets && f.typ == typePacket {
			return len(p), nil
		}
	}
}

func (w *inboundWire) closeWithError(err error) {
	w.mu.Lock()
	// QUIC Write queues bytes. A complete logical close must flush its final
	// ACK instead of CancelWrite discarding it after Write reported success.
	drain := err == net.ErrClosed && (w.packets && w.packetFinal || !w.packets && w.finalACK && w.fin != nil && w.fin.flags == flagFIN && w.ack != nil && w.ack.flags&flagACKFinal != 0)
	lanes := w.closeLocked(err)
	w.mu.Unlock()
	if drain {
		for _, lane := range lanes {
			closeCarrier(lane.raw)
			if w.onRetire != nil {
				w.onRetire(lane.raw)
			}
		}
	} else {
		w.retire(lanes)
	}
}

func (w *inboundWire) closeLocked(err error) []*inboundLane {
	if w.closed {
		return nil
	}
	w.closed = true
	w.err = err
	lanes := w.lanes
	w.lanes = nil
	w.queue = nil
	w.replay = nil
	w.replayBytes = 0
	w.queued = 0
	if w.outageStop != nil {
		close(w.outageStop)
		w.outageStop = nil
	}
	w.notifyLocked()
	return lanes
}

func (w *inboundWire) retire(lanes []*inboundLane) {
	for _, lane := range lanes {
		abortCarrier(lane.raw)
		if w.onRetire != nil {
			w.onRetire(lane.raw)
		}
	}
}
func (w *inboundWire) Close() error { w.closeWithError(net.ErrClosed); return nil }
func (w *inboundWire) LocalAddr() net.Addr {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.local == nil {
		return &net.TCPAddr{}
	}
	return w.local
}
func (w *inboundWire) RemoteAddr() net.Addr {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.remote == nil {
		return &net.TCPAddr{}
	}
	return w.remote
}
func (w *inboundWire) SetDeadline(t time.Time) error {
	w.SetReadDeadline(t)
	return w.SetWriteDeadline(t)
}
func (w *inboundWire) SetReadDeadline(t time.Time) error {
	w.mu.Lock()
	w.readDeadline = t
	w.notifyLocked()
	w.mu.Unlock()
	return nil
}
func (w *inboundWire) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	w.writeDeadline = t
	w.mu.Unlock()
	return nil
}

var _ net.Conn = (*inboundWire)(nil)
