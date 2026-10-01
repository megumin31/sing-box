package queqiao

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"time"
)

const (
	typePacket       byte = 8
	maxUDPDatagram        = 65507
	maxQueuedPackets      = 64
	udpCloseTimeout       = 500 * time.Millisecond
)

func encodePacket(destination string, payload []byte) ([]byte, error) {
	address, err := canonicalAddress(destination, 255)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxUDPDatagram {
		return nil, errors.New("queqiao: UDP datagram exceeds 65507 bytes")
	}
	out := make([]byte, 2+len(address)+len(payload))
	binary.BigEndian.PutUint16(out, uint16(len(address)))
	copy(out[2:], address)
	copy(out[2+len(address):], payload)
	return out, nil
}

func decodePacket(payload []byte) (string, []byte, error) {
	if len(payload) < 3 {
		return "", nil, errors.New("queqiao: truncated PACKET")
	}
	n := int(binary.BigEndian.Uint16(payload))
	if n == 0 || n > 255 || 2+n > len(payload) || len(payload)-2-n > maxUDPDatagram {
		return "", nil, errors.New("queqiao: invalid PACKET length")
	}
	address, err := canonicalAddress(string(payload[2:2+n]), 255)
	if err != nil {
		return "", nil, err
	}
	return address, payload[2+n:], nil
}

// One fixed bitmap admits reordered packets within the previous 64 numbers.
// A gap is loss, not a protocol error; duplicates and older packets are dropped.
type packetWindow struct {
	initialized bool
	high, bits  uint64
}

func (w *packetWindow) accept(sequence uint64) bool {
	if !w.initialized {
		w.initialized = true
		w.high = sequence
		w.bits = 1
		return true
	}
	if sequence > w.high {
		shift := sequence - w.high
		if shift >= 64 {
			w.bits = 1
		} else {
			w.bits = w.bits<<shift | 1
		}
		w.high = sequence
		return true
	}
	distance := w.high - sequence
	if distance >= 64 {
		return false
	}
	bit := uint64(1) << distance
	if w.bits&bit != 0 {
		return false
	}
	w.bits |= bit
	return true
}

type udpPacket struct {
	payload []byte
	source  *net.UDPAddr
}

type packetConn struct {
	wire                       *Conn
	resume                     udpResumeFunc
	token                      [16]byte
	queue                      []udpPacket
	queueBytes                 int
	window                     packetWindow
	next                       uint64
	closing, closeAcknowledged bool
}

var _ net.PacketConn = (*packetConn)(nil)

func newPacketConn(raw net.Conn, session [16]byte, flow uint64, onClose func()) *packetConn {
	return newResumablePacketConn(raw, session, flow, onClose, nil, [16]byte{}, nil)
}
func newResumablePacketConn(raw net.Conn, session [16]byte, flow uint64, onClose func(), ctx context.Context, token [16]byte, resume udpResumeFunc) *packetConn {
	p := &packetConn{wire: newConnState(raw, session, flow, onClose), token: token, resume: resume}
	if resume != nil {
		p.wire.recoveryCtx, p.wire.recoveryCancel = context.WithCancel(ctx)
	}
	go p.readLoop()
	return p
}

func (p *packetConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c := p.wire
	for {
		c.mu.Lock()
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			c.mu.Unlock()
			return 0, nil, os.ErrDeadlineExceeded
		}
		if len(p.queue) > 0 {
			packet := p.queue[0]
			p.queue[0] = udpPacket{}
			p.queue = p.queue[1:]
			p.queueBytes -= len(packet.payload)
			c.mu.Unlock()
			// As with net.UDPConn, a small read buffer truncates this datagram, rather
			// than spilling its remainder into the next ReadFrom.
			return copy(buffer, packet.payload), packet.source, nil
		}
		if c.closed || p.closing {
			err := c.err
			c.mu.Unlock()
			if err == nil {
				err = net.ErrClosed
			}
			return 0, nil, err
		}
		changed, deadline := c.changed, c.readDeadline
		c.mu.Unlock()
		if err := waitChange(changed, c.done, deadline); errors.Is(err, os.ErrDeadlineExceeded) {
			return 0, nil, err
		}
	}
}

func (p *packetConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	if address == nil {
		return 0, errors.New("queqiao: UDP destination is required")
	}
	c := p.wire
	if err := c.acquire(c.applicationGate, true); err != nil {
		return 0, err
	}
	defer func() { c.applicationGate <- struct{}{} }()
	// Only the active application writer owns an encoded packet. Waiting
	// callers do not accumulate one copied datagram each during an outage.
	encoded, err := encodePacket(address.String(), payload)
	if err != nil {
		return 0, err
	}
	for {
		if err = c.waitReady(true, time.Time{}); err != nil {
			return 0, err
		}
		if err = c.acquire(c.writeGate, true); err != nil {
			return 0, err
		}
		c.mu.Lock()
		if c.closed || p.closing {
			c.mu.Unlock()
			c.writeGate <- struct{}{}
			return 0, net.ErrClosed
		}
		if c.recovering || c.carrier == nil {
			c.mu.Unlock()
			c.writeGate <- struct{}{}
			continue
		}
		if p.next == math.MaxUint64 {
			c.mu.Unlock()
			c.writeGate <- struct{}{}
			c.terminate(errors.New("queqiao: packet number exhausted"))
			return 0, errors.New("queqiao: packet number exhausted")
		}
		f := frame{typ: typePacket, session: c.session, flow: c.flow, sequence: p.next, payload: encoded}
		p.next++
		raw := c.carrier
		c.writingApplication = true
		raw.SetWriteDeadline(c.writeDeadline)
		c.mu.Unlock()
		err = writeFrame(raw, f)
		c.mu.Lock()
		c.writingApplication = false
		raw.SetWriteDeadline(time.Time{})
		c.mu.Unlock()
		c.writeGate <- struct{}{}
		if err != nil {
			if !p.failCarrier(raw, err) {
				return 0, err
			}
			// UDP permits loss. Consuming the ambiguous datagram after a
			// successful reclaim keeps sing-box's packet-copy loop alive,
			// without replaying a packet that may already have been delivered.
			if err = c.waitReady(true, time.Time{}); err != nil {
				return 0, err
			}
			return len(payload), nil
		}
		break
	}
	return len(payload), nil
}

func (p *packetConn) LocalAddr() net.Addr                { return p.wire.LocalAddr() }
func (p *packetConn) SetDeadline(t time.Time) error      { return p.wire.SetDeadline(t) }
func (p *packetConn) SetReadDeadline(t time.Time) error  { return p.wire.SetReadDeadline(t) }
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.wire.SetWriteDeadline(t) }

func (p *packetConn) Close() error {
	c := p.wire
	c.mu.Lock()
	if c.closed || p.closing {
		c.mu.Unlock()
		return nil
	}
	p.closing = true
	if c.recoveryCancel != nil {
		c.recoveryCancel()
	}
	c.notifyLocked()
	c.mu.Unlock()
	// Do not queue CLOSE behind a blocked application writer. In that case,
	// carrier cancellation ends the local association instead.
	select {
	case <-c.writeGate:
		raw := c.currentCarrier()
		if raw == nil {
			c.writeGate <- struct{}{}
			c.terminate(net.ErrClosed)
			return nil
		}
		deadline := time.Now().Add(udpCloseTimeout)
		raw.SetWriteDeadline(deadline)
		err := writeFrame(raw, frame{typ: typeClose, flags: flagFIN, session: c.session, flow: c.flow})
		c.writeGate <- struct{}{}
		if err == nil {
			timer := time.NewTimer(time.Until(deadline))
			select {
			case <-c.done:
			case <-timer.C:
			}
			timer.Stop()
		}
	default:
	}
	c.terminate(net.ErrClosed)
	return nil
}

func (p *packetConn) readLoop() {
	c := p.wire
	for {
		if err := c.waitReady(false, time.Time{}); err != nil {
			return
		}
		c.mu.Lock()
		raw, session, flow := c.carrier, c.session, c.flow
		c.mu.Unlock()
		if raw == nil {
			continue
		}
		f, err := readFrame(raw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			if p.failCarrier(raw, err) {
				continue
			}
			return
		}
		c.mu.Lock()
		stale := raw != c.carrier || c.closed
		c.mu.Unlock()
		if stale {
			continue
		}
		if f.session != session || f.flow != flow {
			c.terminate(errors.New("queqiao: packet belongs to another association"))
			return
		}
		switch f.typ {
		case typePacket:
			if f.flags != 0 {
				c.terminate(errors.New("queqiao: invalid PACKET flags"))
				return
			}
			destination, payload, err := decodePacket(f.payload)
			if err != nil {
				c.terminate(err)
				return
			}
			numeric, err := netip.ParseAddrPort(destination)
			if err != nil {
				c.terminate(errors.New("queqiao: gateway UDP reply must have a numeric source"))
				return
			}
			c.mu.Lock()
			if !c.closed && raw == c.carrier && !p.closing && p.window.accept(f.sequence) && len(p.queue) < maxQueuedPackets && p.queueBytes+len(payload) <= receiveLimit {
				p.queue = append(p.queue, udpPacket{payload: append([]byte(nil), payload...), source: net.UDPAddrFromAddrPort(numeric)})
				p.queueBytes += len(payload)
				c.notifyLocked()
			}
			c.mu.Unlock()
		case typeACK:
			c.mu.Lock()
			valid := p.closing && f.flags == flagACKFinal && f.sequence == 0 && len(f.payload) == 0
			if valid {
				p.closeAcknowledged = true
			}
			c.mu.Unlock()
			if !valid {
				c.terminate(errors.New("queqiao: invalid UDP final ACK"))
				return
			}
			c.terminate(net.ErrClosed)
			return
		case typeClose:
			if f.flags != flagFIN || f.sequence != 0 || len(f.payload) != 0 {
				c.terminate(errors.New("queqiao: invalid UDP CLOSE"))
				return
			}
			c.mu.Lock()
			p.closing = true
			c.notifyLocked()
			c.mu.Unlock()
			// Peer Close is terminal, including during a concurrent lane failure.
			select {
			case <-c.writeGate:
				raw.SetWriteDeadline(time.Now().Add(udpCloseTimeout))
				_ = writeFrame(raw, frame{typ: typeACK, flags: flagACKFinal, session: session, flow: flow})
				c.writeGate <- struct{}{}
			default:
			}
			c.terminate(net.ErrClosed)
			return
		case typeReset:
			c.terminate(resetError(f))
			return
		default:
			c.terminate(errors.New("queqiao: unexpected frame in UDP association"))
			return
		}
	}
}
