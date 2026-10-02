package queqiao

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// This PacketConn remains attached to sing-box's routed UDP relay across wire
// generations. The token switches its wire, not the router or destination socket.
type inboundPacketConn struct {
	h                           *Inbound
	principal                   inboundPrincipal
	ctx                         context.Context
	cancel                      context.CancelFunc
	mu                          sync.Mutex
	readMu, writeMu             sync.Mutex
	wire                        *inboundWire
	window                      packetWindow
	next                        uint64
	closed                      bool
	readDeadline, writeDeadline time.Time
}

var _ N.PacketConn = (*inboundPacketConn)(nil)

func (p *inboundPacketConn) ReaderMTU() int { return maxUDPDatagram }
func (p *inboundPacketConn) WriterMTU() int { return maxUDPDatagram }

func newInboundPacketConn(h *Inbound, principal inboundPrincipal) *inboundPacketConn {
	ctx, cancel := context.WithCancel(h.ctx)
	return &inboundPacketConn{h: h, principal: principal, ctx: ctx, cancel: cancel}
}
func (p *inboundPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	for {
		p.mu.Lock()
		wire := p.wire
		closed := p.closed
		p.mu.Unlock()
		if closed || wire == nil {
			return M.Socksaddr{}, net.ErrClosed
		}
		f, err := readFrame(wire)
		p.mu.Lock()
		if wire != p.wire {
			p.mu.Unlock()
			continue
		}
		if p.closed {
			p.mu.Unlock()
			return M.Socksaddr{}, net.ErrClosed
		}
		if err != nil {
			p.mu.Unlock()
			return M.Socksaddr{}, err
		}
		if f.typ == typeClose && f.flags == flagFIN && f.sequence == 0 && len(f.payload) == 0 {
			p.mu.Unlock()
			wire.SetWriteDeadline(time.Now().Add(udpCloseTimeout))
			_ = writeFrame(wire, frame{typ: typeACK, flags: flagACKFinal, session: wire.key.session, flow: wire.key.flow})
			p.Close()
			return M.Socksaddr{}, net.ErrClosed
		}
		if f.typ != typePacket || f.flags != 0 {
			p.mu.Unlock()
			return M.Socksaddr{}, protocolError{errors.New("queqiao: invalid native server UDP frame")}
		}
		if !p.window.accept(f.sequence) {
			p.mu.Unlock()
			continue
		}
		p.mu.Unlock()
		destination, payload, err := decodePacket(f.payload)
		if err != nil {
			return M.Socksaddr{}, err
		}
		if _, err = buffer.Write(payload); err != nil {
			return M.Socksaddr{}, err
		}
		return M.ParseSocksaddr(destination), nil
	}
}
func (p *inboundPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if destination.IsFqdn() {
		return errors.New("queqiao: native UDP reply source must be numeric")
	}
	payload, err := encodePacket(destination.String(), buffer.Bytes())
	if err != nil {
		return err
	}
	p.mu.Lock()
	wire, next, closed := p.wire, p.next, p.closed
	if !closed {
		p.next++
	}
	p.mu.Unlock()
	if closed || wire == nil {
		return net.ErrClosed
	}
	return writeFrame(wire, frame{typ: typePacket, session: wire.key.session, flow: wire.key.flow, sequence: next, payload: payload})
}
func (p *inboundPacketConn) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	wire := p.wire
	p.cancel()
	p.mu.Unlock()
	if wire != nil {
		wire.Close()
	}
	p.h.mu.Lock()
	removed := false
	for key, s := range p.h.sessions {
		if s.packet == p {
			delete(p.h.sessions, key)
			removed = true
		}
	}
	for token, held := range p.h.udpTokens {
		if held == p {
			delete(p.h.udpTokens, token)
		}
	}
	if removed {
		p.h.active--
	}
	p.h.mu.Unlock()
	return nil
}
func (p *inboundPacketConn) LocalAddr() net.Addr {
	p.mu.Lock()
	wire := p.wire
	p.mu.Unlock()
	if wire == nil {
		return &net.UDPAddr{}
	}
	return wire.LocalAddr()
}
func (p *inboundPacketConn) SetDeadline(t time.Time) error {
	p.SetReadDeadline(t)
	return p.SetWriteDeadline(t)
}
func (p *inboundPacketConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	wire := p.wire
	p.mu.Unlock()
	if wire != nil {
		wire.SetReadDeadline(t)
	}
	return nil
}
func (p *inboundPacketConn) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.writeDeadline = t
	wire := p.wire
	p.mu.Unlock()
	if wire != nil {
		wire.SetWriteDeadline(t)
	}
	return nil
}
