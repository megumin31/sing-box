package queqiao

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.QueqiaoInboundOptions](registry, C.TypeQueqiao, NewInbound)
}

type nativeSession struct {
	key                inboundFlowKey
	principal          inboundPrincipal
	wire               *inboundWire
	conn               *Conn
	packet             *inboundPacketConn
	laneIDs            map[uint64]bool
	reserved           bool
	completed          bool
	expires            time.Time
	upFinal, downFinal uint64
}

type Inbound struct {
	inbound.Adapter
	ctx                 context.Context
	cancel              context.CancelFunc
	router              adapter.ConnectionRouterEx
	logger              log.ContextLogger
	listener            *listener.Listener
	tlsConfig           *tls.Config
	allowed             map[inboundPrincipal]string
	provider            string
	transport           string
	idle                time.Duration
	maxSessions, active int
	mu                  sync.Mutex
	udpAdmissionMu      sync.Mutex
	closed              bool
	sessions            map[inboundFlowKey]*nativeSession
	udpTokens           map[[16]byte]*inboundPacketConn
	raw                 map[net.Conn]struct{}
	handshakes          chan struct{}
	closeQUIC           func() error
}

var _ adapter.Inbound = (*Inbound)(nil)

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.QueqiaoInboundOptions) (adapter.Inbound, error) {
	if options.ListenPort == 0 {
		return nil, errors.New("queqiao: native server requires an explicit listen_port")
	}
	transport := options.Transport
	if transport == "" {
		transport = "auto"
	}
	if transport != "tcp" && transport != "quic" && transport != "auto" {
		return nil, errors.New("queqiao: server transport must be tcp, quic or auto")
	}
	if transport != "tcp" {
		if err := checkQUIC(); err != nil {
			return nil, err
		}
	}
	limit := options.MaxSessions
	if limit == 0 {
		limit = 16
	}
	if limit < 1 || limit > 64 {
		return nil, errors.New("queqiao: max_sessions must be 1 to 64")
	}
	idle := time.Duration(options.QUICIdleTimeout)
	if idle == 0 {
		idle = 30 * time.Second
	}
	if idle < 5*time.Second || idle > time.Minute {
		return nil, errors.New("queqiao: quic_idle_timeout must be between 5s and 1m")
	}
	config, allowed, err := loadServerProfile(options.CredentialsPath, options.Users)
	if err != nil {
		return nil, err
	}
	// The verified gateway URI identifies its provider; no caller-supplied
	// principal override or insecure TLS option exists.
	leaf := config.Certificates[0].Leaf
	if leaf == nil {
		return nil, errors.New("queqiao: verified gateway leaf missing")
	}
	lifetime, cancel := context.WithCancel(ctx)
	h := &Inbound{Adapter: inbound.NewAdapter(C.TypeQueqiao, tag), ctx: lifetime, cancel: cancel, router: router, logger: logger, tlsConfig: config, allowed: allowed, provider: leaf.URIs[0].Host, transport: transport, idle: idle, maxSessions: limit, sessions: make(map[inboundFlowKey]*nativeSession), udpTokens: make(map[[16]byte]*inboundPacketConn), raw: make(map[net.Conn]struct{}), handshakes: make(chan struct{}, 32)}
	h.listener = listener.New(listener.Options{Context: lifetime, Logger: logger, Listen: options.ListenOptions})
	return h, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.transport != "quic" {
		l, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		go h.acceptTCP(l)
	}
	if h.transport != "tcp" {
		if err := startNativeQUICInbound(h); err != nil {
			h.listener.Close()
			return err
		}
	}
	go h.sweep()
	return nil
}
func (h *Inbound) sweep() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case now := <-ticker.C:
			h.mu.Lock()
			for key, f := range h.sessions {
				if f.completed && !now.Before(f.expires) {
					delete(h.sessions, key)
				}
			}
			h.mu.Unlock()
		}
	}
}
func (h *Inbound) track(raw net.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.raw[raw] = struct{}{}
	return true
}
func (h *Inbound) untrack(raw net.Conn) { h.mu.Lock(); delete(h.raw, raw); h.mu.Unlock() }
func (h *Inbound) acceptTCP(l net.Listener) {
	for {
		raw, err := l.Accept()
		if err != nil {
			return
		}
		select {
		case h.handshakes <- struct{}{}:
		default:
			raw.Close()
			continue
		}
		if !h.track(raw) {
			raw.Close()
			<-h.handshakes
			return
		}
		go func() {
			defer func() { <-h.handshakes; h.untrack(raw) }()
			ctx, cancel := context.WithTimeout(h.ctx, 15*time.Second)
			defer cancel()
			secure := tls.Server(raw, h.tlsConfig)
			if secure.HandshakeContext(ctx) != nil {
				raw.Close()
				return
			}
			state := secure.ConnectionState()
			principal, err := parseInboundPrincipal(state.PeerCertificates[0], h.provider)
			if err != nil {
				raw.Close()
				return
			}
			if !h.track(secure) {
				raw.Close()
				return
			}
			h.handleCarrier(secure, true, principal)
		}()
	}
}
func (h *Inbound) handleCarrier(raw net.Conn, tcp bool, principal inboundPrincipal) {
	success := false
	defer func() {
		if !success {
			abortCarrier(raw)
			h.untrack(raw)
		}
	}()
	raw.SetDeadline(time.Now().Add(15 * time.Second))
	f, err := readFrame(raw)
	if err != nil {
		return
	}
	key := inboundFlowKey{f.session, f.flow}
	if key.session == ([16]byte{}) || key.flow == 0 || f.sequence != 0 {
		h.reset(raw, key, 1)
		return
	}
	raw.SetDeadline(time.Time{})
	if f.typ == typeJoin {
		if f.flags & ^uint16(flagReserve) != 0 || len(f.payload) != 8 || binary.BigEndian.Uint64(f.payload) == 0 {
			h.reset(raw, key, 1)
			return
		}
		id := binary.BigEndian.Uint64(f.payload)
		h.mu.Lock()
		session := h.sessions[key]
		if session == nil || session.principal != principal || session.packet != nil || session.laneIDs[id] || len(session.laneIDs) >= 16 {
			h.mu.Unlock()
			h.reset(raw, key, 1)
			return
		}
		if f.flags&flagReserve != 0 && (tcp || !session.reserved) {
			h.mu.Unlock()
			h.reset(raw, key, 1)
			return
		}
		session.laneIDs[id] = true
		completed := session.completed
		up, down := session.upFinal, session.downFinal
		h.mu.Unlock()
		if completed {
			h.completedJOIN(raw, key, up, down)
			return
		}
		if err = session.wire.admit(raw, tcp, f.flags&flagReserve != 0, frame{typ: typeOpenOK, session: key.session, flow: key.flow}); err != nil {
			var reset gatewayResetError
			code := byte(1)
			if errors.As(err, &reset) {
				code = reset.code
			}
			h.reset(raw, key, code)
			return
		}
		h.logAdmission(tcp, "JOIN")
		success = true
		return
	}
	if f.typ != typeOpen || f.flags & ^uint16(flagReserve) != 0 || tcp && f.flags&flagReserve != 0 {
		h.reset(raw, key, 1)
		return
	}
	isUDP := len(f.payload) == 5 && string(f.payload) == "WOUD\x01" || isUDPResumeOpen(f.payload)
	if isUDP {
		if f.flags != 0 {
			h.reset(raw, key, 1)
			return
		}
		success = h.openUDP(raw, tcp, principal, key, f.payload)
		return
	}
	address, err := canonicalAddress(string(f.payload), 255)
	if err != nil {
		h.reset(raw, key, 1)
		return
	}
	wire := newInboundWire(key, false, f.flags&flagReserve != 0)
	wire.onRetire = h.untrack
	session := &nativeSession{key: key, principal: principal, wire: wire, reserved: wire.reserved, laneIDs: make(map[uint64]bool)}
	c := newConnState(wire, key.session, key.flow, func() { h.tcpEnded(session) })
	session.conn = c
	h.mu.Lock()
	if h.closed || h.active >= h.maxSessions || len(h.sessions) >= h.maxSessions*16 || h.sessions[key] != nil {
		h.mu.Unlock()
		h.reset(raw, key, 4)
		wire.Close()
		return
	}
	h.sessions[key] = session
	h.active++
	h.mu.Unlock()
	go c.ackLoop()
	go c.readLoop()
	routed := &inboundTCPConn{Conn: c, h: h, session: session, raw: raw, tcp: tcp}
	metadata := adapter.InboundContext{Inbound: h.Tag(), InboundType: h.Type(), Source: M.SocksaddrFromNet(raw.RemoteAddr()), Destination: M.ParseSocksaddr(address), User: h.allowed[principal], Network: N.NetworkTCP}
	h.router.RouteConnectionEx(h.ctx, routed, metadata, nil)
	success = true
}
func (h *Inbound) reset(raw net.Conn, key inboundFlowKey, code byte) {
	raw.SetWriteDeadline(time.Now().Add(time.Second))
	_ = writeFrame(raw, frame{typ: typeReset, session: key.session, flow: key.flow, payload: []byte{code}})
}
func (h *Inbound) completedJOIN(raw net.Conn, key inboundFlowKey, up, down uint64) {
	raw.SetDeadline(time.Now().Add(joinTimeout))
	if writeFrame(raw, frame{typ: typeOpenOK, session: key.session, flow: key.flow}) != nil {
		return
	}
	if writeFrame(raw, frame{typ: typeACK, flags: flagACKUp | flagACKFinal, session: key.session, flow: key.flow, sequence: up}) != nil {
		return
	}
	if writeFrame(raw, frame{typ: typeClose, flags: flagFIN, session: key.session, flow: key.flow, sequence: down}) != nil {
		return
	}
	for range 16 {
		f, err := readFrame(raw)
		if err != nil {
			return
		}
		if f.session != key.session || f.flow != key.flow {
			return
		}
		if f.typ == typeACK && f.flags == flagACKDown|flagACKFinal && f.sequence == down {
			return
		}
	}
}
func (h *Inbound) tcpEnded(f *nativeSession) {
	c := f.conn
	c.mu.Lock()
	completed := errors.Is(c.err, io.EOF)
	up, down := c.remoteFinal, c.sendNext
	c.mu.Unlock()
	h.mu.Lock()
	if h.sessions[f.key] == f {
		h.active--
		if completed && !h.closed {
			// The tombstone must not retain Conn's unread application buffers
			// or the physical mux. Routing may finish draining the old Conn
			// independently; only final metadata is reachable from this map.
			h.sessions[f.key] = &nativeSession{key: f.key, principal: f.principal, reserved: f.reserved, laneIDs: f.laneIDs, completed: true, expires: time.Now().Add(recoveryTimeout), upFinal: up, downFinal: down}
		} else {
			delete(h.sessions, f.key)
		}
	}
	h.mu.Unlock()
	h.releaseWire(f.wire)
}
func (h *Inbound) releaseWire(w *inboundWire) { w.Close() }
func (h *Inbound) logAdmission(tcp bool, operation string) {
	if h.logger != nil {
		carrier := "quic"
		if tcp {
			carrier = "tcp"
		}
		h.logger.Debug("native reliable ", operation, " admitted on ", carrier)
	}
}
func (h *Inbound) Close() error {
	h.cancel()
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	h.active = 0
	sessions := h.sessions
	raw := h.raw
	h.sessions = make(map[inboundFlowKey]*nativeSession)
	h.raw = make(map[net.Conn]struct{})
	h.udpTokens = make(map[[16]byte]*inboundPacketConn)
	h.mu.Unlock()
	for _, f := range sessions {
		if f.conn != nil {
			f.conn.terminate(net.ErrClosed)
		} else if f.packet != nil {
			f.packet.Close()
		}
	}
	for conn := range raw {
		abortCarrier(conn)
	}
	if h.closeQUIC != nil {
		h.closeQUIC()
	}
	return h.listener.Close()
}

type inboundTCPConn struct {
	*Conn
	h       *Inbound
	session *nativeSession
	raw     net.Conn
	tcp     bool
	once    sync.Once
	err     error
}

// The router closes both copies when their application EOFs have arrived.
// Logical FIN/ACK completion can still be in flight at that point. Preserve
// the passive session for the existing recovery grace instead of converting
// a normal close into ABORT and deleting the state needed by a late JOIN.
func (c *inboundTCPConn) Close() error {
	c.mu.Lock()
	finishing := !c.closed && c.localFIN && c.remoteFIN && !c.remoteAbort && c.recvNext == c.remoteFinal
	c.mu.Unlock()
	if finishing {
		timer := time.NewTimer(recoveryTimeout)
		select {
		case <-c.done:
		case <-c.h.ctx.Done():
		case <-timer.C:
		}
		timer.Stop()
	}
	return c.Conn.Close()
}

func (c *inboundTCPConn) HandshakeSuccess() error {
	c.once.Do(func() {
		key := c.session.key
		c.err = c.session.wire.admit(c.raw, c.tcp, c.session.wire.reserved, frame{typ: typeOpenOK, session: key.session, flow: key.flow})
		if c.err != nil {
			c.Conn.terminate(c.err)
		} else {
			c.h.logAdmission(c.tcp, "OPEN")
		}
	})
	return c.err
}
func (c *inboundTCPConn) HandshakeFailure(err error) error {
	c.once.Do(func() {
		c.err = err
		c.h.reset(c.raw, c.session.key, 3)
		c.Conn.terminate(err)
		abortCarrier(c.raw)
		c.h.untrack(c.raw)
	})
	return nil
}

func (h *Inbound) openUDP(raw net.Conn, tcp bool, principal inboundPrincipal, key inboundFlowKey, payload []byte) bool {
	// Serialize token claims through admission. No new generation may replace
	// another generation that is still completing OPEN_OK.
	h.udpAdmissionMu.Lock()
	defer h.udpAdmissionMu.Unlock()
	resumable := isUDPResumeOpen(payload)
	var requested [16]byte
	if len(payload) == 21 {
		copy(requested[:], payload[5:])
	}
	var token [16]byte
	if resumable {
		for token == ([16]byte{}) {
			if _, err := rand.Read(token[:]); err != nil {
				return false
			}
		}
	}
	h.mu.Lock()
	if h.closed || h.sessions[key] != nil {
		h.mu.Unlock()
		h.reset(raw, key, 1)
		return false
	}
	p := h.udpTokens[requested]
	resumed := requested != ([16]byte{}) && p != nil && p.principal == principal
	if resumed {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			h.mu.Unlock()
			h.reset(raw, key, 1)
			return false
		}
	}
	if !resumed {
		if h.active >= h.maxSessions || len(h.sessions) >= h.maxSessions*16 {
			h.mu.Unlock()
			h.reset(raw, key, 4)
			return false
		}
		p = newInboundPacketConn(h, principal)
		h.active++
	} else {
		delete(h.udpTokens, requested)
		for oldKey, s := range h.sessions {
			if s.packet == p {
				delete(h.sessions, oldKey)
			}
		}
	}
	wire := newInboundWire(key, true, false)
	wire.onRetire = h.untrack
	session := &nativeSession{key: key, principal: principal, wire: wire, packet: p}
	h.sessions[key] = session
	if resumable {
		h.udpTokens[token] = p
	}
	h.mu.Unlock()
	// Wait for an old reply write before switching generations. Physical UDP
	// writes are bounded; packets in flight are never replayed.
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		wire.Close()
		return false
	}
	old := p.wire
	p.wire = wire
	p.window = packetWindow{}
	p.next = 0
	wire.SetReadDeadline(p.readDeadline)
	wire.SetWriteDeadline(p.writeDeadline)
	p.mu.Unlock()
	if old != nil {
		h.releaseWire(old)
	}
	grant := []byte(nil)
	if resumable {
		grant = append([]byte{0}, token[:]...)
		if resumed {
			grant[0] = 1
		}
	}
	if err := wire.admit(raw, tcp, false, frame{typ: typeOpenOK, session: key.session, flow: key.flow, payload: grant}); err != nil {
		p.Close()
		return false
	}
	h.logAdmission(tcp, "UDP OPEN")
	if !resumed {
		go func() {
			buffer := buf.NewSize(maxUDPDatagram)
			destination, err := p.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				p.Close()
				return
			}
			cached := bufio.NewCachedPacketConn(p, buffer, destination)
			buffer.Release()
			metadata := adapter.InboundContext{Inbound: h.Tag(), InboundType: h.Type(), Source: M.SocksaddrFromNet(raw.RemoteAddr()), Destination: destination, User: h.allowed[principal], Network: N.NetworkUDP, UDPDisableDomainUnmapping: true}
			h.router.RoutePacketConnectionEx(p.ctx, cached, metadata, nil)
		}()
	}
	return true
}
