package queqiao

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.QueqiaoOutboundOptions](registry, C.TypeQueqiao, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)
var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)

type carrierPool interface {
	Open(context.Context) (net.Conn, error)
	Reset(bool)
}

// Outbound authenticates reliable carriers for TCP flows and basic UDP
// associations. QUIC streams share a bounded, outbound-local connection pool.
type Outbound struct {
	outbound.Adapter
	dialer          N.Dialer
	server          M.Socksaddr
	tlsConfig       *tls.Config
	pool            carrierPool
	tcpRecovery     bool
	tcpLanes        int
	udpResume       bool
	initialFallback bool
	pathProbe       bool
	dataIsolation   bool
	logger          log.ContextLogger
	generation      uint64
	transport       string
	mu              sync.Mutex
	closed          bool
	active          map[net.Conn]io.Closer
	ctx             context.Context
	cancel          context.CancelFunc
	slots           chan struct{}
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.QueqiaoOutboundOptions) (adapter.Outbound, error) {
	if options.ProfilePath == "" {
		return nil, errors.New("queqiao: profile_path is required")
	}
	if options.TCPLanes < 0 || options.TCPLanes > 2 {
		return nil, errors.New("queqiao: tcp_lanes must be 1 or 2 (0 means 1)")
	}
	if options.TCPLanes == 2 && (options.Transport != "tcp" || !options.TCPRecovery) {
		return nil, errors.New("queqiao: tcp_lanes 2 requires explicit transport tcp and tcp_recovery")
	}
	if options.QUICDataIsolation && (options.Transport != "quic" || !options.TCPRecovery) {
		return nil, errors.New("queqiao: quic_data_isolation requires explicit transport quic and tcp_recovery")
	}
	transport := options.Transport
	if transport == "" {
		transport = "tcp"
	}
	if options.QUICPathProbe && transport != "quic" {
		return nil, errors.New("queqiao: quic_path_probe requires transport quic")
	}
	if options.QUICInitialFallback && transport != "quic" {
		return nil, errors.New("queqiao: quic_initial_fallback requires transport quic")
	}
	switch transport {
	case "tcp":
	case "quic":
		if err := checkQUIC(); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("queqiao: transport must be tcp or quic")
	}
	config, endpoint, err := loadProfile(options.ProfilePath)
	if err != nil {
		return nil, err
	}
	server := M.ParseSocksaddr(endpoint)
	d, err := dialer.New(ctx, options.DialerOptions, server.IsFqdn())
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	o := &Outbound{Adapter: outbound.NewAdapterWithDialerOptions(C.TypeQueqiao, tag, options.Network.Build(), options.DialerOptions), dialer: d, server: server, tlsConfig: config, transport: transport, tcpRecovery: options.TCPRecovery, udpResume: options.UDPResume, active: make(map[net.Conn]io.Closer), ctx: lifetime, cancel: cancel, slots: make(chan struct{}, 256)}
	o.tcpLanes = max(1, options.TCPLanes)
	o.initialFallback = options.QUICInitialFallback
	o.pathProbe, o.logger = options.QUICPathProbe, logger
	o.dataIsolation = options.QUICDataIsolation
	if transport == "quic" {
		o.pool = newQUICPool(o)
	}
	return o, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	network = N.NetworkName(network)
	if !slices.Contains(o.Network(), network) {
		return nil, errors.New("queqiao: network is not enabled")
	}
	switch network {
	case N.NetworkTCP:
		address, err := canonicalAddress(destination.String(), 255)
		if err != nil {
			return nil, err
		}
		opened, err := o.openFlow(ctx, []byte(address), destination)
		if err != nil {
			return nil, err
		}
		var join joinLaneFunc
		if o.tcpRecovery {
			join = func(ctx context.Context, session [16]byte, flow, lane uint64) (net.Conn, error) {
				return o.joinFlowOnTransport(ctx, destination, opened.generation, session, flow, lane, opened.useTCP)
			}
		}
		var c *Conn
		if o.dataIsolation && !opened.useTCP {
			controlJoin := func(ctx context.Context, session [16]byte, flow, lane uint64) (net.Conn, error) {
				return o.joinLaneOnTransport(ctx, destination, opened.generation, session, flow, lane, false, flagReserve, false)
			}
			dataJoin := func(ctx context.Context, session [16]byte, flow, lane uint64) (net.Conn, error) {
				return o.joinLaneOnTransport(ctx, destination, opened.generation, session, flow, lane, false, 0, true)
			}
			second, joinErr := joinInitialBundleLane(ctx, dataJoin, opened.session, opened.flow)
			joinErr = normalizeRoleAdmissionError(joinErr)
			if joinErr != nil && (!isolationMayDegrade(joinErr) || o.initialDialState(ctx, opened.generation) != nil) {
				abortInitialBundleFlow(ctx, opened)
				return nil, joinErr
			}
			c = newQUICRoleConn(opened.conn, second, opened.session, opened.flow, opened.remove, context.WithoutCancel(ctx), controlJoin)
		} else if o.tcpLanes == 2 {
			second, joinErr := joinInitialBundleLane(ctx, join, opened.session, opened.flow)
			if joinErr != nil {
				abortInitialBundleFlow(ctx, opened)
				return nil, joinErr
			}
			c = newBundleConn(opened.conn, second, opened.session, opened.flow, opened.remove, context.WithoutCancel(ctx), join)
		} else {
			c = newRecoverableConn(opened.conn, opened.session, opened.flow, opened.remove, context.WithoutCancel(ctx), join)
		}
		if err = opened.install(c); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	case N.NetworkUDP:
		if _, err := canonicalAddress(destination.String(), 255); err != nil {
			return nil, err
		}
		c, err := o.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(c, destination), nil
	default:
		return nil, errors.New("queqiao: unsupported network")
	}
}

type openedFlow struct {
	useTCP     bool
	generation uint64
	grant      []byte
	conn       net.Conn
	session    [16]byte
	flow       uint64
	remove     func()
	install    func(io.Closer) error
}

func (o *Outbound) openFlow(ctx context.Context, payload []byte, destination M.Socksaddr) (result *openedFlow, resultErr error) {
	select {
	case o.slots <- struct{}{}:
	default:
		return nil, errors.New("queqiao: connection limit reached (256)")
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { <-o.slots }) }
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	// Bound DNS/TCP, TLS and OPEN as one operation, including caller cancellation.
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	defer func() {
		if resultErr != nil && dialCtx.Err() != nil {
			resultErr = dialCtx.Err()
		}
	}()
	stopLifetime := context.AfterFunc(o.ctx, cancel)
	defer stopLifetime()
	o.mu.Lock()
	closed := o.closed
	generation := o.generation
	o.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	raw, useTCP, err := o.dialInitialCarrier(dialCtx, generation)
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	if o.closed || o.generation != generation {
		o.mu.Unlock()
		raw.Close()
		return nil, net.ErrClosed
	}
	o.active[raw] = raw
	o.mu.Unlock()
	remove := func() { o.mu.Lock(); delete(o.active, raw); o.mu.Unlock(); release() }
	success := false
	carrier := raw
	defer func() {
		if !success {
			closeCarrier(carrier)
			raw.Close()
			remove()
		}
	}()
	stopCancel := context.AfterFunc(dialCtx, func() { raw.Close() })
	defer stopCancel()
	if useTCP {
		secure := tls.Client(raw, o.tlsConfig)
		err = secure.HandshakeContext(dialCtx)
		carrier = secure
	}
	if err != nil {
		return nil, fmt.Errorf("queqiao: authenticated carrier handshake: %w", err)
	}
	var session [16]byte
	var id [8]byte
	for session == ([16]byte{}) {
		if _, err = rand.Read(session[:]); err != nil {
			return nil, err
		}
	}
	for id == ([8]byte{}) {
		if _, err = rand.Read(id[:]); err != nil {
			return nil, err
		}
	}
	flow := binary.BigEndian.Uint64(id[:])
	deadline, _ := dialCtx.Deadline()
	carrier.SetDeadline(deadline)
	flags := uint16(0)
	// The private openFlow callers use only canonical TCP destinations or the
	// exact basic/resumable UDP markers. Reserve only logical TCP flows.
	isUDP := len(payload) == 5 && string(payload[:4]) == "WOUD" || isUDPResumeOpen(payload)
	if o.dataIsolation && !useTCP && !isUDP {
		flags = flagReserve
	}
	if err = writeFrame(carrier, frame{typ: typeOpen, flags: flags, session: session, flow: flow, payload: payload}); err != nil {
		return nil, err
	}
	response, err := readFrame(carrier)
	if err != nil {
		return nil, fmt.Errorf("queqiao: read OPEN response: %w", err)
	}
	if response.session != session || response.flow != flow {
		return nil, errors.New("queqiao: OPEN response identity mismatch")
	}
	if response.typ == typeReset {
		return nil, resetError(response)
	}
	if response.typ != typeOpenOK || response.flags != 0 || response.sequence != 0 {
		return nil, errors.New("queqiao: invalid OPEN_OK")
	}
	if isUDPResumeOpen(payload) {
		if _, _, err = decodeUDPGrant(response.payload); err != nil {
			return nil, err
		}
		if response.payload[0] != 0 {
			return nil, protocolError{errors.New("queqiao: initial UDP association cannot be resumed")}
		}
	} else if len(response.payload) != 0 {
		return nil, protocolError{errors.New("queqiao: unexpected OPEN_OK payload")}
	}
	if !stopCancel() || dialCtx.Err() != nil {
		return nil, dialCtx.Err()
	}
	carrier.SetDeadline(time.Time{})
	opened := &openedFlow{useTCP: useTCP, generation: generation, grant: response.payload, conn: carrier, session: session, flow: flow, remove: remove}
	opened.install = func(conn io.Closer) error {
		o.mu.Lock()
		defer o.mu.Unlock()
		if o.closed || o.generation != generation {
			return net.ErrClosed
		}
		if _, ok := o.active[raw]; !ok {
			return net.ErrClosed
		}
		o.active[raw] = conn
		return nil
	}
	success = true
	retained = true
	return opened, nil
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !slices.Contains(o.Network(), N.NetworkUDP) {
		return nil, errors.New("queqiao: UDP is not enabled")
	}
	payload := []byte{'W', 'O', 'U', 'D', 1}
	if o.udpResume {
		payload[4] = 2
	}
	opened, err := o.openFlow(ctx, payload, destination)
	if err != nil {
		return nil, err
	}
	var resume udpResumeFunc
	var token [16]byte
	if o.udpResume {
		_, token, _ = decodeUDPGrant(opened.grant)
		resume = func(ctx context.Context, token [16]byte) (*udpReplacement, error) {
			return o.resumeUDPOnTransport(ctx, destination, opened.generation, token, opened.useTCP)
		}
	}
	c := newResumablePacketConn(opened.conn, opened.session, opened.flow, opened.remove, context.WithoutCancel(ctx), token, resume)
	if err = opened.install(c); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (o *Outbound) closeConnections(permanent bool) {
	o.mu.Lock()
	o.generation++
	if o.pool != nil {
		o.pool.Reset(permanent)
	}
	if permanent {
		o.closed = true
		o.cancel()
	}
	connections := make([]io.Closer, 0, len(o.active))
	for _, c := range o.active {
		connections = append(connections, c)
	}
	o.mu.Unlock()
	for _, c := range connections {
		c.Close()
	}
}
func (o *Outbound) Close() error                     { o.closeConnections(true); return nil }
func (o *Outbound) InterfaceUpdated(context.Context) { o.closeConnections(false) }
