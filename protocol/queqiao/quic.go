//go:build with_quic

package queqiao

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/qlogwriter"
)

const (
	maxQUICConnections  = 4
	maxQUICStreams      = 64
	quicPoolIdleTimeout = 30 * time.Second
)

func checkQUIC() error { return nil }

func initialQUICTerminalFailure(err error) bool {
	var transport *quic.TransportError
	var application *quic.ApplicationError
	var version *quic.VersionNegotiationError
	var reset *quic.StatelessResetError
	var stream *quic.StreamError
	return errors.As(err, &transport) || errors.As(err, &application) ||
		errors.As(err, &version) || errors.As(err, &reset) || errors.As(err, &stream)
}

func activeQUICTerminalFailure(err error) bool {
	return visitErrorTree(err, func(err error) bool {
		switch e := err.(type) {
		case *quic.TransportError:
			return e.ErrorCode != 0
		case *quic.ApplicationError:
			return e.ErrorCode != 0
		case *quic.StreamError:
			return e.ErrorCode != 0
		case *quic.VersionNegotiationError:
			return true
		}
		return false
	})
}

func activeQUICCarrierLoss(err error) bool {
	return visitErrorTree(err, func(err error) bool {
		switch e := err.(type) {
		case *quic.StatelessResetError:
			return true
		case *quic.TransportError:
			return e.ErrorCode == 0
		case *quic.ApplicationError:
			return e.ErrorCode == 0
		case *quic.StreamError:
			return e.ErrorCode == 0
		}
		return false
	})
}

// Pool identity is the immutable authenticated profile, endpoint and common
// dialer of this outbound. No cross-outbound or cross-principal sharing occurs.
type quicPool struct {
	owner       *Outbound
	mu          sync.Mutex
	entries     []*quicPoolEntry
	closed      bool
	idleTimeout time.Duration
	inflight    int // includes retired entries until their socket-owner exits
}
type quicPoolEntry struct {
	ctx          context.Context
	cancel       context.CancelFunc
	ready        chan struct{}
	probeStarted chan struct{} // closed after identity validation, before probing
	probe        probeResult   // published by ready
	connection   *quic.Conn    // published by closing ready
	expires      time.Time
	drain        *quicDrain
	err          error
	exclusive    bool
	users        int // reservations, open streams and streams draining their last bytes
	idle         *time.Timer
}

func newQUICPool(o *Outbound) carrierPool {
	return &quicPool{owner: o, idleTimeout: quicPoolIdleTimeout}
}

func (p *quicPool) Open(ctx context.Context) (net.Conn, error)          { return p.open(ctx, false) }
func (p *quicPool) OpenExclusive(ctx context.Context) (net.Conn, error) { return p.open(ctx, true) }
func (p *quicPool) open(ctx context.Context, exclusive bool) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.closed || p.owner.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	// A just-failed shared connection must not consume every flow's first
	// JOIN attempt while its socket-owner goroutine is still being scheduled.
	for i := 0; i < len(p.entries); {
		candidate := p.entries[i]
		alive := candidate.ctx.Err() == nil
		select {
		case <-candidate.ready:
			alive = alive && candidate.err == nil && candidate.connection.Context().Err() == nil && time.Now().Before(candidate.expires)
		default:
		}
		if !alive {
			candidate.cancel()
			p.remove(candidate)
			continue
		}
		i++
	}
	var e *quicPoolEntry
	for _, candidate := range p.entries {
		if !exclusive && !candidate.exclusive && candidate.ctx.Err() == nil && candidate.drain.healthy() && candidate.users < maxQUICStreams {
			e = candidate
			break
		}
	}
	if e == nil {
		if len(p.entries) >= maxQUICConnections || p.owner.dataIsolation && p.inflight >= maxQUICConnections {
			p.mu.Unlock()
			return nil, errQUICConnectionCapacity
		}
		lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
		e = &quicPoolEntry{exclusive: exclusive, ctx: lifetime, cancel: cancel, ready: make(chan struct{}), drain: newQUICDrain()}
		if p.owner.pathProbe {
			e.probeStarted = make(chan struct{})
		}
		p.entries = append(p.entries, e)
		p.inflight++
		stopOwner := context.AfterFunc(p.owner.ctx, cancel)
		go func() { defer stopOwner(); p.run(e) }()
	}
	e.users++
	if e.idle != nil {
		e.idle.Stop()
		e.idle = nil
	}
	p.mu.Unlock()
	if err := waitQUICEntry(ctx, e); err != nil {
		p.release(e)
		return nil, err
	}
	if !time.Now().Before(e.expires) {
		e.cancel()
		p.release(e)
		return nil, net.ErrClosed
	}
	stream, err := e.connection.OpenStreamSync(ctx)
	if err != nil {
		p.release(e)
		return nil, quicStreamOpenError{err}
	}
	if ctx.Err() != nil || e.ctx.Err() != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		p.release(e)
		if ctx.Err() != nil {
			return nil, quicStreamOpenError{ctx.Err()}
		}
		return nil, net.ErrClosed
	}
	e.drain.register(int64(stream.StreamID()))
	return &quicCarrier{Stream: stream, connection: e.connection, drain: e.drain, release: func() { p.release(e) }}, nil
}

func waitQUICEntry(ctx context.Context, e *quicPoolEntry) (resultErr error) {
	defer func() {
		if resultErr != nil {
			select {
			case <-e.probeStarted:
				resultErr = quicProbeError{resultErr}
			default:
			}
		}
	}()
	select {
	case <-ctx.Done():
	case <-e.ready:
	case <-e.ctx.Done():
	}
	// Explicit caller cancellation wins and cannot trigger fallback. A timeout
	// must not hide an already published refusal, regardless of which ready
	// channel the select chose. Read err only after observing ready's close.
	if ctx.Err() == context.Canceled {
		return context.Canceled
	}
	select {
	case <-e.ready:
		if e.err != nil {
			return e.err
		}
	default:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	if e.ctx.Err() != nil {
		return net.ErrClosed
	}
	return nil
}

// A shared handshake belongs to its entry, not to whichever flow happened to
// arrive first. Canceling the last reservation cancels the handshake as well.
func (p *quicPool) run(e *quicPoolEntry) {
	defer func() { e.cancel(); p.mu.Lock(); p.remove(e); p.inflight--; p.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	defer cancel()
	raw, err := p.owner.dialer.DialContext(ctx, "udp", p.owner.server)
	if err != nil {
		e.err = err
		close(e.ready)
		return
	}
	defer raw.Close()
	stopCancel := context.AfterFunc(ctx, func() { raw.Close() })
	connection, err := quic.DialConn(ctx, raw, p.owner.tlsConfig, &quic.Config{
		HandshakeIdleTimeout: 15 * time.Second, MaxIdleTimeout: time.Minute, KeepAlivePeriod: 15 * time.Second,
		InitialStreamReceiveWindow: 256 << 10, MaxStreamReceiveWindow: receiveLimit,
		InitialConnectionReceiveWindow: 512 << 10, MaxConnectionReceiveWindow: 16 << 20,
		MaxIncomingStreams: -1, MaxIncomingUniStreams: -1,
		// Enabling DATAGRAM authorizes the gateway to send coded DATA. Reliable
		// pooling must not negotiate it until the independent decoder exists.
		EnableDatagrams: false,
		Tracer:          func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return e.drain },
	})
	stopped := stopCancel()
	if err == nil && (!stopped || ctx.Err() != nil) {
		connection.CloseWithError(0, "handshake canceled")
		err = ctx.Err()
		if err == nil {
			err = context.Canceled
		}
	}
	if err == nil {
		e.expires, err = quicIdentityExpiry(p.owner.tlsConfig, connection.ConnectionState().TLS.PeerCertificates, time.Now())
	}
	if err == nil && p.owner.pathProbe {
		close(e.probeStarted)
		e.probe, err = probeQUICConnection(ctx, connection)
		if p.owner.logger != nil {
			if e.probe.status == "protocol_error" {
				p.owner.logger.WarnContext(ctx, "QUIC path probe protocol violation")
			} else {
				p.owner.logger.DebugContext(ctx, "QUIC path probe ", e.probe.status, ": sent=", e.probe.sent, " received=", e.probe.received, " elapsed=", e.probe.elapsed)
			}
		}
		if err != nil {
			err = quicProbeError{err}
		}
	}
	if err != nil && connection != nil {
		connection.CloseWithError(0, "connection preflight rejected")
	}
	e.connection, e.err = connection, err
	close(e.ready)
	if err != nil {
		return
	}
	defer connection.CloseWithError(0, "pool entry closed")
	// Do not retain the 15-second handshake deadline for the connection lifetime.
	cancel()
	expiryTimer := time.NewTimer(time.Until(e.expires))
	defer expiryTimer.Stop()
	select {
	case <-expiryTimer.C:
	case <-e.ctx.Done():
	case <-connection.Context().Done():
	}
}

// remove requires p.mu. Canceling removes capacity immediately; its run owner
// still closes the socket, including if a dial finishes concurrently with reset.
func (p *quicPool) remove(e *quicPoolEntry) {
	for i, candidate := range p.entries {
		if candidate == e {
			p.entries = append(p.entries[:i], p.entries[i+1:]...)
			break
		}
	}
	if e.idle != nil {
		e.idle.Stop()
		e.idle = nil
	}
}
func (p *quicPool) release(e *quicPoolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e.users--
	if e.users != 0 || e.ctx.Err() != nil {
		return
	}
	if e.exclusive {
		e.cancel()
		p.remove(e)
		return
	}
	select {
	case <-e.ready:
		if e.err != nil || !e.drain.healthy() {
			e.cancel()
			p.remove(e)
			return
		}
	default:
		e.cancel()
		p.remove(e)
		return
	}
	var timer *time.Timer
	timer = time.AfterFunc(p.idleTimeout, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if e.users == 0 && e.idle == timer {
			e.cancel()
			p.remove(e)
		}
	})
	e.idle = timer
}
func (p *quicPool) Reset(permanent bool) {
	p.mu.Lock()
	if permanent {
		p.closed = true
	}
	for _, e := range p.entries {
		e.cancel()
		if e.idle != nil {
			e.idle.Stop()
		}
	}
	p.entries = nil
	p.mu.Unlock()
}

type quicCarrier struct {
	*quic.Stream
	connection *quic.Conn
	once       sync.Once
	drain      *quicDrain
	release    func()
	written    int64
	writeMu    sync.Mutex
	writers    int
	closing    bool
	closeErr   error
}

func (c *quicCarrier) LocalAddr() net.Addr  { return c.connection.LocalAddr() }
func (c *quicCarrier) RemoteAddr() net.Addr { return c.connection.RemoteAddr() }
func (c *quicCarrier) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	if c.closing {
		c.writeMu.Unlock()
		return 0, net.ErrClosed
	}
	c.writers++
	c.writeMu.Unlock()
	n, err := c.Stream.Write(p)
	c.writeMu.Lock()
	c.writers--
	c.written += int64(n)
	c.writeMu.Unlock()
	return n, err
}
func (c *quicCarrier) Close() error {
	c.once.Do(func() {
		c.writeMu.Lock()
		c.closing = true
		writing, end := c.writers > 0, c.written
		c.writeMu.Unlock()
		if writing {
			c.Stream.CancelWrite(0)
		} else {
			_ = c.Stream.Close()
			c.closeErr = c.drain.wait(c.connection.Context(), int64(c.StreamID()), end, 2*time.Second)
			// A failed drain cannot retain a stream indefinitely. Reset only this
			// stream; other users of the authenticated connection remain untouched.
			if c.closeErr != nil {
				c.Stream.CancelWrite(0)
			}
		}
		c.Stream.CancelRead(0)
		c.drain.unregister(int64(c.StreamID()))
		c.release()
	})
	return c.closeErr
}

// Reuse cannot extend either principal's certificate validity past the original
// TLS authentication. Bound the entire pooled connection by the earliest local
// or peer chain expiry, including the pinned root and intermediate issuers.
func quicIdentityExpiry(config *tls.Config, peer []*x509.Certificate, now time.Time) (time.Time, error) {
	if len(peer) == 0 || len(config.Certificates) == 0 {
		return time.Time{}, identityError{errors.New("queqiao: pooled identity is missing")}
	}
	chain := append([]*x509.Certificate(nil), peer...)
	for _, raw := range config.Certificates[0].Certificate {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return time.Time{}, err
		}
		chain = append(chain, cert)
	}
	expires := chain[0].NotAfter
	for _, cert := range chain {
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return time.Time{}, identityError{errors.New("queqiao: pooled identity is outside certificate validity")}
		}
		if cert.NotAfter.Before(expires) {
			expires = cert.NotAfter
		}
	}
	return expires, nil
}

func (c *quicCarrier) Abort() error {
	c.once.Do(func() {
		c.writeMu.Lock()
		c.closing = true
		c.writeMu.Unlock()
		c.Stream.CancelWrite(0)
		c.Stream.CancelRead(0)
		c.drain.unregister(int64(c.StreamID()))
		c.release()
	})
	return c.closeErr
}
