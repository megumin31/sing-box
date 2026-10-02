package queqiao

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// joinFlow never OPENs a replacement destination. The existing principal and
// logical IDs are immutable; a refusal fails the logical flow rather than
// silently starting another upstream connection or changing transports.
func (o *Outbound) joinFlow(ctx context.Context, destination M.Socksaddr, generation uint64, session [16]byte, flow, lane uint64) (result net.Conn, resultErr error) {
	return o.joinFlowOnTransport(ctx, destination, generation, session, flow, lane, o.pool == nil)
}

func (o *Outbound) joinFlowOnTransport(ctx context.Context, destination M.Socksaddr, generation uint64, session [16]byte, flow, lane uint64, useTCP bool) (result net.Conn, resultErr error) {
	return o.joinLaneOnTransport(ctx, destination, generation, session, flow, lane, useTCP, 0, false)
}

func (o *Outbound) joinLaneOnTransport(ctx context.Context, destination M.Socksaddr, generation uint64, session [16]byte, flow, lane uint64, useTCP bool, flags uint16, exclusive bool) (result net.Conn, resultErr error) {
	if lane == 0 || flow == 0 || session == ([16]byte{}) {
		return nil, protocolError{errors.New("queqiao: invalid JOIN identity")}
	}
	var payload [8]byte
	binary.BigEndian.PutUint64(payload[:], lane)
	carrier, response, err := o.exchangeRecoveryOpenWithRole(ctx, destination, generation, frame{typ: typeJoin, flags: flags, session: session, flow: flow, payload: payload[:]}, useTCP, exclusive)
	if err != nil {
		return nil, err
	}
	if len(response.payload) != 0 {
		abortCarrier(carrier)
		return nil, protocolError{errors.New("queqiao: invalid JOIN acknowledgement")}
	}
	return carrier, nil
}

// exchangeRecoveryOpen authenticates a replacement using the immutable profile
// and dialer generation. It does not allocate a second logical outbound slot.
func (o *Outbound) exchangeRecoveryOpen(ctx context.Context, destination M.Socksaddr, generation uint64, request frame) (result net.Conn, response frame, resultErr error) {
	return o.exchangeRecoveryOpenOnTransport(ctx, destination, generation, request, o.pool == nil)
}

func (o *Outbound) exchangeRecoveryOpenOnTransport(ctx context.Context, destination M.Socksaddr, generation uint64, request frame, useTCP bool) (result net.Conn, response frame, resultErr error) {
	return o.exchangeRecoveryOpenWithRole(ctx, destination, generation, request, useTCP, false)
}

func (o *Outbound) exchangeRecoveryOpenWithRole(ctx context.Context, destination M.Socksaddr, generation uint64, request frame, useTCP, exclusive bool) (result net.Conn, response frame, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, frame{}, err
	}
	// The loaded profile is immutable. Reject a device/issuer/root that has
	// expired since construction before opening another authenticated socket.
	if err := validateRecoveryIdentity(o.tlsConfig, time.Now()); err != nil {
		return nil, frame{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		if resultErr != nil && ctx.Err() != nil {
			// An active handoff must preserve a parsed identity, permission or
			// protocol refusal even if cancellation races with its response.
			if o.activeFallback && carrierHandoffDenied(resultErr) {
				return
			}
			// A role JOIN can leave a surviving flow active on transient failure.
			// Never turn a parsed refusal into an allowed deadline degradation.
			role := exclusive || request.flags&flagReserve != 0
			if role && ctx.Err() == context.DeadlineExceeded && !isolationMayDegrade(normalizeRoleAdmissionError(resultErr)) {
				return
			}
			resultErr = ctx.Err()
		}
	}()
	stopLifetime := context.AfterFunc(o.ctx, cancel)
	defer stopLifetime()
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	o.mu.Lock()
	closed := o.closed || o.generation != generation
	o.mu.Unlock()
	if closed {
		return nil, frame{}, net.ErrClosed
	}
	var raw net.Conn
	var err error
	if exclusive {
		raw, err = o.dialExclusiveQUIC(ctx)
	} else {
		raw, err = o.dialFixedCarrier(ctx, useTCP)
	}
	if err != nil {
		return nil, frame{}, err
	}
	carrier := raw
	success := false
	stop := context.AfterFunc(ctx, func() { abortCarrier(raw) })
	defer stop()
	defer func() {
		if !success {
			abortCarrier(carrier)
		}
	}()
	if useTCP {
		secure := tls.Client(raw, o.tlsConfig)
		carrier = secure
		if err = secure.HandshakeContext(ctx); err != nil {
			return nil, frame{}, err
		}
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(joinTimeout)
	}
	carrier.SetDeadline(deadline)
	if err = writeFrame(carrier, request); err != nil {
		return nil, frame{}, err
	}
	response, err = readFrame(carrier)
	if err != nil {
		return nil, frame{}, err
	}
	if response.session != request.session || response.flow != request.flow {
		return nil, frame{}, protocolError{errors.New("queqiao: replacement OPEN response identity mismatch")}
	}
	if response.typ == typeReset {
		return nil, frame{}, resetError(response)
	}
	if response.typ != typeOpenOK || response.flags != 0 || response.sequence != 0 {
		return nil, frame{}, protocolError{errors.New("queqiao: invalid replacement OPEN acknowledgement")}
	}
	if !stop() || ctx.Err() != nil {
		return nil, frame{}, ctx.Err()
	}
	o.mu.Lock()
	closed = o.closed || o.generation != generation
	o.mu.Unlock()
	if closed {
		return nil, frame{}, net.ErrClosed
	}
	carrier.SetDeadline(time.Time{})
	success = true
	return carrier, response, nil
}

func validateRecoveryIdentity(config *tls.Config, now time.Time) error {
	if len(config.Certificates) == 0 || len(config.Certificates[0].Certificate) < 2 {
		return identityError{errors.New("queqiao: recovery identity is incomplete")}
	}
	for _, raw := range config.Certificates[0].Certificate {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return identityError{err}
		}
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return identityError{errors.New("queqiao: recovery identity is outside certificate validity")}
		}
	}
	return nil
}
