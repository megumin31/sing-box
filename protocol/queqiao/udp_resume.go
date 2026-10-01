package queqiao

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	maxUDPResumeAttempts = 3 // lifetime budget, not reset on successful replacement
	udpResumeTimeout     = 20 * time.Second
)

type udpReplacement struct {
	conn    net.Conn
	session [16]byte
	flow    uint64
	token   [16]byte
}
type udpResumeFunc func(context.Context, [16]byte) (*udpReplacement, error)

func isUDPResumeOpen(payload []byte) bool {
	return (len(payload) == 5 || len(payload) == 21) && string(payload[:5]) == "WOUD\x02"
}
func decodeUDPGrant(payload []byte) (bool, [16]byte, error) {
	var token [16]byte
	if len(payload) != 17 || payload[0] > 1 {
		return false, token, protocolError{errors.New("queqiao: invalid UDP resume grant")}
	}
	copy(token[:], payload[1:])
	return payload[0] == 1, token, nil
}

func (o *Outbound) resumeUDP(ctx context.Context, destination M.Socksaddr, generation uint64, token [16]byte) (*udpReplacement, error) {
	return o.resumeUDPOnTransport(ctx, destination, generation, token, o.pool == nil)
}

func (o *Outbound) resumeUDPOnTransport(ctx context.Context, destination M.Socksaddr, generation uint64, token [16]byte, useTCP bool) (*udpReplacement, error) {
	r := new(udpReplacement)
	var id [8]byte
	for r.session == ([16]byte{}) {
		if _, err := rand.Read(r.session[:]); err != nil {
			return nil, err
		}
	}
	for r.flow == 0 {
		if _, err := rand.Read(id[:]); err != nil {
			return nil, err
		}
		r.flow = binary.BigEndian.Uint64(id[:])
	}
	payload := append([]byte("WOUD\x02"), token[:]...)
	raw, response, err := o.exchangeRecoveryOpenOnTransport(ctx, destination, generation, frame{typ: typeOpen, session: r.session, flow: r.flow, payload: payload}, useTCP)
	if err != nil {
		return nil, err
	}
	resumed, grant, err := decodeUDPGrant(response.payload)
	if err != nil {
		abortCarrier(raw)
		return nil, err
	}
	if !resumed {
		// A fresh relay changes the source endpoint observed by every destination.
		// Never silently accept that change for a live PacketConn. Gracefully release
		// the rejected fresh relay instead of parking it for another resume.
		deadline := time.Now().Add(udpCloseTimeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		raw.SetDeadline(deadline)
		stop := context.AfterFunc(ctx, func() { abortCarrier(raw) })
		defer stop()
		if writeFrame(raw, frame{typ: typeClose, flags: flagFIN, session: r.session, flow: r.flow}) == nil {
			_, _ = readFrame(raw)
		}
		abortCarrier(raw)
		return nil, protocolError{errors.New("queqiao: original UDP relay could not be resumed; source endpoint would change")}
	}
	r.conn, r.token = raw, grant
	return r, nil
}

// No PACKET is replayed. A failed carrier write has indeterminate delivery;
// successful recovery consumes that datagram as possibly lost. A new association gets new
// IDs and independent sequence windows, even when it reclaims the same socket.
func (p *packetConn) failCarrier(raw net.Conn, err error) bool {
	c := p.wire
	c.mu.Lock()
	if c.closed || p.closing {
		c.mu.Unlock()
		return false
	}
	if raw != c.carrier {
		c.mu.Unlock()
		return true
	}
	if p.resume == nil || permanentRecoveryError(err) {
		c.mu.Unlock()
		c.terminate(err)
		return false
	}
	c.carrier = nil
	c.recovering = true
	c.notifyLocked()
	if !c.recoveryRunning {
		c.recoveryRunning = true
		go p.resumeLoop()
	}
	c.mu.Unlock()
	abortCarrier(raw)
	return true
}

func (p *packetConn) resumeLoop() {
	c := p.wire
	ctx, cancel := context.WithTimeout(c.recoveryCtx, udpResumeTimeout)
	defer cancel()
	last := errors.New("association carrier failed")
	for {
		c.mu.Lock()
		if c.closed || p.closing {
			c.mu.Unlock()
			return
		}
		if c.recoveryAttempts >= maxUDPResumeAttempts {
			c.mu.Unlock()
			c.terminate(fmt.Errorf("queqiao: UDP resume attempts exhausted: %w", last))
			return
		}
		c.recoveryAttempts++
		attempt, token := c.recoveryAttempts, p.token
		c.mu.Unlock()
		// Give the gateway's old lane teardown a bounded head start to park its
		// relay. An early fresh response is still terminal, not an unsafe retry.
		timer := time.NewTimer(time.Duration(100*(1<<(attempt-1))) * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			c.terminate(ctx.Err())
			return
		}
		attemptCtx, stop := context.WithTimeout(ctx, joinTimeout)
		replacement, err := p.resume(attemptCtx, token)
		stop()
		if err != nil {
			last = err
			if permanentRecoveryError(err) || ctx.Err() != nil {
				c.terminate(err)
				return
			}
			continue
		}
		// Serialize with an old lane's writer and Close. No stale writer may use
		// the replacement IDs or clear a new carrier's deadline.
		select {
		case <-c.writeGate:
		case <-ctx.Done():
			abortCarrier(replacement.conn)
			c.terminate(ctx.Err())
			return
		case <-c.done:
			abortCarrier(replacement.conn)
			return
		}
		c.mu.Lock()
		if c.closed || p.closing || ctx.Err() != nil {
			c.mu.Unlock()
			c.writeGate <- struct{}{}
			abortCarrier(replacement.conn)
			if ctx.Err() != nil {
				c.terminate(ctx.Err())
			}
			return
		}
		c.carrier, c.session, c.flow = replacement.conn, replacement.session, replacement.flow
		p.token = replacement.token
		p.next, p.window = 0, packetWindow{}
		c.recovering, c.recoveryRunning = false, false
		c.notifyLocked()
		c.mu.Unlock()
		c.writeGate <- struct{}{}
		return
	}
}
