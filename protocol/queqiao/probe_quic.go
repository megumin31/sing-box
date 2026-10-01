//go:build with_quic

package queqiao

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/sagernet/quic-go"
)

func probeQUICConnection(ctx context.Context, connection *quic.Conn) (probeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, pathProbeBudget)
	defer cancel()
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return probeResult{status: "transport_error"}, err
	}
	interrupt := func() { stream.CancelRead(0); stream.CancelWrite(0) }
	var session [16]byte
	for session == ([16]byte{}) {
		if _, err = rand.Read(session[:]); err != nil {
			interrupt()
			return probeResult{status: "transport_error"}, err
		}
	}
	result, err := exchangePathProbe(ctx, stream, stream.Close, interrupt, session, make([]byte, maxProbePayload), pathProbeFrames)
	// Cancellation retires only this probe stream. The pool may retain a live
	// connection after an unfinished measurement, but never after a violation.
	stream.CancelRead(0)
	if err != nil || result.status != "conformant" {
		stream.CancelWrite(0)
	}
	var violation protocolError
	if connection.Context().Err() != nil && !errors.As(err, &violation) {
		result.status = "transport_error"
		return result, context.Cause(connection.Context())
	}
	// Clear only the probe stream's deadline; pooled application streams have
	// their own deadlines and do not inherit this bounded measurement budget.
	stream.SetDeadline(time.Time{})
	return result, err
}
