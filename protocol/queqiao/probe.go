package queqiao

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const (
	typeProbe       byte = 9
	maxProbePayload      = 1200
	maxProbeFrames       = 128
	maxProbeBytes        = 128 * 1024
	pathProbeFrames      = 4
	pathProbeBudget      = 3 * time.Second
)

// A probe starts only after authentication. Its errors, including a caller
// timeout while waiting for it, are never initial connection fallback signals.
type quicProbeError struct{ error }

func (e quicProbeError) Unwrap() error { return e.error }

type probeResult struct {
	status         string
	sent, received int
	elapsed        time.Duration
}
type probeStream interface {
	io.Reader
	io.Writer
	SetDeadline(time.Time) error
}

// exchangePathProbe checks the bounded echo contract. It measures no path
// capacity or loss rate. interrupt must stop both I/O directions without
// closing a shared underlying connection; all writer work is joined on return.
func exchangePathProbe(ctx context.Context, stream probeStream, halfClose func() error, interrupt func(), session [16]byte, payload []byte, count int) (result probeResult, resultErr error) {
	start := time.Now()
	defer func() { result.elapsed = time.Since(start) }()
	if session == ([16]byte{}) || len(payload) == 0 || len(payload) > maxProbePayload || count < 1 || count > maxProbeFrames || count*len(payload) > maxProbeBytes {
		result.status = "invalid_request"
		return result, errors.New("queqiao: invalid bounded path probe")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		result.status = "invalid_request"
		return result, errors.New("queqiao: path probe requires a deadline")
	}
	if err := stream.SetDeadline(deadline); err != nil {
		result.status = "transport_error"
		return result, err
	}
	stop := context.AfterFunc(ctx, interrupt)
	defer stop()
	type writeResult struct {
		sent int
		err  error
	}
	writerDone := make(chan writeResult, 1)
	go func() {
		w := writeResult{}
		for i := 0; i < count; i++ {
			if w.err = writeFrame(stream, frame{typ: typeProbe, session: session, sequence: uint64(i), payload: payload}); w.err != nil {
				break
			}
			w.sent++
		}
		if w.err == nil {
			w.err = halfClose()
		}
		if w.err != nil {
			interrupt()
		}
		writerDone <- w
	}()
	var readErr error
	for i := 0; i < count; i++ {
		if err := readPathProbeEcho(stream, session, uint64(i), payload); err != nil {
			readErr = err
			break
		}
		result.received++
	}
	if readErr == nil {
		// Observe trailing bytes until response EOF or the same bounded deadline.
		// A delayed EOF alone does not invalidate already complete echoes.
		var extra [1]byte
		n, err := io.ReadFull(stream, extra[:])
		if n != 0 {
			readErr = protocolError{errors.New("queqiao: path probe has trailing echo bytes")}
		} else if !errors.Is(err, io.EOF) {
			readErr = err
		}
	}
	if readErr != nil {
		interrupt()
	}
	w := <-writerDone
	result.sent = w.sent
	if ctx.Err() == context.Canceled {
		result.status = "canceled"
		return result, context.Canceled
	}
	// Known malformed echoes must not be hidden by the writer interruption
	// used to stop its concurrent work, or by a simultaneously expired budget.
	var violation protocolError
	if errors.As(readErr, &violation) {
		result.status = "protocol_error"
		return result, readErr
	}
	if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
		result.status = "protocol_error"
		return result, protocolError{errors.New("queqiao: path probe echo ended early")}
	}
	var timeout net.Error
	if w.err == nil && result.received == count && (readErr == nil || ctx.Err() == context.DeadlineExceeded || errors.As(readErr, &timeout) && timeout.Timeout()) {
		// All expected frames already matched (§14.2 case 1). A response EOF
		// delayed beyond the same budget is not a missing echo or violation.
		result.status = "conformant"
		return result, nil
	}
	if ctx.Err() == context.DeadlineExceeded || errors.As(readErr, &timeout) && timeout.Timeout() || errors.As(w.err, &timeout) && timeout.Timeout() {
		result.status = "incomplete"
		return result, nil
	}
	if w.err != nil {
		result.status = "transport_error"
		return result, w.err
	}
	if readErr != nil {
		result.status = "transport_error"
		return result, readErr
	}

	result.status = "conformant"
	return result, nil
}

// Validate each completely available part before awaiting the next one. A
// peer cannot hide a known wrong header or payload prefix by stalling until
// the read budget expires. The exact expected length also bounds allocation.
func readPathProbeEcho(r io.Reader, session [16]byte, sequence uint64, payload []byte) error {
	var b, expected [headerSize]byte
	expected[0], expected[1], expected[2], expected[3] = 'W', 'O', 1, typeProbe
	copy(expected[6:22], session[:])
	binary.BigEndian.PutUint64(expected[30:38], sequence)
	binary.BigEndian.PutUint32(expected[38:42], uint32(len(payload)))
	n, err := io.ReadFull(r, b[:])
	if !bytes.Equal(b[:n], expected[:n]) {
		return protocolError{errors.New("queqiao: path probe echo header mismatch")}
	}
	if err != nil {
		return err
	}
	body := make([]byte, len(payload))
	n, err = io.ReadFull(r, body)
	if !bytes.Equal(body[:n], payload[:n]) {
		return protocolError{errors.New("queqiao: path probe echo payload mismatch")}
	}
	return err
}
