//go:build with_quic

package queqiao

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/qlogwriter"
)

func checkQUIC() error { return nil }

func dialQUIC(ctx context.Context, raw net.Conn, config *tls.Config) (net.Conn, error) {
	drain := newQUICDrain()
	connection, err := quic.DialConn(ctx, raw, config, &quic.Config{
		HandshakeIdleTimeout:           15 * time.Second,
		MaxIdleTimeout:                 time.Minute,
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     256 << 10,
		MaxStreamReceiveWindow:         receiveLimit,
		InitialConnectionReceiveWindow: 512 << 10,
		MaxConnectionReceiveWindow:     receiveLimit,
		MaxIncomingStreams:             -1,
		MaxIncomingUniStreams:          -1,
		// Negotiating DATAGRAM would authorize the gateway to send coded DATA.
		// This reliable-only implementation must never advertise it.
		EnableDatagrams: false,
		Tracer:          func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return drain },
	})
	if err != nil {
		return nil, err
	}
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		connection.CloseWithError(0, "open failed")
		raw.Close()
		return nil, err
	}
	return &quicCarrier{Stream: stream, connection: connection, raw: raw, drain: drain}, nil
}

type quicCarrier struct {
	*quic.Stream
	connection *quic.Conn
	raw        net.Conn
	once       sync.Once
	drain      *quicDrain
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
			// Complete the stream first and preserve the carrier until QUIC ACKs
			// cover its bytes. This is bounded even if the peer disappears.
			_ = c.Stream.Close()
			c.closeErr = c.drain.wait(c.connection.Context(), end, 2*time.Second)
		}
		c.Stream.CancelRead(0)
		_ = c.connection.CloseWithError(0, "flow closed")
		_ = c.raw.Close()
	})
	return c.closeErr
}
