//go:build with_quic

package queqiao

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
)

type inboundQUICStream struct {
	stream     *quic.Stream
	connection *quic.Conn
}

func (c *inboundQUICStream) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *inboundQUICStream) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *inboundQUICStream) Close() error                { c.stream.CancelRead(0); return c.stream.Close() }
func (c *inboundQUICStream) Abort() error {
	c.stream.CancelRead(0)
	c.stream.CancelWrite(0)
	return nil
}
func (c *inboundQUICStream) LocalAddr() net.Addr                { return c.connection.LocalAddr() }
func (c *inboundQUICStream) RemoteAddr() net.Addr               { return c.connection.RemoteAddr() }
func (c *inboundQUICStream) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *inboundQUICStream) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *inboundQUICStream) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

func startNativeQUICInbound(h *Inbound) error {
	packet, err := h.listener.ListenUDP()
	if err != nil {
		return err
	}
	transport := &quic.Transport{Conn: packet}
	listener, err := transport.Listen(h.tlsConfig, &quic.Config{HandshakeIdleTimeout: 15 * time.Second, MaxIdleTimeout: h.idle, MaxIncomingStreams: 64, MaxIncomingUniStreams: -1, InitialStreamReceiveWindow: 256 << 10, MaxStreamReceiveWindow: receiveLimit, InitialConnectionReceiveWindow: 512 << 10, MaxConnectionReceiveWindow: 8 << 20, EnableDatagrams: false})
	if err != nil {
		transport.Close()
		return err
	}
	h.closeQUIC = func() error { listener.Close(); return transport.Close() }
	var active atomic.Int32
	go func() {
		for {
			connection, err := listener.Accept(h.ctx)
			if err != nil {
				if h.ctx.Err() == nil && h.logger != nil {
					h.logger.Error("native QUIC listener stopped: ", err)
				}
				return
			}
			if active.Add(1) > 8 {
				active.Add(-1)
				connection.CloseWithError(1, "connection limit")
				continue
			}
			go func() {
				defer active.Add(-1)
				defer connection.CloseWithError(0, "server connection ended")
				state := connection.ConnectionState().TLS
				principal, err := parseInboundPrincipal(state.PeerCertificates[0], h.provider)
				if err != nil {
					return
				}
				for {
					stream, err := connection.AcceptStream(h.ctx)
					if err != nil {
						return
					}
					raw := &inboundQUICStream{stream, connection}
					select {
					case h.handshakes <- struct{}{}:
					default:
						raw.Abort()
						continue
					}
					if !h.track(raw) {
						raw.Abort()
						<-h.handshakes
						return
					}
					go func() { defer func() { <-h.handshakes }(); h.handleCarrier(raw, false, principal) }()
				}
			}()
		}
	}()
	return nil
}
