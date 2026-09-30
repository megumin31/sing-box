//go:build !with_quic

package queqiao

import (
	"context"
	"crypto/tls"
	C "github.com/sagernet/sing-box/constant"
	"net"
)

func checkQUIC() error { return C.ErrQUICNotIncluded }
func dialQUIC(context.Context, net.Conn, *tls.Config) (net.Conn, error) {
	return nil, C.ErrQUICNotIncluded
}
