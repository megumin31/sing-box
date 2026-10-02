//go:build !with_quic

package queqiao

import C "github.com/sagernet/sing-box/constant"

func startNativeQUICInbound(*Inbound) error { return C.ErrQUICNotIncluded }
