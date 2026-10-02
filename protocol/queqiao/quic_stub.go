//go:build !with_quic

package queqiao

import C "github.com/sagernet/sing-box/constant"

func checkQUIC() error                      { return C.ErrQUICNotIncluded }
func newQUICPool(*Outbound) carrierPool     { return nil }
func initialQUICTerminalFailure(error) bool { return false }
func activeQUICTerminalFailure(error) bool  { return false }
func activeQUICCarrierLoss(error) bool      { return false }
