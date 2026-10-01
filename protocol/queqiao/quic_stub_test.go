//go:build !with_quic

package queqiao

import (
	"context"
	"errors"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"testing"
)

func TestQUICUnavailableWithoutBuildTag(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		_, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: "unused", Transport: "quic", QUICInitialFallback: fallback})
		if !errors.Is(err, C.ErrQUICNotIncluded) {
			t.Fatalf("QUIC without build tag (fallback=%v): %v", fallback, err)
		}
	}
}

func testOfficialQUICPool(t *testing.T, profile string, destination M.Socksaddr) {
	t.Skip("QUIC build tag disabled")
}

func breakTestCarrier(c *Conn, shared bool) { abortCarrier(c.currentCarrier()) }

func assertTestSharedCarrier(t *testing.T, conns []*Conn) { t.Fatal("QUIC unavailable") }

func TestQUICRolesRequiresBuildTag(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: "unused", Transport: "quic", TCPRecovery: true, QUICDataIsolation: true, QUICInitialFallback: true})
	if !errors.Is(err, C.ErrQUICNotIncluded) {
		t.Fatalf("isolation bypassed QUIC requirement: %v", err)
	}
}
