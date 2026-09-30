//go:build !with_quic

package queqiao

import (
	"context"
	"errors"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"testing"
)

func TestQUICUnavailableWithoutBuildTag(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: "unused", Transport: "quic"})
	if !errors.Is(err, C.ErrQUICNotIncluded) {
		t.Fatalf("QUIC without build tag: %v", err)
	}
}
