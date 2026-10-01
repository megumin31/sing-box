//go:build !with_quic

package queqiao

import (
	"context"
	"github.com/sagernet/sing-box/option"
	"testing"
)

func TestPathProbeRequiresQUICBuild(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: "not-opened", Transport: "quic", QUICPathProbe: true, QUICInitialFallback: true})
	if err == nil || err.Error() != checkQUIC().Error() {
		t.Fatalf("probe bypassed QUIC build requirement: %v", err)
	}
}
