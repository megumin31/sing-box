//go:build with_quic

package queqiao

import (
	"errors"
	"testing"

	"github.com/sagernet/quic-go"
)

func TestActiveFallbackQUICCloseClassification(t *testing.T) {
	for _, v := range []struct {
		name    string
		err     error
		allowed bool
	}{
		{"transport-close", &quic.TransportError{ErrorCode: 0}, true},
		{"application-close", &quic.ApplicationError{ErrorCode: 0}, true},
		{"stream-close", &quic.StreamError{ErrorCode: 0}, true},
		{"stateless-reset", &quic.StatelessResetError{}, true},
		{"transport-refusal", &quic.TransportError{ErrorCode: 1}, false},
		{"application-refusal", &quic.ApplicationError{ErrorCode: 1}, false},
		{"stream-refusal", &quic.StreamError{ErrorCode: 1}, false},
		{"version-refusal", &quic.VersionNegotiationError{}, false},
		{"reset-hides-refusal", errors.Join(&quic.StatelessResetError{}, &quic.ApplicationError{ErrorCode: 1}), false},
	} {
		t.Run(v.name, func(t *testing.T) {
			h := newCarrierHandoff(false, true)
			if h.prepare(v.err) != v.allowed || h.tcp() != v.allowed {
				t.Fatal("incorrect established-carrier admission")
			}
			if initialFallbackAllowed(v.err) {
				t.Fatal("active policy changed pre-OPEN admission")
			}
		})
	}
}
