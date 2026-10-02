package queqiao

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
)

// These are the three reliable-frame vector groups not already consumed by
// frame_test.go and packet/udp_resume_test.go. No coded substrate is exercised.
func TestFrozenReliableConformance(t *testing.T) {
	raw, err := os.ReadFile("testdata/protocol1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		ACK []struct {
			Name, Hex  string
			Cumulative uint64
			Ranges     [][2]uint64
			Reject     bool
		} `json:"ack_ranges"`
		Destinations []struct {
			Name, Input, Canonical, Hex string
			Reject                      bool
		} `json:"destinations"`
		Reset []struct {
			Name, Message, Hex string
			Code               byte
		} `json:"reset_payloads"`
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.ACK) != 12 || len(vectors.Destinations) != 17 || len(vectors.Reset) != 7 {
		t.Fatal("pinned reliable vector inventory changed")
	}
	decode := func(t *testing.T, s string) []byte {
		t.Helper()
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	for _, v := range vectors.ACK {
		t.Run("ACK/"+v.Name, func(t *testing.T) {
			payload := decode(t, v.Hex)
			flags := uint16(flagACKUp)
			if len(payload) > 0 {
				flags |= flagRanges
			}
			// Range conformance has no particular connection's send limit. The separate
			// state tests enforce that an actual peer cannot ACK beyond bytes sent.
			err := validateACK(frame{typ: typeACK, flags: flags, sequence: v.Cumulative, payload: payload}, math.MaxUint64, false)
			if (err != nil) != v.Reject {
				t.Fatalf("reject=%v error=%v", v.Reject, err)
			}
			if !v.Reject {
				var encoded []byte
				for _, r := range v.Ranges {
					encoded = binary.BigEndian.AppendUint64(encoded, r[0])
					encoded = binary.BigEndian.AppendUint64(encoded, r[1])
				}
				if !bytes.Equal(encoded, payload) {
					t.Fatal("frozen ACK range bytes differ")
				}
			}
		})
	}
	for _, v := range vectors.Destinations {
		t.Run("destination/"+v.Name, func(t *testing.T) {
			if v.Reject {
				if _, err := canonicalAddress(v.Input, 255); err == nil {
					t.Fatal("accepted invalid destination")
				}
				return
			}
			wire := decode(t, v.Hex)
			if string(wire) != v.Canonical {
				t.Fatal("frozen canonical spelling differs from wire")
			}
			got, err := canonicalAddress(string(wire), 255)
			if err != nil || got != v.Canonical {
				t.Fatalf("canonical wire %q: %q %v", wire, got, err)
			}
			if strings.TrimSpace(v.Input) != v.Input {
				// Upstream vectors also describe its CLI's raw-string trimming. This
				// outbound accepts structured SOCKS destinations and strict profile fields,
				// not that CLI. Keep strict rejection and verify the canonical wire above.
				if _, err := canonicalAddress(v.Input, 255); err == nil {
					t.Fatal("strict address field unexpectedly trims whitespace")
				}
				t.Log("raw CLI whitespace normalization is outside this outbound API; canonical wire verified")
				return
			}
			got, err = canonicalAddress(v.Input, 255)
			if err != nil || got != v.Canonical {
				t.Fatalf("destination canonicalization %q: %q %v", v.Input, got, err)
			}
		})
	}
	for _, v := range vectors.Reset {
		t.Run("RESET/"+v.Name, func(t *testing.T) {
			payload := decode(t, v.Hex)
			if !bytes.Equal(payload, append([]byte{v.Code}, []byte(v.Message)...)) {
				t.Fatal("frozen RESET bytes differ")
			}
			err := resetError(frame{typ: typeReset, payload: payload})
			var reset gatewayResetError
			if !errors.As(err, &reset) || reset.code != v.Code {
				t.Fatalf("RESET code%v: %v", v.Code, err)
			}
			if v.Message != "" && strings.Contains(err.Error(), v.Message) {
				t.Fatal("peer diagnostic leaked into error")
			}
		})
	}
}
