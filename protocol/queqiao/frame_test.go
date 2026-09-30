package queqiao

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

func TestFrozenFrameHeaders(t *testing.T) {
	raw, err := os.ReadFile("testdata/protocol1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	type vector struct {
		Name string `json:"name"`
		Hex  string `json:"hex"`
	}
	var vectors struct {
		Headers struct{ Accept, Reject []vector } `json:"frame_headers"`
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors.Headers.Accept {
		t.Run("accept/"+v.Name, func(t *testing.T) {
			b, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			if err = validateHeader(b); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, int(binary.BigEndian.Uint32(b[38:42])))
			wire := append(append([]byte(nil), b...), payload...)
			f, err := readFrame(bytes.NewReader(wire))
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err = writeFrame(&out, f); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), wire) {
				t.Fatal("round trip changed frozen wire bytes")
			}
		})
	}
	for _, v := range vectors.Headers.Reject {
		t.Run("reject/"+v.Name, func(t *testing.T) {
			b, _ := hex.DecodeString(v.Hex)
			if validateHeader(b) == nil {
				t.Fatal("accepted invalid header")
			}
		})
	}
}

func TestFrameBoundsAndTruncation(t *testing.T) {
	for _, n := range []int{0, 1, maxPayload} {
		var b bytes.Buffer
		err := writeFrame(&b, frame{typ: typeData, payload: make([]byte, n)})
		if err != nil {
			t.Fatal(err)
		}
		f, err := readFrame(&b)
		if err != nil || len(f.payload) != n {
			t.Fatalf("size %d: %v", n, err)
		}
	}
	var b bytes.Buffer
	if writeFrame(&b, frame{typ: typeData, payload: make([]byte, maxPayload+1)}) == nil {
		t.Fatal("accepted oversized frame")
	}
	_ = writeFrame(&b, frame{typ: typeData, payload: []byte("data")})
	raw := b.Bytes()
	for i := 0; i < len(raw); i++ {
		if _, err := readFrame(bytes.NewReader(raw[:i])); err == nil {
			t.Fatalf("accepted truncated length %d", i)
		}
	}
	bad := append([]byte(nil), raw...)
	bad[2] = 2
	_, err := readFrame(bytes.NewReader(bad))
	var version versionError
	if !errors.As(err, &version) {
		t.Fatal("version mismatch not distinct")
	}
}

func TestACKValidation(t *testing.T) {
	ranges := func(values ...uint64) []byte {
		var b []byte
		for _, v := range values {
			b = binary.BigEndian.AppendUint64(b, v)
		}
		return b
	}
	cases := []struct {
		name         string
		f            frame
		final, valid bool
	}{
		{"cumulative", frame{flags: flagACKUp, sequence: 10}, false, true},
		{"ranges", frame{flags: flagACKUp | flagRanges, sequence: 10, payload: ranges(10, 20, 30, 40)}, false, true},
		{"wrong direction", frame{flags: flagACKDown}, false, false},
		{"both directions", frame{flags: flagACKUp | flagACKDown}, false, false},
		{"future", frame{flags: flagACKUp, sequence: 101}, false, false},
		{"unflagged payload", frame{flags: flagACKUp, payload: ranges(10, 20)}, false, false},
		{"overlap", frame{flags: flagACKUp | flagRanges, payload: ranges(10, 30, 20, 40)}, false, false},
		{"range beyond sent", frame{flags: flagACKUp | flagRanges, payload: ranges(10, 101)}, false, false},
		{"final", frame{flags: flagACKUp | flagACKFinal, sequence: 100}, true, true},
		{"unsolicited final", frame{flags: flagACKUp | flagACKFinal, sequence: 100}, false, false},
		{"wrong final offset", frame{flags: flagACKUp | flagACKFinal, sequence: 99}, true, false},
		{"final ranges", frame{flags: flagACKUp | flagACKFinal | flagRanges, sequence: 100}, true, false},
	}
	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			err := validateACK(v.f, 100, v.final)
			if (err == nil) != v.valid {
				t.Fatalf("valid=%v error=%v", v.valid, err)
			}
		})
	}
}

func FuzzReadFrame(f *testing.F) {
	var b bytes.Buffer
	_ = writeFrame(&b, frame{typ: typeData, payload: []byte("hello")})
	f.Add(b.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		parsed, err := readFrame(bytes.NewReader(b))
		if err == nil {
			if len(parsed.payload) > maxPayload {
				t.Fatal("unbounded frame")
			}
			if err = writeFrame(io.Discard, parsed); err != nil {
				t.Fatal(err)
			}
		}
	})
}
