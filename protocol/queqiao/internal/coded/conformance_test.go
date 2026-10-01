package coded

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestOfficialFrozenConformance(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/protocol1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Coefficients []struct {
			RID   uint32
			Count int
			Hex   string `json:"coefficients_hex"`
		} `json:"fec_coefficients"`
		Repairs []struct {
			Name         string
			RID          uint32
			Symbols      []string `json:"symbols_hex"`
			Count, First int
			Vector       string `json:"vector_hex"`
		} `json:"fec_repairs"`
		Datagrams []struct {
			Name, Hex string
			Frames    []string
			Reject    bool
		} `json:"coded_datagrams"`
		Limits struct {
			Span  int `json:"max_repair_window"`
			Width int `json:"min_decoder_width"`
		} `json:"limits"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Coefficients) != 10 || len(v.Repairs) != 5 || len(v.Datagrams) != 12 {
		t.Fatalf("review changed vector inventory: %d/%d/%d", len(v.Coefficients), len(v.Repairs), len(v.Datagrams))
	}
	if v.Limits.Span != MaxRepairSpan || v.Limits.Width != DecoderWidth {
		t.Fatal("normative limits differ")
	}
	for _, row := range v.Coefficients {
		got, e := Coefficients(row.RID, row.Count)
		if e != nil || !bytes.Equal(got, unhex(t, row.Hex)) {
			t.Fatalf("coefficient RID=%d: %x %v", row.RID, got, e)
		}
	}
	for _, row := range v.Repairs {
		t.Run(row.Name, func(t *testing.T) {
			var vectors [][]byte
			for _, s := range row.Symbols[row.First : row.First+row.Count] {
				vectors = append(vectors, unhex(t, s))
			}
			got, e := RepairVector(row.RID, vectors)
			if e != nil || !bytes.Equal(got, unhex(t, row.Vector)) {
				t.Fatalf("repair: %x %v", got, e)
			}
		})
	}
	for _, row := range v.Datagrams {
		t.Run(row.Name, func(t *testing.T) {
			decoder, _ := NewDecoder(Config{})
			data := unhex(t, row.Hex)
			packet, e := Parse(data)
			if row.Reject {
				if e == nil {
					t.Fatal("forbidden datagram parsed")
				}
				_, e = decoder.Input(data)
				if e == nil || decoder.Stats().Lost != 0 {
					t.Fatal("invalid repair admitted or counted as erasure")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			encoded, e := packet.Marshal()
			if e != nil || !bytes.Equal(encoded, data) {
				t.Fatalf("wire roundtrip: %x %v", encoded, e)
			}
			out, e := decoder.Input(data)
			if e != nil {
				t.Fatal(e)
			}
			if len(out.Frames) != len(row.Frames) {
				t.Fatalf("delivered %d want %d", len(out.Frames), len(row.Frames))
			}
			for i, want := range row.Frames {
				if !bytes.Equal(out.Frames[i], unhex(t, want)) {
					t.Fatalf("frame %d mismatch", i)
				}
			}
		})
	}
}
func TestFieldIdentities(t *testing.T) {
	for a := 0; a < 256; a++ {
		if products[a][0] != 0 || products[a][1] != byte(a) {
			t.Fatal("identity")
		}
		if a != 0 && products[a][inverse(byte(a))] != 1 {
			t.Fatalf("inverse %d", a)
		}
		for b := 0; b < 256; b++ {
			if products[a][b] != products[b][a] {
				t.Fatal("commutativity")
			}
			c := byte((a*73 + b*29) & 255)
			if products[a][byte(b)^c] != products[a][b]^products[a][c] {
				t.Fatal("distributivity")
			}
		}
	}
}
