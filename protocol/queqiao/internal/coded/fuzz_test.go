package coded

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func checkBounds(t *testing.T, d *Decoder, out Result) {
	t.Helper()
	s := d.Stats()
	maxVector := d.cfg.DatagramBytes - RepairHeader
	if s.Slots != DecoderWidth || s.Equations > DecoderWidth || s.Groups > DecoderWidth || s.Fragments > DecoderWidth || s.BufferedBytes > 3*DecoderWidth*maxVector+DecoderWidth*DecoderWidth || s.LastWork < 0 || s.LastWork > d.cfg.WorkLimit {
		t.Fatalf("decoder exceeded bound: %+v", s)
	}
	n := 0
	for _, f := range out.Frames {
		n += len(f)
		if len(f) > MaxFrameBytes {
			t.Fatal("oversized output frame")
		}
	}
	if len(out.Frames) > MaxOutputFrames || n > MaxOutputBytes || len(out.Lost) > DecoderWidth {
		t.Fatal("oversized output batch")
	}
}
func FuzzDatagram(f *testing.F) {
	raw, _ := os.ReadFile("../../testdata/protocol1-vectors.json")
	var vectors struct {
		Datagrams []struct{ Hex string } `json:"coded_datagrams"`
	}
	json.Unmarshal(raw, &vectors)
	for _, v := range vectors.Datagrams {
		b, _ := hex.DecodeString(v.Hex)
		f.Add(b)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		d, _ := NewDecoder(Config{WorkLimit: 65536})
		out, err := d.Input(wire)
		if err != nil && len(out.Frames) != 0 {
			t.Fatal("partial output on error")
		}
		checkBounds(t, d, out)
	})
}
func FuzzDatagramSequence(f *testing.F) {
	e, _ := NewEncoder(Config{})
	var script []byte
	for i := 0; i < 4; i++ {
		w, _ := e.EncodeFrame(bytes.Repeat([]byte{byte(i)}, 20+i))
		script = binary.BigEndian.AppendUint16(script, uint16(len(w[0])))
		script = append(script, w[0]...)
	}
	for i := 0; i < 3; i++ {
		w, _ := e.Repair(4)
		script = binary.BigEndian.AppendUint16(script, uint16(len(w)))
		script = append(script, w...)
	}
	f.Add(script)
	f.Add([]byte{0, 0, 0, 2, 1, 2})
	f.Fuzz(func(t *testing.T, script []byte) {
		d, _ := NewDecoder(Config{WorkLimit: 65536})
		for step := 0; step < 64 && len(script) >= 2; step++ {
			n := int(binary.BigEndian.Uint16(script))
			script = script[2:]
			n = min(n, len(script))
			wire := script[:n]
			script = script[n:]
			before := d.Stats()
			out, err := d.Input(wire)
			if err == ErrDatagram && d.Stats().Lost != before.Lost {
				t.Fatal("malformed input reported erasure")
			}
			if err != nil && len(out.Frames) != 0 {
				t.Fatal("partial output")
			}
			checkBounds(t, d, out)
			if d.failed != nil {
				d.Reset()
			}
		}
	})
}
func FuzzEncoderReassembly(f *testing.F) {
	f.Add([]byte("hello"), uint16(1200))
	f.Add(bytes.Repeat([]byte{0xa5}, 4096), uint16(26))
	f.Add([]byte{}, uint16(4111))
	f.Fuzz(func(t *testing.T, frame []byte, mtu uint16) {
		if len(frame) > MaxFrameBytes+1 {
			return
		}
		size := 26 + int(mtu)%(4111-26+1)
		cfg := Config{DatagramBytes: size}
		enc, _ := NewEncoder(cfg)
		dec, _ := NewDecoder(cfg)
		wires, err := enc.EncodeFrame(frame)
		if err != nil {
			if err != ErrBudget {
				t.Fatal(err)
			}
			return
		}
		var got [][]byte
		for i := len(wires) - 1; i >= 0; i-- {
			out, e := dec.Input(wires[i])
			if e != nil {
				t.Fatal(e)
			}
			checkBounds(t, dec, out)
			got = append(got, out.Frames...)
		}
		if len(got) != 1 || !bytes.Equal(got[0], frame) {
			t.Fatalf("reassembly mismatch datagram=%d frame=%d fragments=%d got=%d", size, len(frame), len(wires), len(got))
		}
	})
}
func BenchmarkRepairFullSpan(b *testing.B) {
	vectors := make([][]byte, MaxRepairSpan)
	for i := range vectors {
		vectors[i] = bytes.Repeat([]byte{byte(i)}, 1185)
	}
	b.ReportAllocs()
	b.SetBytes(256 * 1185)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, e := RepairVector(uint32(i), vectors); e != nil {
			b.Fatal(e)
		}
	}
}
func BenchmarkDecodeFullSpan(b *testing.B) {
	e, _ := NewEncoder(Config{})
	for i := 0; i < 256; i++ {
		e.EncodeFrame(bytes.Repeat([]byte{byte(i)}, 100))
	}
	repairs := make([][]byte, 270)
	for i := range repairs {
		repairs[i], _ = e.Repair(256)
	}
	b.ReportAllocs()
	b.SetBytes(256 * 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d, _ := NewDecoder(Config{})
		for _, w := range repairs {
			if _, err := d.Input(w); err != nil {
				b.Fatal(err)
			}
		}
	}
}
