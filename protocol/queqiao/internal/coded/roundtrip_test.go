package coded

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/rand"
	"testing"
)

func TestRandomErasureReorderingAndDuplication(t *testing.T) {
	rng := rand.New(rand.NewSource(58392))
	for trial := 0; trial < 100; trial++ {
		enc, _ := NewEncoder(Config{})
		dec, _ := NewDecoder(Config{})
		n := 1 + rng.Intn(64)
		var wires [][]byte
		want := make(map[string]bool)
		for i := 0; i < n; i++ {
			f := make([]byte, 4+rng.Intn(900))
			binary.BigEndian.PutUint32(f, uint32(i))
			rng.Read(f[4:])
			want[string(f)] = true
			d, e := enc.EncodeFrame(f)
			if e != nil {
				t.Fatal(e)
			}
			if i%3 != 0 {
				wires = append(wires, d...)
			}
		}
		for i := 0; i < n/3+12; i++ {
			wire, e := enc.Repair(n)
			if e != nil {
				t.Fatal(e)
			}
			wires = append(wires, wire)
		}
		rng.Shuffle(len(wires), func(i, j int) { wires[i], wires[j] = wires[j], wires[i] })
		seen := make(map[string]bool)
		for _, wire := range wires {
			for duplicate := 0; duplicate < 2; duplicate++ {
				out, e := dec.Input(wire)
				if e != nil {
					t.Fatalf("trial %d: %v", trial, e)
				}
				for _, f := range out.Frames {
					if !want[string(f)] || seen[string(f)] {
						t.Fatalf("wrong or duplicate recovered frame trial %d", trial)
					}
					seen[string(f)] = true
				}
			}
		}
		if len(seen) != len(want) {
			t.Fatalf("trial %d delivered %d/%d", trial, len(seen), len(want))
		}
	}
}
func TestFragmentRecoveryMaximumFrameAndWrap(t *testing.T) {
	for _, wrap := range []bool{false, true} {
		enc, _ := NewEncoder(Config{})
		dec, _ := NewDecoder(Config{})
		if wrap {
			enc.nextSource = math.MaxUint32 - 5
			enc.nextSequence = math.MaxUint32 - 3
			enc.nextRepair = math.MaxUint32 - 2
		}
		frame := bytes.Repeat([]byte{0x53}, MaxFrameBytes)
		wires, e := enc.EncodeFrame(frame)
		if e != nil {
			t.Fatal(e)
		}
		if len(wires) > MaxRepairSpan {
			t.Fatal("test frame exceeds single repair span")
		}
		var arrived [][]byte
		for i, w := range wires {
			if i%7 != 0 {
				arrived = append(arrived, w)
			}
		}
		for i := 0; i < len(wires)/7+10; i++ {
			w, e := enc.Repair(len(wires))
			if e != nil {
				t.Fatal(e)
			}
			arrived = append(arrived, w)
		}
		rand.New(rand.NewSource(37)).Shuffle(len(arrived), func(i, j int) { arrived[i], arrived[j] = arrived[j], arrived[i] })
		var got [][]byte
		for _, w := range arrived {
			out, e := dec.Input(w)
			if e != nil {
				t.Fatal(e)
			}
			got = append(got, out.Frames...)
		}
		if len(got) != 1 || !bytes.Equal(got[0], frame) {
			t.Fatalf("fragment wrap=%v delivered=%d", wrap, len(got))
		}
		for _, w := range wires {
			out, e := dec.Input(w)
			if e != nil || len(out.Frames) != 0 {
				t.Fatalf("duplicate fragments after completion: %v", e)
			}
		}
	}
}
func TestLateFullSpanRepairRetains512Slots(t *testing.T) {
	enc, _ := NewEncoder(Config{})
	dec, _ := NewDecoder(Config{})
	var original []byte
	for i := 0; i < 256; i++ {
		f := binary.BigEndian.AppendUint32(nil, uint32(i))
		wire, _ := enc.EncodeFrame(f)
		if i == 0 {
			original = append([]byte(nil), f...)
		} else if _, e := dec.Input(wire[0]); e != nil {
			t.Fatal(e)
		}
	}
	repair, e := enc.Repair(256)
	if e != nil {
		t.Fatal(e)
	}
	for i := 256; i < 512; i++ {
		wire, _ := enc.EncodeFrame(binary.BigEndian.AppendUint32(nil, uint32(i)))
		if _, e := dec.Input(wire[0]); e != nil {
			t.Fatal(e)
		}
	}
	out, e := dec.Input(repair)
	if e != nil || len(out.Frames) != 1 || !bytes.Equal(out.Frames[0], original) {
		t.Fatalf("legal delayed full-span repair: %d %v", len(out.Frames), e)
	}
	if dec.Stats().Slots != 512 || dec.Stats().Lost != 0 {
		t.Fatalf("window shrank or evicted too soon: %+v", dec.Stats())
	}
}
func TestAllErasedFullSpan(t *testing.T) {
	enc, _ := NewEncoder(Config{})
	dec, _ := NewDecoder(Config{})
	for i := 0; i < 256; i++ {
		enc.EncodeFrame(binary.BigEndian.AppendUint32(nil, uint32(i)))
	}
	seen := make(map[uint32]bool)
	for i := 0; i < 280 && len(seen) < 256; i++ {
		w, _ := enc.Repair(256)
		out, e := dec.Input(w)
		if e != nil {
			t.Fatal(e)
		}
		for _, f := range out.Frames {
			if len(f) != 4 {
				t.Fatal("wrong frame size")
			}
			n := binary.BigEndian.Uint32(f)
			if n >= 256 || seen[n] {
				t.Fatal("wrong or duplicate frame")
			}
			seen[n] = true
		}
	}
	if len(seen) != 256 {
		t.Fatalf("recovered %d/256", len(seen))
	}
}

func TestPackingToFragmentBoundary(t *testing.T) {
	for datagram := 26; datagram < 90; datagram++ {
		size := datagram - RepairHeader - SymbolHeader
		for length := size - 4; length <= size+1; length++ {
			enc, _ := NewEncoder(Config{DatagramBytes: datagram})
			dec, _ := NewDecoder(Config{DatagramBytes: datagram})
			frame := bytes.Repeat([]byte{0x30}, length)
			wires, err := enc.EncodeFrame(frame)
			if err != nil {
				t.Fatal(err)
			}
			var got [][]byte
			for _, wire := range wires {
				out, e := dec.Input(wire)
				if e != nil {
					t.Fatal(e)
				}
				got = append(got, out.Frames...)
			}
			if len(got) != 1 || !bytes.Equal(got[0], frame) {
				t.Fatalf("packing boundary datagram=%d length=%d", datagram, length)
			}
		}
	}
}

func TestMaximumVectorsFullSpanFitsWorkBudget(t *testing.T) {
	cfg := Config{DatagramBytes: RepairHeader + MaxVectorBytes}
	enc, _ := NewEncoder(cfg)
	dec, _ := NewDecoder(cfg)
	for i := 0; i < 256; i++ {
		frame := bytes.Repeat([]byte{byte(i)}, MaxVectorBytes-SymbolHeader-4)
		binary.BigEndian.PutUint32(frame, uint32(i))
		if _, e := enc.EncodeFrame(frame); e != nil {
			t.Fatal(e)
		}
	}
	seen := make(map[uint32]bool)
	maxWork := 0
	for i := 0; i < 280 && len(seen) < 256; i++ {
		w, e := enc.Repair(256)
		if e != nil {
			t.Fatal(e)
		}
		out, e := dec.Input(w)
		if e != nil {
			t.Fatal(e)
		}
		checkBounds(t, dec, out)
		maxWork = max(maxWork, dec.Stats().LastWork)
		for _, f := range out.Frames {
			id := binary.BigEndian.Uint32(f)
			if len(f) != 4086 || id >= 256 || seen[id] || !bytes.Equal(f[4:], bytes.Repeat([]byte{byte(id)}, len(f)-4)) {
				t.Fatal("maximum vector data corrupted")
			}
			seen[id] = true
		}
	}
	if len(seen) != 256 || maxWork > DefaultWorkLimit {
		t.Fatalf("recovered=%d work=%d", len(seen), maxWork)
	}
	t.Logf("maximum-vector full-span peak charged work per input: %d", maxWork)
}

func Test512UnknownsAcrossIndependentRepairWindows(t *testing.T) {
	dec, _ := NewDecoder(Config{})
	vectors := make([][]byte, 512)
	for i := range vectors {
		vectors[i] = packedVector(binary.BigEndian.AppendUint32(nil, uint32(i)))
	}
	seen := make(map[uint32]bool)
	peakRows := 0
	accept := func(first int, rid uint32) {
		out, e := dec.Input(repairWire(t, rid, uint32(first), vectors[first:first+256]))
		if e != nil {
			t.Fatal(e)
		}
		checkBounds(t, dec, out)
		peakRows = max(peakRows, dec.Stats().Equations)
		for _, f := range out.Frames {
			if len(f) != 4 {
				t.Fatal("bad frame")
			}
			id := binary.BigEndian.Uint32(f)
			if id >= 512 || seen[id] {
				t.Fatal("wrong or duplicate frame")
			}
			seen[id] = true
		}
	}
	for _, first := range []int{0, 256} {
		for rid := uint32(0); rid < 255; rid++ {
			accept(first, rid+uint32(first)*4)
		}
	}
	for rid := uint32(255); rid < 265 && len(seen) < 512; rid++ {
		accept(0, rid)
		accept(256, rid+1024)
	}
	if len(seen) != 512 || peakRows < 500 {
		t.Fatalf("recovered=%d peak simultaneous equations=%d", len(seen), peakRows)
	}
	t.Logf("peak simultaneous equations: %d", peakRows)
}
