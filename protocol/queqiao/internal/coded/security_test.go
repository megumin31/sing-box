package coded

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"
	"time"
)

func sourceWire(t *testing.T, id uint32, vector []byte) []byte {
	t.Helper()
	b, e := (Datagram{Kind: SourceKind, ID: id, Vector: vector}).Marshal()
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func packedVector(payload []byte) []byte {
	return symbol(append(binary.BigEndian.AppendUint32(nil, uint32(len(payload))), payload...), 0, 1)
}
func repairWire(t *testing.T, rid, first uint32, vectors [][]byte) []byte {
	t.Helper()
	v, e := RepairVector(rid, vectors)
	if e != nil {
		t.Fatal(e)
	}
	b, e := (Datagram{Kind: RepairKind, ID: rid, First: first, Count: len(vectors), Vector: v}).Marshal()
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestReduceLaterPivotsBeforeSelectingEarlierPivot(t *testing.T) {
	dec, _ := NewDecoder(Config{})
	v := [][]byte{packedVector([]byte("first")), packedVector([]byte("second")), packedVector([]byte("third"))}
	var got [][]byte
	for _, w := range [][]byte{repairWire(t, 1, 1, v[1:]), repairWire(t, 2, 0, v), sourceWire(t, 2, v[2])} {
		out, e := dec.Input(w)
		if e != nil {
			t.Fatal(e)
		}
		got = append(got, out.Frames...)
	}
	seen := map[string]bool{}
	for _, f := range got {
		seen[string(f)] = true
	}
	if len(got) != 3 || !seen["first"] || !seen["second"] || !seen["third"] {
		t.Fatalf("pivot reduction corrupted values: %q", got)
	}
}
func TestInvalidRepairCannotMoveWindowOrInflateLoss(t *testing.T) {
	dec, _ := NewDecoder(Config{})
	dec.Input(sourceWire(t, 0, packedVector([]byte{1})))
	before := dec.Stats()
	for _, n := range []uint16{0, 257, 65535} {
		b := make([]byte, RepairHeader+1)
		b[4] = RepairKind
		binary.BigEndian.PutUint32(b[9:], 1<<30)
		binary.BigEndian.PutUint16(b[13:], n)
		out, e := dec.Input(b)
		if !errors.Is(e, ErrDatagram) || len(out.Frames) != 0 || len(out.Lost) != 0 || dec.high != 0 || dec.Stats().Lost != before.Lost {
			t.Fatalf("span %d entered decoder: %v", n, e)
		}
	}
	if dec.Stats().Malformed != 3 {
		t.Fatal("malformed accounting")
	}
}
func TestConflictsAndMalformedRecoveredSymbols(t *testing.T) {
	for _, kind := range []string{"source", "equation", "repair-id", "recovered-header"} {
		t.Run(kind, func(t *testing.T) {
			dec, _ := NewDecoder(Config{})
			vector := packedVector([]byte("safe"))
			wire := sourceWire(t, 0, vector)
			if kind == "repair-id" {
				dec.Input(repairWire(t, 7, 0, [][]byte{vector, vector}))
				b := repairWire(t, 7, 1, [][]byte{vector, vector})
				out, e := dec.Input(b)
				if e != ErrConflict || len(out.Frames) != 0 {
					t.Fatal(e)
				}
				return
			}
			var out Result
			var err error
			if kind == "recovered-header" {
				out, err = dec.Input(repairWire(t, 1, 0, [][]byte{{0}}))
				if err != ErrSymbol {
					t.Fatal(err)
				}
			} else {
				dec.Input(wire)
				if kind == "source" {
					changed := append([]byte(nil), vector...)
					changed[len(changed)-1] ^= 1
					out, err = dec.Input(sourceWire(t, 0, changed))
				} else {
					b := repairWire(t, 11, 0, [][]byte{vector})
					b[len(b)-1] ^= 1
					out, err = dec.Input(b)
				}
				if err != ErrConflict {
					t.Fatal(err)
				}
			}
			if len(out.Frames) != 0 || dec.Stats().BufferedBytes != 0 {
				t.Fatal("conflict retained poisoned state or partial result")
			}
			if _, e := dec.Input(wire); e != err {
				t.Fatal("poison silently cleared")
			}
			dec.Reset()
			if o, e := dec.Input(wire); e != nil || len(o.Frames) != 1 {
				t.Fatal("explicit reset failed", e)
			}
		})
	}
}
func TestCorruptionIsNotAnIntegrityGuarantee(t *testing.T) {
	dec, _ := NewDecoder(Config{})
	wire := sourceWire(t, 0, packedVector([]byte("original")))
	wire[len(wire)-1] ^= 1
	out, err := dec.Input(wire)
	if err != nil || len(out.Frames) != 1 || bytes.Equal(out.Frames[0], []byte("original")) {
		t.Fatal("test must demonstrate undetectable valid-format corruption")
	}
	// The erasure codec has no MAC. An authenticated carrier and inner-frame
	// validation are mandatory; redundancy cannot promise malicious-bit detection.
}
func TestFragmentMetadataConflicts(t *testing.T) {
	for _, vector := range [][]byte{symbol([]byte("b"), 1, 3), packedVector([]byte("b")), symbol([]byte("b"), 0, 2)} {
		dec, _ := NewDecoder(Config{})
		dec.Input(sourceWire(t, 0, symbol([]byte("a"), 0, 2)))
		out, err := dec.Input(sourceWire(t, 1, vector))
		if err != ErrConflict || len(out.Frames) != 0 {
			t.Fatal("overlapping or inconsistent fragments accepted", err)
		}
	}
}
func TestFixedSlotsFragmentAndOutputBudgets(t *testing.T) {
	dec, _ := NewDecoder(Config{})
	if s := dec.Stats(); s.Slots != 512 || s.LastWork != 0 {
		t.Fatalf("constructor limits: %+v", s)
	}
	for i := 0; i < 512; i++ {
		out, e := dec.Input(sourceWire(t, uint32(i), symbol([]byte{byte(i)}, i, 512)))
		if e != nil {
			t.Fatal(e)
		}
		if i < 511 && len(out.Frames) != 0 {
			t.Fatal("incomplete fragment emitted")
		}
		if i == 511 && (len(out.Frames) != 1 || len(out.Frames[0]) != 512) {
			t.Fatal("512 fragments failed")
		}
	}
	dec.Reset()
	out, e := dec.Input(sourceWire(t, 0, symbol([]byte{1}, 0, 65535)))
	if e != ErrBudget || len(out.Frames) != 0 || dec.started {
		t.Fatal("fragment count allocated state before budget check", e)
	}
	large, _ := NewDecoder(Config{DatagramBytes: RepairHeader + MaxVectorBytes})
	var err error
	for i := 0; i < 512; i++ {
		_, err = large.Input(sourceWire(t, uint32(i), symbol(make([]byte, MaxVectorBytes-SymbolHeader), i, 512)))
		if err != nil {
			break
		}
	}
	if err != ErrBudget || large.Stats().BufferedBytes != 0 {
		t.Fatal("oversized assembled frame did not exhaust safely", err)
	}
	// Enough empty packed frames recovered in one operation must hit the result
	// cardinality limit, even though their aggregate payload byte size is zero.
	zero := symbol(make([]byte, 4000), 0, 1)
	vectors := [][]byte{zero, zero, zero, zero, zero}
	bounded, _ := NewDecoder(Config{DatagramBytes: 4111})
	err = nil
	for rid := uint32(0); rid < 20; rid++ {
		_, err = bounded.Input(repairWire(t, rid, 0, vectors))
		if err != nil {
			break
		}
	}
	if err != ErrBudget {
		t.Fatalf("output frame cardinality not bounded: %v", err)
	}
}
func TestCPUAndLargeSerialJumpBudgets(t *testing.T) {
	dec, _ := NewDecoder(Config{WorkLimit: 1})
	wire := sourceWire(t, 0, packedVector([]byte{1}))
	out, err := dec.Input(wire)
	if err != ErrBudget || len(out.Frames) != 0 || dec.Stats().LastWork > 1 || dec.Stats().BufferedBytes != 0 {
		t.Fatal("work budget", err)
	}
	dec, _ = NewDecoder(Config{})
	dec.Input(wire)
	done := make(chan error, 1)
	go func() {
		out, e := dec.Input(sourceWire(t, 1<<30, packedVector([]byte("far"))))
		if len(out.Lost) > 512 || dec.Stats().LastWork > DefaultWorkLimit {
			done <- ErrBudget
		} else {
			done <- e
		}
	}()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("large ESI gap performed an unbounded walk")
	}
	before := dec.high
	_, err = dec.Input(sourceWire(t, before+1<<31, packedVector([]byte("ambiguous"))))
	if err != ErrSequence || dec.high != before {
		t.Fatal("half-space serial comparison", err)
	}
}
func TestCallerBufferOwnership(t *testing.T) {
	enc, _ := NewEncoder(Config{})
	input := []byte("owned")
	wires, _ := enc.EncodeFrame(input)
	input[0] = 'X'
	original := append([]byte(nil), wires[0]...)
	wires[0][len(wires[0])-1] ^= 1
	repair, _ := enc.Repair(1)
	dec, _ := NewDecoder(Config{})
	out, e := dec.Input(repair)
	if e != nil || len(out.Frames) != 1 || string(out.Frames[0]) != "owned" {
		t.Fatal("encoder retained caller buffer", e)
	}
	out.Frames[0][0] = 'Y'
	again, e := dec.Input(original)
	if e != nil || len(again.Frames) != 0 {
		t.Fatal("output mutation altered decoder symbols", e)
	}
	packet, _ := Parse(original)
	packet.Vector[len(packet.Vector)-1] ^= 1
	if original[len(original)-1] == []byte("owned")[4] {
		t.Fatal("Parse should document a borrowed view")
	}
}
func TestEncoderAndConfigurationBounds(t *testing.T) {
	for _, cfg := range []Config{{DatagramBytes: 25}, {DatagramBytes: 4112}, {WorkLimit: -1}, {WorkLimit: 65 << 20}} {
		if _, e := NewDecoder(cfg); e != ErrConfig {
			t.Fatal(e)
		}
		if _, e := NewEncoder(cfg); e != ErrConfig {
			t.Fatal(e)
		}
	}
	enc, _ := NewEncoder(Config{})
	if _, e := enc.EncodeFrame(make([]byte, MaxFrameBytes+1)); e != ErrBudget {
		t.Fatal(e)
	}
	if enc.nextSource != 0 || enc.nextSequence != 0 {
		t.Fatal("rejected frame changed numbering")
	}
	for _, n := range []int{0, 257, math.MaxInt} {
		if _, e := enc.Repair(n); e != ErrDatagram {
			t.Fatal(e)
		}
		if _, e := Coefficients(0, n); e != ErrDatagram {
			t.Fatal(e)
		}
	}
	small, _ := NewEncoder(Config{DatagramBytes: 26})
	if _, e := small.EncodeFrame(make([]byte, MaxFrameBytes)); e != ErrBudget {
		t.Fatal("fragmentation budget", e)
	}
	for i := 0; i < 1000; i++ {
		enc.EncodeFrame([]byte{byte(i)})
	}
	if enc.held != 256 {
		t.Fatal("unbounded encoder window")
	}
	if _, e := enc.Repair(256); e != nil {
		t.Fatal(e)
	}
}

func TestRejectedFragmentCountDoesNotAllocateByCount(t *testing.T) {
	dec, _ := NewDecoder(Config{})
	wire := sourceWire(t, 0, symbol([]byte{1}, 0, 65535))
	allocations := testing.AllocsPerRun(100, func() {
		if _, e := dec.Input(wire); e != ErrBudget {
			panic("unexpected admission")
		}
	})
	if allocations > 1 {
		t.Fatalf("rejected count allocated buffers: %f", allocations)
	}
}

func TestWorkBudgetIncludesPaddingCopiesAndDuplicates(t *testing.T) {
	vector := append(symbol(nil, 0, 1), make([]byte, MaxVectorBytes-SymbolHeader)...)
	wire := sourceWire(t, 0, vector)
	limited, _ := NewDecoder(Config{DatagramBytes: 4111, WorkLimit: 513})
	if out, err := limited.Input(wire); err != ErrBudget || len(out.Frames) != 0 || limited.started {
		t.Fatalf("oversized scan admitted: %+v %v", out, err)
	}
	dec, _ := NewDecoder(Config{DatagramBytes: 4111})
	if _, err := dec.Input(wire); err != nil {
		t.Fatal(err)
	}
	if dec.Stats().LastWork < 4*MaxVectorBytes {
		t.Fatalf("source validation/copy work missing: %+v", dec.Stats())
	}
	if _, err := dec.Input(wire); err != nil {
		t.Fatal(err)
	}
	if dec.Stats().LastWork < 2*MaxVectorBytes || dec.Stats().Duplicates != 1 {
		t.Fatalf("duplicate padding/equality work missing: %+v", dec.Stats())
	}
	// A short admitted vector can later be presented in zero-extended form.
	// Budget the comparison separately from validation, even though it is equal.
	limited, _ = NewDecoder(Config{DatagramBytes: 4111, WorkLimit: 5000})
	if _, err := limited.Input(sourceWire(t, 0, symbol(nil, 0, 1))); err != nil {
		t.Fatal(err)
	}
	extended := append(symbol(nil, 0, 1), make([]byte, 3000-SymbolHeader)...)
	if out, err := limited.Input(sourceWire(t, 0, extended)); err != ErrBudget || len(out.Frames) != 0 || limited.failed != ErrBudget {
		t.Fatalf("comparison exceeded budget: %+v %v", out, err)
	}
}

func TestInferredMissingFragmentLoss(t *testing.T) {
	for _, first := range []uint32{0, math.MaxUint32 - 1} {
		dec, _ := NewDecoder(Config{})
		if out, err := dec.Input(sourceWire(t, first+1, symbol([]byte("tail"), 1, 2))); err != nil || len(out.Frames) != 0 {
			t.Fatalf("tail setup: %+v %v", out, err)
		}
		out, err := dec.Input(sourceWire(t, first+DecoderWidth, packedVector([]byte("new"))))
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Lost) != 1 || out.Lost[0] != first || dec.Stats().Lost != 1 || dec.Stats().Groups != 0 {
			t.Fatalf("missing inferred prefix not reported: %+v %+v", out, dec.Stats())
		}
		out, err = dec.Input(sourceWire(t, first+DecoderWidth+1, packedVector([]byte("next"))))
		if err != nil || len(out.Lost) != 0 || dec.Stats().Lost != 1 {
			t.Fatalf("already reported loss or known tail counted again: %+v %v", out, err)
		}
	}
}
