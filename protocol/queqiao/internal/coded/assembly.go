package coded

import "encoding/binary"

type assembly struct {
	count int
	parts map[int][]byte
	bytes int
}

func (d *Decoder) dropGroup(first uint32) {
	g := d.groups[first]
	if g == nil {
		return
	}
	d.fragments -= len(g.parts)
	d.assemblyBytes -= g.bytes
	delete(d.groups, first)
}
func (d *Decoder) appendFrame(frame []byte, out *Result) error {
	if len(frame) > MaxFrameBytes || len(out.Frames) >= MaxOutputFrames {
		return ErrBudget
	}
	if out.outputBytes+len(frame) > MaxOutputBytes {
		return ErrBudget
	}
	out.outputBytes += len(frame)
	if err := d.spend(len(frame) + 1); err != nil {
		return err
	}
	out.Frames = append(out.Frames, append([]byte(nil), frame...))
	return nil
}
func (d *Decoder) assemble(id uint32, vector []byte, out *Result) error {
	payload, index, count, err := parseSymbolWithBudget(vector, d.spend)
	if err != nil {
		return err
	}
	first := id - uint32(index)
	if int32(first-d.low) < 0 {
		return nil
	}
	// A received tail fragment identifies the existence of the missing
	// prefix inside this window, even when it predates the first received ESI.
	if int32(first-d.origin) < 0 {
		d.origin = first
	}
	if err = d.spend(len(d.groups) + count); err != nil {
		return err
	}
	for begin, g := range d.groups {
		if begin == first {
			if g.count != count {
				return ErrConflict
			}
			continue
		}
		diff := int32(first - begin)
		if diff >= 0 && diff < int32(g.count) || diff < 0 && -diff < int32(count) {
			return ErrConflict
		}
	}
	// Already known symbols inside this interval must describe the same frame.
	for i := 0; i < count; i++ {
		esi := first + uint32(i)
		v := d.known[esi%DecoderWidth]
		if v != nil && v.id == esi {
			if len(v.vector) < SymbolHeader || int(binary.BigEndian.Uint16(v.vector[2:])) != i || int(binary.BigEndian.Uint16(v.vector[4:])) != count {
				return ErrConflict
			}
		}
	}
	if count == 1 {
		for len(payload) >= 4 {
			n := uint64(binary.BigEndian.Uint32(payload))
			payload = payload[4:]
			// Frozen vectors intentionally include incomplete packed frames. They
			// produce no partial frame; lengths are compared before converting to int.
			if n > uint64(len(payload)) {
				break
			}
			if n > MaxFrameBytes {
				return ErrBudget
			}
			if err = d.appendFrame(payload[:int(n)], out); err != nil {
				return err
			}
			payload = payload[int(n):]
		}
		return nil
	}
	g := d.groups[first]
	if g == nil {
		if len(d.groups) >= DecoderWidth {
			return ErrBudget
		}
		g = &assembly{count: count, parts: make(map[int][]byte)}
		d.groups[first] = g
	}
	if _, exists := g.parts[index]; exists {
		return ErrConflict
	}
	if d.fragments >= DecoderWidth || g.bytes+len(payload) > MaxFrameBytes || d.assemblyBytes+len(payload) > MaxOutputBytes {
		return ErrBudget
	}
	// Vectors are immutable owned decoder buffers, so retain a view, not a
	// second payload copy. Both the assembly and source window have fixed bounds.
	g.parts[index] = payload
	g.bytes += len(payload)
	d.fragments++
	d.assemblyBytes += len(payload)
	if len(g.parts) != g.count {
		return nil
	}
	if err = d.spend(g.bytes); err != nil {
		return err
	}
	frame := make([]byte, 0, g.bytes)
	for i := 0; i < g.count; i++ {
		frame = append(frame, g.parts[i]...)
	}
	d.dropGroup(first)
	return d.appendFrame(frame, out)
}
