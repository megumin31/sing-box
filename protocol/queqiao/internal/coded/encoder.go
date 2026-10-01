package coded

import "encoding/binary"

type Encoder struct {
	cfg                                  Config
	nextSequence, nextSource, nextRepair uint32
	held                                 int
	vectors                              [MaxRepairSpan][]byte
}

func NewEncoder(cfg Config) (*Encoder, error) {
	c, err := cfg.normalized()
	if err != nil {
		return nil, err
	}
	return &Encoder{cfg: c}, nil
}
func (e *Encoder) payloadBytes() int { return e.cfg.DatagramBytes - RepairHeader - SymbolHeader }
func (e *Encoder) source(vector []byte) []byte {
	esi := e.nextSource
	e.nextSource++
	e.vectors[esi%MaxRepairSpan] = append([]byte(nil), vector...)
	e.held = min(e.held+1, MaxRepairSpan)
	b, _ := (Datagram{Sequence: e.nextSequence, Kind: SourceKind, ID: esi, Vector: vector}).Marshal()
	e.nextSequence++
	return b
}

// EncodePacked emits one symbol. There is no implicit queue or automatic repair
// policy: callers choose when to request parity from the bounded encoder window.
func (e *Encoder) EncodePacked(frames ...[]byte) ([]byte, error) {
	n := 0
	for _, f := range frames {
		if len(f) > MaxFrameBytes || len(f)+4 > e.payloadBytes()-n {
			return nil, ErrBudget
		}
		n += 4 + len(f)
	}
	p := make([]byte, 0, n)
	for _, f := range frames {
		p = binary.BigEndian.AppendUint32(p, uint32(len(f)))
		p = append(p, f...)
	}
	return e.source(symbol(p, 0, 1)), nil
}
func (e *Encoder) EncodeFrame(frame []byte) ([][]byte, error) {
	if len(frame) > MaxFrameBytes {
		return nil, ErrBudget
	}
	size := e.payloadBytes()
	if len(frame)+4 <= size {
		d, err := e.EncodePacked(frame)
		if err != nil {
			return nil, err
		}
		return [][]byte{d}, nil
	}
	count := (len(frame) + size - 1) / size
	// count=1 means length-prefixed packing on the wire. A frame that fits
	// raw but not with its four-byte prefix therefore needs two fragments.
	if count == 1 {
		count = 2
		size = (len(frame) + 1) / 2
	}
	if count > MaxFragments {
		return nil, ErrBudget
	}
	out := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		end := min((i+1)*size, len(frame))
		out = append(out, e.source(symbol(frame[i*size:end], i, count)))
	}
	return out, nil
}
func (e *Encoder) Repair(count int) ([]byte, error) {
	if count < 1 || count > MaxRepairSpan {
		return nil, ErrDatagram
	}
	if count > e.held {
		return nil, ErrBudget
	}
	first := e.nextSource - uint32(count)
	vectors := make([][]byte, count)
	for i := range vectors {
		vectors[i] = e.vectors[(first+uint32(i))%MaxRepairSpan]
	}
	vector, err := RepairVector(e.nextRepair, vectors)
	if err != nil {
		return nil, err
	}
	b, err := (Datagram{Sequence: e.nextSequence, Kind: RepairKind, ID: e.nextRepair, First: first, Count: count, Vector: vector}).Marshal()
	if err != nil {
		return nil, err
	}
	e.nextSequence++
	e.nextRepair++
	return b, nil
}
