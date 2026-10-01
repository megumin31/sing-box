// Package coded implements the offline Queqiao protocol-1 coded-datagram
// format. It has no carrier, timers, goroutines or connection integration.
// Decoder and Encoder belong to one caller; they are not concurrency-safe.
// Frames are opaque bytes: a future caller MUST authenticate the carrier and
// validate each reconstructed Queqiao frame before dispatching it.
package coded

import (
	"encoding/binary"
	"errors"
)

const (
	SourceKind       byte = 0
	RepairKind       byte = 1
	SourceHeader          = 9
	RepairHeader          = 15
	SymbolHeader          = 6
	MaxRepairSpan         = 256
	DecoderWidth          = 512
	MaxVectorBytes        = 4096 // local resource ceiling, not a protocol wire constant
	MaxFrameBytes         = 46 + 128<<10
	MaxFragments          = DecoderWidth
	MaxOutputFrames       = 4096
	MaxOutputBytes        = 4 << 20
	DefaultWorkLimit      = 16 << 20 // charged byte operations per Input
)

var (
	ErrDatagram = errors.New("coded: malformed datagram")
	ErrSymbol   = errors.New("coded: malformed source symbol")
	ErrConflict = errors.New("coded: inconsistent symbols or equations")
	ErrBudget   = errors.New("coded: resource or work budget exceeded")
	ErrSequence = errors.New("coded: ambiguous serial number distance")
	ErrConfig   = errors.New("coded: invalid local limits")
)

type Config struct {
	// DatagramBytes reserves room for the larger repair header on send. The
	// fixed 512-slot decoder window never grows in response to wire input.
	DatagramBytes int
	WorkLimit     int
}

func (c Config) normalized() (Config, error) {
	if c.DatagramBytes == 0 {
		c.DatagramBytes = 1200
	}
	if c.WorkLimit == 0 {
		c.WorkLimit = DefaultWorkLimit
	}
	if c.DatagramBytes < 26 || c.DatagramBytes > RepairHeader+MaxVectorBytes || c.WorkLimit < 1 || c.WorkLimit > 64<<20 {
		return c, ErrConfig
	}
	return c, nil
}

// Datagram.Vector borrows the Parse input; retain it only by making a copy.
type Datagram struct {
	Sequence uint32
	Kind     byte
	ID       uint32 // source ESI or repair RID
	First    uint32
	Count    int
	Vector   []byte
}

func Parse(b []byte) (Datagram, error) {
	if len(b) < SourceHeader {
		return Datagram{}, ErrDatagram
	}
	d := Datagram{Sequence: binary.BigEndian.Uint32(b), Kind: b[4], ID: binary.BigEndian.Uint32(b[5:])}
	switch d.Kind {
	case SourceKind:
		d.Vector = b[SourceHeader:]
	case RepairKind:
		if len(b) < RepairHeader {
			return Datagram{}, ErrDatagram
		}
		d.First = binary.BigEndian.Uint32(b[9:])
		d.Count = int(binary.BigEndian.Uint16(b[13:]))
		if d.Count < 1 || d.Count > MaxRepairSpan {
			return Datagram{}, ErrDatagram
		}
		d.Vector = b[RepairHeader:]
	default:
		return Datagram{}, ErrDatagram
	}
	if len(d.Vector) > MaxVectorBytes {
		return Datagram{}, ErrBudget
	}
	return d, nil
}
func (d Datagram) Marshal() ([]byte, error) {
	n := SourceHeader
	if len(d.Vector) > MaxVectorBytes {
		return nil, ErrBudget
	}
	switch d.Kind {
	case SourceKind:
	case RepairKind:
		if d.Count < 1 || d.Count > MaxRepairSpan {
			return nil, ErrDatagram
		}
		n = RepairHeader
	default:
		return nil, ErrDatagram
	}
	b := make([]byte, n+len(d.Vector))
	binary.BigEndian.PutUint32(b, d.Sequence)
	b[4] = d.Kind
	binary.BigEndian.PutUint32(b[5:], d.ID)
	if d.Kind == RepairKind {
		binary.BigEndian.PutUint32(b[9:], d.First)
		binary.BigEndian.PutUint16(b[13:], uint16(d.Count))
	}
	copy(b[n:], d.Vector)
	return b, nil
}
func symbol(payload []byte, index, count int) []byte {
	b := make([]byte, SymbolHeader+len(payload))
	binary.BigEndian.PutUint16(b, uint16(len(payload)))
	binary.BigEndian.PutUint16(b[2:], uint16(index))
	binary.BigEndian.PutUint16(b[4:], uint16(count))
	copy(b[SymbolHeader:], payload)
	return b
}
func parseSymbol(b []byte) (payload []byte, index, count int, err error) {
	return parseSymbolWithBudget(b, nil)
}

func parseSymbolWithBudget(b []byte, spend func(int) error) (payload []byte, index, count int, err error) {
	if len(b) < SymbolHeader {
		return nil, 0, 0, ErrSymbol
	}
	n := int(binary.BigEndian.Uint16(b))
	index = int(binary.BigEndian.Uint16(b[2:]))
	count = int(binary.BigEndian.Uint16(b[4:]))
	if count == 0 || index >= count || n > len(b)-SymbolHeader {
		return nil, 0, 0, ErrSymbol
	}
	if count > MaxFragments {
		return nil, 0, 0, ErrBudget
	}
	// Header validation is fixed work; charge the complete vector before any
	// length-dependent padding scan (also conservatively accounts for payload).
	if spend != nil {
		if err = spend(len(b)); err != nil {
			return nil, 0, 0, err
		}
	}
	// The only extra bytes reconstruction may introduce are zero extension.
	for _, v := range b[SymbolHeader+n:] {
		if v != 0 {
			return nil, 0, 0, ErrSymbol
		}
	}
	return b[SymbolHeader : SymbolHeader+n], index, count, nil
}
