// Package queqiao implements reliable TCP and basic UDP flows in Queqiao protocol 1.
// It does not import or wrap the official Queqiao client.
package queqiao

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	headerSize          = 46
	maxPayload          = 128 * 1024
	dataALPN            = "queqiao/1"
	typeOpen     byte   = 1
	typeOpenOK   byte   = 2
	typeJoin     byte   = 3
	typeData     byte   = 4
	typeACK      byte   = 5
	typeClose    byte   = 6
	typeReset    byte   = 7
	flagFIN      uint16 = 1
	flagACKFinal uint16 = 2
	flagACKUp    uint16 = 4
	flagACKDown  uint16 = 8
	flagAbort    uint16 = 16
	flagReserve  uint16 = 32
	flagRanges   uint16 = 128
)

type frame struct {
	typ            byte
	flags          uint16
	session        [16]byte
	flow, sequence uint64
	class          byte
	payload        []byte
}

type versionError struct{ peer byte }

func (e versionError) Error() string {
	return fmt.Sprintf("queqiao: unsupported wire version %d (expected 1)", e.peer)
}

func validateHeader(b []byte) error {
	if b[0] != 'W' || b[1] != 'O' {
		return fmt.Errorf("queqiao: invalid frame magic")
	}
	if b[2] != 1 {
		return versionError{b[2]}
	}
	if b[3] < 1 || b[3] > 9 || b[42] > 2 || b[43]|b[44]|b[45] != 0 {
		return fmt.Errorf("queqiao: invalid frame header")
	}
	flags := binary.BigEndian.Uint16(b[4:6])
	if flags & ^uint16(191) != 0 || flags&flagReserve != 0 && b[3] != typeOpen && b[3] != typeJoin || flags&flagRanges != 0 && b[3] != typeACK {
		return fmt.Errorf("queqiao: invalid frame flags")
	}
	if binary.BigEndian.Uint32(b[38:42]) > maxPayload {
		return fmt.Errorf("queqiao: frame exceeds 128 KiB protocol limit")
	}
	return nil
}

func readFrame(r io.Reader) (frame, error) {
	var b [headerSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return frame{}, err
	}
	if err := validateHeader(b[:]); err != nil {
		return frame{}, protocolError{err}
	}
	f := frame{typ: b[3], flags: binary.BigEndian.Uint16(b[4:6]), flow: binary.BigEndian.Uint64(b[22:30]), sequence: binary.BigEndian.Uint64(b[30:38]), class: b[42]}
	copy(f.session[:], b[6:22])
	f.payload = make([]byte, int(binary.BigEndian.Uint32(b[38:42])))
	_, err := io.ReadFull(r, f.payload)
	return f, err
}

func writeFrame(w io.Writer, f frame) error {
	if len(f.payload) > maxPayload {
		return fmt.Errorf("queqiao: frame exceeds 128 KiB protocol limit")
	}
	b := make([]byte, headerSize+len(f.payload))
	b[0], b[1], b[2], b[3] = 'W', 'O', 1, f.typ
	binary.BigEndian.PutUint16(b[4:6], f.flags)
	copy(b[6:22], f.session[:])
	binary.BigEndian.PutUint64(b[22:30], f.flow)
	binary.BigEndian.PutUint64(b[30:38], f.sequence)
	binary.BigEndian.PutUint32(b[38:42], uint32(len(f.payload)))
	b[42] = f.class
	if err := validateHeader(b[:headerSize]); err != nil {
		return err
	}
	copy(b[headerSize:], f.payload)
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// Selective ranges are validated, but only cumulative ACKs release replay data.
func validateACK(f frame, sent uint64, final bool) error {
	if f.flags&flagACKUp == 0 || f.flags & ^uint16(flagACKUp|flagACKFinal|flagRanges) != 0 || f.sequence > sent {
		return fmt.Errorf("queqiao: invalid upstream ACK")
	}
	if f.flags&flagACKFinal != 0 {
		if !final || f.sequence != sent || f.flags&flagRanges != 0 || len(f.payload) != 0 {
			return fmt.Errorf("queqiao: invalid final ACK")
		}
		return nil
	}
	if f.flags&flagRanges == 0 && len(f.payload) != 0 || len(f.payload) > 256 || len(f.payload)%16 != 0 {
		return fmt.Errorf("queqiao: invalid ACK range payload")
	}
	end := f.sequence
	for i := 0; i < len(f.payload); i += 16 {
		start, next := binary.BigEndian.Uint64(f.payload[i:]), binary.BigEndian.Uint64(f.payload[i+8:])
		if start < end || start >= next || next > sent {
			return fmt.Errorf("queqiao: invalid ACK range")
		}
		end = next
	}
	return nil
}

func resetError(f frame) error {
	// Peer-supplied text is intentionally not logged: it may contain private targets.
	if f.flags != 0 || f.sequence != 0 || len(f.payload) < 1 || len(f.payload) > 257 || f.payload[0] < 1 || f.payload[0] > 5 {
		return protocolError{fmt.Errorf("queqiao: malformed RESET")}
	}
	return gatewayResetError{code: f.payload[0]}
}

type protocolError struct{ error }

func (e protocolError) Unwrap() error { return e.error }

type gatewayResetError struct{ code byte }

func (e gatewayResetError) Error() string {
	return fmt.Sprintf("queqiao: gateway reset (code %d)", e.code)
}
