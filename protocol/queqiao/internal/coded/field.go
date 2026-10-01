package coded

// Multiplication is polynomial reduction by x^8+x^4+x^3+x^2+1. Build the
// bounded table from the bit operation, independently of logarithm tables.
var products = func() (table [256][256]byte) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			x, y, value := uint16(a), uint16(b), uint16(0)
			for y != 0 {
				if y&1 != 0 {
					value ^= x
				}
				y >>= 1
				x <<= 1
				if x&256 != 0 {
					x ^= 0x11d
				}
			}
			table[a][b] = byte(value)
		}
	}
	return
}()

func inverse(a byte) byte {
	result := byte(1)
	for power := 254; power != 0; power >>= 1 {
		if power&1 != 0 {
			result = products[result][a]
		}
		a = products[a][a]
	}
	return result
}
func coefficient(rid uint32, index int) byte {
	x := rid*2654435761 + uint32(index)*2246822519
	x ^= x >> 15
	x *= 2654435761
	x ^= x >> 13
	x *= 2246822519
	x ^= x >> 16
	return byte(x%255) + 1
}
func Coefficients(rid uint32, count int) ([]byte, error) {
	if count < 1 || count > MaxRepairSpan {
		return nil, ErrDatagram
	}
	b := make([]byte, count)
	for i := range b {
		b[i] = coefficient(rid, i)
	}
	return b, nil
}

// RepairVector combines exactly the supplied consecutive source vectors. The
// caller supplies First separately when marshaling; short vectors extend by 0.
func RepairVector(rid uint32, vectors [][]byte) ([]byte, error) {
	if len(vectors) < 1 || len(vectors) > MaxRepairSpan {
		return nil, ErrDatagram
	}
	width := 0
	for _, v := range vectors {
		if len(v) > MaxVectorBytes {
			return nil, ErrBudget
		}
		width = max(width, len(v))
	}
	out := make([]byte, width)
	for i, v := range vectors {
		table := &products[coefficient(rid, i)]
		for j, b := range v {
			out[j] ^= table[b]
		}
	}
	return out, nil
}
