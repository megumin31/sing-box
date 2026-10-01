package coded

import (
	"crypto/sha256"
	"math"
)

type Result struct {
	Frames      [][]byte
	Recovered   int
	Lost        []uint32
	outputBytes int
}
type Stats struct {
	Accepted, Malformed, RejectedSymbols, Duplicates, OutsideWindow, Recovered, Lost, Conflicts, BudgetFailures uint64
	Slots, Equations, Groups, Fragments, BufferedBytes, LastWork                                                int
}
type knownSymbol struct {
	id        uint32
	vector    []byte
	delivered bool
}

func (s *knownSymbol) pending() bool  { return !s.delivered }
func (s *knownSymbol) markDelivered() { s.delivered = true }

type equation struct {
	coefficients [DecoderWidth]byte
	data         []byte
	nonzero      int
}
type repairIdentity struct {
	seen      bool
	id, first uint32
	count     int
	digest    [32]byte
}

type Decoder struct {
	cfg                      Config
	started                  bool
	high, low, origin        uint32
	known                    [DecoderWidth]*knownSymbol
	rows                     [DecoderWidth]*equation
	repairs                  [DecoderWidth]repairIdentity
	groups                   map[uint32]*assembly
	fragments, assemblyBytes int
	work                     int
	failed                   error
	stats                    Stats
}

func NewDecoder(cfg Config) (*Decoder, error) {
	c, err := cfg.normalized()
	if err != nil {
		return nil, err
	}
	return &Decoder{cfg: c, work: c.WorkLimit, groups: make(map[uint32]*assembly)}, nil
}
func (d *Decoder) Stats() Stats {
	s := d.stats
	s.Slots = DecoderWidth
	s.Groups = len(d.groups)
	s.Fragments = d.fragments
	s.BufferedBytes = d.assemblyBytes
	s.LastWork = d.cfg.WorkLimit - d.work
	for _, v := range d.known {
		if v != nil {
			s.BufferedBytes += len(v.vector)
		}
	}
	for _, r := range d.rows {
		if r != nil {
			s.Equations++
			s.BufferedBytes += DecoderWidth + len(r.data)
		}
	}
	return s
}

// Reset discards the direction's state. Online callers must not reset silently
// and then present repeated frames as new application data.
func (d *Decoder) Reset() {
	cfg := d.cfg
	*d = Decoder{cfg: cfg, work: cfg.WorkLimit, groups: make(map[uint32]*assembly)}
}
func (d *Decoder) spend(n int) error {
	if n > d.work {
		return ErrBudget
	}
	d.work -= n
	return nil
}
func (d *Decoder) poison(err error) (Result, error) {
	if err == ErrBudget {
		d.stats.BudgetFailures++
	} else if err == ErrConflict {
		d.stats.Conflicts++
	} else {
		d.stats.RejectedSymbols++
	}
	d.failed = err
	d.known = [DecoderWidth]*knownSymbol{}
	d.rows = [DecoderWidth]*equation{}
	clear(d.groups)
	d.fragments, d.assemblyBytes = 0, 0
	return Result{}, err
}
func equalExtended(a, b []byte) bool {
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y byte
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return false
		}
	}
	return true
}

// Input performs a bounded amount of synchronous work. Invalid headers and
// spans never enter the window and never count as erased symbols. Conflicting
// equations or exhausted work budgets poison this instance until Reset; an
// error never returns partially decoded frames.
func (d *Decoder) Input(wire []byte) (Result, error) {
	d.work = d.cfg.WorkLimit
	if d.failed != nil {
		return Result{}, d.failed
	}
	packet, err := Parse(wire)
	if err != nil {
		if err == ErrBudget {
			d.stats.BudgetFailures++
		} else {
			d.stats.Malformed++
		}
		return Result{}, err
	}
	if len(wire) > d.cfg.DatagramBytes || len(packet.Vector) > d.cfg.DatagramBytes-RepairHeader {
		d.stats.BudgetFailures++
		return Result{}, ErrBudget
	}
	if packet.Kind == SourceKind {
		if _, _, _, err = parseSymbolWithBudget(packet.Vector, d.spend); err != nil {
			if err == ErrBudget {
				d.stats.BudgetFailures++
			} else {
				d.stats.RejectedSymbols++
			}
			return Result{}, err
		}
	} else if len(packet.Vector) == 0 {
		d.stats.Accepted++
		return Result{}, nil
	}
	var repairHash [32]byte
	if packet.Kind == RepairKind {
		if err = d.spend(len(packet.Vector)); err != nil {
			return d.poison(err)
		}
		repairHash = sha256.Sum256(packet.Vector)
		old := &d.repairs[packet.ID%DecoderWidth]
		if old.seen && old.id == packet.ID {
			if old.first != packet.First || old.count != packet.Count || old.digest != repairHash {
				return d.poison(ErrConflict)
			}
			d.stats.Duplicates++
			return Result{}, nil
		}
	}
	d.stats.Accepted++
	var out Result
	last := packet.ID
	if packet.Kind == RepairKind {
		last = packet.First + uint32(packet.Count-1)
	}
	admitted, err := d.advance(last, &out)
	if err != nil {
		if err == ErrBudget {
			return d.poison(err)
		}
		d.stats.Malformed++
		return Result{}, err
	}
	if !admitted {
		d.stats.OutsideWindow++
		return out, nil
	}
	first := packet.ID
	if packet.Kind == RepairKind {
		first = packet.First
	}
	if int32(first-d.low) < 0 {
		d.stats.OutsideWindow++
		return out, nil
	}
	if int32(first-d.origin) < 0 {
		d.origin = first
	}
	if packet.Kind == SourceKind {
		if v := d.known[packet.ID%DecoderWidth]; v != nil && v.id == packet.ID {
			if err = d.spend(max(len(v.vector), len(packet.Vector))); err != nil {
				return d.poison(err)
			}
			if !equalExtended(v.vector, packet.Vector) {
				return d.poison(ErrConflict)
			}
			d.stats.Duplicates++
			return out, nil
		}
	} else {
		d.repairs[packet.ID%DecoderWidth] = repairIdentity{seen: true, id: packet.ID, first: packet.First, count: packet.Count, digest: repairHash}
	}
	if err = d.spend(len(packet.Vector)); err != nil {
		return d.poison(err)
	}
	row := &equation{data: append([]byte(nil), packet.Vector...)}
	if packet.Kind == SourceKind {
		row.coefficients[packet.ID%DecoderWidth] = 1
		row.nonzero = 1
	} else {
		for i := 0; i < packet.Count; i++ {
			row.coefficients[(packet.First+uint32(i))%DecoderWidth] = coefficient(packet.ID, i)
		}
		row.nonzero = packet.Count
	}
	if err = d.insert(row); err != nil {
		return d.poison(err)
	}
	for i, row := range d.rows {
		if row == nil || row.nonzero != 1 {
			continue
		}
		// A reduced singleton is a source vector. Reject impossible recovered
		// headers before exposing any frames from this Input.
		if _, _, _, err = parseSymbolWithBudget(row.data, d.spend); err != nil {
			return d.poison(err)
		}
		id := d.low + uint32((i-int(d.low%DecoderWidth)+DecoderWidth)%DecoderWidth)
		d.known[i] = &knownSymbol{id: id, vector: row.data}
		d.rows[i] = nil
		if packet.Kind != SourceKind || id != packet.ID {
			out.Recovered++
			d.stats.Recovered++
		}
	}
	// Deliver newly known symbols once. Take a bounded snapshot so reassembly
	// errors cannot cause iteration over data introduced by a later Input.
	for _, v := range d.known {
		if v != nil && v.pending() {
			v.markDelivered()
			if err = d.assemble(v.id, v.vector, &out); err != nil {
				return d.poison(err)
			}
		}
	}
	return out, nil
}

func (d *Decoder) advance(id uint32, out *Result) (bool, error) {
	if !d.started {
		d.started = true
		d.high = id
		d.low = id - (DecoderWidth - 1)
		d.origin = id
		return true, nil
	}
	distance := int32(id - d.high)
	if distance == math.MinInt32 {
		return false, ErrSequence
	}
	if distance <= 0 {
		return int32(id-d.low) >= 0, nil
	}
	count := min(int(distance), DecoderWidth)
	if err := d.spend(count + DecoderWidth); err != nil {
		return false, err
	}
	for n := 0; n < count; n++ {
		leaving := d.low + uint32(n)
		i := leaving % DecoderWidth
		if d.known[i] == nil && int32(leaving-d.origin) >= 0 {
			out.Lost = append(out.Lost, leaving)
			d.stats.Lost++
		}
		d.known[i] = nil
	}
	if distance >= DecoderWidth {
		d.rows = [DecoderWidth]*equation{}
		d.repairs = [DecoderWidth]repairIdentity{}
	} else {
		for i, row := range d.rows {
			if row == nil {
				continue
			}
			if err := d.spend(count); err != nil {
				return false, err
			}
			for n := 0; n < count; n++ {
				if row.coefficients[(d.low+uint32(n))%DecoderWidth] != 0 {
					d.rows[i] = nil
					break
				}
			}
		}
	}
	d.high = id
	d.low = id - (DecoderWidth - 1)
	if distance >= DecoderWidth {
		d.origin = id
	} else if int32(d.origin-d.low) < 0 {
		d.origin = d.low
	}
	for first := range d.groups {
		if int32(first-d.low) < 0 {
			d.dropGroup(first)
		}
	}
	return true, nil
}
func (d *Decoder) addData(dst *[]byte, src []byte, factor byte) error {
	width := max(len(*dst), len(src))
	if err := d.spend(width); err != nil {
		return err
	}
	if len(*dst) < width {
		// A growing append may copy the old prefix and zero the new suffix.
		if err := d.spend(width); err != nil {
			return err
		}
		*dst = append(*dst, make([]byte, width-len(*dst))...)
	}
	table := &products[factor]
	for i, b := range src {
		(*dst)[i] ^= table[b]
	}
	return nil
}
func (d *Decoder) combine(dst, src *equation, factor byte) error {
	if err := d.spend(DecoderWidth); err != nil {
		return err
	}
	table := &products[factor]
	for i, b := range src.coefficients {
		old := dst.coefficients[i]
		next := old ^ table[b]
		if old == 0 && next != 0 {
			dst.nonzero++
		} else if old != 0 && next == 0 {
			dst.nonzero--
		}
		dst.coefficients[i] = next
	}
	return d.addData(&dst.data, src.data, factor)
}
func (d *Decoder) insert(row *equation) error {
	if err := d.spend(DecoderWidth); err != nil {
		return err
	}
	for i, c := range row.coefficients {
		if c != 0 && d.known[i] != nil {
			if err := d.addData(&row.data, d.known[i].vector, c); err != nil {
				return err
			}
			row.coefficients[i] = 0
			row.nonzero--
		}
	}
	// Eliminate every existing pivot before choosing a new one. A missing
	// earlier pivot does not mean the row is reduced against later pivots.
	for i, old := range d.rows {
		if old != nil && row.coefficients[i] != 0 {
			if err := d.combine(row, old, row.coefficients[i]); err != nil {
				return err
			}
		}
	}
	for i, c := range row.coefficients {
		if c == 0 {
			continue
		}
		if c != 1 {
			if err := d.spend(DecoderWidth + len(row.data)); err != nil {
				return err
			}
			table := &products[inverse(c)]
			for j, b := range row.coefficients {
				row.coefficients[j] = table[b]
			}
			for j, b := range row.data {
				row.data[j] = table[b]
			}
		}
		for _, old := range d.rows {
			if old != nil && old.coefficients[i] != 0 {
				if err := d.combine(old, row, old.coefficients[i]); err != nil {
					return err
				}
			}
		}
		d.rows[i] = row
		return nil
	}
	if err := d.spend(len(row.data)); err != nil {
		return err
	}
	for _, b := range row.data {
		if b != 0 {
			return ErrConflict
		}
	}
	d.stats.Duplicates++
	return nil
}
