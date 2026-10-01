//go:build with_quic

package queqiao

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/sagernet/quic-go/qlog"
	"github.com/sagernet/quic-go/qlogwriter"
)

const maxDrainRecords = 4096
const maxDrainSpans = 65536

type byteSpan struct{ start, end int64 }
type streamSpan struct {
	id int64
	byteSpan
}
type streamDrain struct {
	acked int64
	spans []byteSpan
}

// Stream.Write queues bytes. This bounded in-memory trace observes transport
// ACKs before releasing a stream's pool reservation. It holds byte ranges only,
// never payloads, and uses quic-go's public trace API. ACK state belongs to the
// actual stream ID; a shared packet may advance several independent streams.
type quicDrain struct {
	mu      sync.Mutex
	packets map[qlog.PacketNumber][]streamSpan
	streams map[int64]*streamDrain
	records int
	failed  bool
	changed chan struct{}
}

func newQUICDrain() *quicDrain {
	return &quicDrain{packets: make(map[qlog.PacketNumber][]streamSpan), streams: make(map[int64]*streamDrain), changed: make(chan struct{})}
}
func (d *quicDrain) healthy() bool                    { d.mu.Lock(); defer d.mu.Unlock(); return !d.failed }
func (d *quicDrain) AddProducer() qlogwriter.Recorder { return d }
func (d *quicDrain) SupportsSchemas(string) bool      { return true }
func (d *quicDrain) Close() error                     { return nil }
func (d *quicDrain) notify()                          { close(d.changed); d.changed = make(chan struct{}) }
func (d *quicDrain) register(id int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.streams[id] = &streamDrain{}
}
func (d *quicDrain) unregister(id int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.streams, id)
	d.prune()
	d.notify()
}
func (d *quicDrain) fail() {
	d.failed = true
	d.packets = nil
	d.records = 0
	for _, s := range d.streams {
		s.spans = nil
	}
	d.notify()
}

// prune retains late original packets until their stream bytes are ACKed: a
// late original ACK can cancel a retransmission before it is ever sent.
func (d *quicDrain) prune() {
	for n, spans := range d.packets {
		retained := spans[:0]
		for _, span := range spans {
			if s := d.streams[span.id]; s != nil && span.end > s.acked {
				retained = append(retained, span)
			}
		}
		d.records -= len(spans) - len(retained)
		if len(retained) == 0 {
			delete(d.packets, n)
		} else {
			d.packets[n] = retained
		}
	}
}
func (d *quicDrain) RecordEvent(event qlogwriter.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed {
		return
	}
	switch e := event.(type) {
	case qlog.PacketSent:
		if e.Header.PacketType != qlog.PacketType1RTT {
			return
		}
		var spans []streamSpan
		for _, f := range e.Frames {
			if s, ok := f.Frame.(*qlog.StreamFrame); ok && s.Length > 0 {
				id := int64(s.StreamID)
				if state := d.streams[id]; state != nil && s.Offset+s.Length > state.acked {
					spans = append(spans, streamSpan{id, byteSpan{s.Offset, s.Offset + s.Length}})
				}
			}
		}
		if len(spans) > 0 {
			if len(d.packets) >= maxDrainRecords || d.records+len(spans) > maxDrainSpans {
				d.fail()
				return
			}
			d.records -= len(d.packets[e.Header.PacketNumber])
			d.packets[e.Header.PacketNumber] = spans
			d.records += len(spans)
		}
	case qlog.PacketReceived:
		if e.Header.PacketType != qlog.PacketType1RTT {
			return
		}
		changed := false
		for _, f := range e.Frames {
			ack, ok := f.Frame.(*qlog.AckFrame)
			if !ok || len(ack.AckRanges) == 0 {
				continue
			}
			for n, spans := range d.packets {
				if !ack.AcksPacket(n) {
					continue
				}
				for _, span := range spans {
					if s := d.streams[span.id]; s != nil {
						s.spans = append(s.spans, span.byteSpan)
					}
				}
				d.records -= len(spans)
				delete(d.packets, n)
				changed = true
			}
		}
		if changed {
			total := 0
			for _, s := range d.streams {
				sort.Slice(s.spans, func(i, j int) bool { return s.spans[i].start < s.spans[j].start })
				merged := s.spans[:0]
				for _, span := range s.spans {
					if span.end <= s.acked {
						continue
					}
					if span.start <= s.acked {
						s.acked = span.end
						continue
					}
					n := len(merged)
					if n > 0 && span.start <= merged[n-1].end {
						merged[n-1].end = max(merged[n-1].end, span.end)
					} else {
						merged = append(merged, span)
					}
				}
				s.spans = merged
				total += len(merged)
			}
			d.prune()
			if total > maxDrainSpans {
				d.fail()
				return
			}
			d.notify()
		}
	}
}
func (d *quicDrain) wait(ctx context.Context, id, end int64, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		d.mu.Lock()
		s, failed, ch := d.streams[id], d.failed, d.changed
		acked := int64(-1)
		if s != nil {
			acked = s.acked
		}
		d.mu.Unlock()
		if acked >= end {
			return nil
		}
		if failed {
			return errors.New("queqiao: QUIC drain metadata limit exceeded")
		}
		if acked < 0 {
			return errors.New("queqiao: QUIC drain stream is not registered")
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-timer.C:
			return errors.New("queqiao: QUIC final frame acknowledgement timeout")
		}
	}
}
