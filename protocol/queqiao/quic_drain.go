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

type byteSpan struct{ start, end int64 }

// QUIC Stream.Write only queues bytes. Closing the dedicated connection right
// after its last ACK_FINAL can discard that frame before it reaches the peer.
// This bounded, in-memory trace observes transport ACKs (no payloads, logging or
// files) so teardown waits until every queued stream byte has been delivered.
// It uses only the existing quic-go public trace API, not a private/forked API.
type quicDrain struct {
	mu      sync.Mutex
	packets map[qlog.PacketNumber][]byteSpan
	spans   []byteSpan
	acked   int64
	records int
	failed  bool
	changed chan struct{}
}

func newQUICDrain() *quicDrain {
	return &quicDrain{packets: make(map[qlog.PacketNumber][]byteSpan), changed: make(chan struct{})}
}
func (d *quicDrain) AddProducer() qlogwriter.Recorder { return d }
func (d *quicDrain) SupportsSchemas(string) bool      { return true }
func (d *quicDrain) Close() error                     { return nil }
func (d *quicDrain) notify()                          { close(d.changed); d.changed = make(chan struct{}) }
func (d *quicDrain) fail() {
	d.failed = true
	d.packets = nil
	d.spans = nil
	d.records = 0
	d.notify()
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
		var spans []byteSpan
		for _, f := range e.Frames {
			if s, ok := f.Frame.(*qlog.StreamFrame); ok && s.StreamID == 0 && s.Length > 0 && s.Offset+s.Length > d.acked {
				spans = append(spans, byteSpan{s.Offset, s.Offset + s.Length})
			}
		}
		if len(spans) > 0 {
			if len(d.packets) >= maxDrainRecords || d.records+len(spans) > maxDrainRecords {
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
			for number, spans := range d.packets {
				if !ack.AcksPacket(number) {
					continue
				}
				d.spans = append(d.spans, spans...)
				d.records -= len(spans)
				delete(d.packets, number)
				changed = true
			}
		}
		if changed {
			sort.Slice(d.spans, func(i, j int) bool { return d.spans[i].start < d.spans[j].start })
			merged := d.spans[:0]
			for _, span := range d.spans {
				if span.end <= d.acked {
					continue
				}
				if span.start <= d.acked {
					d.acked = span.end
					continue
				}
				n := len(merged)
				if n > 0 && span.start <= merged[n-1].end {
					merged[n-1].end = max(merged[n-1].end, span.end)
				} else {
					merged = append(merged, span)
				}
			}
			d.spans = merged
			// Keep declared-lost packets until their bytes are acknowledged:
			// a late original ACK can cancel retransmission. Prune covered
			// historical packets so loss never accumulates unbounded metadata.
			for number, spans := range d.packets {
				retained := spans[:0]
				for _, span := range spans {
					if span.end > d.acked {
						retained = append(retained, span)
					}
				}
				d.records -= len(spans) - len(retained)
				if len(retained) == 0 {
					delete(d.packets, number)
				} else {
					d.packets[number] = retained
				}
			}
			if len(d.spans) > maxDrainRecords {
				d.fail()
				return
			}
			d.notify()
		}
	}
}

func (d *quicDrain) wait(ctx context.Context, end int64, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		d.mu.Lock()
		acked, failed, ch := d.acked, d.failed, d.changed
		d.mu.Unlock()
		if acked >= end {
			return nil
		}
		if failed {
			return errors.New("queqiao: QUIC drain metadata limit exceeded")
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
