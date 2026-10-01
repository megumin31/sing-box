//go:build with_quic

package queqiao

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/quic-go/qlog"
)

func drainSent(d *quicDrain, number int, start, end int64) {
	d.RecordEvent(qlog.PacketSent{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT, PacketNumber: qlog.PacketNumber(number)}, Frames: []qlog.Frame{{Frame: &qlog.StreamFrame{StreamID: 0, Offset: start, Length: end - start}}}})
}
func drainACK(d *quicDrain, low, high int) {
	d.RecordEvent(qlog.PacketReceived{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT}, Frames: []qlog.Frame{{Frame: &qlog.AckFrame{AckRanges: []qlog.AckRange{{Smallest: qlog.PacketNumber(low), Largest: qlog.PacketNumber(high)}}}}}})
}
func TestQUICDrainLossAndReordering(t *testing.T) {
	d := newQUICDrain()
	d.register(0)
	drainSent(d, 1, 0, 10)
	drainSent(d, 2, 10, 20)
	drainSent(d, 3, 20, 30)
	drainACK(d, 2, 3)
	if d.streams[0].acked != 0 {
		t.Fatal("acknowledged past a gap")
	}
	d.RecordEvent(qlog.PacketLost{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT, PacketNumber: 1}})
	// The original lost packet can arrive before its retransmission is sent.
	drainACK(d, 1, 1)
	if d.streams[0].acked != 30 || len(d.packets) != 0 || len(d.streams[0].spans) != 0 {
		t.Fatalf("late ACK: %d packets=%d spans=%d", d.streams[0].acked, len(d.packets), len(d.streams[0].spans))
	}
	drainSent(d, 4, 30, 40)
	drainSent(d, 5, 30, 40)
	drainACK(d, 5, 5)
	if d.streams[0].acked != 40 || len(d.packets) != 0 || d.records != 0 {
		t.Fatal("retransmission metadata retained")
	}
	if err := d.wait(context.Background(), 0, 40, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := d.wait(context.Background(), 0, 41, time.Millisecond); err == nil {
		t.Fatal("drain completed before byte delivery")
	}
}
func TestQUICDrainBoundAndCancellation(t *testing.T) {
	d := newQUICDrain()
	d.register(0)
	for i := 0; i <= maxDrainRecords; i++ {
		drainSent(d, i, int64(i), int64(i+1))
	}
	if !d.failed || len(d.packets) != 0 || len(d.streams[0].spans) != 0 {
		t.Fatal("metadata bound not enforced")
	}
	if err := d.wait(context.Background(), 0, 1, time.Second); err == nil {
		t.Fatal("overflow drain succeeded")
	}
	d = newQUICDrain()
	d.register(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.wait(ctx, 0, 1, time.Second); err == nil {
		t.Fatal("canceled drain succeeded")
	}
}

func TestQUICDrainStreamOwnership(t *testing.T) {
	d := newQUICDrain()
	d.register(0)
	d.register(4)
	d.RecordEvent(qlog.PacketSent{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT, PacketNumber: 1}, Frames: []qlog.Frame{
		{Frame: &qlog.StreamFrame{StreamID: 0, Offset: 0, Length: 10}},
		{Frame: &qlog.StreamFrame{StreamID: 4, Offset: 10, Length: 10}},
	}})
	drainACK(d, 1, 1)
	if d.streams[0].acked != 10 || d.streams[4].acked != 0 {
		t.Fatal("ACK crossed stream ownership")
	}
	d.unregister(0)
	if err := d.wait(context.Background(), 4, 20, time.Millisecond); err == nil {
		t.Fatal("other stream filled gap")
	}
	d.RecordEvent(qlog.PacketSent{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT, PacketNumber: 2}, Frames: []qlog.Frame{{Frame: &qlog.StreamFrame{StreamID: 4, Offset: 0, Length: 10}}}})
	drainACK(d, 2, 2)
	if err := d.wait(context.Background(), 4, 20, time.Second); err != nil {
		t.Fatal(err)
	}
	d.unregister(4)
	if len(d.streams) != 0 || len(d.packets) != 0 || d.records != 0 {
		t.Fatal("closed stream metadata retained")
	}
	// Late retransmissions/ACKs after release must not recreate tombstones.
	drainSent(d, 3, 0, 10)
	drainACK(d, 3, 3)
	if len(d.streams) != 0 || len(d.packets) != 0 {
		t.Fatal("late packet resurrected released stream")
	}
}
