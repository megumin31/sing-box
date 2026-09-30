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
	drainSent(d, 1, 0, 10)
	drainSent(d, 2, 10, 20)
	drainSent(d, 3, 20, 30)
	drainACK(d, 2, 3)
	if d.acked != 0 {
		t.Fatal("acknowledged past a gap")
	}
	d.RecordEvent(qlog.PacketLost{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT, PacketNumber: 1}})
	// The original lost packet can arrive before its retransmission is sent.
	drainACK(d, 1, 1)
	if d.acked != 30 || len(d.packets) != 0 || len(d.spans) != 0 {
		t.Fatalf("late ACK: %d packets=%d spans=%d", d.acked, len(d.packets), len(d.spans))
	}
	drainSent(d, 4, 30, 40)
	drainSent(d, 5, 30, 40)
	drainACK(d, 5, 5)
	if d.acked != 40 || len(d.packets) != 0 || d.records != 0 {
		t.Fatal("retransmission metadata retained")
	}
	if err := d.wait(context.Background(), 40, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := d.wait(context.Background(), 41, time.Millisecond); err == nil {
		t.Fatal("drain completed before byte delivery")
	}
}
func TestQUICDrainBoundAndCancellation(t *testing.T) {
	d := newQUICDrain()
	for i := 0; i <= maxDrainRecords; i++ {
		drainSent(d, i, int64(i), int64(i+1))
	}
	if !d.failed || len(d.packets) != 0 || len(d.spans) != 0 {
		t.Fatal("metadata bound not enforced")
	}
	if err := d.wait(context.Background(), 1, time.Second); err == nil {
		t.Fatal("overflow drain succeeded")
	}
	d = newQUICDrain()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.wait(ctx, 1, time.Second); err == nil {
		t.Fatal("canceled drain succeeded")
	}
}
