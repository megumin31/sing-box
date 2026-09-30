package queqiao

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func packetPair(t *testing.T) (*packetConn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	p := newPacketConn(a, [16]byte{1}, 1, nil)
	p.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { b.Close(); p.Close() })
	return p, b
}

func TestFrozenUDPPackets(t *testing.T) {
	raw, err := os.ReadFile("testdata/protocol1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	type vector struct {
		Name, Destination string
		PayloadHex        string `json:"payload_hex"`
		Hex               string
	}
	var v struct {
		UDP struct {
			Packets []vector
			Reject  []vector `json:"reject_packets"`
		}
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, p := range v.UDP.Packets {
		t.Run(p.Name, func(t *testing.T) {
			payload, _ := hex.DecodeString(p.PayloadHex)
			expected, _ := hex.DecodeString(p.Hex)
			encoded, err := encodePacket(p.Destination, payload)
			if err != nil || !bytes.Equal(encoded, expected) {
				t.Fatalf("encode mismatch %x: %v", encoded, err)
			}
			destination, decoded, err := decodePacket(encoded)
			if err != nil || destination != p.Destination || !bytes.Equal(decoded, payload) {
				t.Fatal("decode mismatch", err)
			}
		})
	}
	for _, p := range v.UDP.Reject {
		t.Run(p.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(p.Hex)
			if _, _, err := decodePacket(raw); err == nil {
				t.Fatal("accepted invalid PACKET")
			}
		})
	}
}

func TestPacketBoundaries(t *testing.T) {
	// 249 host bytes + ':65535' exactly fills the destination bound.
	destination := strings.Repeat("a", 249) + ":65535"
	encoded, err := encodePacket(destination, make([]byte, maxUDPDatagram))
	if err != nil || len(encoded) != 65764 {
		t.Fatalf("maximum packet: %d %v", len(encoded), err)
	}
	if _, data, err := decodePacket(encoded); err != nil || len(data) != maxUDPDatagram {
		t.Fatal("maximum decode", err)
	}
	if _, err = encodePacket(destination, make([]byte, maxUDPDatagram+1)); err == nil {
		t.Fatal("oversized UDP accepted")
	}
	if _, err = encodePacket("a"+destination, nil); err == nil {
		t.Fatal("oversized destination accepted")
	}
	if _, _, err = decodePacket(append(encoded, 0)); err == nil {
		t.Fatal("oversized wire UDP accepted")
	}
}

func TestPacketReplayWindow(t *testing.T) {
	var w packetWindow
	for _, test := range []struct {
		seq    uint64
		accept bool
	}{{10, true}, {12, true}, {11, true}, {11, false}, {10, false}, {9, true}, {80, true}, {16, false}, {17, true}, {17, false}, {math.MaxUint64, true}, {math.MaxUint64 - 1, true}, {0, false}} {
		if got := w.accept(test.seq); got != test.accept {
			t.Fatalf("sequence %d: %v", test.seq, got)
		}
	}
}

func TestPacketReadReplayAndBoundedQueue(t *testing.T) {
	p, peer := packetPair(t)
	done := make(chan error, 1)
	go func() {
		for _, seq := range []uint64{2, 0, 1, 1, 100, 0} {
			payload, _ := encodePacket("127.0.0.1:53", []byte{byte(seq)})
			if err := sendPeer(peer, frame{typ: typePacket, sequence: seq, payload: payload}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for _, want := range []byte{2, 0, 1, 100} {
		var b [1]byte
		n, source, err := p.ReadFrom(b[:])
		if err != nil || n != 1 || b[0] != want || source.String() != "127.0.0.1:53" {
			t.Fatalf("packet %d: %d %v %v", want, n, source, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	p.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, _, err := p.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("duplicate delivered: %v", err)
	}
	p.SetReadDeadline(time.Now().Add(time.Second))
	for i := uint64(101); i < 301; i++ {
		payload, _ := encodePacket("127.0.0.1:53", []byte{byte(i)})
		if err := sendPeer(peer, frame{typ: typePacket, sequence: i, payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	// A final control frame proves the preceding packet stream was consumed even
	// though the application queue is full; overflow cannot block dissociation.
	go func() {
		sendPeer(peer, frame{typ: typeClose, flags: flagFIN})
		ack, err := readFrame(peer)
		if err == nil && (ack.typ != typeACK || ack.flags != flagACKFinal || ack.sequence != 0) {
			err = errors.New("bad UDP final ACK")
		}
		done <- err
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	p.wire.mu.Lock()
	queued := len(p.queue)
	p.wire.mu.Unlock()
	if queued != maxQueuedPackets {
		t.Fatalf("queue bound=%d", queued)
	}
}

func TestPacketCloseHandshake(t *testing.T) {
	p, peer := packetPair(t)
	done := make(chan error, 1)
	go func() {
		f, err := readFrame(peer)
		if err == nil && (f.typ != typeClose || f.flags != flagFIN || f.sequence != 0 || len(f.payload) != 0) {
			err = errors.New("bad UDP CLOSE")
		}
		if err == nil {
			err = sendPeer(peer, frame{typ: typeACK, flags: flagACKFinal})
		}
		done <- err
	}()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	p.wire.mu.Lock()
	acked := p.closeAcknowledged
	p.wire.mu.Unlock()
	if !acked {
		t.Fatal("CLOSE ACK missing")
	}
}

func TestPacketBlockedWriteAndConcurrentClose(t *testing.T) {
	p, _ := packetPair(t)
	done := make(chan error, 1)
	go func() {
		_, err := p.WriteTo([]byte("blocked"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
		done <- err
	}()
	p.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("write deadline did not fire")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); p.SetDeadline(time.Now()); p.Close() }()
	}
	wg.Wait()
}

func TestInvalidPacketState(t *testing.T) {
	packet, _ := encodePacket("localhost:53", []byte("x"))
	numeric, _ := encodePacket("127.0.0.1:53", nil)
	for _, f := range []frame{{typ: typePacket, payload: packet}, {typ: typePacket, flags: flagFIN, payload: numeric}, {typ: typePacket, payload: []byte{0}}, {typ: typeData}, {typ: typeACK, flags: flagACKFinal}, {typ: typeClose, flags: flagFIN | flagAbort}, {typ: typeClose, flags: flagFIN, sequence: 1}} {
		p, peer := packetPair(t)
		go sendPeer(peer, f)
		_, _, err := p.ReadFrom(make([]byte, 1))
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("invalid UDP state not rejected", err)
		}
	}
}

func FuzzDecodePacket(f *testing.F) {
	seed, _ := encodePacket("127.0.0.1:53", []byte("seed"))
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		address, payload, err := decodePacket(b)
		if err == nil {
			encoded, err := encodePacket(address, payload)
			if err != nil || len(encoded) > 65764 {
				t.Fatal("unbounded packet", err)
			}
			if _, _, err = decodePacket(encoded); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestPacketDeadlineAppliesToQueuedDatagram(t *testing.T) {
	p, peer := packetPair(t)
	encoded, _ := encodePacket("127.0.0.1:53", []byte("queued"))
	if err := sendPeer(peer, frame{typ: typePacket, payload: encoded}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		p.wire.mu.Lock()
		ready := len(p.queue) > 0
		p.wire.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("datagram not queued")
		}
		time.Sleep(time.Millisecond)
	}
	p.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := p.ReadFrom(make([]byte, 10)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("queued deadline: %v", err)
	}
	p.SetReadDeadline(time.Time{})
	buffer := make([]byte, 10)
	n, _, err := p.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "queued" {
		t.Fatalf("deadline consumed packet: %q %v", buffer[:n], err)
	}
}
