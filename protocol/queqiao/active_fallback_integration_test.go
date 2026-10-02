package queqiao

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// Runs only within the existing opt-in official gateway fixture. A single send
// per probe exposes a lost reply instead of concealing it behind an app retry.
func testOfficialUDPActiveFallback(t *testing.T, profile string) {
	a, err := NewOutbound(context.Background(), nil, nil, "active-udp", option.QueqiaoOutboundOptions{
		ProfilePath: profile, Transport: "quic", Network: "udp", UDPResume: true, QUICActiveFallback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
	sizes := []int{0, 1, 1200, 8192}
	if testLocalUDPSize(t, maxUDPDatagram) {
		sizes = append(sizes, maxUDPDatagram)
	}
	probe := newUDPProbe(t)
	raw, err := o.ListenPacket(context.Background(), M.ParseSocksaddr(probe.conn.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	p := raw.(*packetConn)
	defer p.Close()
	stage := "initial"
	exchange := func(payload []byte) {
		t.Helper()
		p.SetDeadline(time.Now().Add(3 * time.Second))
		if n, err := p.WriteTo(payload, probe.conn.LocalAddr()); err != nil || n != len(payload) {
			t.Fatalf("write: %d %v", n, err)
		}
		buffer := make([]byte, maxUDPDatagram)
		n, source, err := p.ReadFrom(buffer)
		if err != nil || !bytes.Equal(buffer[:n], payload) || source.String() != probe.conn.LocalAddr().String() {
			t.Fatalf("single-send echo stage=%s size=%d: %d %v", stage, len(payload), n, err)
		}
	}
	exchange([]byte("before handoff"))
	endpoint := probe.onlySource(t)
	if _, tcp := p.wire.currentCarrier().(*tls.Conn); tcp {
		t.Fatal("initial association did not use QUIC")
	}
	for attempt := 0; attempt < 2; attempt++ {
		stage = "QUIC-to-TCP"
		if attempt > 0 {
			stage = "TCP-to-TCP"
		}
		p.wire.mu.Lock()
		session, flow, token := p.wire.session, p.wire.flow, p.token
		before := p.wire.recoveryAttempts
		p.wire.mu.Unlock()
		abortCarrier(p.wire.currentCarrier())
		waitUDPReplacement(t, p, before)
		if _, tcp := p.wire.currentCarrier().(*tls.Conn); !tcp {
			t.Fatal("handoff did not remain TLS/TCP")
		}
		p.wire.mu.Lock()
		rotated := p.wire.session != session && p.wire.flow != flow && p.token != token
		p.wire.mu.Unlock()
		if !rotated {
			t.Fatal("UDP token and wire IDs did not rotate")
		}
		for _, size := range sizes {
			exchange(bytes.Repeat([]byte{byte(attempt + 1)}, size))
		}
		if probe.onlySource(t) != endpoint {
			t.Fatal("gateway did not retain original relay socket")
		}
	}
}

// The tunnel's PACKET bound is independent of the host's UDP send limit. Only
// EMSGSIZE excludes this real-socket probe; permissions and other failures fail
// the test. Maximum migrated wire frames are covered by the net.Pipe test.
func testLocalUDPSize(t *testing.T, size int) bool {
	t.Helper()
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	sender.SetWriteDeadline(time.Now().Add(3 * time.Second))
	n, err := sender.WriteToUDP(make([]byte, size), receiver.LocalAddr().(*net.UDPAddr))
	if errors.Is(err, syscall.EMSGSIZE) {
		t.Logf("real UDP size %d excluded: local kernel returned EMSGSIZE; migrated maximum PACKET frame is tested separately", size)
		return false
	}
	if err != nil || n != size {
		t.Fatalf("local UDP capability write: size=%d n=%d err=%v", size, n, err)
	}
	receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = receiver.ReadFromUDP(make([]byte, size+1))
	if err != nil || n != size {
		t.Fatalf("local UDP capability receive: size=%d n=%d err=%v", size, n, err)
	}
	return true
}
