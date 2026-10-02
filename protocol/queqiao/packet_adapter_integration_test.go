package queqiao

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

func testPacketAdapterGateway(t *testing.T, o *Outbound) {
	v4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer v4.Close()
	port := v4.LocalAddr().(*net.UDPAddr).Port
	v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: port})
	if err != nil {
		if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.ENETUNREACH) {
			t.Skipf("IPv6 loopback target unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer v6.Close()
	var workers sync.WaitGroup
	var mu sync.Mutex
	received := 0
	for _, listener := range []*net.UDPConn{v4, v6} {
		workers.Add(1)
		go func(c *net.UDPConn) {
			defer workers.Done()
			b := make([]byte, 2048)
			for {
				n, a, e := c.ReadFromUDP(b)
				if e != nil {
					return
				}
				mu.Lock()
				received++
				mu.Unlock()
				if _, e = c.WriteToUDP(b[:n], a); e != nil {
					return
				}
			}
		}(listener)
	}
	defer func() { v4.Close(); v6.Close(); workers.Wait() }()
	raw, err := o.ListenPacket(context.Background(), M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	adapter := bufio.NewPacketConn(raw)
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		destination := M.ParseSocksaddr(net.JoinHostPort(host, strconv.Itoa(port)))
		for _, size := range []int{0, 1200} {
			payload := bytes.Repeat([]byte{byte(size % 251)}, size)
			output := buf.NewSize(max(1, size))
			_, _ = output.Write(payload)
			if err = adapter.WritePacket(output, destination); err != nil {
				t.Fatalf("%s size%d write: %v", host, size, err)
			}
			input := buf.NewSize(2048)
			source, e := adapter.ReadPacket(input)
			valid := e == nil && bytes.Equal(input.Bytes(), payload) && source.Port == uint16(port) && source.Addr.IsLoopback()
			if host != "localhost" {
				valid = valid && source.Addr.Unmap() == netip.MustParseAddr(host)
			}
			input.Release()
			if !valid {
				t.Fatalf("%s size%d reply source=%s error=%v", host, size, source, e)
			}
		}
	}
	mu.Lock()
	count := received
	mu.Unlock()
	if count != 6 {
		t.Fatalf("target receipts=%d want6", count)
	}
	raw.Close()
	p := raw.(*packetConn)
	p.wire.mu.Lock()
	acked := p.closeAcknowledged
	p.wire.mu.Unlock()
	if !acked {
		t.Fatal("UDP dissociation final ACK missing")
	}
	t.Log("actual sing-box packet adapter: six single-send domain/IPv4/IPv6 packets and final ACK verified")
}
