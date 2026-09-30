package queqiao

import (
	"bytes"
	"context"
	binaryencoding "encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// This opt-in test runs a separately built, unmodified official gateway. It
// generates disposable provider/device identities in t.TempDir and removes
// them afterwards. The outbound has no source dependency on that executable.
func TestOfficialGateway(t *testing.T) {
	for _, transport := range []string{"tcp", "quic"} {
		t.Run(transport, func(t *testing.T) {
			if transport == "quic" && checkQUIC() != nil {
				t.Skip("QUIC build tag disabled")
			}
			testOfficialGateway(t, transport)
		})
	}
}

func testOfficialGateway(t *testing.T, transport string) {
	binary := os.Getenv("QUEQIAO_GATEWAY_BINARY")
	if binary == "" {
		t.Skip("set QUEQIAO_GATEWAY_BINARY to an official queqiaod executable")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "provider")
	profile := filepath.Join(dir, "profile.json")
	run := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("gateway command %s failed: %v: %s", args[0], err, out)
		}
		return strings.TrimSpace(string(out))
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := listener.Addr().String()
	listener.Close()
	run("provider", "init", "--state", state, "--name", "native-interoperability-test", "--endpoint", endpoint)
	run("provider", "add-user", "--state", state, "--name", "test")
	invite := run("provider", "invite", "--state", state, "--user", "test")
	gatewayLog, err := os.Create(filepath.Join(dir, "gateway.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer gatewayLog.Close()
	gateway := exec.Command(binary, "server", "--state", state, "--listen", endpoint, "--transport", "auto", "--allow-private-destinations", "--log-file", "none", "--log-level", "error")
	gateway.Stdout, gateway.Stderr = gatewayLog, gatewayLog
	if err = gateway.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gateway.Process.Kill(); gateway.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", endpoint, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("official gateway did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	run("enroll", "--invite", invite, "--profile", profile, "--device-name", "native-test", "--local-address", "127.0.0.1")
	newOutbound := func() *Outbound {
		t.Helper()
		a, err := NewOutbound(context.Background(), nil, nil, "test", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: transport})
		if err != nil {
			t.Fatal(err)
		}
		o := a.(*Outbound)
		t.Cleanup(func() { o.Close() })
		return o
	}
	o := newOutbound()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	destination := M.ParseSocksaddr(target.Addr().String())
	t.Run("sing-box-config-and-optional-SOCKS", func(t *testing.T) {
		executable := os.Getenv("QUEQIAO_SING_BOX_BINARY")
		if transport == "quic" {
			executable = os.Getenv("QUEQIAO_SING_BOX_QUIC_BINARY")
		}
		if executable == "" {
			t.Skip("set QUEQIAO_SING_BOX_BINARY for complete sing-box process test")
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		proxyAddress := l.Addr().String()
		proxyPort := l.Addr().(*net.TCPAddr).Port
		l.Close()
		config := map[string]any{
			"log":       map[string]any{"level": "error"},
			"inbounds":  []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": proxyPort}},
			"outbounds": []any{map[string]any{"type": "queqiao", "tag": "native", "profile_path": profile, "transport": transport}},
		}
		raw, _ := json.Marshal(config)
		configPath := filepath.Join(dir, "sing-box.json")
		if err = os.WriteFile(configPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(executable, "check", "-c", configPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check: %v %s", err, output)
		}
		if os.Getenv("QUEQIAO_RUN_SING_BOX") != "1" {
			t.Log("sing-box configuration accepted; set QUEQIAO_RUN_SING_BOX=1 to test the SOCKS service in a netlink-capable environment")
			return
		}
		process := exec.Command(executable, "run", "-c", configPath)
		process.Stdout, process.Stderr = gatewayLog, gatewayLog
		if err = process.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { process.Process.Kill(); process.Wait() }()
		var proxy net.Conn
		deadline := time.Now().Add(5 * time.Second)
		for {
			proxy, err = net.DialTimeout("tcp", proxyAddress, 100*time.Millisecond)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				output, _ := os.ReadFile(filepath.Join(dir, "gateway.log"))
				t.Fatalf("sing-box did not start: %s", output)
			}
			time.Sleep(20 * time.Millisecond)
		}
		defer proxy.Close()
		proxy.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = proxy.Write([]byte{5, 1, 0}); err != nil {
			t.Fatal(err)
		}
		var greeting [2]byte
		if _, err = io.ReadFull(proxy, greeting[:]); err != nil || greeting != ([2]byte{5, 0}) {
			t.Fatalf("SOCKS greeting: %v %v", greeting, err)
		}
		host, portText, _ := net.SplitHostPort(target.Addr().String())
		port, _ := strconv.Atoi(portText)
		request := []byte{5, 1, 0, 1}
		request = append(request, net.ParseIP(host).To4()...)
		request = binaryencoding.BigEndian.AppendUint16(request, uint16(port))
		if _, err = proxy.Write(request); err != nil {
			t.Fatal(err)
		}
		var reply [10]byte
		if _, err = io.ReadFull(proxy, reply[:]); err != nil || reply[1] != 0 || reply[3] != 1 {
			t.Fatalf("SOCKS connect: %v %v", reply, err)
		}
		if _, err = proxy.Write([]byte("through-real-sing-box")); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len("through-real-sing-box"))
		if _, err = io.ReadFull(proxy, response); err != nil || string(response) != "through-real-sing-box" {
			t.Fatalf("SOCKS echo: %q %v", response, err)
		}
	})
	t.Run("large-full-duplex-and-half-close", func(t *testing.T) {
		conn, err := o.DialContext(context.Background(), "tcp", destination)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		payload := bytes.Repeat([]byte("native-queqiao-wire"), 400000)
		written := make(chan error, 1)
		go func() {
			_, err := conn.Write(payload)
			if err == nil {
				err = conn.(*Conn).CloseWrite()
			}
			written <- err
		}()
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch: received %d wanted %d", len(got), len(payload))
		}
		if err = <-written; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("concurrent-flows", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 12)
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := o.DialContext(context.Background(), "tcp", destination)
				if err != nil {
					errs <- err
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err = c.Write([]byte("isolated")); err == nil {
					err = c.(*Conn).CloseWrite()
				}
				if err == nil {
					var got []byte
					got, err = io.ReadAll(c)
					if string(got) != "isolated" {
						err = errors.New("flow echo mismatch")
					}
				}
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Error(err)
			}
		}
	})
	t.Run("destination-reset", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		if c, err := o.DialContext(context.Background(), "tcp", M.ParseSocksaddr(addr)); err == nil {
			c.Close()
			t.Fatal("unreachable destination accepted")
		}
	})
	t.Run("disabled-UDP-refused-locally", func(t *testing.T) {
		a, err := NewOutbound(context.Background(), nil, nil, "restricted", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: transport, Network: "tcp"})
		if err != nil {
			t.Fatal(err)
		}
		o := a.(*Outbound)
		defer o.Close()
		if _, err := o.DialContext(context.Background(), "udp", destination); err == nil {
			t.Fatal("UDP accepted")
		}
		if _, err := o.ListenPacket(context.Background(), destination); err == nil {
			t.Fatal("packet association accepted")
		}
	})
	testOfficialUDP(t, o)
	t.Run("close-cleans-active-flows", func(t *testing.T) {
		other := newOutbound()
		c, err := other.DialContext(context.Background(), "tcp", destination)
		if err != nil {
			t.Fatal(err)
		}
		other.Close()
		if _, err = c.Read(make([]byte, 1)); err == nil {
			t.Fatal("outbound close did not close flow")
		}
	})
	t.Run("revoked-device-rejected", func(t *testing.T) {
		raw, err := os.ReadFile(profile)
		if err != nil {
			t.Fatal(err)
		}
		var p clientProfile
		if err = json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		run("provider", "revoke-device", "--state", state, "--device", p.DeviceID)
		// The official gateway refreshes CLI authorization changes once a second.
		deadline := time.Now().Add(3 * time.Second)
		for {
			c, err := o.DialContext(context.Background(), "tcp", destination)
			if err != nil {
				break
			}
			c.Close()
			if time.Now().After(deadline) {
				t.Fatal("revoked identity still accepted after refresh window")
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
}

func testOfficialUDP(t *testing.T, o *Outbound) {
	t.Helper()
	echo := func() *net.UDPConn {
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			buffer := make([]byte, maxUDPDatagram)
			for {
				n, source, err := listener.ReadFromUDP(buffer)
				if err != nil {
					return
				}
				if _, err = listener.WriteToUDP(buffer[:n], source); err != nil {
					return
				}
			}
		}()
		return listener
	}
	first, second := echo(), echo()
	open := func(t *testing.T) *packetConn {
		t.Helper()
		c, err := o.ListenPacket(context.Background(), M.Socksaddr{})
		if err != nil {
			t.Fatal(err)
		}
		p := c.(*packetConn)
		t.Cleanup(func() { p.Close() })
		p.SetDeadline(time.Now().Add(5 * time.Second))
		return p
	}
	t.Run("UDP-sizes-addresses-and-final-ACK", func(t *testing.T) {
		p := open(t)
		for i, size := range []int{0, 1, 1200, 65000, maxUDPDatagram} {
			destination := first.LocalAddr()
			if i%2 != 0 {
				destination = second.LocalAddr()
			}
			payload := bytes.Repeat([]byte{byte(37 + i)}, size)
			if n, err := p.WriteTo(payload, destination); err != nil || n != len(payload) {
				t.Fatalf("UDP write size %d: %d %v", size, n, err)
			}
			buffer := make([]byte, maxUDPDatagram)
			n, source, err := p.ReadFrom(buffer)
			if err != nil || !bytes.Equal(buffer[:n], payload) || source.String() != destination.String() {
				t.Fatalf("UDP echo size %d: n=%d source=%v error=%v", size, n, source, err)
			}
		}
		if _, err := p.WriteTo(make([]byte, maxUDPDatagram+1), first.LocalAddr()); err == nil {
			t.Fatal("oversized datagram accepted")
		}
		// localhost commonly resolves to ::1 before 127.0.0.1. Listen on both
		// loopback families at this port so UDP's first successful send does
		// not target an unopened IPv6 socket.
		v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: first.LocalAddr().(*net.UDPAddr).Port})
		if err != nil {
			t.Fatal(err)
		}
		defer v6.Close()
		go func() {
			buffer := make([]byte, 65535)
			for {
				n, addr, err := v6.ReadFromUDP(buffer)
				if err != nil {
					return
				}
				v6.WriteToUDP(buffer[:n], addr)
			}
		}()
		// DNS is performed at the gateway; the response is a numeric source.
		_, port, _ := net.SplitHostPort(first.LocalAddr().String())
		if _, err := p.WriteTo([]byte("domain"), M.ParseSocksaddr(net.JoinHostPort("localhost", port))); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 32)
		n, source, err := p.ReadFrom(buffer)
		if err != nil || string(buffer[:n]) != "domain" || source.(*net.UDPAddr).Port != first.LocalAddr().(*net.UDPAddr).Port || !source.(*net.UDPAddr).IP.IsLoopback() {
			t.Fatalf("UDP domain: %q %v %v", buffer[:n], source, err)
		}
		if _, err = p.WriteTo([]byte("ipv6"), v6.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		n, source, err = p.ReadFrom(buffer)
		if err != nil || string(buffer[:n]) != "ipv6" || source.String() != v6.LocalAddr().String() {
			t.Fatalf("IPv6 UDP: %q %v %v", buffer[:n], source, err)
		}
		p.Close()
		p.wire.mu.Lock()
		acked := p.closeAcknowledged
		p.wire.mu.Unlock()
		if !acked {
			t.Fatal("UDP CLOSE was not acknowledged")
		}
	})
	t.Run("UDP-truncation-deadline-and-connected", func(t *testing.T) {
		p := open(t)
		p.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		if _, _, err := p.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("UDP read deadline: %v", err)
		}
		p.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := p.WriteTo([]byte("abcdef"), first.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		var short [3]byte
		n, _, err := p.ReadFrom(short[:])
		if err != nil || n != 3 || string(short[:]) != "abc" {
			t.Fatalf("truncation: %d %q %v", n, short, err)
		}
		if _, err = p.WriteTo([]byte("next"), first.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 32)
		n, _, err = p.ReadFrom(buffer)
		if err != nil || string(buffer[:n]) != "next" {
			t.Fatalf("boundary: %q %v", buffer[:n], err)
		}
		c, err := o.DialContext(context.Background(), "udp", M.ParseSocksaddr(first.LocalAddr().String()))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = c.Write([]byte("connected")); err != nil {
			t.Fatal(err)
		}
		n, err = c.Read(buffer)
		if err != nil || string(buffer[:n]) != "connected" {
			t.Fatalf("connected UDP: %q %v", buffer[:n], err)
		}
	})
	t.Run("UDP-concurrent-associations", func(t *testing.T) {
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c, err := o.DialContext(context.Background(), "udp", M.ParseSocksaddr(second.LocalAddr().String()))
				if err != nil {
					errs <- err
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte{byte(i)}, 1024)
				if _, err = c.Write(payload); err == nil {
					buffer := make([]byte, 2048)
					var n int
					n, err = c.Read(buffer)
					if err == nil && !bytes.Equal(buffer[:n], payload) {
						err = errors.New("association crossed payloads")
					}
				}
				errs <- err
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Error(err)
			}
		}
	})
}
