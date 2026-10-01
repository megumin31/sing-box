//go:build with_quic

package queqiao

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// Opt-in official-gateway acceptance. All listeners, enrollment, destinations,
// and test identities are confined to localhost and t.TempDir. The executable
// is supplied separately; this test neither modifies nor embeds official code.
func TestInitialFallbackOfficialGateway(t *testing.T) {
	binary := os.Getenv("QUEQIAO_GATEWAY_BINARY")
	if binary == "" {
		t.Skip("set QUEQIAO_GATEWAY_BINARY to the pinned official gateway")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	dir := t.TempDir()
	state, profile := filepath.Join(dir, "provider"), filepath.Join(dir, "profile.json")
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := reserve.Addr().String()
	reserve.Close()
	sink, err := net.ListenPacket("udp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	var packets atomic.Int32
	sinkDone := make(chan struct{})
	go func() {
		defer close(sinkDone)
		b := make([]byte, 2048)
		for {
			if _, _, err := sink.ReadFrom(b); err != nil {
				return
			}
			packets.Add(1)
		}
	}()
	t.Cleanup(func() { sink.Close(); <-sinkDone })
	run := func(args ...string) string {
		t.Helper()
		commandCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		output, err := exec.CommandContext(commandCtx, binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("official fixture command %s failed: %v", args[0], err)
		}
		return strings.TrimSpace(string(output))
	}
	run("provider", "init", "--state", state, "--name", "fallback-test", "--endpoint", endpoint)
	run("provider", "add-user", "--state", state, "--name", "test")
	invite := run("provider", "invite", "--state", state, "--user", "test")
	logPath := filepath.Join(dir, "gateway.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	gateway := exec.CommandContext(ctx, binary, "server", "--state", state, "--listen", endpoint, "--transport", "tcp", "--allow-private-destinations", "--log-file", "none", "--log-level", "error")
	gateway.Stdout, gateway.Stderr = log, log
	if err = gateway.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		gateway.Process.Kill()
		gateway.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Logf("official gateway error log: %s", b)
		}
	})
	startup := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp4", endpoint, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(startup) {
			t.Fatal("official gateway startup timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	run("enroll", "--invite", invite, "--profile", profile, "--device-name", "fallback-test", "--local-address", "127.0.0.1")
	a, err := NewOutbound(ctx, nil, nil, "official-fallback", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: "quic", QUICInitialFallback: true, TCPRecovery: true, UDPResume: true})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
	var udpCalls, tcpCalls atomic.Int32
	dialer := o.dialer
	o.dialer = testDialer{dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if destination.String() != endpoint {
			return nil, errors.New("gateway dial escaped local endpoint")
		}
		if network == "udp" {
			udpCalls.Add(1)
		} else if network == "tcp" {
			tcpCalls.Add(1)
		} else {
			return nil, errors.New("unexpected carrier network")
		}
		return dialer.DialContext(ctx, network, destination)
	}}
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts atomic.Int32
	var peers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			peers.Add(1)
			go func() {
				defer peers.Done()
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	t.Cleanup(func() { cancel(); target.Close(); <-acceptDone; peers.Wait() })
	probes := []*officialFallbackUDPProbe{fallbackOfficialUDPProbe(t), fallbackOfficialUDPProbe(t)}
	type result struct {
		index int
		tcp   *Conn
		udp   *packetConn
		err   error
	}
	results := make(chan result, 4)
	var callers sync.WaitGroup
	t.Cleanup(func() { cancel(); callers.Wait() })
	canceledCtx, cancelWaiter := context.WithCancel(ctx)
	defer cancelWaiter()
	canceledResult := make(chan error, 1)
	callers.Add(1)
	go func() {
		defer callers.Done()
		c, err := o.DialContext(canceledCtx, "tcp", M.ParseSocksaddr(target.Addr().String()))
		if c != nil {
			c.Close()
		}
		canceledResult <- err
	}()
	for i := 0; i < 4; i++ {
		callers.Add(1)
		go func(i int) {
			defer callers.Done()
			r := result{index: i}
			if i < 2 {
				c, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr(target.Addr().String()))
				r.err = err
				if c != nil {
					r.tcp = c.(*Conn)
				}
			} else {
				p, err := o.ListenPacket(ctx, M.ParseSocksaddr(probes[i-2].conn.LocalAddr().String()))
				r.err = err
				if p != nil {
					r.udp = p.(*packetConn)
				}
			}
			results <- r
		}(i)
	}
	pool := o.pool.(*quicPool)
	admission := time.Now().Add(2 * time.Second)
	for {
		pool.mu.Lock()
		shared := len(pool.entries) == 1 && pool.entries[0].users == 5
		pool.mu.Unlock()
		if shared {
			break
		}
		if time.Now().After(admission) {
			t.Fatal("five callers did not share one actual pending handshake")
		}
		time.Sleep(time.Millisecond)
	}
	cancelWaiter()
	select {
	case err := <-canceledResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("canceled waiter stalled")
	}
	pool.mu.Lock()
	viable := len(pool.entries) == 1 && pool.entries[0].users == 4 && pool.entries[0].ctx.Err() == nil
	pool.mu.Unlock()
	if !viable {
		t.Fatal("one caller cancellation destroyed other pending reservations")
	}
	flows := make([]result, 4)
	for i := 0; i < 4; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatal(r.err)
			}
			flows[r.index] = r
			if r.tcp != nil {
				defer r.tcp.Close()
			} else {
				defer r.udp.Close()
			}
		case <-ctx.Done():
			t.Fatal("initial fallback stalled")
		}
	}
	if udpCalls.Load() != 1 || tcpCalls.Load() != 4 || packets.Load() == 0 {
		t.Fatalf("shared handshake/fallback counts: UDP=%d TCP=%d packets=%d", udpCalls.Load(), tcpCalls.Load(), packets.Load())
	}
	deadline := time.Now().Add(8 * time.Second)
	for i, r := range flows {
		if r.tcp != nil {
			c := r.tcp
			c.SetDeadline(deadline)
			if _, ok := c.currentCarrier().(*tls.Conn); !ok {
				t.Fatal("official fallback did not select TLS")
			}
			before := bytes.Repeat([]byte{byte(i + 1)}, 4096)
			if _, err = c.Write(before); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, len(before))
			if _, err = io.ReadFull(c, b); err != nil || !bytes.Equal(b, before) {
				t.Fatalf("official initial TCP: %v", err)
			}
			abortCarrier(c.currentCarrier())
			waitOfficialFallbackTCP(t, c)
			after := bytes.Repeat([]byte{byte(i + 11)}, 64<<10)
			if _, err = c.Write(after); err != nil {
				t.Fatal(err)
			}
			b = make([]byte, len(after))
			if _, err = io.ReadFull(c, b); err != nil || !bytes.Equal(b, after) {
				t.Fatalf("official recovered TCP: %v", err)
			}
			if err = c.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			rest, err := io.ReadAll(c)
			if err != nil || len(rest) != 0 {
				t.Fatalf("official recovered FIN/duplicate bytes: length=%d err=%v", len(rest), err)
			}
			select {
			case <-c.done:
			case <-ctx.Done():
				t.Fatal("official final ACK timeout")
			}
			c.mu.Lock()
			finalErr, retained, attempts := c.err, len(c.replay), c.recoveryAttempts
			complete := c.localFinalACK && c.remoteFinalACKSent
			c.mu.Unlock()
			if !errors.Is(finalErr, io.EOF) || retained != 0 || attempts != 1 || !complete {
				t.Fatalf("official TCP completion: error=%v replay=%d attempts=%d final-ACKs=%v", finalErr, retained, attempts, complete)
			}
		} else {
			p, probe := r.udp, probes[i-2]
			exchangeOfficialFallbackUDPOnce(t, p, probe, []byte("before fallback relay interruption"))
			source := probe.onlySource(t)
			p.wire.mu.Lock()
			token, session, flow := p.token, p.wire.session, p.wire.flow
			p.wire.mu.Unlock()
			abortCarrier(p.wire.currentCarrier())
			waitUDPReplacement(t, p, 0)
			p.wire.mu.Lock()
			rotated := p.token != token && p.wire.session != session && p.wire.flow != flow
			p.wire.mu.Unlock()
			if !rotated {
				t.Fatal("official resume did not rotate token/IDs")
			}
			for _, size := range []int{0, 1200, maxUDPDatagram} {
				exchangeOfficialFallbackUDPOnce(t, p, probe, bytes.Repeat([]byte{byte(i + 1)}, size))
			}
			if probe.onlySource(t) != source {
				t.Fatal("official UDP relay source endpoint changed")
			}
			probe.mu.Lock()
			received := probe.sources[source]
			probe.mu.Unlock()
			if received != 4 {
				t.Fatalf("UDP target observed %d packets for four single-attempt application probes", received)
			}
			p.Close()
			p.wire.mu.Lock()
			closeAcknowledged := p.closeAcknowledged
			p.wire.mu.Unlock()
			if !closeAcknowledged {
				t.Fatal("official UDP CLOSE was not acknowledged")
			}
		}
	}
	if accepts.Load() != 2 || udpCalls.Load() != 1 || tcpCalls.Load() != 8 {
		t.Fatalf("recovery reopened destination or QUIC: destinations=%d UDP=%d TCP=%d", accepts.Load(), udpCalls.Load(), tcpCalls.Load())
	}
	// done is signaled before onClose releases the logical slot. Observe normal
	// release boundedly before forcing outbound shutdown, as in the peer test.
	cleanupDeadline := time.Now().Add(time.Second)
	for {
		o.mu.Lock()
		active := len(o.active)
		o.mu.Unlock()
		if active == 0 && len(o.slots) == 0 {
			break
		}
		if time.Now().After(cleanupDeadline) {
			t.Fatalf("official flow cleanup: active=%d slots=%d", active, len(o.slots))
		}
		time.Sleep(time.Millisecond)
	}
	o.Close()
	pool.mu.Lock()
	entries := len(pool.entries)
	pool.mu.Unlock()
	if entries != 0 {
		t.Fatalf("pool shutdown retained %d entries", entries)
	}
	t.Log("actual shared QUIC handshake: five waiters, one canceled, four authenticated TCP fallbacks; two TCP JOIN and two UDP resume; destination sockets and UDP source endpoints preserved")
}

func waitOfficialFallbackTCP(t *testing.T, c *Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		ready, closed, err := c.recoveryAttempts == 1 && !c.recovering, c.closed, c.err
		c.mu.Unlock()
		if closed {
			t.Fatalf("official TCP recovery failed: %v", err)
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("official JOIN did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}

type officialFallbackUDPProbe struct {
	*udpEchoProbe
	replies atomic.Int32
}

func fallbackOfficialUDPProbe(t *testing.T) *officialFallbackUDPProbe {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &officialFallbackUDPProbe{udpEchoProbe: &udpEchoProbe{conn: conn, sources: make(map[string]int)}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, maxUDPDatagram)
		for {
			n, source, err := conn.ReadFromUDP(b)
			if err != nil {
				return
			}
			p.mu.Lock()
			p.sources[source.String()]++
			p.mu.Unlock()
			if _, err := conn.WriteToUDP(b[:n], source); err == nil {
				p.replies.Add(1)
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return p
}

// Recovery has already settled. Send exactly once so that this test cannot
// hide UDP loss behind application retries. This is a finite local probe, not
// a claim that UDP or handover guarantees lossless/exactly-once delivery.
func exchangeOfficialFallbackUDPOnce(t *testing.T, p *packetConn, probe *officialFallbackUDPProbe, payload []byte) {
	t.Helper()
	p.SetDeadline(time.Now().Add(3 * time.Second))
	if n, err := p.WriteTo(payload, probe.conn.LocalAddr()); err != nil || n != len(payload) {
		t.Fatalf("single UDP write: %d/%d %v", n, len(payload), err)
	}
	b := make([]byte, maxUDPDatagram)
	n, source, err := p.ReadFrom(b)
	if err != nil || !bytes.Equal(b[:n], payload) || source.String() != probe.conn.LocalAddr().String() {
		probe.mu.Lock()
		targetPackets := 0
		for _, count := range probe.sources {
			targetPackets += count
		}
		probe.mu.Unlock()
		p.wire.mu.Lock()
		initialized, high, next, recovering, closed := p.window.initialized, p.window.high, p.next, p.wire.recovering, p.wire.closed
		p.wire.mu.Unlock()
		// Preserve failure while collecting the remaining independent sizes;
		// do not resend this payload or turn a lost reply into success.
		t.Errorf("single UDP echo size=%d: got=%d source=%v err=%v; target packets=%d replies=%d receive-window=%v/%d next-send=%d recovering=%v closed=%v", len(payload), n, source, err, targetPackets, probe.replies.Load(), initialized, high, next, recovering, closed)
		return
	}
	t.Logf("single UDP echo delivered size=%d", len(payload))
}
