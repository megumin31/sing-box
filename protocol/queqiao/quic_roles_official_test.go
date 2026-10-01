//go:build with_quic

package queqiao

import (
	"bytes"
	"context"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
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
)

func TestQUICRolesOfficialGateway(t *testing.T) {
	binary := os.Getenv("QUEQIAO_GATEWAY_BINARY")
	if binary == "" {
		t.Skip("set QUEQIAO_GATEWAY_BINARY to the pinned official gateway")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir := t.TempDir()
	state, profile := filepath.Join(dir, "provider"), filepath.Join(dir, "profile.json")
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := reserve.Addr().String()
	reserve.Close()
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
	gateway := exec.CommandContext(ctx, binary, "server", "--state", state, "--listen", endpoint, "--transport", "auto", "--allow-private-destinations", "--log-file", "none", "--log-level", "error")
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
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var peers sync.WaitGroup
	var accepts atomic.Int32
	acceptedDone := make(chan struct{})
	go func() {
		defer close(acceptedDone)
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			accepts.Add(1)
			peers.Add(1)
			go func() {
				defer peers.Done()
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	t.Cleanup(func() { cancel(); target.Close(); <-acceptedDone; peers.Wait() })
	for _, failure := range []string{"none", "data", "control", "all"} {
		t.Run(failure, func(t *testing.T) {
			a, e := NewOutbound(ctx, nil, nil, "official-roles", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: "quic", TCPRecovery: true, QUICDataIsolation: true, QUICPathProbe: failure == "none"})
			if e != nil {
				t.Fatal(e)
			}
			o := a.(*Outbound)
			defer o.Close()
			meter := newRoleSocketMeter(o)
			holderRaw, e := o.DialContext(ctx, "tcp", M.ParseSocksaddr(target.Addr().String()))
			if e != nil {
				t.Fatal(e)
			}
			holder := holderRaw.(*Conn)
			defer holder.Close()
			holder.SetDeadline(time.Now().Add(12 * time.Second))
			if _, e = holder.Write([]byte("hold")); e != nil {
				t.Fatal(e)
			}
			tiny := make([]byte, 4)
			if _, e = io.ReadFull(holder, tiny); e != nil {
				t.Fatal(e)
			}
			if string(tiny) != "hold" {
				t.Fatalf("holder echo=%q", tiny)
			}
			raw, e := o.DialContext(ctx, "tcp", M.ParseSocksaddr(target.Addr().String()))
			if e != nil {
				t.Fatal(e)
			}
			c := raw.(*Conn)
			defer c.Close()
			c.SetDeadline(time.Now().Add(12 * time.Second))
			c.mu.Lock()
			lanes := c.bundle.lanes
			c.mu.Unlock()
			holder.mu.Lock()
			other := holder.bundle.lanes
			holder.mu.Unlock()
			if lanes[0] == nil || lanes[1] == nil || other[0] == nil || other[1] == nil {
				t.Fatal("two-flow isolation not admitted")
			}
			control, data := lanes[0].raw.(*quicCarrier), lanes[1].raw.(*quicCarrier)
			if control.connection == data.connection || control.connection != other[0].raw.(*quicCarrier).connection || data.connection == other[1].raw.(*quicCarrier).connection {
				t.Fatal("shared/exclusive connection identities wrong")
			}
			// The pinned default classifier requires age >=1s as well as bytes.
			// A subsecond localhost transfer is intentionally not BULK. Mature the
			// same live flow before sending this finite payload; do not tune server
			// policy or mistake connection creation for downstream isolation.
			select {
			case <-time.After(1100 * time.Millisecond):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			before := meter.received(data.LocalAddr().String())
			payload := bytes.Repeat([]byte("reliable-quic-role-0123456789"), 100000)
			wrote := make(chan error, 1)
			go func() {
				_, err := c.Write(payload)
				if err == nil {
					err = c.CloseWrite()
				}
				wrote <- err
			}()
			prefix := make([]byte, 128<<10)
			if _, e = io.ReadFull(c, prefix); e != nil {
				t.Fatal(e)
			}
			if failure == "data" || failure == "all" {
				data.connection.CloseWithError(0, "local test data interruption")
			}
			if failure == "control" || failure == "all" {
				control.connection.CloseWithError(0, "local test control interruption")
			}
			rest, e := io.ReadAll(c)
			if e != nil {
				t.Fatalf("strict logical FIN: %v", e)
			}
			if e = <-wrote; e != nil {
				t.Fatalf("write/half-close: %v", e)
			}
			if !bytes.Equal(append(prefix, rest...), payload) {
				t.Fatal("payload duplicated or lost")
			}
			select {
			case <-c.done:
			case <-ctx.Done():
				t.Fatal("subject final ACK incomplete")
			}
			c.mu.Lock()
			attempts, finalErr := c.recoveryAttempts, c.err
			complete := c.localFinalACK && c.remoteFIN && c.recvNext == c.remoteFinal && len(c.replay) == 0
			c.mu.Unlock()
			if finalErr != io.EOF || !complete {
				t.Fatalf("subject final error: %v", finalErr)
			}
			wireDown := meter.received(data.LocalAddr().String()) - before
			if failure == "none" && wireDown < int64(len(payload)/2) {
				t.Fatalf("isolated connection did not carry substantial downstream traffic: %d wire bytes", wireDown)
			}
			if e = holder.CloseWrite(); e != nil {
				t.Fatal(e)
			}
			holderRest, e := io.ReadAll(holder)
			if e != nil || len(holderRest) != 0 {
				t.Fatalf("other pooled flow lost/duplicated: bytes=%d err=%v", len(holderRest), e)
			}
			select {
			case <-holder.done:
			case <-ctx.Done():
				t.Fatal("holder final ACK incomplete")
			}
			holder.mu.Lock()
			holderErr, holderReplay := holder.err, len(holder.replay)
			holderFinal := holder.localFinalACK && holder.remoteFIN && holder.recvNext == holder.remoteFinal
			holder.mu.Unlock()
			if holderErr != io.EOF || holderReplay != 0 || !holderFinal {
				t.Fatalf("holder final error=%v replay=%d final=%v", holderErr, holderReplay, holderFinal)
			}
			eventually(t, func() bool { o.mu.Lock(); n := len(o.active); o.mu.Unlock(); return n == 0 && len(o.slots) == 0 })
			o.Close()
			eventually(t, func() bool { return meter.active.Load() == 0 })
			if meter.peak.Load() > 4 {
				t.Fatalf("hard connection quota exceeded: %d", meter.peak.Load())
			}
			t.Logf("mode=%s application_bytes=%d recovery_JOINs=%d isolated_downstream_wire_bytes=%d peak_connections=%d", failure, len(payload), attempts, wireDown, meter.peak.Load())
		})
	}
	if accepts.Load() != 8 {
		t.Fatalf("destination sockets=%d want8", accepts.Load())
	}
}

type roleCountedSocket struct {
	net.Conn
	owner *roleSocketMeter
	reads atomic.Int64
	once  sync.Once
}

func (c *roleCountedSocket) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.reads.Add(int64(n))
	return n, e
}
func (c *roleCountedSocket) Close() error {
	var e error
	c.once.Do(func() { e = c.Conn.Close(); c.owner.active.Add(-1) })
	return e
}

type roleSocketMeter struct {
	mu           sync.Mutex
	sockets      map[string]*roleCountedSocket
	active, peak atomic.Int32
}

func newRoleSocketMeter(o *Outbound) *roleSocketMeter {
	m := &roleSocketMeter{sockets: make(map[string]*roleCountedSocket)}
	base := o.dialer
	o.dialer = testDialer{dial: func(ctx context.Context, n string, d M.Socksaddr) (net.Conn, error) {
		raw, e := base.DialContext(ctx, n, d)
		if e != nil {
			return nil, e
		}
		c := &roleCountedSocket{Conn: raw, owner: m}
		now := m.active.Add(1)
		for old := m.peak.Load(); now > old && !m.peak.CompareAndSwap(old, now); old = m.peak.Load() {
		}
		m.mu.Lock()
		m.sockets[raw.LocalAddr().String()] = c
		m.mu.Unlock()
		return c, nil
	}}
	return m
}
func (m *roleSocketMeter) received(addr string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.sockets[addr]; c != nil {
		return c.reads.Load()
	}
	return 0
}
