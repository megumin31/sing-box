package queqiao

import (
	"bytes"
	"context"
	"errors"
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

func TestTCPBundleOfficialGateway(t *testing.T) {
	binary := os.Getenv("QUEQIAO_GATEWAY_BINARY")
	if binary == "" {
		t.Skip("set QUEQIAO_GATEWAY_BINARY to the pinned official gateway")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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
	gateway := exec.CommandContext(ctx, binary, "server", "--state", state, "--listen", endpoint, "--transport", "tcp", "--tcp-fallback-lanes", "2", "--allow-private-destinations", "--log-file", "none", "--log-level", "error")
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
	a, err := NewOutbound(ctx, nil, nil, "official-bundle", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: "tcp", TCPRecovery: true, TCPLanes: 2})
	if err != nil {
		t.Fatal(err)
	}
	o := a.(*Outbound)
	defer o.Close()
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
	for _, failure := range []string{"none", "one", "all"} {
		t.Run(failure, func(t *testing.T) {
			raw, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr(target.Addr().String()))
			if err != nil {
				t.Fatal(err)
			}
			c := raw.(*Conn)
			defer c.Close()
			c.SetDeadline(time.Now().Add(12 * time.Second))
			c.mu.Lock()
			lanes := c.bundle.lanes
			c.mu.Unlock()
			if lanes[0] == nil || lanes[1] == nil {
				t.Fatal("second lane not admitted")
			}
			payload := bytes.Repeat([]byte("reliable-two-lane-0123456789"), 80000)
			wrote := make(chan error, 1)
			go func() {
				_, e := c.Write(payload)
				if e == nil {
					e = c.CloseWrite()
				}
				wrote <- e
			}()
			prefix := make([]byte, 64<<10)
			if _, err = io.ReadFull(c, prefix); err != nil {
				t.Fatal(err)
			}
			if failure != "none" {
				abortCarrier(lanes[0].raw)
			}
			if failure == "all" {
				abortCarrier(lanes[1].raw)
			}
			rest, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("strict FIN read: %v", err)
			}
			if err = <-wrote; err != nil {
				t.Fatalf("write/half-close: %v", err)
			}
			got := append(prefix, rest...)
			if !bytes.Equal(got, payload) {
				t.Fatalf("duplicate/lost data: got %d want %d", len(got), len(payload))
			}
			select {
			case <-c.done:
			case <-ctx.Done():
				t.Fatal("final ACK did not release flow")
			}
			c.mu.Lock()
			attempts, retained, finalErr := c.recoveryAttempts, len(c.replay), c.err
			c.mu.Unlock()
			if retained != 0 || !errors.Is(finalErr, io.EOF) {
				t.Fatalf("retained=%d err=%v", retained, finalErr)
			}
			if failure == "all" && attempts == 0 {
				t.Fatal("all-lane interruption did not exercise JOIN")
			}
			t.Logf("mode=%s bytes=%d recovery_JOINs=%d", failure, len(got), attempts)
		})
	}
	if accepts.Load() != 3 {
		t.Fatalf("destination accepts=%d want3", accepts.Load())
	}
	deadline := time.Now().Add(time.Second)
	for {
		o.mu.Lock()
		active := len(o.active)
		o.mu.Unlock()
		if active == 0 && len(o.slots) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("natural resource release active=%d slots=%d", active, len(o.slots))
		}
		time.Sleep(time.Millisecond)
	}
}
