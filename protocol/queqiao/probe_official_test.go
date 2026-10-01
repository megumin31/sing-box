//go:build with_quic

package queqiao

import (
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
	"testing"
	"time"
)

func TestPathProbeOfficialGateway(t *testing.T) {
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
	a, err := NewOutbound(ctx, nil, nil, "official-fallback", option.QueqiaoOutboundOptions{ProfilePath: profile, Transport: "quic", QUICPathProbe: true})
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
	acceptedDone := make(chan struct{})
	go func() {
		defer close(acceptedDone)
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			peers.Add(1)
			go func() {
				defer peers.Done()
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { cancel(); target.Close(); <-acceptedDone; peers.Wait() })
	var entry *quicPoolEntry
	for i := 0; i < 2; i++ {
		c, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr(target.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = c.Write([]byte("probe preflight")); err != nil {
			c.Close()
			t.Fatal(err)
		}
		reply := make([]byte, len("probe preflight"))
		_, err = io.ReadFull(c, reply)
		c.Close()
		if err != nil || string(reply) != "probe preflight" {
			t.Fatalf("post-probe application echo: %v", err)
		}
		pool := o.pool.(*quicPool)
		pool.mu.Lock()
		if len(pool.entries) != 1 {
			pool.mu.Unlock()
			t.Fatal("unexpected probe pool size")
		}
		current := pool.entries[0]
		pool.mu.Unlock()
		<-current.ready
		if current.probe.status != "conformant" || current.probe.sent != 4 || current.probe.received != 4 {
			t.Fatalf("official probe result: %+v", current.probe)
		}
		if entry != nil && entry != current {
			t.Fatal("second flow did not reuse verified connection")
		}
		entry = current
	}
	// This is a conforming echo preflight, not directional capacity measurement.
	if entry == nil || entry.connection.Context().Err() != nil {
		t.Fatal(errors.New("verified pool connection not retained"))
	}
}
