package queqiao

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func pair(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	c := newConn(a, [16]byte{1}, 1, nil)
	t.Cleanup(func() { c.Close(); b.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b.SetDeadline(time.Now().Add(5 * time.Second))
	return c, b
}
func sendPeer(p net.Conn, f frame) error {
	f.session = [16]byte{1}
	f.flow = 1
	return writeFrame(p, f)
}
func exchangePeer(p net.Conn, f frame, want uint64, final bool) error {
	if err := sendPeer(p, f); err != nil {
		return err
	}
	ack, err := readFrame(p)
	if err != nil {
		return err
	}
	flags := flagACKDown
	if final {
		flags |= flagACKFinal
	}
	if ack.typ != typeACK || ack.flags != flags || ack.sequence != want {
		return errors.New("incorrect downstream ACK")
	}
	return nil
}

func TestHalfCloseAndLargeTransfer(t *testing.T) {
	c, p := pair(t)
	payload := bytes.Repeat([]byte("bidirectional"), 250000)
	server := make(chan error, 1)
	go func() {
		var received []byte
		for {
			f, err := readFrame(p)
			if err != nil {
				server <- err
				return
			}
			if f.typ == typeClose {
				if f.flags != flagFIN || f.sequence != uint64(len(received)) {
					server <- errors.New("bad upstream FIN")
					return
				}
				if !bytes.Equal(received, payload) {
					server <- errors.New("upload mismatch")
					return
				}
				if err = sendPeer(p, frame{typ: typeACK, flags: flagACKUp | flagACKFinal, sequence: f.sequence}); err != nil {
					server <- err
					return
				}
				break
			}
			if f.typ != typeData || f.sequence != uint64(len(received)) {
				server <- errors.New("bad upstream offset")
				return
			}
			received = append(received, f.payload...)
			if err = sendPeer(p, frame{typ: typeACK, flags: flagACKUp, sequence: uint64(len(received))}); err != nil {
				server <- err
				return
			}
		}
		for offset := 0; offset < len(payload); {
			n := min(maxPayload, len(payload)-offset)
			err := exchangePeer(p, frame{typ: typeData, sequence: uint64(offset), payload: payload[offset : offset+n]}, uint64(offset+n), false)
			if err != nil {
				server <- err
				return
			}
			offset += n
		}
		server <- exchangePeer(p, frame{typ: typeClose, flags: flagFIN, sequence: uint64(len(payload))}, uint64(len(payload)), true)
	}()
	if n, err := c.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write %d: %v", n, err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("download mismatch")
	}
	if err = <-server; err != nil {
		t.Fatal(err)
	}
}

func TestReorderOverlapAndEarlyFIN(t *testing.T) {
	c, p := pair(t)
	done := make(chan error, 1)
	go func() {
		if err := exchangePeer(p, frame{typ: typeData, sequence: 3, payload: []byte("def")}, 0, false); err != nil {
			done <- err
			return
		}
		if err := sendPeer(p, frame{typ: typeClose, flags: flagFIN, sequence: 6}); err != nil {
			done <- err
			return
		}
		done <- exchangePeer(p, frame{typ: typeData, sequence: 0, payload: []byte("abcd")}, 6, true)
	}()
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "abcdef" {
		t.Fatalf("got %q: %v", b, err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRemoteHalfCloseStillAllowsWrite(t *testing.T) {
	c, p := pair(t)
	done := make(chan error, 1)
	go func() {
		if err := sendPeer(p, frame{typ: typeClose, flags: flagFIN}); err != nil {
			done <- err
			return
		}
		data, ack := false, false
		for !data || !ack {
			f, err := readFrame(p)
			if err != nil {
				done <- err
				return
			}
			switch f.typ {
			case typeData:
				data = string(f.payload) == "after EOF"
			case typeACK:
				ack = f.flags == flagACKDown|flagACKFinal && f.sequence == 0
			default:
				done <- errors.New("unexpected frame")
				return
			}
		}
		done <- nil
	}()
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("after EOF")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReadDeadlineCanBeCleared(t *testing.T) {
	c, p := pair(t)
	c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	c.SetReadDeadline(time.Time{})
	go exchangePeer(p, frame{typ: typeData, payload: []byte("x")}, 1, false)
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil || b[0] != 'x' {
		t.Fatalf("after clear: %v", err)
	}
}

func TestBlockedWriteDeadlineAndClose(t *testing.T) {
	for _, closeInstead := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "close"}[closeInstead], func(t *testing.T) {
			c, _ := pair(t)
			done := make(chan error, 1)
			go func() { _, err := c.Write([]byte("blocked")); done <- err }()
			if closeInstead {
				c.Close()
			} else {
				c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("blocked write succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("write did not unblock")
			}
		})
	}
}

func TestConcurrentCloseDeadlines(t *testing.T) {
	c, _ := pair(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.SetDeadline(time.Now().Add(time.Millisecond))
			c.SetReadDeadline(time.Time{})
			c.SetWriteDeadline(time.Time{})
			c.Close()
		}()
	}
	wg.Wait()
}

func TestInvalidStateFrames(t *testing.T) {
	tests := []frame{
		{typ: typeData, flags: flagFIN, payload: []byte("x")},
		{typ: typeACK, flags: flagACKDown},
		{typ: typeACK, flags: flagACKUp, sequence: 1},
		{typ: typeACK, flags: flagACKUp | flagACKFinal},
		{typ: typeClose},
		{typ: typeClose, flags: flagFIN, sequence: receiveLimit + 1},
		{typ: typeData, sequence: math.MaxUint64, payload: []byte("xx")},
		{typ: typeData, sequence: receiveLimit, payload: []byte("x")},
		{typ: typeOpenOK},
	}
	for i, f := range tests {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			c, p := pair(t)
			go sendPeer(p, f)
			_, err := c.Read(make([]byte, 1))
			if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("invalid frame not rejected: %v", err)
			}
		})
	}
}

func TestReceiveStorageBound(t *testing.T) {
	c := &Conn{}
	// Tiny out-of-order frames cannot create unbounded segment metadata.
	for i := 0; i < 1024; i++ {
		if err := c.insertLocked(uint64(1+2*i), []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.insertLocked(3000, []byte("x")); err == nil {
		t.Fatal("accepted too many fragments")
	}
	c = &Conn{}
	if err := c.insertLocked(0, make([]byte, receiveLimit)); err != nil {
		t.Fatal(err)
	}
	if err := c.insertLocked(receiveLimit, []byte("x")); err == nil {
		t.Fatal("accepted unbounded unread data")
	}
}

func TestReadDeadlineAppliesToBufferedData(t *testing.T) {
	c, peer := pair(t)
	if err := exchangePeer(peer, frame{typ: typeData, payload: []byte("buffered")}, 8, false); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := c.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("buffered read deadline: %v", err)
	}
	c.SetReadDeadline(time.Time{})
	data := make([]byte, 8)
	if _, err := io.ReadFull(c, data); err != nil || string(data) != "buffered" {
		t.Fatalf("after clear: %q %v", data, err)
	}
}
