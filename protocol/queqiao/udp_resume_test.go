package queqiao

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestUDPResumeFrozenVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/protocol1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	type vector struct {
		Name, Canonical, Hex string
		Reject               bool
	}
	var v struct {
		UDP struct {
			Opens  []vector `json:"resume_opens"`
			Grants []vector `json:"resume_grants"`
		}
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, x := range v.UDP.Opens {
		b, _ := hex.DecodeString(x.Hex)
		if isUDPResumeOpen(b) == x.Reject {
			t.Errorf("open %s", x.Name)
		}
	}
	for _, x := range v.UDP.Grants {
		b, _ := hex.DecodeString(x.Hex)
		resumed, token, err := decodeUDPGrant(b)
		if (err != nil) != x.Reject {
			t.Errorf("grant %s: %v", x.Name, err)
		}
		if !x.Reject && (hex.EncodeToString(token[:]) != x.Canonical || resumed != (b[0] == 1)) {
			t.Errorf("grant value %s", x.Name)
		}
	}
}

func TestUDPResumeWindowAndNoReplay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		next, peer := net.Pipe()
		defer peer.Close()
		p := newResumablePacketConn(a, [16]byte{1}, 1, nil, context.Background(), [16]byte{7}, func(ctx context.Context, token [16]byte) (*udpReplacement, error) {
			if token != ([16]byte{7}) {
				t.Error("wrong resume token")
			}
			return &udpReplacement{conn: next, session: [16]byte{2}, flow: 2, token: [16]byte{8}}, nil
		})
		defer p.Close()
		packet := func(c net.Conn, session byte, flow, seq uint64, value byte) {
			payload, _ := encodePacket("127.0.0.1:53", []byte{value})
			if err := writeFrame(c, frame{typ: typePacket, session: [16]byte{session}, flow: flow, sequence: seq, payload: payload}); err != nil {
				t.Error(err)
			}
		}
		go packet(b, 1, 1, 99, 10)
		var buf [1]byte
		if _, _, err := p.ReadFrom(buf[:]); err != nil || buf[0] != 10 {
			t.Fatal("initial packet", err)
		}
		b.Close()
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		// Sequence zero on the replacement is new. Within that generation reorder
		// and duplicate suppression still apply; there is deliberately no cross-
		// generation packet-content deduplication.
		go func() {
			for _, v := range []struct {
				s uint64
				b byte
			}{{2, 20}, {0, 10}, {1, 30}, {1, 99}, {70, 40}, {0, 99}} {
				packet(peer, 2, 2, v.s, v.b)
			}
		}()
		for _, want := range []byte{20, 10, 30, 40} {
			if _, _, err := p.ReadFrom(buf[:]); err != nil || buf[0] != want {
				t.Fatalf("packet got %d want %d: %v", buf[0], want, err)
			}
		}
		p.SetReadDeadline(time.Now().Add(time.Millisecond))
		if _, _, err := p.ReadFrom(buf[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("duplicate delivered: %v", err)
		}
		// Nothing is sent automatically when resuming an idle association.
		peer.SetReadDeadline(time.Now().Add(time.Millisecond))
		if _, err := readFrame(peer); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("unsolicited replay/control: %v", err)
		}
		peer.Close()
	})
}

type acceptedErrorConn struct{ net.Conn }

func (c acceptedErrorConn) Abort() error { abortCarrier(c.Conn); return nil }

func (c acceptedErrorConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
func TestUDPResumeAmbiguousWriteIsNotReplayed(t *testing.T) {
	testUDPResumeAmbiguousWriteIsNotReplayed(t, false)
}

func TestActiveFallbackUDPDoesNotReplayAmbiguousWrite(t *testing.T) {
	testUDPResumeAmbiguousWriteIsNotReplayed(t, true)
}

func testUDPResumeAmbiguousWriteIsNotReplayed(t *testing.T, active bool) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		next, peer := net.Pipe()
		defer peer.Close()
		h := newCarrierHandoff(false, active)
		p := newResumablePacketConnWithPolicy(acceptedErrorConn{a}, [16]byte{1}, 1, nil, context.Background(), [16]byte{1}, func(_ context.Context, token [16]byte) (*udpReplacement, error) {
			if h.tcp() != active || token != ([16]byte{1}) {
				t.Error("wrong UDP carrier or resume identity")
			}
			return &udpReplacement{conn: next, session: [16]byte{2}, flow: 2, token: [16]byte{2}}, nil
		}, h.prepare)
		defer p.Close()
		original := make(chan frame, 1)
		go func() { f, _ := readFrame(b); original <- f }()
		destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
		if n, err := p.WriteTo([]byte("uncertain"), destination); n != len("uncertain") || err != nil {
			t.Fatalf("ambiguous write: %d %v", n, err)
		}
		f := <-original
		_, payload, _ := decodePacket(f.payload)
		if string(payload) != "uncertain" {
			t.Fatal("fault did not deliver original")
		}
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		got := make(chan frame, 1)
		go func() { f, _ := readFrame(peer); got <- f }()
		newPayload := []byte("new")
		if active {
			// Exercise the maximum migrated wire frame independently of the
			// host UDP socket's (possibly smaller) native datagram limit.
			newPayload = bytes.Repeat([]byte{0xab}, maxUDPDatagram)
		}
		if _, err := p.WriteTo(newPayload, destination); err != nil {
			t.Fatal(err)
		}
		f = <-got
		_, payload, _ = decodePacket(f.payload)
		if !bytes.Equal(payload, newPayload) || f.sequence != 0 || f.flow != 2 {
			t.Fatalf("old packet replayed or sequence retained: sequence=%d flow=%d payload_bytes=%d", f.sequence, f.flow, len(payload))
		}
		peer.Close()
	})
}
func TestUDPResumeCancellationAndDeadline(t *testing.T) {
	testUDPResumeCancellationAndDeadline(t, false)
}

func TestActiveFallbackUDPCancellationAndDeadline(t *testing.T) {
	testUDPResumeCancellationAndDeadline(t, true)
}

func testUDPResumeCancellationAndDeadline(t *testing.T, active bool) {
	for _, kind := range []string{"close-backoff", "close-open", "read-deadline", "write-deadline", "permanent", "budget"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := net.Pipe()
				defer b.Close()
				entered := make(chan struct{})
				cancelled := make(chan struct{})
				var attempts atomic.Int32
				h := newCarrierHandoff(false, active)
				p := newResumablePacketConnWithPolicy(a, [16]byte{1}, 1, nil, context.Background(), [16]byte{1}, func(ctx context.Context, _ [16]byte) (*udpReplacement, error) {
					if h.tcp() != active {
						t.Error("resume selected wrong carrier")
					}
					attempts.Add(1)
					if kind == "permanent" {
						return nil, identityError{errors.New("expired")}
					}
					if kind == "budget" {
						return nil, io.ErrUnexpectedEOF
					}
					close(entered)
					<-ctx.Done()
					close(cancelled)
					return nil, ctx.Err()
				}, h.prepare)
				defer p.Close()
				b.Close()
				synctest.Wait()
				if kind == "close-backoff" {
					p.Close()
					synctest.Wait()
					if attempts.Load() != 0 {
						t.Fatal("close allowed another attempt")
					}
					return
				}
				if kind == "budget" || kind == "permanent" {
					<-p.wire.done
					want := int32(3)
					if kind == "permanent" {
						want = 1
					}
					if attempts.Load() != want {
						t.Fatalf("attempts=%d", attempts.Load())
					}
					return
				}
				<-entered
				if kind == "read-deadline" {
					p.SetReadDeadline(time.Now().Add(time.Millisecond))
					if _, _, err := p.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatal(err)
					}
				}
				if kind == "write-deadline" {
					p.SetWriteDeadline(time.Now().Add(time.Millisecond))
					if _, err := p.WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}); !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatal(err)
					}
				}
				p.Close()
				<-cancelled
				select {
				case <-p.wire.done:
				default:
					t.Fatal("Close did not terminate")
				}
			})
		})
	}
}

func TestUDPResumeMalformedPacketIsTerminal(t *testing.T) {
	for _, kind := range []string{"flags", "identity", "source", "reset", "frame"} {
		t.Run(kind, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			var attempts atomic.Int32
			p := newResumablePacketConn(a, [16]byte{1}, 1, nil, context.Background(), [16]byte{}, func(context.Context, [16]byte) (*udpReplacement, error) { attempts.Add(1); return nil, io.EOF })
			defer p.Close()
			payload, _ := encodePacket("127.0.0.1:53", []byte{1})
			f := frame{typ: typePacket, session: [16]byte{1}, flow: 1, payload: payload}
			switch kind {
			case "flags":
				f.flags = flagFIN
			case "identity":
				f.flow = 2
			case "source":
				f.payload, _ = encodePacket("example.com:53", nil)
			case "reset":
				f.typ = typeReset
				f.payload = []byte{4}
			case "frame":
				f.typ = typeData
			}
			go writeFrame(b, f)
			select {
			case <-p.wire.done:
			case <-time.After(time.Second):
				t.Fatal("invalid packet did not terminate")
			}
			if attempts.Load() != 0 {
				t.Fatal("protocol violation caused recovery")
			}
		})
	}
}
func TestUDPResumeAttemptExhaustionError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		p := newResumablePacketConn(a, [16]byte{1}, 1, nil, context.Background(), [16]byte{}, func(context.Context, [16]byte) (*udpReplacement, error) { return nil, io.EOF })
		defer p.Close()
		b.Close()
		<-p.wire.done
		p.wire.mu.Lock()
		err := p.wire.err
		p.wire.mu.Unlock()
		if !strings.Contains(err.Error(), "attempts exhausted") {
			t.Fatal(err)
		}
	})
}

type udpCopySource struct{ packets [][]byte }

func (s *udpCopySource) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	if len(s.packets) == 0 {
		return M.Socksaddr{}, io.EOF
	}
	_, err := b.Write(s.packets[0])
	s.packets = s.packets[1:]
	return M.ParseSocksaddr("127.0.0.1:53"), err
}
func TestUDPResumeSingBoxCopyContinuesAfterAmbiguousWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		next, peer := net.Pipe()
		defer peer.Close()
		p := newResumablePacketConn(acceptedErrorConn{a}, [16]byte{1}, 1, nil, context.Background(), [16]byte{}, func(context.Context, [16]byte) (*udpReplacement, error) {
			return &udpReplacement{conn: next, session: [16]byte{2}, flow: 2}, nil
		})
		defer p.Close()
		seen := make(chan string, 2)
		go func() { f, _ := readFrame(b); _, data, _ := decodePacket(f.payload); seen <- string(data) }()
		go func() { f, _ := readFrame(peer); _, data, _ := decodePacket(f.payload); seen <- string(data) }()
		n, err := bufio.CopyPacket(bufio.NewPacketConn(p), &udpCopySource{packets: [][]byte{[]byte("uncertain"), []byte("following")}})
		if n != 18 || !errors.Is(err, io.EOF) {
			t.Fatalf("native CopyPacket stopped on recoverable carrier error: %d %v", n, err)
		}
		got := map[string]int{}
		got[<-seen]++
		got[<-seen]++
		if got["uncertain"] != 1 || got["following"] != 1 {
			t.Fatalf("copy dropped following packet or replayed: %v", got)
		}
		peer.Close()
	})
}
