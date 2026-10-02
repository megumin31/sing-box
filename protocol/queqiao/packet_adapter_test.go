package queqiao

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

// Exercise the same adapter used by route/conn.go, not only direct WriteTo.
func TestPacketAdapterPreservesDestination(t *testing.T) {
	for _, address := range []string{"localhost:5353", "127.0.0.1:5353", "[::1]:5353"} {
		for _, size := range []int{0, 1200} {
			t.Run(fmt.Sprintf("%s/%d", address, size), func(t *testing.T) {
				p, peer := packetPair(t)
				type result struct {
					f   frame
					err error
				}
				received := make(chan result, 1)
				go func() { f, e := readFrame(peer); received <- result{f, e} }()
				payload := bytes.Repeat([]byte{42}, size)
				buffer := buf.NewSize(max(1, size))
				_, _ = buffer.Write(payload)
				err := bufio.NewPacketConn(p).WritePacket(buffer, M.ParseSocksaddr(address))
				if buffer.Cap() != 0 {
					t.Error("WritePacket did not release owned buffer")
				}
				if err != nil {
					peer.Close()
					<-received
					t.Fatalf("actual routing adapter rejected destination: %v", err)
				}
				got := <-received
				if got.err != nil {
					t.Fatal(got.err)
				}
				destination, body, e := decodePacket(got.f.payload)
				if e != nil || destination != address || !bytes.Equal(body, payload) || got.f.typ != typePacket || got.f.sequence != 0 || got.f.session != [16]byte{1} || got.f.flow != 1 {
					t.Fatalf("wire destination=%q size=%d frame=%+v error=%v", destination, len(body), got.f, e)
				}
			})
		}
	}
}

func TestPacketAdapterWriteFailureReleasesBuffer(t *testing.T) {
	for _, kind := range []string{"invalid-address", "oversized", "closed", "write-deadline"} {
		t.Run(kind, func(t *testing.T) {
			p, _ := packetPair(t)
			address := M.ParseSocksaddr("127.0.0.1:5353")
			size := 1
			switch kind {
			case "invalid-address":
				address = M.Socksaddr{}
			case "oversized":
				size = maxUDPDatagram + 1
			case "closed":
				p.wire.terminate(io.ErrClosedPipe)
			case "write-deadline":
				p.SetWriteDeadline(time.Now().Add(-time.Second))
			}
			buffer := buf.NewSize(size)
			_, _ = buffer.Write(make([]byte, size))
			if err := bufio.NewPacketConn(p).WritePacket(buffer, address); err == nil {
				t.Fatal("invalid write succeeded")
			}
			if buffer.Cap() != 0 {
				t.Fatal("failed WritePacket retained owned buffer")
			}
		})
	}
}

func TestPacketAdapterReadBufferContract(t *testing.T) {
	p, peer := packetPair(t)
	adapter := bufio.NewPacketConn(p)
	source := "[::1]:5353"
	full := buf.NewSize(1)
	_, _ = full.WriteString("x")
	_, fullErr := adapter.ReadPacket(full)
	if !errors.Is(fullErr, io.ErrShortBuffer) || string(full.Bytes()) != "x" {
		t.Fatalf("full read buffer contract: %v", fullErr)
	}
	full.Release()
	for seq, payload := range [][]byte{nil, []byte("abcdef"), []byte("next")} {
		encoded, err := encodePacket(source, payload)
		if err != nil {
			t.Fatal(err)
		}
		wrote := make(chan error, 1)
		go func() {
			wrote <- writeFrame(peer, frame{typ: typePacket, session: [16]byte{1}, flow: 1, sequence: uint64(seq), payload: encoded})
		}()
		buffer := buf.NewSize(8)
		_, _ = buffer.WriteString("pre")
		got, err := adapter.ReadPacket(buffer)
		if err != nil || got.String() != source {
			buffer.Release()
			t.Fatalf("source=%s err=%v", got, err)
		}
		want := append([]byte("pre"), payload[:min(5, len(payload))]...)
		if !bytes.Equal(buffer.Bytes(), want) {
			t.Errorf("read/truncate changed datagram: %q", buffer.Bytes())
		}
		if buffer.Cap() == 0 {
			t.Error("ReadPacket released caller-owned buffer")
		}
		buffer.Release()
		if err = <-wrote; err != nil {
			t.Fatal(err)
		}
	}
	p.SetReadDeadline(time.Now().Add(-time.Second))
	buffer := buf.NewSize(8)
	defer buffer.Release()
	_, _ = buffer.WriteString("pre")
	_, err := adapter.ReadPacket(buffer)
	if !errors.Is(err, os.ErrDeadlineExceeded) || string(buffer.Bytes()) != "pre" || buffer.Cap() == 0 {
		t.Fatalf("failed read changed/released buffer: %q %v", buffer.Bytes(), err)
	}
}
