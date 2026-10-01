package queqiao

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestJoinResponseValidation(t *testing.T) {
	for _, kind := range []string{"valid", "identity", "flags", "sequence", "payload", "wrong-type", "capacity", "authentication", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			profile, certificate, _ := testIdentity(t)
			data, _ := json.Marshal(profile)
			path := filepath.Join(t.TempDir(), "profile.json")
			os.WriteFile(path, data, 0600)
			a, err := NewOutbound(context.Background(), nil, nil, "join", option.QueqiaoOutboundOptions{ProfilePath: path, TCPRecovery: true})
			if err != nil {
				t.Fatal(err)
			}
			o := a.(*Outbound)
			defer o.Close()
			ready := make(chan struct{})
			o.dialer = testDialer{dial: func(ctx context.Context, n string, d M.Socksaddr) (net.Conn, error) {
				client, peer := net.Pipe()
				go func() {
					defer peer.Close()
					server := tls.Server(peer, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{dataALPN}})
					f, e := readFrame(server)
					if e != nil {
						return
					}
					if f.typ != typeJoin || f.flags != 0 || f.sequence != 0 || len(f.payload) != 8 || binary.BigEndian.Uint64(f.payload) != 3 {
						t.Errorf("invalid outgoing JOIN: %+v", f)
						return
					}
					close(ready)
					if kind == "cancel" {
						io.Copy(io.Discard, server)
						return
					}
					response := frame{typ: typeOpenOK, session: f.session, flow: f.flow}
					switch kind {
					case "identity":
						response.flow++
					case "flags":
						response.flags = flagFIN
					case "sequence":
						response.sequence = 1
					case "payload":
						response.payload = []byte{1}
					case "wrong-type":
						response.typ = typeData
					case "capacity":
						response.typ = typeReset
						response.payload = []byte{4}
					case "authentication":
						response.typ = typeReset
						response.payload = []byte{2}
					}
					writeFrame(server, response)
				}()
				return client, nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if kind == "cancel" {
				go func() { <-ready; cancel() }()
			}
			joined, err := o.joinFlow(ctx, M.ParseSocksaddr("example.com:443"), 0, [16]byte{1}, 2, 3)
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				joined.Close()
				return
			}
			if joined != nil {
				joined.Close()
				t.Fatal("invalid JOIN response accepted")
			}
			if kind == "cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("JOIN cancel: %v", err)
				}
				return
			}
			if kind == "capacity" {
				if err == nil || permanentRecoveryError(err) {
					t.Fatalf("capacity not classified transient: %v", err)
				}
			} else if !permanentRecoveryError(err) {
				t.Fatalf("bad JOIN response not terminal: %v", err)
			}
		})
	}
}
