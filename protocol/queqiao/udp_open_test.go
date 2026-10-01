package queqiao

import (
	"bytes"
	"context"
	"crypto/tls"
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

func TestUDPResumeResponseValidation(t *testing.T) {
	for _, kind := range []string{"valid", "fresh", "identity", "flags", "sequence", "short", "long", "invalid-status", "wrong-type", "capacity", "authentication", "cancel", "initial-valid", "initial-resumed", "initial-empty"} {
		t.Run(kind, func(t *testing.T) {
			profile, certificate, _ := testIdentity(t)
			data, _ := json.Marshal(profile)
			path := filepath.Join(t.TempDir(), "profile.json")
			os.WriteFile(path, data, 0600)
			a, err := NewOutbound(context.Background(), nil, nil, "udp-open", option.QueqiaoOutboundOptions{ProfilePath: path, UDPResume: true})
			if err != nil {
				t.Fatal(err)
			}
			o := a.(*Outbound)
			defer o.Close()
			ready := make(chan struct{})
			closedFresh := make(chan bool, 1)
			o.dialer = testDialer{dial: func(ctx context.Context, n string, d M.Socksaddr) (net.Conn, error) {
				client, peer := net.Pipe()
				go func() {
					defer peer.Close()
					server := tls.Server(peer, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{dataALPN}})
					f, e := readFrame(server)
					if e != nil {
						return
					}
					if f.typ != typeOpen || f.flags != 0 || f.sequence != 0 || !isUDPResumeOpen(f.payload) {
						t.Error("invalid outgoing UDP OPEN")
						return
					}
					initial := len(f.payload) == 5
					if !initial && !bytes.Equal(f.payload[5:], bytes.Repeat([]byte{7}, 16)) {
						t.Error("wrong outgoing token")
					}
					close(ready)
					if kind == "cancel" {
						io.Copy(io.Discard, server)
						return
					}
					grant := append([]byte{1}, bytes.Repeat([]byte{8}, 16)...)
					response := frame{typ: typeOpenOK, session: f.session, flow: f.flow, payload: grant}
					switch kind {
					case "fresh", "initial-valid":
						response.payload[0] = 0
					case "identity":
						response.flow++
					case "flags":
						response.flags = flagFIN
					case "sequence":
						response.sequence = 1
					case "short":
						response.payload = grant[:16]
					case "long":
						response.payload = append(grant, 1)
					case "invalid-status":
						response.payload[0] = 2
					case "wrong-type":
						response.typ = typeData
					case "capacity":
						response.typ = typeReset
						response.payload = []byte{4}
					case "authentication":
						response.typ = typeReset
						response.payload = []byte{2}
					case "initial-empty":
						response.payload = nil
					}
					if writeFrame(server, response) != nil {
						return
					}
					if kind == "fresh" {
						f, e = readFrame(server)
						closedFresh <- e == nil && f.typ == typeClose && f.flags == flagFIN && f.sequence == 0
						if e == nil {
							writeFrame(server, frame{typ: typeACK, flags: flagACKFinal, session: f.session, flow: f.flow})
						}
					}
					if kind == "valid" || kind == "initial-valid" {
						io.Copy(io.Discard, server)
					}
				}()
				return client, nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if kind == "cancel" {
				go func() { <-ready; cancel() }()
			}
			if len(kind) >= 8 && kind[:8] == "initial-" {
				opened, e := o.openFlow(ctx, []byte("WOUD\x02"), M.ParseSocksaddr("example.com:53"))
				if kind == "initial-valid" {
					if e != nil {
						t.Fatal(e)
					}
					closeCarrier(opened.conn)
					opened.remove()
				} else if e == nil {
					closeCarrier(opened.conn)
					opened.remove()
					t.Fatal("invalid initial grant accepted")
				}
				return
			}
			var token [16]byte
			copy(token[:], bytes.Repeat([]byte{7}, 16))
			r, err := o.resumeUDP(ctx, M.ParseSocksaddr("example.com:53"), 0, token)
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				closeCarrier(r.conn)
				return
			}
			if r != nil {
				closeCarrier(r.conn)
				t.Fatal("invalid resume response accepted")
			}
			if kind == "cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				return
			}
			if kind == "capacity" {
				if err == nil || permanentRecoveryError(err) {
					t.Fatalf("capacity classification: %v", err)
				}
			} else if !permanentRecoveryError(err) {
				t.Fatalf("invalid grant not terminal: %v", err)
			}
			if kind == "fresh" && !<-closedFresh {
				t.Fatal("rejected fresh relay was not gracefully closed")
			}
		})
	}
}
