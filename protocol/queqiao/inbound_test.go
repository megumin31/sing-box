package queqiao

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// These tests use in-memory pipes, never a host network listener.
func TestInboundProfileMutualTLSAuthorization(t *testing.T) {
	client, gateway, _ := testIdentity(t)
	profile := serverProfile{Version: 1, ProviderID: client.ProviderID, GatewayID: client.GatewayID, RootPin: client.RootPin, RootCertificate: client.RootCertificate}
	for _, der := range gateway.Certificate {
		profile.GatewayCertificate += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	der, err := x509.MarshalPKCS8PrivateKey(gateway.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	profile.GatewayPrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	clientConfig, err := client.tlsConfig(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var deviceChain []*x509.Certificate
	for _, der := range clientConfig.Certificates[0].Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		deviceChain = append(deviceChain, cert)
	}
	principal, err := parseInboundPrincipal(deviceChain[0], client.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[inboundPrincipal]string{principal: "test-device"}
	config, err := profile.serverTLSConfig(allowed, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: dataALPN, PeerCertificates: deviceChain}
	if err = config.VerifyConnection(state); err != nil {
		t.Fatalf("valid pinned device was rejected: %v", err)
	}
	delete(allowed, principal)
	wrongKey := principal
	wrongKey.public[0] ^= 1
	allowed[wrongKey] = "same IDs, different key"
	if err = config.VerifyConnection(state); err == nil {
		t.Fatal("accepted unpinned device key with matching IDs")
	}
	profile.RootPin = "invalid"
	if _, err = profile.serverTLSConfig(allowed, time.Now()); err == nil {
		t.Fatal("accepted invalid provider root pin")
	}
}

func TestInboundPrincipalPinsDevicePublicKey(t *testing.T) {
	provider := strings.Repeat("1", 32)
	u, err := url.Parse("queqiao://" + provider + "/account/" + strings.Repeat("2", 32) + "/device/" + strings.Repeat("3", 32))
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{PublicKey: ed25519.PublicKey(make([]byte, 32)), URIs: []*url.URL{u}}
	first, err := parseInboundPrincipal(leaf, provider)
	if err != nil {
		t.Fatal(err)
	}
	leaf.PublicKey.(ed25519.PublicKey)[0] = 1
	second, err := parseInboundPrincipal(leaf, provider)
	if err != nil || first == second {
		t.Fatalf("same routing IDs with a different device key must not share a principal: %v", err)
	}
	if _, err = parseInboundPrincipal(leaf, strings.Repeat("4", 32)); err == nil {
		t.Fatal("accepted the wrong provider")
	}
}

func TestInboundWireFailedTCPAdmissionExpires(t *testing.T) {
	w := newInboundWire(inboundFlowKey{session: [16]byte{1}, flow: 2}, false, true)
	w.grace = 20 * time.Millisecond
	defer w.Close()
	old, oldPeer := net.Pipe()
	defer oldPeer.Close()
	w.lanes = []*inboundLane{{raw: old, control: true}}
	raw, peer := net.Pipe()
	peer.Close()
	defer raw.Close()
	if err := w.admit(raw, true, false, frame{typ: typeOpenOK, session: w.key.session, flow: w.key.flow}); err == nil {
		t.Fatal("accepted a failed TCP admission")
	}
	w.SetReadDeadline(time.Now().Add(time.Second))
	_, err := w.Read(make([]byte, 1))
	if err == nil || !strings.Contains(err.Error(), "replacement grace exhausted") {
		t.Fatalf("failed admission leaked its logical flow: %v", err)
	}
	if !w.tcpMode {
		t.Fatal("failed TCP admission reverted the sticky selection")
	}
}

func TestInboundWireOrdinaryTCPRetiresRolesAndReplaysFIN(t *testing.T) {
	key := inboundFlowKey{session: [16]byte{1}, flow: 2}
	w := newInboundWire(key, false, true)
	defer w.Close()
	control, controlPeer := net.Pipe()
	data, dataPeer := net.Pipe()
	defer controlPeer.Close()
	defer dataPeer.Close()
	w.lanes = []*inboundLane{{raw: control, control: true}, {raw: data}}
	w.replay = []frame{{typ: typeData, session: key.session, flow: key.flow, payload: []byte("abcdef")}}
	w.replayBytes, w.sent = 6, 6
	w.ack = &frame{typ: typeACK, flags: flagACKUp, session: key.session, flow: key.flow, sequence: 4}
	w.fin = &frame{typ: typeClose, flags: flagFIN, session: key.session, flow: key.flow, sequence: 6}
	raw, peer := net.Pipe()
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	admitted := make(chan error, 1)
	go func() {
		admitted <- w.admit(raw, true, false, frame{typ: typeOpenOK, session: key.session, flow: key.flow})
	}()
	want := []byte{typeOpenOK, typeACK, typeData, typeClose}
	for _, typ := range want {
		f, err := readFrame(peer)
		if err != nil || f.typ != typ {
			t.Fatalf("admission replay type=%d got=%+v err=%v", typ, f, err)
		}
		if typ == typeData && string(f.payload) != "abcdef" || typ == typeClose && (f.flags != flagFIN || f.sequence != 6) {
			t.Fatalf("replay payload or FIN changed: %+v", f)
		}
	}
	if err := <-admitted; err != nil {
		t.Fatal(err)
	}
	for _, old := range []net.Conn{controlPeer, dataPeer} {
		if _, err := old.Write([]byte{1}); err == nil {
			t.Fatal("a retired QUIC role remained writable")
		}
	}
	if err := writeFrame(peer, frame{typ: typeACK, flags: flagACKDown, session: key.session, flow: key.flow, sequence: 3}); err != nil {
		t.Fatal(err)
	}
	w.SetReadDeadline(time.Now().Add(time.Second))
	f, err := readFrame(w)
	if err != nil || f.flags != flagACKUp || f.sequence != 3 {
		t.Fatalf("server ACK orientation was not mirrored: %+v %v", f, err)
	}
	w.mu.Lock()
	correct := len(w.lanes) == 1 && w.lanes[0].tcp && !w.lanes[0].control && w.replayBytes == 3 && w.replay[0].sequence == 3 && string(w.replay[0].payload) == "def"
	w.mu.Unlock()
	if !correct {
		t.Fatal("ordinary TCP admission or cumulative replay trimming is incorrect")
	}
	late, latePeer := net.Pipe()
	defer late.Close()
	defer latePeer.Close()
	if err = w.admit(late, false, true, frame{typ: typeOpenOK}); err == nil {
		t.Fatal("late QUIC role admission reversed sticky TCP")
	}
}

func TestInboundWirePacketOutageDoesNotReplay(t *testing.T) {
	w := newInboundWire(inboundFlowKey{session: [16]byte{1}, flow: 2}, true, false)
	defer w.Close()
	if err := writeFrame(w, frame{typ: typePacket, session: w.key.session, flow: w.key.flow, payload: []byte("possibly lost")}); err != nil {
		t.Fatal(err)
	}
	if len(w.replay) != 0 || w.replayBytes != 0 {
		t.Fatal("a datagram was retained for replay")
	}
}

type inboundCloseRecorder struct {
	net.Conn
	drained, aborted bool
}

func (c *inboundCloseRecorder) Close() error { c.drained = true; return c.Conn.Close() }
func (c *inboundCloseRecorder) Abort() error { c.aborted = true; return c.Conn.Close() }

func TestInboundCompletedClosePreservesQueuedFinalACK(t *testing.T) {
	for _, complete := range []bool{false, true} {
		raw, peer := net.Pipe()
		defer peer.Close()
		physical := &inboundCloseRecorder{Conn: raw}
		w := newInboundWire(inboundFlowKey{}, false, false)
		w.lanes = []*inboundLane{{raw: physical}}
		w.finalACK = complete
		w.fin = &frame{typ: typeClose, flags: flagFIN}
		w.ack = &frame{typ: typeACK, flags: flagACKUp | flagACKFinal}
		w.Close()
		if physical.drained != complete || physical.aborted == complete {
			t.Fatalf("complete=%v drain=%v abort=%v", complete, physical.drained, physical.aborted)
		}
	}
}

func TestInboundPacketCloseReclaimsGenerationAndToken(t *testing.T) {
	h := &Inbound{ctx: context.Background(), sessions: make(map[inboundFlowKey]*nativeSession), udpTokens: make(map[[16]byte]*inboundPacketConn), active: 1}
	p := newInboundPacketConn(h, inboundPrincipal{})
	key := inboundFlowKey{session: [16]byte{1}, flow: 2}
	p.wire = newInboundWire(key, true, false)
	h.sessions[key] = &nativeSession{packet: p}
	h.udpTokens[[16]byte{3}] = p
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if h.active != 0 || len(h.sessions) != 0 || len(h.udpTokens) != 0 {
		t.Fatal("UDP close leaked admission quota or resumable identity")
	}
	if err := p.Close(); err != nil || h.active != 0 {
		t.Fatal("repeated UDP close altered quota")
	}
	if _, err := p.wire.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Fatalf("UDP close left its wire open: %v", err)
	}
}

func TestNativePacketCopyPreservesMaximumPayload(t *testing.T) {
	h := &Inbound{ctx: context.Background(), sessions: make(map[inboundFlowKey]*nativeSession), udpTokens: make(map[[16]byte]*inboundPacketConn)}
	p := newInboundPacketConn(h, inboundPrincipal{})
	defer p.Close()
	key := inboundFlowKey{session: [16]byte{1}, flow: 2}
	w := newInboundWire(key, true, false)
	p.wire = w
	payload := strings.Repeat("x", maxUDPDatagram)
	encoded, err := encodePacket("127.0.0.1:53", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	w.queue = []frame{{typ: typePacket, session: key.session, flow: key.flow, payload: encoded}}
	w.queued = headerSize + len(encoded)
	for _, endpoint := range []any{p, &packetConn{}} {
		if N.CalculateMTU(endpoint, endpoint) != maxUDPDatagram {
			t.Fatal("native endpoint hid its maximum UDP capacity")
		}
	}
	buffer := N.NewReadWaitOptions(p, nil).NewPacketBuffer()
	defer buffer.Release()
	destination, err := p.ReadPacket(buffer)
	if err != nil || destination.String() != "127.0.0.1:53" || string(buffer.Bytes()) != payload {
		t.Fatalf("packet copy truncated a valid maximum payload: bytes=%d err=%v", buffer.Len(), err)
	}
}

func TestInboundCompletionTombstoneRetainsOnlyMetadata(t *testing.T) {
	h := &Inbound{sessions: make(map[inboundFlowKey]*nativeSession), active: 1}
	key := inboundFlowKey{session: [16]byte{1}, flow: 2}
	w := newInboundWire(key, false, true)
	c := newConnState(w, key.session, key.flow, nil)
	c.err, c.remoteFinal, c.sendNext = io.EOF, 4, 6
	c.queue.WriteString("application buffer still owned by router")
	f := &nativeSession{key: key, wire: w, conn: c, reserved: true, laneIDs: map[uint64]bool{3: true}}
	h.sessions[key] = f
	h.tcpEnded(f)
	tombstone := h.sessions[key]
	if tombstone == f || !tombstone.completed || !tombstone.reserved || tombstone.conn != nil || tombstone.wire != nil || tombstone.packet != nil || tombstone.upFinal != 4 || tombstone.downFinal != 6 || h.active != 0 {
		t.Fatal("completed flow retained payload/carrier state or lost final metadata")
	}
}

func TestInboundRouterCloseWaitsForFinalConfirmation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newConnState(new(fallbackMemoryConn), [16]byte{1}, 2, nil)
	c.localFIN, c.remoteFIN = true, true
	c.sendNext, c.recvNext, c.remoteFinal = 2, 3, 3
	routed := &inboundTCPConn{Conn: c, h: &Inbound{ctx: ctx}}
	closed := make(chan error, 1)
	go func() { closed <- routed.Close() }()
	select {
	case <-closed:
		t.Fatal("router EOF aborted the session before final confirmation")
	case <-time.After(20 * time.Millisecond):
	}
	c.mu.Lock()
	c.localFinalACK, c.remoteFinalACKSent = true, true
	c.mu.Unlock()
	c.finishIfComplete()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("router close did not settle after logical completion")
	}
	if !errors.Is(c.err, io.EOF) {
		t.Fatalf("normal close lost completion state: %v", c.err)
	}
}

func TestInboundRouterCompletionWaitIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := newConnState(new(fallbackMemoryConn), [16]byte{1}, 2, nil)
	c.localFIN, c.remoteFIN = true, true
	routed := &inboundTCPConn{Conn: c, h: &Inbound{ctx: ctx}}
	closed := make(chan error, 1)
	go func() { closed <- routed.Close() }()
	cancel()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("server shutdown retained the completion wait")
	}
}
