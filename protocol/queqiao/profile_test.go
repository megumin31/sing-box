package queqiao

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testIdentity(t *testing.T) (clientProfile, tls.Certificate, []*x509.Certificate) {
	t.Helper()
	now := time.Now()
	serial := int64(0)
	issue := func(parent *x509.Certificate, parentKey ed25519.PrivateKey, ca bool, usage x509.ExtKeyUsage, uri string) (*x509.Certificate, ed25519.PrivateKey) {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial++
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "synthetic-test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
		if ca {
			template.KeyUsage |= x509.KeyUsageCertSign
			template.MaxPathLen = 0
			template.MaxPathLenZero = true
		}
		if parent == nil {
			template.MaxPathLen = 1
			template.MaxPathLenZero = false
			parent = template
			parentKey = key
		}
		if usage != 0 {
			template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		}
		if uri != "" {
			u, err := url.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			template.URIs = []*url.URL{u}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}
	root, rootKey := issue(nil, nil, true, 0, "")
	sum := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	provider := hex.EncodeToString(sum[:16])
	gateway := "11111111111111111111111111111111"
	account := "22222222222222222222222222222222"
	device := "33333333333333333333333333333333"
	gatewayIssuer, gatewayIssuerKey := issue(root, rootKey, true, x509.ExtKeyUsageServerAuth, "")
	deviceIssuer, deviceIssuerKey := issue(root, rootKey, true, x509.ExtKeyUsageClientAuth, "")
	gatewayCert, gatewayKey := issue(gatewayIssuer, gatewayIssuerKey, false, x509.ExtKeyUsageServerAuth, "queqiao://"+provider+"/gateway/"+gateway)
	deviceCert, deviceKey := issue(deviceIssuer, deviceIssuerKey, false, x509.ExtKeyUsageClientAuth, "queqiao://"+provider+"/account/"+account+"/device/"+device)
	certPEM := func(c *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(root.Raw)
	p := clientProfile{Version: 1, Name: "test", DeviceName: "synthetic", ProviderID: provider, GatewayID: gateway, AccountID: account, DeviceID: device, Endpoint: "127.0.0.1:12345", CreatedAt: now.Format(time.RFC3339), RootPin: base64.RawURLEncoding.EncodeToString(pin[:]), RootCertificate: certPEM(root), DeviceCertificate: certPEM(deviceCert) + certPEM(deviceIssuer) + certPEM(root), DevicePrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))}
	return p, tls.Certificate{Certificate: [][]byte{gatewayCert.Raw, gatewayIssuer.Raw, root.Raw}, PrivateKey: gatewayKey}, []*x509.Certificate{gatewayCert, gatewayIssuer, root}
}

func TestProfileAndGatewayAuthentication(t *testing.T) {
	p, _, chain := testIdentity(t)
	config, err := p.tlsConfig(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: dataALPN, PeerCertificates: chain}
	if err = config.VerifyConnection(state); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		name   string
		change func(*clientProfile)
	}{
		{"pin", func(p *clientProfile) { p.RootPin = "wrong" }},
		{"provider", func(p *clientProfile) { p.ProviderID = p.GatewayID }},
		{"device metadata", func(p *clientProfile) { p.DeviceID = p.AccountID }},
		{"account metadata", func(p *clientProfile) { p.AccountID = p.DeviceID }},
		{"key mismatch", func(p *clientProfile) { p.DevicePrivateKey = "invalid" }},
		{"root trailing", func(p *clientProfile) { p.RootCertificate += "junk" }},
		{"version", func(p *clientProfile) { p.Version = 2 }},
		{"endpoint", func(p *clientProfile) { p.Endpoint = "host:0" }},
	} {
		t.Run(v.name, func(t *testing.T) {
			q := p
			v.change(&q)
			if _, err := q.tlsConfig(time.Now()); err == nil {
				t.Fatal("accepted invalid profile")
			}
		})
	}
	if _, err := p.tlsConfig(time.Now().Add(2 * time.Hour)); err == nil {
		t.Fatal("accepted expired device certificate")
	}
	for _, v := range []struct {
		name   string
		change func(*tls.ConnectionState)
	}{
		{"wrong ALPN", func(s *tls.ConnectionState) { s.NegotiatedProtocol = "queqiao-enroll/1" }},
		{"missing ALPN", func(s *tls.ConnectionState) { s.NegotiatedProtocol = "" }},
		{"TLS12", func(s *tls.ConnectionState) { s.Version = tls.VersionTLS12 }},
		{"missing root", func(s *tls.ConnectionState) { s.PeerCertificates = chain[:2] }},
		{"wrong gateway", func(s *tls.ConnectionState) {
			leaf := *chain[0]
			u, _ := url.Parse("queqiao://" + p.ProviderID + "/gateway/" + p.DeviceID)
			leaf.URIs = []*url.URL{u}
			s.PeerCertificates = []*x509.Certificate{&leaf, chain[1], chain[2]}
		}},
		{"wrong EKU", func(s *tls.ConnectionState) {
			leaf := *chain[0]
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			s.PeerCertificates = []*x509.Certificate{&leaf, chain[1], chain[2]}
		}},
		{"expired gateway", func(s *tls.ConnectionState) {
			leaf := *chain[0]
			leaf.NotAfter = time.Now().Add(-time.Second)
			s.PeerCertificates = []*x509.Certificate{&leaf, chain[1], chain[2]}
		}},
	} {
		t.Run(v.name, func(t *testing.T) {
			bad := state
			v.change(&bad)
			if config.VerifyConnection(bad) == nil {
				t.Fatal("accepted unauthenticated gateway")
			}
		})
	}
}

func TestProfileFileBoundsAndPermissions(t *testing.T) {
	p, _, _ := testIdentity(t)
	raw, _ := json.Marshal(p)
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadProfile(path); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0644)
	if _, _, err := loadProfile(path); err == nil {
		t.Fatal("accepted publicly readable private key")
	}
	os.Chmod(path, 0600)
	os.WriteFile(path, append(raw, []byte(" {}")...), 0600)
	if _, _, err := loadProfile(path); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	os.WriteFile(path, make([]byte, maxProfileSize+1), 0600)
	if _, _, err := loadProfile(path); err == nil {
		t.Fatal("accepted oversized profile")
	}
}

func TestCanonicalDestination(t *testing.T) {
	for _, v := range []struct{ in, out string }{{"example.com:00080", "example.com:80"}, {"[::1]:443", "[::1]:443"}} {
		got, err := canonicalAddress(v.in, 255)
		if err != nil || got != v.out {
			t.Fatalf("%q: %q %v", v.in, got, err)
		}
	}
	for _, bad := range []string{"host:0", "host:65536", "host:+80", ":80", "a b:80", "a\n:80", "::1:80"} {
		if _, err := canonicalAddress(bad, 255); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
