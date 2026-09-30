package queqiao

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxProfileSize = 1 << 20

type clientProfile struct {
	Version           int    `json:"version"`
	Name              string `json:"name"`
	ProviderID        string `json:"provider_id"`
	Endpoint          string `json:"endpoint"`
	GatewayID         string `json:"gateway_id"`
	RootPin           string `json:"root_pin"`
	RootCertificate   string `json:"root_certificate_pem"`
	AccountID         string `json:"account_id"`
	DeviceID          string `json:"device_id"`
	DeviceName        string `json:"device_name"`
	DeviceCertificate string `json:"device_certificate_pem"`
	DevicePrivateKey  string `json:"device_private_key_pem"`
	CreatedAt         string `json:"created_at"`
	HopPortCount      int    `json:"hop_port_count,omitempty"`
}

func validID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && strings.ToLower(id) == id
}

func canonicalAddress(address string, limit int) (string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" || !utf8.ValidString(host) {
		return "", errors.New("queqiao: invalid host:port")
	}
	for _, r := range host {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", errors.New("queqiao: invalid host characters")
		}
	}
	for _, r := range portText {
		if r < '0' || r > '9' {
			return "", errors.New("queqiao: non-decimal port")
		}
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", errors.New("queqiao: invalid port")
	}
	result := net.JoinHostPort(host, strconv.FormatUint(port, 10))
	if len(result) > limit {
		return "", errors.New("queqiao: address exceeds protocol limit")
	}
	return result, nil
}

func loadProfile(path string) (*tls.Config, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("queqiao: open profile: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() || info.Size() > maxProfileSize {
		return nil, "", errors.New("queqiao: profile must be a regular file of at most 1 MiB")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, "", errors.New("queqiao: profile contains a private key; permissions must exclude group and other users")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxProfileSize+1))
	if err != nil || len(raw) > maxProfileSize {
		return nil, "", errors.New("queqiao: could not read bounded profile")
	}
	var p clientProfile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	// Do not wrap JSON parser errors: they may contain credential fragments.
	if decoder.Decode(&p) != nil {
		return nil, "", errors.New("queqiao: invalid profile JSON")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return nil, "", errors.New("queqiao: trailing profile data")
	}
	config, err := p.tlsConfig(time.Now())
	return config, p.Endpoint, err
}

func (p clientProfile) tlsConfig(now time.Time) (*tls.Config, error) {
	if p.Version != 1 {
		return nil, fmt.Errorf("queqiao: unsupported profile version %d", p.Version)
	}
	for _, id := range []string{p.ProviderID, p.GatewayID, p.AccountID, p.DeviceID} {
		if !validID(id) {
			return nil, errors.New("queqiao: invalid profile identity")
		}
	}
	for _, name := range []string{p.Name, p.DeviceName} {
		if name == "" || len(name) > 128 || strings.TrimSpace(name) != name {
			return nil, errors.New("queqiao: invalid profile name")
		}
	}
	if _, err := time.Parse(time.RFC3339, p.CreatedAt); err != nil {
		return nil, errors.New("queqiao: invalid profile creation time")
	}
	if _, err := canonicalAddress(p.Endpoint, 512); err != nil {
		return nil, err
	}
	block, rest := pem.Decode([]byte(p.RootCertificate))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("queqiao: invalid provider root PEM")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("queqiao: invalid provider root certificate")
	}
	if !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 || root.MaxPathLen != 1 || root.CheckSignatureFrom(root) != nil {
		return nil, errors.New("queqiao: root is not a self-signed constrained CA")
	}
	if _, ok := root.PublicKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("queqiao: provider root must use Ed25519")
	}
	pin := sha256.Sum256(root.Raw)
	provider := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	if p.RootPin != base64.RawURLEncoding.EncodeToString(pin[:]) || p.ProviderID != hex.EncodeToString(provider[:16]) {
		return nil, errors.New("queqiao: profile root pin or provider identity mismatch")
	}
	cert, err := tls.X509KeyPair([]byte(p.DeviceCertificate), []byte(p.DevicePrivateKey))
	if err != nil || len(cert.Certificate) < 2 {
		return nil, errors.New("queqiao: invalid device key or certificate chain")
	}
	chain := make([]*x509.Certificate, len(cert.Certificate))
	for i, raw := range cert.Certificate {
		chain[i], err = x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.New("queqiao: invalid device certificate")
		}
	}
	if _, ok := chain[0].PublicKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("queqiao: device key must use Ed25519")
	}
	wantDevice := "queqiao://" + p.ProviderID + "/account/" + p.AccountID + "/device/" + p.DeviceID
	if len(chain[0].URIs) != 1 || chain[0].URIs[0].String() != wantDevice {
		return nil, errors.New("queqiao: device certificate does not match profile identity")
	}
	if err = verifyChain(chain, root, x509.ExtKeyUsageClientAuth, now); err != nil {
		return nil, fmt.Errorf("queqiao: verify device certificate: %w", err)
	}
	wantGateway := "queqiao://" + p.ProviderID + "/gateway/" + p.GatewayID
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{dataALPN}, Certificates: []tls.Certificate{cert},
		// Queqiao uses a pinned provider root and a URI identity, never DNS/WebPKI.
		// This mandatory callback replaces all default verification; no insecure option exists.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != dataALPN {
				return errors.New("queqiao: TLS version or ALPN mismatch")
			}
			if len(state.PeerCertificates) < 2 {
				return errors.New("queqiao: gateway certificate chain is incomplete")
			}
			found := false
			for _, c := range state.PeerCertificates[1:] {
				if c.Equal(root) {
					found = true
				}
			}
			if !found {
				return errors.New("queqiao: gateway did not supply pinned provider root")
			}
			if err := verifyChain(state.PeerCertificates, root, x509.ExtKeyUsageServerAuth, time.Now()); err != nil {
				return fmt.Errorf("queqiao: verify gateway: %w", err)
			}
			leaf := state.PeerCertificates[0]
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != wantGateway {
				return errors.New("queqiao: gateway URI identity mismatch")
			}
			return nil
		},
	}, nil
}

func verifyChain(chain []*x509.Certificate, root *x509.Certificate, usage x509.ExtKeyUsage, now time.Time) error {
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, c := range chain[1:] {
		if !c.Equal(root) {
			intermediates.AddCert(c)
		}
	}
	_, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}})
	return err
}
