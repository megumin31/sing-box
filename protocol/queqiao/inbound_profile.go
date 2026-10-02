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
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
)

type serverProfile struct {
	Version            int    `json:"version"`
	ProviderID         string `json:"provider_id"`
	GatewayID          string `json:"gateway_id"`
	RootPin            string `json:"root_pin"`
	RootCertificate    string `json:"root_certificate_pem"`
	GatewayCertificate string `json:"gateway_certificate_pem"`
	GatewayPrivateKey  string `json:"gateway_private_key_pem"`
}

type inboundPrincipal struct {
	account, device string
	public          [32]byte
}

// Read only a specifically configured gateway credential file. Reuse the
// existing no-follow opening policy, bounds and private-key permission rule.
func loadServerProfile(path string, users []option.QueqiaoInboundUser) (*tls.Config, map[inboundPrincipal]string, error) {
	allowed := make(map[inboundPrincipal]string, len(users))
	devices := make(map[[2]string]bool, len(users))
	if len(users) == 0 || len(users) > 256 {
		return nil, nil, errors.New("queqiao: server requires 1 to 256 explicit authorized devices")
	}
	for _, user := range users {
		if !validID(user.AccountID) || !validID(user.DeviceID) || len(user.Name) > 128 {
			return nil, nil, errors.New("queqiao: invalid authorized device")
		}
		public, err := base64.RawURLEncoding.DecodeString(user.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return nil, nil, errors.New("queqiao: authorized device requires an Ed25519 public_key")
		}
		key := inboundPrincipal{account: user.AccountID, device: user.DeviceID}
		copy(key.public[:], public)
		device := [2]string{user.AccountID, user.DeviceID}
		if devices[device] {
			return nil, nil, errors.New("queqiao: duplicate authorized device")
		}
		devices[device] = true
		allowed[key] = user.Name
	}
	f, err := openProfileFile(path)
	if err != nil {
		return nil, nil, errors.New("queqiao: could not open gateway credentials")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxProfileSize || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, nil, errors.New("queqiao: gateway credentials require a bounded private regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxProfileSize+1))
	if err != nil || len(raw) > maxProfileSize {
		return nil, nil, errors.New("queqiao: could not read bounded gateway credentials")
	}
	var p serverProfile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil {
		return nil, nil, errors.New("queqiao: invalid gateway credentials JSON")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return nil, nil, errors.New("queqiao: trailing gateway credentials data")
	}
	config, err := p.serverTLSConfig(allowed, time.Now())
	return config, allowed, err
}

func (p serverProfile) serverTLSConfig(allowed map[inboundPrincipal]string, now time.Time) (*tls.Config, error) {
	if p.Version != 1 || !validID(p.ProviderID) || !validID(p.GatewayID) {
		return nil, errors.New("queqiao: invalid gateway credential identity")
	}
	block, rest := pem.Decode([]byte(p.RootCertificate))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("queqiao: invalid server provider root PEM")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 || root.MaxPathLen != 1 || root.CheckSignatureFrom(root) != nil {
		return nil, errors.New("queqiao: invalid server provider root")
	}
	if _, ok := root.PublicKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("queqiao: server provider root must use Ed25519")
	}
	pin, provider := sha256.Sum256(root.Raw), sha256.Sum256(root.RawSubjectPublicKeyInfo)
	if p.RootPin != base64.RawURLEncoding.EncodeToString(pin[:]) || p.ProviderID != hex.EncodeToString(provider[:16]) {
		return nil, errors.New("queqiao: server root pin or provider identity mismatch")
	}
	cert, err := tls.X509KeyPair([]byte(p.GatewayCertificate), []byte(p.GatewayPrivateKey))
	if err != nil || len(cert.Certificate) < 2 {
		return nil, errors.New("queqiao: invalid gateway certificate chain or key")
	}
	chain := make([]*x509.Certificate, len(cert.Certificate))
	for i, raw := range cert.Certificate {
		chain[i], err = x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.New("queqiao: invalid gateway certificate")
		}
	}
	if _, ok := chain[0].PublicKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("queqiao: gateway key must use Ed25519")
	}
	if len(chain[0].URIs) != 1 || chain[0].URIs[0].String() != "queqiao://"+p.ProviderID+"/gateway/"+p.GatewayID {
		return nil, errors.New("queqiao: gateway certificate URI mismatch")
	}
	foundRoot := false
	for _, c := range chain[1:] {
		foundRoot = foundRoot || c.Equal(root)
	}
	if !foundRoot || verifyChain(chain, root, x509.ExtKeyUsageServerAuth, now) != nil {
		return nil, errors.New("queqiao: gateway chain verification failed")
	}
	cert.Leaf = chain[0]
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{dataALPN}, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != dataALPN || len(state.PeerCertificates) < 2 {
				return identityError{errors.New("queqiao: invalid authenticated device handshake")}
			}
			if verifyChain(state.PeerCertificates, root, x509.ExtKeyUsageClientAuth, time.Now()) != nil {
				return identityError{errors.New("queqiao: device chain verification failed")}
			}
			principal, err := parseInboundPrincipal(state.PeerCertificates[0], p.ProviderID)
			if err != nil {
				return err
			}
			if _, ok := allowed[principal]; !ok {
				return identityError{errors.New("queqiao: device is not authorized")}
			}
			return nil
		},
	}, nil
}

func parseInboundPrincipal(leaf *x509.Certificate, provider string) (inboundPrincipal, error) {
	var principal inboundPrincipal
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok || len(leaf.URIs) != 1 {
		return principal, identityError{errors.New("queqiao: invalid device certificate identity")}
	}
	u := leaf.URIs[0]
	parts := strings.Split(u.Path, "/")
	if u.Scheme != "queqiao" || u.Host != provider || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || len(parts) != 5 || parts[0] != "" || parts[1] != "account" || parts[3] != "device" || !validID(parts[2]) || !validID(parts[4]) {
		return principal, identityError{errors.New("queqiao: device URI identity mismatch")}
	}
	principal.account, principal.device = parts[2], parts[4]
	copy(principal.public[:], leaf.PublicKey.(ed25519.PublicKey))
	return principal, nil
}
