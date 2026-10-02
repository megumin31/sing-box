package option

import "github.com/sagernet/sing/common/json/badoption"

// QueqiaoInboundOptions is the native reliable server configuration. Gateway
// identity is imported separately; the inbound never issues enrollment keys.
type QueqiaoInboundOptions struct {
	ListenOptions
	CredentialsPath string               `json:"credentials_path"`
	Transport       string               `json:"transport,omitempty" enum:"tcp,quic,auto"`
	Users           []QueqiaoInboundUser `json:"users"`
	MaxSessions     int                  `json:"max_sessions,omitempty"`
	QUICIdleTimeout badoption.Duration   `json:"quic_idle_timeout,omitempty"`
}

type QueqiaoInboundUser struct {
	Name      string `json:"name,omitempty"`
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
}

// QueqiaoOutboundOptions imports an already enrolled official Queqiao profile.
// TLS identity and the endpoint come from the profile, not WebPKI settings.
type QueqiaoOutboundOptions struct {
	DialerOptions
	ProfilePath         string      `json:"profile_path"`
	Transport           string      `json:"transport,omitempty" enum:"tcp,quic"`
	QUICDataIsolation   bool        `json:"quic_data_isolation,omitempty"`
	QUICPathProbe       bool        `json:"quic_path_probe,omitempty"`
	QUICInitialFallback bool        `json:"quic_initial_fallback,omitempty"`
	QUICActiveFallback  bool        `json:"quic_active_fallback,omitempty"`
	UDPResume           bool        `json:"udp_resume,omitempty"`
	TCPLanes            int         `json:"tcp_lanes,omitempty"`
	TCPRecovery         bool        `json:"tcp_recovery,omitempty"`
	Network             NetworkList `json:"network,omitempty"`
}
