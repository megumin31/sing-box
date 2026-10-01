package option

// QueqiaoOutboundOptions imports an already enrolled official Queqiao profile.
// TLS identity and the endpoint come from the profile, not WebPKI settings.
type QueqiaoOutboundOptions struct {
	DialerOptions
	ProfilePath         string      `json:"profile_path"`
	Transport           string      `json:"transport,omitempty" enum:"tcp,quic"`
	QUICDataIsolation   bool        `json:"quic_data_isolation,omitempty"`
	QUICPathProbe       bool        `json:"quic_path_probe,omitempty"`
	QUICInitialFallback bool        `json:"quic_initial_fallback,omitempty"`
	UDPResume           bool        `json:"udp_resume,omitempty"`
	TCPLanes            int         `json:"tcp_lanes,omitempty"`
	TCPRecovery         bool        `json:"tcp_recovery,omitempty"`
	Network             NetworkList `json:"network,omitempty"`
}
