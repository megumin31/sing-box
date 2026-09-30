package option

// QueqiaoOutboundOptions imports an already enrolled official Queqiao profile.
// TLS identity and the endpoint come from the profile, not WebPKI settings.
type QueqiaoOutboundOptions struct {
	DialerOptions
	ProfilePath string      `json:"profile_path"`
	Transport   string      `json:"transport,omitempty" enum:"tcp,quic"`
	Network     NetworkList `json:"network,omitempty"`
}
