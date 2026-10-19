package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type MASQUEOutboundOptions struct {
	DialerOptions
	System               bool                             `json:"system,omitempty"`
	Name                 string                           `json:"name,omitempty"`
	AllowedIPs           badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	UseHTTP2             bool                             `json:"use_http2,omitempty"`
	UseL4Proxy           bool                             `json:"use_l4_proxy,omitempty"`
	UseIPv6              bool                             `json:"use_ipv6,omitempty"`
	Profile              CloudflareProfile                `json:"profile,omitempty"`
	Address              string                           `json:"address,omitempty"`
	Port                 uint16                           `json:"port,omitempty"`
	UDPTimeout           badoption.Duration               `json:"udp_timeout,omitempty"`
	UDPKeepalivePeriod   badoption.Duration               `json:"udp_keepalive_period,omitempty"`
	UDPInitialPacketSize uint16                           `json:"udp_initial_packet_size,omitempty"`
	ReconnectDelay       badoption.Duration               `json:"reconnect_delay,omitempty"`
	HandshakeTimeout     badoption.Duration               `json:"handshake_timeout,omitempty"`
	CongestionController string                           `json:"congestion_controller,omitempty"`
	CWND                 int                              `json:"cwnd,omitempty"`
	MASQUEOutboundTLSOptionsContainer
}

type MASQUEOutboundTLSOptions struct {
	ServerName            string                              `json:"server_name,omitempty"`
	Insecure              bool                                `json:"insecure,omitempty"`
	CipherSuites          badoption.Listable[string]          `json:"cipher_suites,omitempty"`
	CurvePreferences      badoption.Listable[CurvePreference] `json:"curve_preferences,omitempty"`
	Fragment              bool                                `json:"fragment,omitempty"`
	FragmentFallbackDelay badoption.Duration                  `json:"fragment_fallback_delay,omitempty"`
	RecordFragment        bool                                `json:"record_fragment,omitempty"`
	KernelTx              bool                                `json:"kernel_tx,omitempty"`
	KernelRx              bool                                `json:"kernel_rx,omitempty"`
}

type MASQUEOutboundTLSOptionsContainer struct {
	TLS *MASQUEOutboundTLSOptions `json:"tls,omitempty"`
}
