package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

type MASQUEOutboundOptions struct {
	UseHTTP2             bool               `json:"use_http2,omitempty"`
	UseIPv6              bool               `json:"use_ipv6,omitempty"`
	Profile              CloudflareProfile  `json:"profile,omitempty"`
	UDPTimeout           badoption.Duration `json:"udp_timeout,omitempty"`
	UDPKeepalivePeriod   badoption.Duration `json:"udp_keepalive_period,omitempty"`
	UDPInitialPacketSize uint16             `json:"udp_initial_packet_size,omitempty"`
	ReconnectDelay       badoption.Duration `json:"reconnect_delay,omitempty"`
	MASQUEOutboundTLSOptions
	DialerOptions
}

type MASQUEOutboundTLSOptions struct {
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
	TLS *OutboundTLSOptions `json:"tls,omitempty"`
}
