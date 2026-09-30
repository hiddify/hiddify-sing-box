package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

//H — WARP-flavored MASQUE outbound, tunnels through Cloudflare's consumer WARP service

type MASQUEOutboundTLSOptions struct { //H
	Insecure              bool                                `json:"insecure,omitempty"`
	CipherSuites          badoption.Listable[string]          `json:"cipher_suites,omitempty"`
	CurvePreferences      badoption.Listable[CurvePreference] `json:"curve_preferences,omitempty"`
	Fragment              bool                                `json:"fragment,omitempty"`
	FragmentFallbackDelay badoption.Duration                  `json:"fragment_fallback_delay,omitempty"`
	RecordFragment        bool                                `json:"record_fragment,omitempty"`
	KernelTx              bool                                `json:"kernel_tx,omitempty"`
	KernelRx              bool                                `json:"kernel_rx,omitempty"`
}

type MASQUEOutboundOptions struct { //H
	DialerOptions
	Profile                  CloudflareProfile        `json:"profile,omitempty"`
	MASQUEOutboundTLSOptions MASQUEOutboundTLSOptions `json:"tls,omitempty"`
	UseHTTP2                 bool                     `json:"use_http2,omitempty"`
	UseIPv6                  bool                     `json:"use_ipv6,omitempty"`
	UDPTimeout               badoption.Duration       `json:"udp_timeout,omitempty"`
	UDPKeepalivePeriod       badoption.Duration       `json:"udp_keepalive_period,omitempty"`
	UDPInitialPacketSize     uint16                   `json:"udp_initial_packet_size,omitempty"`
	ReconnectDelay           badoption.Duration       `json:"reconnect_delay,omitempty"`
}
