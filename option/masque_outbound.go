package option

import (
	"reflect"

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
	// MTU of the tunnel, 1280 (the IPv6 minimum, and the default) to 9000. Over HTTP/3, a packet
	// larger than the path carries gets an ICMP "packet too big" back, so TCP adjusts.
	MTU uint32 `json:"mtu,omitempty"`
	// UniqueIdentifier names the saved profile and scanner scores; the tag when empty, as for warp.
	UniqueIdentifier string              `json:"unique_identifier,omitempty"`
	ReconnectDelay   badoption.Duration  `json:"reconnect_delay,omitempty"`
	Scanner          *WARPScannerOptions `json:"scanner,omitempty"`
	// VHTTP is the HTTP version: "h3", "h2" or "auto" (HTTP/3, falling back to HTTP/2); empty
	// is "auto", or "h2" with use_http2.
	VHTTP string `json:"vhttp,omitempty"`
	// ServerName is the TLS server name; consumer-masque.cloudflareclient.com when empty.
	ServerName string `json:"server_name,omitempty"`
}

// WARPMASQUEOptions makes a warp endpoint use MASQUE instead of WireGuard: the endpoint
// registers the device and looks up the endpoint, then runs a MASQUE tunnel to it. Any setting
// turns it on; enabled does with every default, since an empty object is dropped. //H
type WARPMASQUEOptions struct {
	Enabled              bool                     `json:"enabled,omitempty"`
	TLS                  MASQUEOutboundTLSOptions `json:"tls,omitempty"`
	UseIPv6              bool                     `json:"use_ipv6,omitempty"`
	UDPKeepalivePeriod   badoption.Duration       `json:"udp_keepalive_period,omitempty"`
	UDPInitialPacketSize uint16                   `json:"udp_initial_packet_size,omitempty"`
	ReconnectDelay       badoption.Duration       `json:"reconnect_delay,omitempty"`
	// VHTTP is "h3", "h2" or "auto" (the default).
	VHTTP string `json:"vhttp,omitempty"`
	// ServerName is the TLS server name; consumer-masque.cloudflareclient.com when empty.
	ServerName string `json:"server_name,omitempty"`
}

// IsEnabled reports whether the warp endpoint uses MASQUE. //H
func (o *WARPMASQUEOptions) IsEnabled() bool {
	return o != nil && (o.Enabled || !reflect.ValueOf(*o).IsZero())
}
