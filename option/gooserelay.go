package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

type GooseRelayOptions struct {
	DialerOptions

	ScriptKeys  []string `json:"script_keys,omitempty"`
	TunnelKey   string   `json:"tunnel_key,omitempty"`
	GoogleHost  string   `json:"google_host,omitempty"`
	SNI         []string `json:"sni,omitempty"`
	DebugTiming bool     `json:"debug_timing,omitempty"`

	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`

	HandshakeTimeout *badoption.Duration `json:"handshake_timeout,omitempty"`
}
