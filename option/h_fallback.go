package option

import "github.com/sagernet/sing/common/json/badoption"

// H: FallbackOutboundOptions is the fallback group: its outbounds are tried in order, and one that
// fails to connect is skipped for blacklist_timeout.
type FallbackOutboundOptions struct {
	Outbounds        []string           `json:"outbounds"`
	BlacklistTimeout badoption.Duration `json:"blacklist_timeout,omitempty"`
}
