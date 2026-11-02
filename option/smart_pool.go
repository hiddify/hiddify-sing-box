package option

import (
	"bytes"

	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// SmartPoolOptions turn on and tune the resolver pool a DNS tunnel outbound (dnstt, masterdns)
// runs for itself (common/dnspool): the tunnel sends its queries to one local address, and the
// pool spreads them over the resolvers that passed the outbound's check, slows down for a
// resolver that rate-limits and skips one that stops answering. It is written either as the
// object below or as a bare `true`, which means enabled with every default.
type SmartPoolOptions struct {
	Enabled bool `json:"enabled,omitempty"`
	// LoadBalance picks the resolver of each query: auto (default: the resolver with the most
	// spare capacity, within the rate each one is learned to take), roundrobin, weighted or
	// lowest_latency.
	LoadBalance string `json:"load_balance,omitempty"`
	// Deadline is the longest time for one query over all tries (default 5s); PerAttempt the
	// longest time for one try at one resolver (default 2s).
	Deadline   badoption.Duration `json:"deadline,omitempty"`
	PerAttempt badoption.Duration `json:"per_attempt,omitempty"`
	// ProbeInterval is how often a down resolver is checked again (default 5s); DownAfter how many
	// timeouts or network errors in a row make a resolver down (default 8).
	ProbeInterval badoption.Duration `json:"probe_interval,omitempty"`
	DownAfter     int                `json:"down_after,omitempty"`
	// Duplicate sends each query to up to this many resolvers, the copies only to resolvers
	// without a rate limit, and passes every answer to the tunnel: the tunnel server answers each
	// copy with data of its own. Default 1 for dnstt; masterdns uses its packet_duplication (2).
	Duplicate int `json:"duplicate,omitempty"`
}

// RawSmartPoolOptions is the object form alone, for the JSON schema.
type RawSmartPoolOptions SmartPoolOptions

// UnmarshalJSON reads the object, or a bare boolean as the old `"smart_pool": true`.
func (o *SmartPoolOptions) UnmarshalJSON(content []byte) error {
	trimmed := bytes.TrimSpace(content)
	if bytes.Equal(trimmed, []byte("true")) || bytes.Equal(trimmed, []byte("false")) {
		*o = SmartPoolOptions{Enabled: bytes.Equal(trimmed, []byte("true"))}
		return nil
	}
	return json.Unmarshal(content, (*RawSmartPoolOptions)(o))
}

// IsEnabled reports whether the pool is on; a nil options block means off.
func (o *SmartPoolOptions) IsEnabled() bool {
	return o != nil && o.Enabled
}
