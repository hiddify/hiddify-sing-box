package option

import (
	"bytes"

	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// SmartPoolOptions turn on and tune the resolver pool a DNS tunnel outbound (dnstt, masterdns, soar)
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
	// Discovery steers how the outbound finds working resolvers among its candidates; nil keeps
	// every default.
	Discovery *ResolverDiscoveryOptions `json:"discovery,omitempty"`
}

// ResolverDiscoveryOptions steer resolver discovery, the same for every DNS tunnel (dnstt,
// masterdns, soar). "auto" stands for the candidates of Soar's discovery (github.com/getlantern/soar):
// the device's own resolvers, the bundled list of Country, global public resolvers, addresses
// sampled from the country's ranges; the pool's built-in list follows them. Soar's own client
// runs that discovery itself; dnstt and masterdns probe the candidates into their pool.
type ResolverDiscoveryOptions struct {
	// Country is the ISO 3166-1 alpha-2 code of the device's network ("ir"): its bundled
	// resolvers are tried first. Empty: no country list.
	Country string `json:"country,omitempty"`
	// SampleRanges is how many addresses of the country's ranges are tried once the lists are
	// used up (default 0, off: probing many addresses in the country is visible).
	SampleRanges int `json:"sample_ranges,omitempty"`
	// Want is how many working resolvers are kept; once fewer work, the next candidates are
	// tried. Default 10 for the pool, 16 for Soar's client.
	Want int `json:"want,omitempty"`
	// Concurrency bounds the candidates tested at once. Default 100 for the pool, 16 for Soar's
	// client.
	Concurrency int `json:"concurrency,omitempty"`
	// Pace is the least gap between starting two tests. Default none for the pool, 20ms for
	// Soar's client.
	Pace badoption.Duration `json:"pace,omitempty"`
}

// DiscoveryOptions returns the discovery block, empty for a nil pool block or none.
func (o *SmartPoolOptions) DiscoveryOptions() ResolverDiscoveryOptions {
	if o == nil || o.Discovery == nil {
		return ResolverDiscoveryOptions{}
	}
	return *o.Discovery
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

// IsEnabledOr reports whether the pool is on, with a nil options block meaning def: for an
// outbound whose pool is on unless the config turns it off (soar).
func (o *SmartPoolOptions) IsEnabledOr(def bool) bool {
	if o == nil {
		return def
	}
	return o.Enabled
}
