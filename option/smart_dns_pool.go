package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

// SmartDNSPoolUpstreamOptions describes one recursive resolver inside a
// smart_dns_pool service. The smart pool carries adaptive AIMD throttling,
// failover, and recovery probing across all upstreams configured here.
type SmartDNSPoolUpstreamOptions struct {
	// Type is one of "udp" | "tcp" | "tls" (DoT) | "https" (DoH).
	Type string `json:"type"`
	// Address is "host:port" for udp/tcp/tls, or a full https URL for DoH
	// (e.g. https://cloudflare-dns.com/dns-query).
	Address string `json:"address"`
	// Weight is consulted by the "weighted" load_balance strategy. 0 means
	// the upstream is a pure fallback (only reached when every weighted
	// candidate is unavailable). Ignored by other strategies.
	Weight int `json:"weight,omitempty"`
	// Name is an optional friendly id surfaced in stats. Defaults to
	// "<type>://<address>".
	Name string `json:"name,omitempty"`
}

// SmartDNSPoolServiceOptions configures a `smart_dns_pool` service: a
// local DNS server (UDP+TCP) that fans queries out to many recursive
// upstream resolvers using github.com/hiddify/hmrd_multi_resolver_dns.
//
// Typical use: configure this with the recursive resolvers you want to
// distribute load across, then point dnstt's `resolvers` at the local
// listen address (e.g. udp://127.0.0.1:19876) instead of a fixed
// `8.8.8.8` etc. dnstt sees a normal local resolver; the pool transparently
// handles failover, AIMD rate-limit throttling, and recovery probing for
// the real upstreams.
type SmartDNSPoolServiceOptions struct {
	ListenOptions
	Upstreams     []SmartDNSPoolUpstreamOptions `json:"upstreams"`
	LoadBalance   string                        `json:"load_balance,omitempty"`   // "roundrobin" (default) | "weighted" | "lowest_latency"
	Deadline      badoption.Duration            `json:"deadline,omitempty"`       // overall query deadline; default 5s
	PerAttempt    badoption.Duration            `json:"per_attempt,omitempty"`    // per-resolver attempt cap; default 2s
	ProbeInterval badoption.Duration            `json:"probe_interval,omitempty"` // recovery probe cadence; default 5s
	DownAfter     int                           `json:"down_after,omitempty"`     // consecutive failures before "down"; default 8
}
