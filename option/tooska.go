package option

import "github.com/sagernet/sing/common/json/badoption"

// TooskaOutboundOptions configures the Tooska outbound. Tooska embeds the
// goBrrrr proxy scanner: it scans the configured target ranges for working
// SOCKS5 / HTTP CONNECT proxies, scores each endpoint between -10 and +10
// based on past results, and tunnels traffic through the best-scored hits.
//
// Note: large CIDR sweeps with high concurrency look like network abuse to
// many ISPs and can trip CGNAT or carrier abuse detection on the user's
// side. Operators should aim Tooska only at trusted ranges and choose
// concurrency / target size with that in mind.
type TooskaOutboundOptions struct {
	DialerOptions

	// Targets is a list of IPs, CIDRs, or "ip:port" entries to scan.
	// Plain IPs/CIDRs are paired with every entry in Ports; "ip:port" is
	// taken as-is and ignores Ports.
	Targets []string `json:"targets,omitempty"`

	// Ports is the list of TCP ports paired with bare IP/CIDR targets. If
	// empty a sensible default proxy-port set is used.
	Ports []int `json:"ports,omitempty"`

	// Concurrency caps simultaneous in-flight TCP connections. Default 256.
	Concurrency int `json:"concurrency,omitempty"`

	// PoolSize caps the number of working endpoints kept warm. Default 16.
	PoolSize int `json:"pool_size,omitempty"`

	// PreferProtocol picks which protocol (socks5 / http) to test first
	// when both are valid for an endpoint. Default empty (try socks5 first).
	PreferProtocol string `json:"prefer_protocol,omitempty"`

	// UserAgent sent in scanner HTTP probes. Default "tooska/1.0".
	UserAgent string `json:"user_agent,omitempty"`

	DialTimeout        *badoption.Duration `json:"dial_timeout,omitempty"`
	FingerprintTimeout *badoption.Duration `json:"fingerprint_timeout,omitempty"`
	ProbeTimeout       *badoption.Duration `json:"probe_timeout,omitempty"`
}
