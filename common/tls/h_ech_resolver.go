package tls

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// echConfigMaxAge is the longest an ECH config fetched by DNS is used before it is fetched again.
// Servers rotate their ECH keys (Cloudflare every hour or two), and a DNS config may stretch every
// TTL (Hiddify rewrites them to a day), so a config kept by the record's TTL went stale and every
// handshake with it failed until the cache expired (hiddify-app#2539).
const echConfigMaxAge = 10 * time.Minute

// echQueryOptions is the query of an ECH config: through the DNS resolvers by the DNS rules, as
// any query, but never answered from the DNS cache, so the answer is the server's current one.
func echQueryOptions() adapter.DNSQueryOptions {
	return adapter.DNSQueryOptions{DisableCache: true}
}

// echConfigTTL is how long a fetched ECH config is kept: the record's TTL, at most echConfigMaxAge.
func echConfigTTL(ttl uint32) time.Duration {
	return min(time.Duration(ttl)*time.Second, echConfigMaxAge)
}
