package option

import "github.com/sagernet/sing/common/json/badoption"

// H: EdgeSearchOptions tune how long and how hard a scanner searches (the WARP endpoint scanner,
// for WARP over WireGuard, AmneziaWG and MASQUE, and the Psiphon CDN edge scanner, see
// hiddify/edgescan), and how it rates the
// address blocks it tries. Zero values keep the defaults.
type EdgeSearchOptions struct {
	// SearchTimeout is how long a search goes on, round after round, before it gives up and
	// offers a deep search; 3m when zero. A deep search has no time limit: below zero, the search
	// is one from the start, and above 3m it is a deep one with that limit (DeepConcurrency
	// workers, and Psiphon's aggressive mode).
	SearchTimeout badoption.Duration `json:"search_timeout,omitempty"`
	// DeepConcurrency is the number of probes a deep search runs at once; twice the scanner's
	// concurrency when zero.
	DeepConcurrency int `json:"deep_concurrency,omitempty"`
	// BlockBitsIPv4 and BlockBitsIPv6 are the size of the address blocks rated on each network
	// (from -10 to 10, like the endpoints), and drawn from by their rating; 24 and 48 when zero.
	BlockBitsIPv4 int `json:"block_bits_ipv4,omitempty"`
	BlockBitsIPv6 int `json:"block_bits_ipv6,omitempty"`
}
