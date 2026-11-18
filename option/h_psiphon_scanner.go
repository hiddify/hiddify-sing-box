package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

// H: PsiphonScannerOptions makes a Psiphon outbound look for CDN edges that Psiphon can front
// through (see hiddify/edgescan, the engine of the WARP scanner too): before the tunnel core
// starts, the edges that worked on this network are tried first, then new ones of the built-in
// CDN sets, each with a TLS handshake; the ones that answer go to the tunnel core first, and its
// own scan of the built-in sets follows them.
type PsiphonScannerOptions struct {
	// Enabled turns the scanner on or off. Unset, it is on when Psiphon is the first hop (no
	// detour and no upstream_proxy_url), and off behind another proxy, which already gets out.
	Enabled *bool `json:"enabled,omitempty"`
	// CIDRs to pick edges from instead of the built-in CDN sets; IPv4 only (the tunnel core
	// fronts over IPv4).
	CIDRs badoption.Listable[netip.Prefix] `json:"cidrs,omitempty"`
	// ServerNames sent with the edges of cidrs; each edge is also tried without one.
	ServerNames badoption.Listable[string] `json:"server_names,omitempty"`
	// Sets limits the built-in CDN sets, for the scanner and the tunnel core, such as "fastly"
	// or "psiphon-akamai"; all when empty.
	Sets badoption.Listable[string] `json:"sets,omitempty"`
	// MaxRTT is the slowest handshake accepted; 2s when zero.
	MaxRTT badoption.Duration `json:"max_rtt,omitempty"`
	// Timeout is the time a single probe waits for its handshake; 3s when zero.
	Timeout badoption.Duration `json:"timeout,omitempty"`
	// Count is the most edges probed in one round of a scan; 256 when zero.
	Count int `json:"count,omitempty"`
	// Concurrency is the number of probes run at once; 16 on Android and iOS, 48 elsewhere, when
	// zero.
	Concurrency int `json:"concurrency,omitempty"`
	// EdgeSearchOptions: how long and how hard the search goes on.
	EdgeSearchOptions
	// Candidates is the number of answering edges of each CDN handed to the tunnel core, for the
	// server entries that front through that CDN; 2 when zero. The scan stops once that many
	// answered per CDN set.
	Candidates int `json:"candidates,omitempty"`
}
