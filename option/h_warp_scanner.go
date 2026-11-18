package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

// H: WARPScannerOptions makes a WARP (WireGuard or MASQUE) client look for a Cloudflare endpoint
// that answers instead of using the profile's: the addresses that worked before are tried
// first, then random addresses in cidrs on ports.
type WARPScannerOptions struct {
	Enabled bool `json:"enabled,omitempty"`
	// Ports to probe; the profile's ports (WireGuard) or warpscan.MASQUEPorts (MASQUE) when empty.
	Ports badoption.Listable[uint16] `json:"ports,omitempty"`
	// CIDRs to pick addresses from; Cloudflare's WARP ranges when empty.
	CIDRs badoption.Listable[netip.Prefix] `json:"cidrs,omitempty"`
	// MaxRTT is the slowest handshake accepted; 1s when zero.
	MaxRTT badoption.Duration `json:"max_rtt,omitempty"`
	// Timeout is the time a single probe waits for its handshake; 2s when zero.
	Timeout badoption.Duration `json:"timeout,omitempty"`
	// Count is the most addresses probed in one round of a scan; 64 when zero.
	Count int `json:"count,omitempty"`
	// Concurrency is the number of probes run at once; 8 on Android and iOS, 32 elsewhere, when
	// zero.
	Concurrency int `json:"concurrency,omitempty"`
	// SearchNoise also looks for noise that gets through (WireGuard and AmneziaWG): when no
	// endpoint answers with the noise drawn first, the scan is tried again with the others, and
	// the one that works gains a point on the network (see warpscan.Book.OrderMethods).
	SearchNoise bool `json:"search_noise,omitempty"`
	// NoisePresets are the presets tried, in a weighted random order by their rating on the
	// network; all of warpscan.NoisePresets when empty.
	NoisePresets badoption.Listable[string] `json:"noise_presets,omitempty"`
	// EdgeSearchOptions: how long and how hard the search goes on.
	EdgeSearchOptions
}
