package cloudflare

import (
	"net/netip"
	"strings"
)

// warpPrefixes are the address ranges of Cloudflare's WARP endpoints: WireGuard, and MASQUE for
// WARP, WARP+ and Zero Trust accounts.
var warpPrefixes = []netip.Prefix{
	netip.MustParsePrefix("162.159.192.0/21"),
	netip.MustParsePrefix("188.114.96.0/20"),
	netip.MustParsePrefix("8.6.112.0/24"),
	netip.MustParsePrefix("8.34.70.0/24"),
	netip.MustParsePrefix("8.34.146.0/24"),
	netip.MustParsePrefix("8.35.211.0/24"),
	netip.MustParsePrefix("8.39.125.0/24"),
	netip.MustParsePrefix("8.39.204.0/24"),
	netip.MustParsePrefix("8.39.214.0/24"),
	netip.MustParsePrefix("8.47.69.0/24"),
	netip.MustParsePrefix("2606:4700:100::/48"),
	netip.MustParsePrefix("2606:4700:d0::/48"),
	netip.MustParsePrefix("2606:4700:102::/48"),
	netip.MustParsePrefix("2606:4700:103::/48"),
	netip.MustParsePrefix("2606:4700:104::/48"),
}

// IsWARPAddress reports an address in the ranges of Cloudflare's WARP endpoints.
func IsWARPAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range warpPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// IsWARPHost reports a host of Cloudflare's WARP: an address in its ranges, or a name under
// cloudflareclient.com (the MASQUE server name, engage.cloudflareclient.com, ...). A host may
// carry a port and IPv6 brackets.
func IsWARPHost(host string) bool {
	host = strings.TrimSpace(host)
	if addrPort, err := netip.ParseAddrPort(host); err == nil {
		return IsWARPAddress(addrPort.Addr())
	}
	host = strings.Trim(host, "[]")
	if addr, err := netip.ParseAddr(host); err == nil {
		return IsWARPAddress(addr)
	}
	if name, _, found := strings.Cut(host, ":"); found {
		host = name
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "cloudflareclient.com" || strings.HasSuffix(host, ".cloudflareclient.com")
}
