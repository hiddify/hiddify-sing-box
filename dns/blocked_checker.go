package dns

import "net/netip"

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("2001:4188:2:600::/64"),
}

func IsBlockedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}

	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func FilterBlocked(addrs []netip.Addr) []netip.Addr {
	if addrs == nil {
		return nil
	}
	if len(addrs) == 0 {
		return addrs
	}
	out := addrs[:0] // in-place filter, no extra alloc
	for _, ip := range addrs {
		if !IsBlockedIP(ip) {
			out = append(out, ip)
		}
	}
	return out
}
