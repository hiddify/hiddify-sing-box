package obfs

import (
	"net/netip"
	"strings"
)

// hHTTPObfsHost brackets a bare IPv6 obfs-host, which a URL host needs: "2001:db8::1" -> "[2001:db8::1]".
func hHTTPObfsHost(host string) string {
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is6() {
		return host
	}
	return "[" + strings.ReplaceAll(addr.String(), "%", "%25") + "]"
}
