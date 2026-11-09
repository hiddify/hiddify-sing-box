package libbox

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Every time in a log (10:01:22) was taken for an IPv6 address, and the reports lost their times.
func TestH_SanitizeReportKeepsTimes(t *testing.T) {
	for input, expected := range map[string]string{
		"[2026-11-09 10:01:22 +0000] (packet-tunnel) starting":        "[2026-11-09 10:01:22 +0000] (packet-tunnel) starting",
		"10:01:22.534989 [DEBUG] dns: exchange":                       "10:01:22.534989 [DEBUG] dns: exchange",
		"+0330 2026-11-09 13:32:04 INFO[0004] started":                "+0330 2026-11-09 13:32:04 INFO[0004] started",
		"connect to 2001:db8::1 failed":                               "connect to <ipv6> failed",
		"connect to [2001:db8:0:0:1:2:3:4]:443":                       "connect to [<ipv6>]:443",
		"from fe80::1%en0: refused":                                   "from <ipv6>: refused",
		"lookup succeed: 2606:4700:4700::1111 2606:4700:4700::1001":   "lookup succeed: <ipv6> <ipv6>",
		"std::vector, Foo::Bar":                                       "std::vector, Foo::Bar",
		"dial ::1 and ::":                                             "dial <ipv6> and <ipv6>",
		"WIFI state changed: SSID=home, BSSID=a4:2b:b0:1c:9e:7f":      "WIFI state changed: SSID=home, BSSID=<mac>",
		"inbound connection from 192.0.2.4:52862 to 198.51.100.7:443": "inbound connection from <ipv4>:52862 to <ipv4>:443",
	} {
		require.Equal(t, expected, string(sanitizeReportText([]byte(input))), input)
	}
}
