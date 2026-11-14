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

// Domains are the sites the user opened; their top-level domain stays, and file names, traces
// and paths are not domains.
func TestH_SanitizeReportHidesDomains(t *testing.T) {
	for input, expected := range map[string]string{
		"connection download closed: remote error: resolve error: lookup ire-oneid.shalltry.com on 10.0.0.1:53: no such host": "connection download closed: remote error: resolve error: lookup <domain>.com on <ipv4>:53: no such host",
		"dns: exchanged A www.digikala.ir. 60 IN A 192.0.2.1":                                                                 "dns: exchanged A <domain>.ir. 60 IN A <ipv4>",
		"outbound/vless[proxy]: outbound connection to Example.CO.uk:443":                                                     "outbound/vless[proxy]: outbound connection to <domain>.uk:443",
		"sniffed domain=api.telegram.org protocol=tls":                                                                        "sniffed domain=<domain>.org protocol=tls",
		"open configuration.json and libbox.so failed":                                                                        "open configuration.json and libbox.so failed",
		"github.com/sagernet/sing-box/route.(*Router).Start":                                                                  "github.com/sagernet/sing-box/route.(*Router).Start",
		"/Applications/Hiddify.app/Contents/MacOS/Hiddify":                                                                    "/Applications/Hiddify.app/Contents/MacOS/Hiddify",
		"#0 ref.read (package:hiddify/main.dart:12)":                                                                          "#0 ref.read (package:hiddify/main.dart:12)",
		"version 5.9.2 build 1.2.3":                                                                                           "version 5.9.2 build 1.2.3",
		"send to bug@hiddify.com":                                                                                             "send to <email>",
		"fetch https://sub.example.com/x?token=1":                                                                             "fetch https://<host>",
	} {
		require.Equal(t, expected, string(sanitizeReportText([]byte(input))), input)
	}
}
