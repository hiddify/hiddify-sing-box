package box_test

import "testing"

// MASQUE to WARP with www.speedtest.net as the TLS server name (the speedtest noise preset):
// Cloudflare's endpoint answers it over HTTP/3 and HTTP/2, and the pinned key still checks it.
func TestH_WARPLiveMASQUESpeedtestServerName(t *testing.T) {
	for _, vhttp := range []string{"h3", "h2"} {
		t.Run(vhttp, func(t *testing.T) {
			hWARPTrace(t, `"endpoints": [{"type": "warp", "tag": "warp", "scanner": {"enabled": true},
				"masque": {"vhttp": "`+vhttp+`", "server_name": "www.speedtest.net"}}]`)
		})
	}
}
