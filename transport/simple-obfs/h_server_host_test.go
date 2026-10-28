package obfs

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// With hosts set, only a client whose HTTP Host or TLS server name is one of them passes;
// any other is not simple-obfs, and its bytes come back for the fallback.
func TestH_ServerHandshakeChecksHost(t *testing.T) {
	for _, mode := range []string{"http", "tls"} {
		for _, test := range []struct {
			name  string
			host  string
			hosts []string
			pass  bool
		}{
			{"no hosts", "www.example.com", nil, true},
			{"listed", "www.example.com", []string{"cdn.example.net", "WWW.example.com"}, true},
			{"not listed", "probe.example.org", []string{"www.example.com"}, false},
		} {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				rawClient, rawServer := hTCPPair(t)
				var client net.Conn
				if mode == "http" {
					client = NewHTTPObfs(rawClient, test.host, "443")
				} else {
					client = NewTLSObfs(rawClient, test.host)
				}
				writeErr := hWriteAsync(client, hRandom(t, 300))
				_, cached, err := ServerHandshake(rawServer, mode, test.hosts...)
				if test.pass {
					require.NoError(t, err)
					require.NoError(t, <-writeErr)
					return
				}
				require.ErrorIs(t, err, ErrNotObfs)
				require.NotEmpty(t, cached)
			})
		}
	}
}
