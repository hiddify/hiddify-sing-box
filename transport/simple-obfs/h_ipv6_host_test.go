package obfs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A bare IPv6 obfs-host used to build "http://2001:db8::1/", a URL net/http cannot parse: the
// request came back nil and the first write took the whole app down. Now it is bracketed, and
// a server that lists the address accepts it, with or without a port.
func TestH_HTTPObfsIPv6Host(t *testing.T) {
	for _, host := range []string{"2001:db8::1", "[2001:db8::1]"} {
		for _, port := range []string{"80", "443"} {
			t.Run(host+"/"+port, func(t *testing.T) {
				rawClient, rawServer := hTCPPair(t)
				var writeErr chan error
				require.NotPanics(t, func() {
					writeErr = hWriteAsync(NewHTTPObfs(rawClient, host, port), hRandom(t, 300))
				})
				_, _, err := ServerHandshake(rawServer, "http", "2001:db8::1")
				require.NoError(t, err)
				require.NoError(t, <-writeErr)
			})
		}
	}
}

// An obfs-host that still makes no URL fails the write instead of crashing.
func TestH_HTTPObfsBadHostIsAnError(t *testing.T) {
	rawClient, _ := hTCPPair(t)
	var err error
	require.NotPanics(t, func() {
		_, err = NewHTTPObfs(rawClient, "bad host", "80").Write([]byte("x"))
	})
	require.Error(t, err)
}
