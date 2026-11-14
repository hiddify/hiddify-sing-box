package xhttp

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// A bare IPv6 address in host (or the server address when host and SNI are empty) used to
// build "http://2001:db8::1/xh/", a URL net/http cannot parse: the request came back nil and
// the next line took the whole app down.
func TestH_BaseRequestURLBracketsIPv6(t *testing.T) {
	dest := M.SocksaddrFromNetIP(netip.MustParseAddrPort("[2001:db8::2]:443"))
	for _, host := range []string{"2001:db8::1", "[2001:db8::1]", ""} {
		options := hOptions(t, fmt.Sprintf(`{"host":%q,"path":"/xh"}`, host))
		requestURL, err := getBaseRequestURL(&options.V2RayXHTTPBaseOptions, dest, nil)
		require.NoError(t, err, host)
		require.Equal(t, "http", requestURL.Scheme)
		if host == "" {
			require.Equal(t, "[2001:db8::2]", requestURL.Host)
		} else {
			require.Equal(t, "[2001:db8::1]", requestURL.Host)
		}
		require.Equal(t, "2001:db8::"+map[bool]string{true: "2", false: "1"}[host == ""], requestURL.Hostname())
	}
	for _, host := range []string{"example.com", "1.2.3.4", "example.com:8443"} {
		require.Equal(t, host, hURLHost(host))
	}
}

// A URL that still cannot be parsed fails the dial instead of crashing on a nil request.
func TestH_OpenStreamBadURLIsAnError(t *testing.T) {
	client := hDialerClient(t, "1.1")
	for _, body := range []bool{false, true} {
		var err error
		require.NotPanics(t, func() {
			if body {
				_, _, _, err = client.OpenStream(context.Background(), "http://2001:db8::1/xh/", "session", strings.NewReader(""), false)
			} else {
				_, _, _, err = client.OpenStream(context.Background(), "http://2001:db8::1/xh/", "session", nil, false)
			}
		})
		require.Error(t, err)
	}
}
