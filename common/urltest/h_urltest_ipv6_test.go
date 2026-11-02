package urltest

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type hPlainDialer struct {
	net.Dialer
	refuse bool
}

func (d *hPlainDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if d.refuse {
		return nil, errors.New("no route to host")
	}
	return d.Dialer.DialContext(ctx, network, destination.String())
}

func (d *hPlainDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

// The test URL is fetched from its host's IPv6 address through the dialer: a host with no IPv6
// address cannot be verified, a dialer that cannot reach it says no, one that can says yes.
func TestH_URLTestIPv6(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback: ", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	link := "http://ipv6.test:" + strconv.Itoa(port) + "/generate_204"
	ctx := context.Background()

	sixOnly := func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::1")}, nil
	}
	carried, err := URLTestIPv6(ctx, link, &hPlainDialer{}, sixOnly)
	require.NoError(t, err)
	require.True(t, carried)

	carried, err = URLTestIPv6(ctx, link, &hPlainDialer{refuse: true}, sixOnly)
	require.NoError(t, err)
	require.False(t, carried, "a dialer that cannot reach the IPv6 address says no")

	fourOnly := func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	_, err = URLTestIPv6(ctx, link, &hPlainDialer{}, fourOnly)
	require.ErrorIs(t, err, ErrNoIPv6Target, "a host without IPv6 cannot be verified")

	_, err = URLTestIPv6(ctx, "http://127.0.0.1:"+strconv.Itoa(port)+"/", &hPlainDialer{}, sixOnly)
	require.ErrorIs(t, err, ErrNoIPv6Target, "an IPv4 literal cannot be verified")

	carried, err = URLTestIPv6(ctx, "http://[::1]:"+strconv.Itoa(port)+"/", &hPlainDialer{}, fourOnly)
	require.NoError(t, err)
	require.True(t, carried, "an IPv6 literal needs no resolution")
}
