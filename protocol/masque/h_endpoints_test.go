package masque

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func hProfileConfig() *Config {
	return &Config{
		EndpointV4:   "162.159.198.1",
		EndpointV6:   "2606:4700:103::1",
		EndpointH2V4: cloudflare.DefaultEndpointH2V4,
		EndpointH2V6: cloudflare.DefaultEndpointH2V6,
	}
}

func hSelect(t *testing.T, mode string, useIPv6 bool, scan func(bool) (net.Addr, error)) (net.Addr, net.Addr, string, error) {
	t.Helper()
	return selectEndpoints(context.Background(), log.NewNOPFactory().Logger(), hProfileConfig(), mode, useIPv6, M.Socksaddr{}, scan)
}

// The profile has no HTTP/2 IPv6 endpoint: auto with use_ipv6 must still start, on HTTP/3.
func TestH_SelectEndpointsAutoIPv6(t *testing.T) {
	endpoint, h2Endpoint, mode, err := hSelect(t, masque.ModeAuto, true, nil)
	require.NoError(t, err)
	require.Equal(t, masque.ModeHTTP3, mode)
	require.Equal(t, "[2606:4700:103::1]:443", endpoint.String())
	require.Nil(t, h2Endpoint)

	_, _, _, err = hSelect(t, masque.ModeHTTP2, true, nil)
	require.Error(t, err, "h2 alone has no endpoint to use")
}

func TestH_SelectEndpointsScanner(t *testing.T) {
	scanned := map[bool]net.Addr{
		false: &net.UDPAddr{IP: net.ParseIP("2606:4700:103::2"), Port: 4443},
		true:  &net.TCPAddr{IP: net.ParseIP("2606:4700:103::5"), Port: 443},
	}
	scan := func(http2 bool) (net.Addr, error) { return scanned[http2], nil }
	endpoint, h2Endpoint, mode, err := hSelect(t, masque.ModeAuto, true, scan)
	require.NoError(t, err)
	require.Equal(t, masque.ModeAuto, mode, "the scanner found an HTTP/2 IPv6 endpoint")
	require.Equal(t, scanned[false], endpoint)
	require.Equal(t, scanned[true], h2Endpoint)

	endpoint, h2Endpoint, mode, err = hSelect(t, masque.ModeAuto, false, func(bool) (net.Addr, error) { return nil, errors.New("nothing answers") })
	require.NoError(t, err)
	require.Equal(t, masque.ModeAuto, mode)
	require.Equal(t, "162.159.198.1:443", endpoint.String(), "a failed scan falls back to the profile")
	require.Equal(t, "162.159.198.2:443", h2Endpoint.String())
}

// Auto scans HTTP/3 and HTTP/2 at once: a slow HTTP/3 scan (UDP dropped) does not hold the
// HTTP/2 one back.
func TestH_SelectEndpointsScansInParallel(t *testing.T) {
	h2Started := make(chan struct{})
	scan := func(http2 bool) (net.Addr, error) {
		if http2 {
			close(h2Started)
			return &net.TCPAddr{IP: net.ParseIP("162.159.198.9"), Port: 443}, nil
		}
		select {
		case <-h2Started:
			return nil, errors.New("UDP dropped")
		case <-time.After(5 * time.Second):
			return nil, errors.New("the HTTP/2 scan waited for the HTTP/3 one")
		}
	}
	endpoint, h2Endpoint, mode, err := hSelect(t, masque.ModeAuto, false, scan)
	require.NoError(t, err)
	require.Equal(t, masque.ModeAuto, mode)
	require.Equal(t, "162.159.198.1:443", endpoint.String(), "the failed HTTP/3 scan falls back to the profile")
	require.Equal(t, "162.159.198.9:443", h2Endpoint.String())
}

func TestH_FirstProbe(t *testing.T) {
	udpBlocked := func(ctx context.Context, http2 bool) (time.Duration, error) {
		if http2 {
			return 30 * time.Millisecond, nil
		}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	rtt, err := firstProbe(context.Background(), udpBlocked)
	require.NoError(t, err, "HTTP/2 over TCP gets through when UDP does not")
	require.Equal(t, 30*time.Millisecond, rtt)

	_, err = firstProbe(context.Background(), func(context.Context, bool) (time.Duration, error) {
		return 0, errors.New("blocked")
	})
	require.ErrorContains(t, err, "HTTP/3")
	require.ErrorContains(t, err, "HTTP/2")
}
