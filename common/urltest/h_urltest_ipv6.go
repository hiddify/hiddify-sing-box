package urltest

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// ErrNoIPv6Target says the test URL's host has no IPv6 address, so nothing can be verified.
var ErrNoIPv6Target = E.New("the test URL has no IPv6 address")

// URLTestIPv6 says whether detour carries IPv6: the test URL is fetched once more through detour,
// from the IPv6 address of its host (the first that resolve gives). Meant after the plain URL
// test passed, so what fails here is the IPv6 path: an exit with no IPv6 route, or one leading
// nowhere. The error is ErrNoIPv6Target when the host has no IPv6 address to try, or what
// resolve returned; a connection or request that fails is a plain false.
func URLTestIPv6(ctx context.Context, link string, detour N.Dialer, resolve func(ctx context.Context, host string) ([]netip.Addr, error)) (bool, error) {
	if detour == nil {
		return false, E.New("urltest dialer is nil")
	}
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return false, err
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return false, E.Cause(err, "test URL port")
	}
	var address netip.Addr
	if literal, parseErr := netip.ParseAddr(hostname); parseErr == nil {
		if !literal.Is6() || literal.Is4In6() {
			return false, ErrNoIPv6Target
		}
		address = literal
	} else {
		addresses, resolveErr := resolve(ctx, hostname)
		if resolveErr != nil {
			return false, E.Cause(resolveErr, "resolve the test URL's IPv6 address")
		}
		for _, candidate := range addresses {
			if candidate.Is6() && !candidate.Is4In6() {
				address = candidate
				break
			}
		}
		if !address.IsValid() {
			return false, ErrNoIPv6Target
		}
	}
	instance, err := detour.DialContext(ctx, N.NetworkTCP, M.SocksaddrFrom(address, uint16(portNumber)))
	if err != nil {
		return false, nil
	}
	defer instance.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, link, nil)
	if err != nil {
		return false, err
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return instance, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: C.TCPTimeout,
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return false, nil
	}
	response.Body.Close()
	return true, nil
}
