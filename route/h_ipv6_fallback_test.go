package route

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// hIPv6TestDialer is the outbound: a dial to an IPv6 address is served by v6, one to a domain by
// domain; each returns the app-facing end of a pipe whose other end a goroutine plays.
type hIPv6TestDialer struct {
	v6, domain func() (net.Conn, error)
	domains    int
}

func (d *hIPv6TestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.IsFqdn() {
		d.domains++
		return d.domain()
	}
	return d.v6()
}

func (d *hIPv6TestDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

// hPeer plays the far end: it reads want from the connection, then answers or closes.
func hPeer(want string, answer string) func() (net.Conn, error) {
	return func() (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			defer remote.Close()
			got := make([]byte, len(want))
			if _, err := io.ReadFull(remote, got); err != nil {
				return
			}
			if answer != "" {
				remote.Write([]byte(answer))
				// the app may still have something to say; wait for it to finish
				io.Copy(io.Discard, remote)
			}
		}()
		return local, nil
	}
}

type hObservations struct {
	mu        sync.Mutex
	seen      []bool
	supported bool
	known     bool
}

func (o *hObservations) OutboundIPv6(tag string) (bool, bool) { return o.supported, o.known }
func (o *hObservations) ObserveIPv6(tag string, carried bool) {
	o.mu.Lock()
	o.seen = append(o.seen, carried)
	o.mu.Unlock()
}

func (o *hObservations) all() []bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]bool(nil), o.seen...)
}

func hRunIPv6Connection(t *testing.T, dialer *hIPv6TestDialer, domain string, request string) (string, error, []bool, <-chan error) {
	t.Helper()
	return hRunIPv6ConnectionKnowing(t, dialer, domain, request, &hObservations{})
}

func hRunIPv6ConnectionKnowing(t *testing.T, dialer *hIPv6TestDialer, domain string, request string, observations *hObservations) (string, error, []bool, <-chan error) {
	t.Helper()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	manager := NewConnectionManager(ctx, log.NewNOPFactory().NewLogger("connection"))
	app, core := net.Pipe()
	closed := make(chan error, 1)
	metadata := adapter.InboundContext{
		Network:       N.NetworkTCP,
		Destination:   M.ParseSocksaddr("[2001:db8::1]:443"),
		Domain:        domain,
		RouteOutbound: "proxy",
	}
	go manager.hNewIPv6Connection(ctx, dialer, core, metadata, func(err error) { closed <- err }, observations)
	go func() {
		app.Write([]byte(request))
	}()
	app.SetReadDeadline(time.Now().Add(5 * time.Second))
	answer := make([]byte, 64)
	n, err := app.Read(answer)
	app.Close()
	return string(answer[:n]), err, observations.all(), closed
}

// The exit has no IPv6: the proxy closes the IPv6 stream with nothing, the same proxy is dialed
// with the domain, the app's request is said again, and the app gets the answer as if nothing
// happened. The outbound is observed not carrying IPv6.
func TestH_IPv6FallbackCarriesOverDomain(t *testing.T) {
	dialer := &hIPv6TestDialer{v6: hPeer("hello", ""), domain: hPeer("hello", "world")}
	answer, err, observed, closed := hRunIPv6Connection(t, dialer, "example.com", "hello")
	require.NoError(t, err)
	require.Equal(t, "world", answer)
	require.Equal(t, 1, dialer.domains)
	require.Equal(t, []bool{false}, observed)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("onClose not called")
	}
}

// The exit carries IPv6: the destination answers over it, nothing is dialed again, and the
// outbound is observed carrying IPv6.
func TestH_IPv6FallbackNotNeeded(t *testing.T) {
	dialer := &hIPv6TestDialer{v6: hPeer("hello", "world"), domain: hPeer("hello", "wrong")}
	answer, err, observed, _ := hRunIPv6Connection(t, dialer, "example.com", "hello")
	require.NoError(t, err)
	require.Equal(t, "world", answer)
	require.Equal(t, 0, dialer.domains)
	require.Equal(t, []bool{true}, observed)
}

// Without a domain there is nothing to carry the connection over with: it ends as it would have,
// and nothing is learned, since the failure may be the destination's.
func TestH_IPv6FallbackNeedsADomain(t *testing.T) {
	dialer := &hIPv6TestDialer{v6: hPeer("hello", ""), domain: hPeer("hello", "world")}
	answer, err, observed, _ := hRunIPv6Connection(t, dialer, "", "hello")
	require.Error(t, err)
	require.Equal(t, "", answer)
	require.Equal(t, 0, dialer.domains)
	require.Empty(t, observed)
}

// The destination answers over neither family: that is the destination, not the exit, so the
// outbound is not blamed.
func TestH_IPv6FallbackDeadDestination(t *testing.T) {
	dialer := &hIPv6TestDialer{v6: hPeer("hello", ""), domain: hPeer("hello", "")}
	answer, err, observed, closed := hRunIPv6Connection(t, dialer, "example.com", "hello")
	require.Error(t, err)
	require.Equal(t, "", answer)
	require.Equal(t, 1, dialer.domains)
	require.Empty(t, observed)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("onClose not called")
	}
}

// A proxy that reports its connects refuses the IPv6 dial itself: the domain is dialed instead.
func TestH_IPv6FallbackAfterDialError(t *testing.T) {
	dialer := &hIPv6TestDialer{
		v6:     func() (net.Conn, error) { return nil, errors.New("socks5: network unreachable") },
		domain: hPeer("hello", "world"),
	}
	answer, err, observed, _ := hRunIPv6Connection(t, dialer, "example.com", "hello")
	require.NoError(t, err)
	require.Equal(t, "world", answer)
	require.Equal(t, []bool{false}, observed)
}

// Only a connection to an IPv6 address the app chose goes through the carry-over.
func TestH_IPv6FallbackApplies(t *testing.T) {
	require.True(t, hIPv6FallbackApplies(&adapter.InboundContext{Network: N.NetworkTCP, Destination: M.ParseSocksaddr("[2001:db8::1]:443")}))
	require.False(t, hIPv6FallbackApplies(&adapter.InboundContext{Network: N.NetworkTCP, Destination: M.ParseSocksaddr("192.0.2.1:443")}))
	require.False(t, hIPv6FallbackApplies(&adapter.InboundContext{Network: N.NetworkTCP, Destination: M.ParseSocksaddr("example.com:443")}))
	require.False(t, hIPv6FallbackApplies(&adapter.InboundContext{Network: N.NetworkUDP, Destination: M.ParseSocksaddr("[2001:db8::1]:443")}))
	require.False(t, hIPv6FallbackApplies(&adapter.InboundContext{Network: N.NetworkTCP, Destination: M.ParseSocksaddr("[2001:db8::1]:443"), TLSFragment: true}))
}

// An outbound known not to carry IPv6 is not asked again: the connection goes over the domain at
// once, with nothing to observe. One known to carry IPv6 is watched like any other, so a change
// of its exit is noticed.
func TestH_IPv6FallbackKnownOutbound(t *testing.T) {
	dialer := &hIPv6TestDialer{v6: hPeer("hello", "six"), domain: hPeer("hello", "four")}
	answer, err, observed, _ := hRunIPv6ConnectionKnowing(t, dialer, "example.com", "hello", &hObservations{supported: true, known: true})
	require.NoError(t, err)
	require.Equal(t, "six", answer)
	require.Equal(t, []bool{true}, observed, "still watched: its exit may lose IPv6")
	require.Equal(t, 0, dialer.domains)

	dialer = &hIPv6TestDialer{v6: hPeer("hello", ""), domain: hPeer("hello", "four")}
	answer, err, observed, _ = hRunIPv6ConnectionKnowing(t, dialer, "example.com", "hello", &hObservations{supported: true, known: true})
	require.NoError(t, err)
	require.Equal(t, "four", answer, "an exit that lost IPv6: carried over, and noticed")
	require.Equal(t, []bool{false}, observed)

	dialer = &hIPv6TestDialer{v6: hPeer("hello", "six"), domain: hPeer("hello", "four")}
	answer, err, observed, _ = hRunIPv6ConnectionKnowing(t, dialer, "example.com", "hello", &hObservations{supported: false, known: true})
	require.NoError(t, err)
	require.Equal(t, "four", answer, "known without IPv6: the domain at once, no IPv6 attempt")
	require.Empty(t, observed)
	require.Equal(t, 1, dialer.domains)
}

// With the route option on, every connection the manager gets to an IPv6 address goes through
// the carry-over, whoever hands it over: the router, or a group routing its own connections.
func TestH_IPv6FallbackThroughConnectionManager(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	manager := NewConnectionManager(ctx, log.NewNOPFactory().NewLogger("connection"))
	hSetIPv6Fallback(manager, true)
	dialer := &hIPv6TestDialer{v6: hPeer("hello", ""), domain: hPeer("hello", "world")}
	app, core := net.Pipe()
	metadata := adapter.InboundContext{Network: N.NetworkTCP, Destination: M.ParseSocksaddr("[2001:db8::1]:443"), Domain: "example.com", RouteOutbound: "proxy"}
	go manager.NewConnection(ctx, dialer, core, metadata, nil)
	go app.Write([]byte("hello"))
	app.SetReadDeadline(time.Now().Add(5 * time.Second))
	answer := make([]byte, 64)
	n, err := app.Read(answer)
	app.Close()
	require.NoError(t, err)
	require.Equal(t, "world", string(answer[:n]))
	require.Equal(t, 1, dialer.domains)
}
