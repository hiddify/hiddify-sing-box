package warp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

// hStatusDetour is a detour with a status of its own that counts the dials through it. They fail
// at once, as those through a WARP that has no tunnel yet do. Once hold is set, a UDP dial (a
// handshake of the race) waits for its context instead: the start then stays in the race until
// the test ends it.
type hStatusDetour struct {
	adapter.Outbound
	tag    string
	status atomic.Uint32
	hold   atomic.Bool
	udp    atomic.Int32
	tcp    atomic.Int32
}

func (d *hStatusDetour) udpDial(ctx context.Context) error {
	d.udp.Add(1)
	if d.hold.Load() {
		<-ctx.Done()
		return ctx.Err()
	}
	return errors.New("WARP is not connected yet, auto mode is choosing a tunnel")
}

func (d *hStatusDetour) Tag() string            { return d.tag }
func (d *hStatusDetour) Status() adapter.Status { return adapter.Status(d.status.Load()) }
func (d *hStatusDetour) dials() int32           { return d.udp.Load() + d.tcp.Load() }
func (d *hStatusDetour) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		return nil, d.udpDial(ctx)
	}
	d.tcp.Add(1)
	return nil, errors.New("WARP is not connected yet, auto mode is choosing a tunnel")
}

func (d *hStatusDetour) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, d.udpDial(ctx)
}

// hGroupDetour is a selector: always ready itself, while the member it selected may not be.
type hGroupDetour struct {
	adapter.Outbound
	tag      string
	selected adapter.Outbound
}

func (g *hGroupDetour) Tag() string                              { return g.tag }
func (g *hGroupDetour) Status() adapter.Status                   { return adapter.StatusReady }
func (g *hGroupDetour) All() []string                            { return []string{g.selected.Tag()} }
func (g *hGroupDetour) Selected(network string) adapter.Outbound { return g.selected }
func (g *hGroupDetour) AttachConnection(io.Closer) func()        { return func() {} }
func (g *hGroupDetour) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return g.selected.DialContext(ctx, network, destination)
}

func (g *hGroupDetour) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return g.selected.ListenPacket(ctx, destination)
}

// hLazyDetour is a lazy outbound at rest: ready while nothing is loaded, as adapter/outbound.Lazy
// is, and the status of the real one, here still searching, once held or dialed.
type hLazyDetour struct {
	*hStatusDetour
	loaded   atomic.Bool
	holds    atomic.Int32
	released atomic.Int32
}

func (l *hLazyDetour) Status() adapter.Status {
	if !l.loaded.Load() {
		return adapter.StatusReady
	}
	return l.hStatusDetour.Status()
}
func (l *hLazyDetour) Loaded() bool    { return l.loaded.Load() }
func (l *hLazyDetour) Acquire() func() { return func() {} }
func (l *hLazyDetour) Unload()         {}
func (l *hLazyDetour) Held() bool      { return l.holds.Load() > l.released.Load() }
func (l *hLazyDetour) Hold() (adapter.Outbound, func(), error) {
	l.loaded.Store(true)
	l.holds.Add(1)
	return l.hStatusDetour, func() { l.released.Add(1) }, nil
}

func (l *hLazyDetour) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	l.loaded.Store(true)
	return l.hStatusDetour.DialContext(ctx, network, destination)
}

func (l *hLazyDetour) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	l.loaded.Store(true)
	return l.hStatusDetour.ListenPacket(ctx, destination)
}

type hDetourManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *hDetourManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

type hNoDNSTransports struct{ adapter.DNSTransportManager }

func (hNoDNSTransports) Transports() []adapter.DNSTransport { return nil }
func (hNoDNSTransports) Default() adapter.DNSTransport      { return nil }

type hNoNetwork struct{ adapter.NetworkManager }

func (hNoNetwork) DefaultOptions() adapter.NetworkOptions             { return adapter.NetworkOptions{} }
func (hNoNetwork) DefaultNetworkInterface() *adapter.NetworkInterface { return nil }

type hFixedDNS struct{ adapter.DNSRouter }

func (hFixedDNS) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}

// hWARPBehind is an auto mode WARP whose detour is the outbound tagged detour among outbounds.
func hWARPBehind(t *testing.T, detour string, outbounds ...adapter.Outbound) *WARPEndpoint {
	manager := &hDetourManager{outbounds: make(map[string]adapter.Outbound)}
	for _, outbound := range outbounds {
		manager.outbounds[outbound.Tag()] = outbound
	}
	cache := &hFakeCacheFile{store: map[string]*adapter.SavedBinary{}}
	ctx := service.ContextWith[adapter.CacheFile](hTestContext(t), cache)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, hNoDNSTransports{})
	ctx = service.ContextWith[adapter.NetworkManager](ctx, hNoNetwork{})
	ctx = service.ContextWith[adapter.DNSRouter](ctx, hFixedDNS{})
	options := option.WARPEndpointOptions{Mode: modeAuto, WARPConfig: hWARPConfig(t, hWARPConfigJSON)}
	options.Detour = detour
	options.Server, options.ServerPort = "162.159.192.1", 2408 // the test profile names its peer by domain
	ep := hNewWARP(t, ctx, options)
	ep.registerWith = func(kind string) (*warpProfile, error) {
		return &warpProfile{Kind: kind, ID: "device-" + kind, Created: time.Now()}, nil
	}
	return ep
}

// hStartWaitsFor starts ep and checks that nothing goes through searching (the outbound that
// carries the detour's traffic) until it is ready: not the network detection, not the race of
// the tunnels. Before, both failed at once, and auto mode drew its tunnel without a race ("no
// tunnel answered") and rated it under a network named by its interface alone.
func hStartWaitsFor(t *testing.T, ep *WARPEndpoint, searching *hStatusDetour) {
	searching.status.Store(uint32(adapter.StatusSearching))
	started := make(chan struct{})
	go func() {
		defer close(started)
		ep.start()
	}()
	time.Sleep(4 * detourReadyPoll)
	require.Zero(t, searching.dials(), "dialed through a detour that is still searching (udp %d, tcp %d)", searching.udp.Load(), searching.tcp.Load())
	_, err := ep.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("1.1.1.1", 443))
	require.EqualError(t, err, "WARP is not connected yet, waiting for its detour "+searching.tag)

	searching.hold.Store(true) // the start stays in the race: the test has no tunnel to connect
	searching.status.Store(uint32(adapter.StatusReady))
	require.Eventually(t, func() bool { return searching.udp.Load() > 0 && searching.tcp.Load() > 0 },
		3*time.Second, 10*time.Millisecond, "no race and no network detection once the detour is ready")
	require.NoError(t, ep.Close())
	<-started
}

func TestH_WARPStartWaitsForItsDetour(t *testing.T) {
	detour := &hStatusDetour{tag: "inner-warp"}
	hStartWaitsFor(t, hWARPBehind(t, detour.tag, detour), detour)
}

// A selector is always ready itself: the start waits for the member it selected.
func TestH_WARPStartWaitsForTheMemberOfAGroupDetour(t *testing.T) {
	member := &hStatusDetour{tag: "inner-warp"}
	group := &hGroupDetour{tag: "select", selected: member}
	hStartWaitsFor(t, hWARPBehind(t, group.tag, group, member), member)
}

// A lazy detour at rest says it is ready, and its real outbound starts only at the first dial,
// which then fails: the start holds it, so it starts now, and waits for it.
func TestH_WARPStartHoldsALazyDetour(t *testing.T) {
	lazy := &hLazyDetour{hStatusDetour: &hStatusDetour{tag: "lazy-warp"}}
	ep := hWARPBehind(t, lazy.Tag(), lazy)
	hStartWaitsFor(t, ep, lazy.hStatusDetour)
	require.Positive(t, lazy.holds.Load(), "the lazy detour was not held")
	require.Equal(t, lazy.holds.Load(), lazy.released.Load(), "the lazy detour is still held")
}

// A detour that failed, or one that never becomes ready, is not waited for longer than it must.
func TestH_WARPStartDoesNotWaitForAFailedDetour(t *testing.T) {
	detour := &hStatusDetour{tag: "broken"}
	detour.status.Store(uint32(adapter.StatusFailed))
	ep := hWARPBehind(t, detour.tag, detour)
	require.True(t, ep.waitDetour(ep.session().done))
	require.Zero(t, ep.waitingDetour.Load())

	unknown := hWARPBehind(t, "not-there")
	require.True(t, unknown.waitDetour(unknown.session().done))

	detour.status.Store(uint32(adapter.StatusConnecting))
	session := ep.session()
	waited := make(chan bool, 1)
	go func() { waited <- ep.waitDetour(session.done) }()
	time.Sleep(2 * detourReadyPoll)
	ep.endSession() // the start ends: it leaves at once
	select {
	case ok := <-waited:
		require.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("the wait did not end with the start")
	}
	require.Zero(t, ep.waitingDetour.Load())
}

// While the detour is down, the tunnel or port in use is not blamed for it.
func TestH_WARPDetourReady(t *testing.T) {
	member := &hStatusDetour{tag: "inner-warp"}
	group := &hGroupDetour{tag: "select", selected: member}
	ep := hWARPBehind(t, group.tag, group, member)
	member.status.Store(uint32(adapter.StatusReconnecting))
	require.False(t, ep.detourReady())
	member.status.Store(uint32(adapter.StatusReady))
	require.True(t, ep.detourReady())
	require.True(t, hWARPBehind(t, "").detourReady())
}

// A detour that registers or searches is waited for as long as it takes: nothing gets through it
// meanwhile. One that is connecting is waited for detourReadyWait, and then dialed through.
func TestH_WARPWaitsForAWarmingDetourWithoutALimit(t *testing.T) {
	limit, poll := detourReadyWait, detourReadyPoll
	detourReadyWait, detourReadyPoll = 100*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { detourReadyWait, detourReadyPoll = limit, poll })

	detour := &hStatusDetour{tag: "inner-warp"}
	ep := hWARPBehind(t, detour.tag, detour)
	for _, status := range []adapter.Status{adapter.StatusRegistering, adapter.StatusSearching} {
		detour.status.Store(uint32(status))
		session := ep.session()
		waited := make(chan bool, 1)
		go func() { waited <- ep.waitDetour(session.done) }()
		select {
		case <-waited:
			t.Fatalf("left a detour that is %s after %s", status, 5*detourReadyWait)
		case <-time.After(5 * detourReadyWait):
		}
		detour.status.Store(uint32(adapter.StatusReady))
		select {
		case ok := <-waited:
			require.True(t, ok)
		case <-time.After(time.Second):
			t.Fatal("the wait did not see the detour become ready")
		}
	}

	detour.status.Store(uint32(adapter.StatusConnecting))
	started := time.Now()
	require.True(t, ep.waitDetour(ep.session().done))
	require.GreaterOrEqual(t, time.Since(started), detourReadyWait)
	require.Less(t, time.Since(started), time.Second)
}
