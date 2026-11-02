package monitoring

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// hFakeDNS answers every lookup with the addresses given; nothing else of a DNS router.
type hFakeDNS struct {
	adapter.DNSRouter
	addresses []netip.Addr
}

func (d *hFakeDNS) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return d.addresses, nil
}

// The monitoring learns an outbound's IPv6 from what the router observed on its connections:
// nothing is known before the first observation; one IPv6 connection that answered says it is
// carried; two in a row that got nothing while IPv4 answered say it is not, for a while; a group
// answers for the member it leads to; the DNS router and the route find it as
// adapter.IPv6Capability in the context.
func TestH_MonitoringLearnsIPv6(t *testing.T) {
	a, b := &fakeOutbound{tag: "a"}, &fakeOutbound{tag: "b"}
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: []string{"a", "b"}, selected: a}
	m := newTestMonitor(t, nil, option.MonitoringOptions{Interval: badoption.Duration(time.Hour)}, a, b, grp)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))

	_, known := m.OutboundIPv6("a")
	require.False(t, known, "nothing is known before an observation")
	_, known = m.OutboundIPv6("grp")
	require.False(t, known)

	m.ObserveIPv6("grp", false) // a group's observation goes to its selected member
	_, known = m.OutboundIPv6("a")
	require.False(t, known, "one failure may be the destination's")
	m.ObserveIPv6("a", false)
	supported, known := m.OutboundIPv6("a")
	require.True(t, known && !supported, "two in a row is the exit")
	supported, known = m.OutboundIPv6("grp")
	require.True(t, known && !supported, "the group answers for its selected member")
	_, known = m.OutboundIPv6("b")
	require.False(t, known, "the other member is untouched")
	his := m.getUrlTest("a")
	require.NotNil(t, his.IPv6)
	require.False(t, *his.IPv6, "shown to the app")

	m.ObserveIPv6("a", true)
	supported, known = m.OutboundIPv6("a")
	require.True(t, known && supported, "an IPv6 connection that answered says it is carried")
	m.ObserveIPv6("a", false)
	supported, known = m.OutboundIPv6("a")
	require.True(t, known && supported, "one failure after a success is the destination's")

	grp.selected = b
	m.ObserveIPv6("b", false)
	m.ObserveIPv6("b", false)
	supported, known = m.OutboundIPv6("grp")
	require.True(t, known && !supported, "the group follows its selection")

	// found without IPv6 long enough ago: let an IPv6 connection through again
	m.ipv6Access.Lock()
	m.ipv6["b"].observedAt = time.Now().Add(-ipv6Forget - time.Second)
	m.ipv6Access.Unlock()
	_, known = m.OutboundIPv6("b")
	require.False(t, known, "forgotten after a while, so the exit may show it gained IPv6")

	capability := service.FromContext[adapter.IPv6Capability](m.ctx)
	require.NotNil(t, capability, "registered for the DNS router and the route")
	supported, known = capability.OutboundIPv6("a")
	require.True(t, known && supported)
	_, known = capability.OutboundIPv6("unregistered")
	require.False(t, known)
}

// A group with no single selection carries IPv6 only when every live member is known to.
func TestH_MonitoringIPv6OfSpreadingGroup(t *testing.T) {
	a, b := &fakeOutbound{tag: "a"}, &fakeOutbound{tag: "b"}
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: []string{"a", "b"}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{Interval: badoption.Duration(time.Hour)}, a, b, grp)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	setHistory(m, "a", 50, false, nil)
	setHistory(m, "b", 60, false, nil)

	m.ObserveIPv6("a", true)
	_, known := m.OutboundIPv6("grp")
	require.False(t, known, "a member not observed yet leaves the group unknown")
	m.ObserveIPv6("b", true)
	supported, known := m.OutboundIPv6("grp")
	require.True(t, known && supported)
	m.ObserveIPv6("b", false)
	m.ObserveIPv6("b", false)
	supported, known = m.OutboundIPv6("grp")
	require.True(t, known && !supported, "one member without IPv6 is enough to say no")
}

// With verify_ipv6, an outbound's URL test is followed once per run by the same URL over the
// host's IPv6 address through it, and what that showed is known, cached with the URL test
// results and shown to the app; a declaration from the link is known from the start.
func TestH_MonitoringVerifiesIPv6AtURLTest(t *testing.T) {
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
	var dialer net.Dialer
	serverAddr := M.ParseSocksaddr("[::1]:" + strconv.Itoa(port))
	// the URL test itself dials the host name (the proxy resolves it); the verification dials
	// the IPv6 address: with6 reaches both, without6 only the name
	outbound := func(tag string, ipv6 bool) *fakeOutbound {
		return &fakeOutbound{tag: tag, dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			if destination.IsFqdn() || ipv6 {
				return dialer.DialContext(ctx, network, serverAddr.String())
			}
			return nil, errors.New("no route to host")
		}}
	}
	with, without, declared, cached := outbound("with6", true), outbound("without6", false), outbound("declared", true), outbound("cached", true)
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        2,
		URLs:           []string{link},
		URLTestTimeout: badoption.Duration(time.Second),
		VerifyIPv6:     true,
		IPv6Declared:   map[string]bool{"declared": false},
	}, with, without, declared, cached)
	service.MustRegister[adapter.DNSRouter](m.ctx, &hFakeDNS{addresses: []netip.Addr{netip.MustParseAddr("::1")}})
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	// an earlier run found cached without IPv6; its exit has it now
	no := false
	setCached(m, "cached", adapter.URLTestHistory{Delay: 50, IPv6: &no, IPv6FromCache: true})
	m.seedIPv6Knowledge()
	supported, known := m.OutboundIPv6("cached")
	require.True(t, known && !supported, "cached: known before any test")
	supported, known = m.OutboundIPv6("declared")
	require.True(t, known && !supported, "declared by the link: known before any test")
	_, known = m.OutboundIPv6("with6")
	require.False(t, known)

	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))
	require.Eventually(t, func() bool {
		_, known1 := m.OutboundIPv6("with6")
		_, known2 := m.OutboundIPv6("without6")
		cachedSupported, _ := m.OutboundIPv6("cached")
		return known1 && known2 && cachedSupported
	}, 10*time.Second, 10*time.Millisecond)
	supported, _ = m.OutboundIPv6("with6")
	require.True(t, supported)
	supported, _ = m.OutboundIPv6("without6")
	require.False(t, supported)
	his := m.getUrlTest("without6")
	require.NotNil(t, his.IPv6)
	require.False(t, *his.IPv6, "cached with the URL test results")
	his = m.getUrlTest("cached")
	require.True(t, *his.IPv6 && !his.IPv6FromCache, "a cached answer is verified again at the first URL test")
}

// What an earlier run cached is known at the start, before any test.
func TestH_MonitoringSeedsIPv6FromCache(t *testing.T) {
	a := &fakeOutbound{tag: "a"}
	m := newTestMonitor(t, nil, option.MonitoringOptions{Interval: badoption.Duration(time.Hour)}, a)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	no := false
	setCached(m, "a", adapter.URLTestHistory{Delay: 50, IPv6: &no})
	m.seedIPv6Knowledge()
	supported, known := m.OutboundIPv6("a")
	require.True(t, known && !supported)
}

// setCached gives the outbound a history as loaded from the cache file.
func setCached(m *OutboundMonitoring, tag string, history adapter.URLTestHistory) {
	s := m.reg().outbounds[tag]
	s.mu.Lock()
	s.history = history
	s.from_cache = true
	s.mu.Unlock()
}
