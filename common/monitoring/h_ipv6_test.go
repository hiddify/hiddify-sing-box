package monitoring

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
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

// After a URL test that answers, the monitoring opens one connection to the IPv6 probe through
// the outbound and records whether it got through; a group answers for its selected member;
// the DNS router and the route find the answer as adapter.IPv6Capability in the context.
func TestH_MonitoringProbesIPv6(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serverAddr := M.ParseSocksaddr(server.Listener.Addr().String())
	probe := M.ParseSocksaddr("[2001:db8::1]:443")
	var dialer net.Dialer
	outbound := func(tag string, ipv6 bool) *fakeOutbound {
		return &fakeOutbound{tag: tag, dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			switch destination {
			case serverAddr:
				return dialer.DialContext(ctx, network, destination.String())
			case probe:
				if ipv6 {
					return dialer.DialContext(ctx, network, serverAddr.String()) // any open connection will do
				}
				return nil, errors.New("no route to host")
			}
			return nil, errors.New("unreachable")
		}}
	}
	with, without := outbound("with6", true), outbound("without6", false)
	grp := &fakeGroup{fakeOutbound: fakeOutbound{tag: "grp"}, all: []string{"with6", "without6"}, selected: without}
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		Interval:       badoption.Duration(time.Hour),
		Workers:        2,
		URLs:           []string{server.URL + "/generate_204"},
		URLTestTimeout: badoption.Duration(time.Second),
		IPv6Probe:      "[2001:db8::1]:443",
	}, with, without, grp)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))

	_, known := m.OutboundIPv6("with6")
	require.False(t, known, "not known before the probe")
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))
	require.Eventually(t, func() bool {
		_, known1 := m.OutboundIPv6("with6")
		_, known2 := m.OutboundIPv6("without6")
		return known1 && known2
	}, 5*time.Second, 10*time.Millisecond)
	supported, _ := m.OutboundIPv6("with6")
	require.True(t, supported)
	supported, _ = m.OutboundIPv6("without6")
	require.False(t, supported)
	supported, known = m.OutboundIPv6("grp")
	require.True(t, known, "a group answers for its selected member")
	require.False(t, supported)
	grp.selected = with
	supported, _ = m.OutboundIPv6("grp")
	require.True(t, supported)

	capability := service.FromContext[adapter.IPv6Capability](m.ctx)
	require.NotNil(t, capability, "registered for the DNS router and the route")
	supported, known = capability.OutboundIPv6("with6")
	require.True(t, known && supported)
}

func TestH_IPv6ProbeAddress(t *testing.T) {
	require.Equal(t, defaultIPv6Probe, ipv6ProbeAddress(""))
	require.Equal(t, "", ipv6ProbeAddress("none"))
	require.Equal(t, "[2001:4860:4860::8888]:443", ipv6ProbeAddress("[2001:4860:4860::8888]:443"))
}
