package monitoring

import (
	"context"
	"net"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type hTypedOutbound struct {
	fakeOutbound
	outboundType string
}

func (o *hTypedOutbound) Type() string { return o.outboundType }

// hWaitDial answers nothing: the dial ends when the test gives up.
func hWaitDial(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestH_TimeoutFactorFollowsDNSTunnels(t *testing.T) {
	soar := &hTypedOutbound{fakeOutbound: fakeOutbound{tag: "soar"}, outboundType: C.TypeSoar}
	plain := &fakeOutbound{tag: "plain"}
	group := &fakeGroup{fakeOutbound: fakeOutbound{tag: "select"}, all: []string{"soar", "plain"}, selected: soar}
	chained := &fakeOutbound{tag: "over-soar", deps: []string{"soar"}}
	m := newTestMonitor(t, nil, option.MonitoringOptions{}, soar, plain, group, chained)
	registry, err := m.buildRegistry(newMonitoringRegistry())
	require.NoError(t, err)
	m.registry.Store(registry)

	require.Equal(t, time.Duration(dnsTunnelTimeoutFactor), m.timeoutFactor(soar))
	require.Equal(t, time.Duration(1), m.timeoutFactor(plain))
	require.Equal(t, time.Duration(dnsTunnelTimeoutFactor), m.timeoutFactor(group), "a group that selects a DNS tunnel")
	require.Equal(t, time.Duration(dnsTunnelTimeoutFactor), m.timeoutFactor(chained), "an outbound that dials through one")
	group.selected = plain
	require.Equal(t, time.Duration(1), m.timeoutFactor(group))
	for _, outboundType := range []string{C.TypeDNSTT, C.TypeMasterDNS} {
		out := &hTypedOutbound{fakeOutbound: fakeOutbound{tag: outboundType}, outboundType: outboundType}
		require.Equal(t, time.Duration(dnsTunnelTimeoutFactor), m.timeoutFactor(out), outboundType)
	}
}

// A Soar server can take seconds to look up the test URL's host, and the test timed out on a
// working DNS tunnel at the same limit as any proxy.
func TestH_DNSTunnelTestWaitsLonger(t *testing.T) {
	soar := &hTypedOutbound{fakeOutbound: fakeOutbound{tag: "soar", dial: hWaitDial}, outboundType: C.TypeSoar}
	plain := &fakeOutbound{tag: "plain", dial: hWaitDial}
	timeout := 100 * time.Millisecond
	m := newTestMonitor(t, nil, option.MonitoringOptions{URLTestTimeout: badoption.Duration(timeout)}, soar, plain)
	registry, err := m.buildRegistry(newMonitoringRegistry())
	require.NoError(t, err)
	m.registry.Store(registry)

	waited := func(tag string) time.Duration {
		start := time.Now()
		_, err := m.tester(context.Background(), tag, nil, false, false)
		require.Error(t, err)
		return time.Since(start)
	}
	require.Less(t, waited("plain"), 2*timeout)
	require.GreaterOrEqual(t, waited("soar"), dnsTunnelTimeoutFactor*timeout)
}
