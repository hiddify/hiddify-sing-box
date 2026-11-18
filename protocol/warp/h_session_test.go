package warp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// A start that was replaced publishes nothing, and its context has ended. It could publish its
// inner endpoint after the restart had taken the old one away, next to the new start's: a second
// device with the same key that nothing closed.
func TestH_WARPEndedStartPublishesNothing(t *testing.T) {
	ep := hNewWARP(t, hTestContext(t), option.WARPEndpointOptions{WARPConfig: hWARPConfig(t, hWARPConfigJSON)})
	session, previous := ep.beginSession()
	require.Nil(t, previous)
	require.True(t, ep.publish(session.done, func() {}))
	require.NoError(t, session.ctx.Err())

	next, ended := ep.beginSession() // what a restart does
	require.Same(t, session, ended)
	require.False(t, ep.publish(session.done, func() { t.Fatal("published by a start that ended") }))
	require.Error(t, session.ctx.Err())
	require.True(t, ep.publish(next.done, func() {}))

	ep.endSession() // what Close does
	require.False(t, ep.publish(next.done, func() { t.Fatal("published by a start that ended") }))

	// the check of a start that ended does nothing, whatever the endpoint has by now
	session.failover = &warpFailover{current: netip.MustParseAddrPort("162.159.192.1:2408")}
	ep.check(session, true)
	require.Zero(t, session.failover.lastTx)
}

// A start waits for the one it replaces to leave: side by side they registered, scanned and
// dialed with one key.
func TestH_WARPStartWaitsForTheOneItReplaces(t *testing.T) {
	options := option.WARPEndpointOptions{WARPConfig: hWARPConfig(t, hWARPConfigJSON)}
	options.Detour = "missing-detour" // the tunnel cannot connect: the start ends with the test
	ep := hNewWARP(t, hTestContext(t), options)
	running, _ := ep.beginSession() // a start that is still on its way out
	started := make(chan struct{})
	go func() {
		ep.start()
		close(started)
	}()
	time.Sleep(200 * time.Millisecond)
	require.Nil(t, ep.currentProfile(), "the new start went on next to the one that had not left")
	select {
	case <-running.done:
	default:
		t.Fatal("the start that is replaced was not told to end")
	}
	close(running.finished) // it has left
	require.Eventually(t, func() bool { return ep.currentProfile() != nil }, 3*time.Second, 10*time.Millisecond)
	require.NoError(t, ep.Close())
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("the start did not end with the endpoint")
	}
}

// The scan of a start that ended stops: it ran on the endpoint's context, to the end of its
// probes, while the next start scanned as well.
func TestH_WARPScanEndsWithItsStart(t *testing.T) {
	ep := hNewWARP(t, hTestContext(t), option.WARPEndpointOptions{
		WARPConfig: hWARPConfig(t, hWARPConfigJSON),
		Scanner:    &option.WARPScannerOptions{Enabled: true, Count: 2, Timeout: badoption.Duration(4 * time.Second)},
	})
	session, _ := ep.beginSession()
	probing := make(chan struct{}, 64)
	silent := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		probing <- struct{}{}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	failover := &warpFailover{
		config:  ep.options.WARPConfig,
		book:    warpscan.NewBook(),
		logger:  hLogger(),
		probes:  map[string]warpscan.Probe{"": silent},
		network: warpscan.NetworkInfo{Name: "wifi/IR", IPv4: true},
	}
	scanned := make(chan error, 1)
	go func() {
		_, _, err := ep.scanWith(session.ctx, failover, nil, false)
		scanned <- err
	}()
	select {
	case <-probing:
	case <-time.After(3 * time.Second):
		t.Fatal("the scan did not probe")
	}
	ep.endSession()
	select {
	case err := <-scanned:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("the scan went on after its start had ended")
	}
}
