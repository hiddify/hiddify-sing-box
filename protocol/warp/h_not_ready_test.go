package warp

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

// A dial while WARP has no tunnel says why: what WARP is doing and why its last attempt failed.
// It said "endpoint not initialized", thousands of times, while the cause (a device registration
// that timed out) was logged once in between.
func TestH_WARPDialSaysWhyItIsNotReady(t *testing.T) {
	cache := &hFakeCacheFile{store: map[string]*adapter.SavedBinary{}}
	ctx := service.ContextWith[adapter.CacheFile](hTestContext(t), cache)
	ep := hNewWARP(t, ctx, option.WARPEndpointOptions{})
	destination := M.ParseSocksaddrHostPort("1.1.1.1", 443)
	dialError := func() error {
		_, err := ep.DialContext(context.Background(), "tcp", destination)
		require.Error(t, err)
		_, packetErr := ep.ListenPacket(context.Background(), destination)
		require.Equal(t, err.Error(), packetErr.Error())
		_, _, packetErr = ep.ListenPacketWithDestination(context.Background(), destination)
		require.Equal(t, err.Error(), packetErr.Error())
		return err
	}
	require.EqualError(t, dialError(), "WARP is not connected yet, connecting")

	attempted := make(chan struct{}, 1)
	ep.registerWith = func(kind string) (*warpProfile, error) {
		select {
		case attempted <- struct{}{}:
		default:
		}
		return nil, E.New(`Post "https://api": net/http: TLS handshake timeout`)
	}
	session := ep.session()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ep.obtainProfile(session.done, kindMASQUE)
	}()
	<-attempted
	require.Eventually(t, func() bool { return ep.attemptError.Get() != nil }, time.Second, time.Millisecond)
	require.EqualError(t, dialError(), `WARP is not connected yet, registering a device; last attempt: register WARP masque device: Post "https://api": net/http: TLS handshake timeout`)
	ep.endSession()
	<-finished

	ep.fail(E.New("start WARP MASQUE tunnel: no route"))
	require.EqualError(t, dialError(), "WARP failed: start WARP MASQUE tunnel: no route")

	require.NoError(t, ep.Close())
	require.EqualError(t, dialError(), "WARP is closed")
}
