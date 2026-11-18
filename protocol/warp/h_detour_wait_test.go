package warp

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/stretchr/testify/require"
)

// The race of auto mode goes through the detour, so it waits for the detour: it ran while the
// inner WARP of warp in warp was still choosing its tunnel, every handshake stayed silent for the
// whole timeout, and the tunnel was drawn without a race.
func TestH_WaitDetourUntilReady(t *testing.T) {
	var status atomic.Uint32
	status.Store(uint32(adapter.StatusSearching))
	read := func() adapter.Status { return adapter.Status(status.Load()) }
	go func() {
		time.Sleep(60 * time.Millisecond)
		status.Store(uint32(adapter.StatusReady))
	}()
	started := time.Now()
	require.True(t, waitReady(make(chan struct{}), read, 5*time.Second, 5*time.Millisecond))
	require.GreaterOrEqual(t, time.Since(started), 60*time.Millisecond, "it did not wait for the detour")
	require.Less(t, time.Since(started), 2*time.Second)
}

func TestH_WaitDetourLeaves(t *testing.T) {
	connecting := func() adapter.Status { return adapter.StatusConnecting }
	// no detour: no wait
	require.True(t, waitReady(make(chan struct{}), nil, time.Hour, time.Millisecond))
	// a detour that gave up is raced through, not waited for
	require.True(t, waitReady(make(chan struct{}), func() adapter.Status { return adapter.StatusFailed }, time.Hour, time.Millisecond))
	// one that never becomes ready is waited for its limit only
	started := time.Now()
	require.True(t, waitReady(make(chan struct{}), connecting, 50*time.Millisecond, 5*time.Millisecond))
	require.Less(t, time.Since(started), 2*time.Second)
	// a start that ends leaves at once, with false
	done := make(chan struct{})
	close(done)
	require.False(t, waitReady(done, connecting, time.Hour, time.Millisecond))
	require.False(t, waitReady(done, nil, time.Hour, time.Millisecond))
}
