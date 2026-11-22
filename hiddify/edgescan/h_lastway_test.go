package edgescan

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/hiddify/rating"

	"github.com/stretchr/testify/require"
)

// The last way is saved with the books and loaded again by a box started again; one older than
// Lifetime is gone.
func TestH_StoreLastWay(t *testing.T) {
	cache := newMemoryCache()
	store := OpenStore(cache, t.Name())
	_, found := store.LastWay("warp/wireguard")
	require.False(t, found)
	target := Target{AddrPort: netip.MustParseAddrPort("162.159.192.7:2408")}
	store.RememberWay("warp/wireguard", LastWay{Network: "wifi/IR", Target: target, Methods: map[string]string{"noise": "sip"}})
	store.RememberWay("warp/auto", LastWay{Methods: map[string]string{"tunnel": "awg"}})
	store.RememberWay("old", LastWay{Target: target, At: time.Now().Add(-Lifetime - time.Hour)})
	require.NoError(t, store.Save())

	restarted := newMemoryCache()
	restarted.data = cache.data
	loaded := OpenStore(restarted, t.Name())
	require.NotSame(t, store, loaded)
	way, found := loaded.LastWay("warp/wireguard")
	require.True(t, found)
	require.Equal(t, "wifi/IR", way.Network)
	require.Equal(t, target, way.Target)
	require.Equal(t, "sip", way.Method("noise"))
	way.Methods["noise"] = "changed"
	way, _ = loaded.LastWay("warp/wireguard")
	require.Equal(t, "sip", way.Method("noise"), "a copy")
	way, found = loaded.LastWay("warp/auto")
	require.True(t, found, "a way may be a method alone")
	require.Equal(t, "awg", way.Method("tunnel"))
	_, found = loaded.LastWay("old")
	require.False(t, found)

	loaded.ForgetWay("warp/wireguard")
	_, found = loaded.LastWay("warp/wireguard")
	require.False(t, found)
}

func TestH_TryLastWay(t *testing.T) {
	target := netip.MustParseAddrPort("162.159.192.7:2408")
	attempts := 0
	rtt, err := TryLastWay(context.Background(), func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		attempts++
		require.Equal(t, target, addrPort)
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("an attempt has a deadline")
		}
		if attempts == 1 {
			return 0, errors.New("lost")
		}
		return 30 * time.Millisecond, nil
	}, target)
	require.NoError(t, err, "one lost packet does not lose the way")
	require.Equal(t, 30*time.Millisecond, rtt)

	attempts = 0
	_, err = TryLastWay(context.Background(), func(context.Context, netip.AddrPort) (time.Duration, error) {
		attempts++
		return 0, errors.New("blocked")
	}, target)
	require.Error(t, err)
	require.Equal(t, LastWayAttempts, attempts)
}

// A working endpoint is left for a clearly better one only: a higher score, or as good a score
// and a much faster handshake.
func TestH_Better(t *testing.T) {
	current := netip.MustParseAddrPort("162.159.192.7:2408")
	other := netip.MustParseAddrPort("162.159.192.9:500")
	result := func(addrPort netip.AddrPort, score int, rtt time.Duration) Result {
		return Result{Target: Target{AddrPort: addrPort}, Score: rating.Score(score), RTT: rtt}
	}
	require.False(t, Better(result(current, 10, time.Millisecond), current, 3, time.Second), "the same endpoint")
	require.True(t, Better(result(other, 4, 300*time.Millisecond), current, 3, 100*time.Millisecond), "a higher score")
	require.False(t, Better(result(other, 2, time.Millisecond), current, 3, time.Second), "a lower score")
	require.True(t, Better(result(other, 3, 50*time.Millisecond), current, 3, 100*time.Millisecond), "half the time")
	require.False(t, Better(result(other, 3, 80*time.Millisecond), current, 3, 100*time.Millisecond), "a small gain")
}
