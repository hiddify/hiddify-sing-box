package edgescan

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/rating"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type hMemoryCache struct {
	adapter.CacheFile
	access sync.Mutex
	data   map[string]*adapter.SavedBinary
}

func newMemoryCache() *hMemoryCache {
	return &hMemoryCache{data: make(map[string]*adapter.SavedBinary)}
}

func (c *hMemoryCache) LoadBinary(tag string) *adapter.SavedBinary {
	c.access.Lock()
	defer c.access.Unlock()
	return c.data[tag]
}

func (c *hMemoryCache) SaveBinary(tag string, binary *adapter.SavedBinary) error {
	c.access.Lock()
	defer c.access.Unlock()
	c.data[tag] = binary
	return nil
}

// The store of a key is one for the process: what one scanner records the others see, and it is
// saved in one entry, with a book per kind, and loaded again.
func TestH_StoreShared(t *testing.T) {
	cache := newMemoryCache()
	key := t.Name()
	first := OpenStore(cache, key)
	second := OpenStore(cache, key)
	require.Same(t, first, second)
	target := netip.MustParseAddrPort("162.159.192.1:2408")
	first.Book(KindWARP).Success("home", target, time.Millisecond, time.Now())
	_, known := second.Book(KindWARP).Score("home", target)
	require.True(t, known)
	_, known = second.Book(KindPsiphon).Score("home", target)
	require.False(t, known, "a book per kind")
	require.NoError(t, second.Save())

	restarted := newMemoryCache() // a box started again: its cache file opened again
	restarted.data = cache.data
	loaded := OpenStore(restarted, key)
	require.NotSame(t, first, loaded)
	_, known = loaded.Book(KindWARP).Score("home", target)
	require.True(t, known, "loaded from the cache file")
	var saved savedStore
	require.NoError(t, json.Unmarshal(cache.data[key].Content, &saved))
	require.Equal(t, storeVersion, saved.Version)
}

// The scores a WARP endpoint kept under its own key join the shared book once.
func TestH_StoreAdopt(t *testing.T) {
	cache := newMemoryCache()
	legacy := NewBook()
	target := netip.MustParseAddrPort("162.159.192.7:2408")
	legacy.Success("home", target, time.Millisecond, time.Now())
	content, err := json.Marshal(legacy)
	require.NoError(t, err)
	cache.data["profile-1/warp-scanner"] = &adapter.SavedBinary{Content: content}
	store := OpenStore(cache, t.Name())
	store.Book(KindWARP).Success("home", netip.MustParseAddrPort("162.159.192.8:2408"), time.Millisecond, time.Now())
	store.Adopt(KindWARP, "profile-1/warp-scanner")
	store.Adopt(KindWARP, "profile-1/warp-scanner")
	score, known := store.Book(KindWARP).Score("home", target)
	require.True(t, known)
	require.Equal(t, rating.Score(1), score)
	preferred, _ := store.Book(KindWARP).Candidates("home")
	require.Len(t, preferred, 2, "both kept")

	// adopted once for good: a box started again does not merge it again
	require.NoError(t, store.Save())
	restarted := newMemoryCache()
	restarted.data = cache.data
	again := OpenStore(restarted, t.Name())
	require.True(t, again.merged["profile-1/warp-scanner"])
}

// The scanners that search the same at the same time share one search; one that leaves does not
// stop it for the others, and the next search runs again.
func TestH_StoreDo(t *testing.T) {
	store := OpenStore(newMemoryCache(), t.Name())
	var runs atomic.Int32
	release := make(chan struct{})
	run := func(ctx context.Context) (any, error) {
		runs.Add(1)
		select {
		case <-release:
			return "found", nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var wait sync.WaitGroup
	results := make([]any, 3)
	for i := range 3 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[i], _ = store.Do(context.Background(), "warp|home", run)
		}()
	}
	leaving, leave := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		leave()
	}()
	_, err := store.Do(leaving, "warp|home", run)
	require.ErrorIs(t, err, context.Canceled)
	close(release)
	wait.Wait()
	require.Equal(t, int32(1), runs.Load(), "one search for all")
	require.Equal(t, []any{"found", "found", "found"}, results)

	value, err := store.Do(context.Background(), "warp|home", func(ctx context.Context) (any, error) { return "again", nil })
	require.NoError(t, err)
	require.Equal(t, "again", value)
}

// A search every caller left stops, and a caller that comes after starts its own.
func TestH_StoreDoAbandoned(t *testing.T) {
	store := OpenStore(nil, t.Name())
	stopped := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := store.Do(ctx, "psiphon|home", func(ctx context.Context) (any, error) {
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	})
	require.Error(t, err)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("the abandoned search goes on")
	}
	value, err := store.Do(context.Background(), "psiphon|home", func(ctx context.Context) (any, error) { return "new", nil })
	require.NoError(t, err)
	require.Equal(t, "new", value)
}

type hDirectOutbound struct {
	adapter.Outbound
	typ string
}

func (o hDirectOutbound) Type() string { return o.typ }

type hOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m hOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

// A scanner reaches the network directly without a detour, or through a direct one.
func TestH_Direct(t *testing.T) {
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), hOutboundManager{outbounds: map[string]adapter.Outbound{
		"direct": hDirectOutbound{typ: C.TypeDirect},
		"proxy":  hDirectOutbound{typ: C.TypeVLESS},
	}})
	require.True(t, Direct(ctx, ""))
	require.True(t, Direct(ctx, "direct"))
	require.False(t, Direct(ctx, "proxy"))
	require.False(t, Direct(ctx, "missing"))
	cache := newMemoryCache()
	ctx = service.ContextWith[adapter.CacheFile](ctx, cache)
	require.Same(t, OpenStore(cache, SharedKey), OpenScannerStore(ctx, "direct", "private"))
	require.NotSame(t, OpenStore(cache, SharedKey), OpenScannerStore(ctx, "proxy", t.Name()))
	require.NotSame(t, OpenStore(nil, SharedKey), OpenStore(nil, SharedKey), "without a cache file, nothing is kept")
}

// The network is named once for every scanner, until it changes.
func TestH_StoreNetwork(t *testing.T) {
	store := OpenStore(nil, t.Name())
	urls := TraceURLs
	defer func() { TraceURLs = urls }()
	TraceURLs = nil
	first := store.Network(context.Background(), nil, nil)
	store.networkAccess.Lock()
	store.network.Name = "remembered"
	store.networkAccess.Unlock()
	require.Equal(t, "remembered", store.Network(context.Background(), nil, nil).Name)
	store.NetworkChanged()
	require.Equal(t, first.Name, store.Network(context.Background(), nil, nil).Name)
	store.networkAccess.Lock()
	store.network.Name = "found after the change"
	store.networkAccess.Unlock()
	store.NetworkChanged() // another scanner told of the same change
	require.Equal(t, "found after the change", store.Network(context.Background(), nil, nil).Name)
}
