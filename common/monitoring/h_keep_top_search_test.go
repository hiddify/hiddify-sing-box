package monitoring

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// searchLazy is a lazy outbound that searches before it works, as WARP: a test creates its real
// one, which fails while it searches and answers once it is ready; an unload closes it, which
// stops the search.
type searchLazy struct {
	fakeLazy
	loaded atomic.Bool
	status atomic.Uint32
}

func newSearchLazy(tag string, addr M.Socksaddr) *searchLazy {
	s := &searchLazy{}
	s.tag = tag
	s.status.Store(uint32(adapter.StatusSearching))
	s.dial = dialTo(addr, func(ctx context.Context) error {
		s.loaded.Store(true) // the test created the real one
		if adapter.Status(s.status.Load()) != adapter.StatusReady {
			return errors.New("endpoint not initialized")
		}
		return nil
	})
	return s
}

func (s *searchLazy) Loaded() bool { return s.loaded.Load() }

// Status is ready while nothing is created, as a lazy outbound's is, else the real one's.
func (s *searchLazy) Status() adapter.Status {
	if !s.loaded.Load() {
		return adapter.StatusReady
	}
	return adapter.Status(s.status.Load())
}
func (s *searchLazy) Unload() {
	s.unloads.Add(1)
	s.loaded.Store(false)
}

func searchTestMonitor(t *testing.T, link string, count int, outbounds ...adapter.Outbound) *OutboundMonitoring {
	t.Helper()
	old := keepTopSearchPoll
	keepTopSearchPoll = 20 * time.Millisecond
	t.Cleanup(func() { keepTopSearchPoll = old })
	m := newTestMonitor(t, nil, option.MonitoringOptions{
		URLs:           []string{link},
		Interval:       badoption.Duration(time.Hour),
		DebounceWindow: badoption.Duration(10 * time.Millisecond),
		URLTestTimeout: badoption.Duration(2 * time.Second),
		KeepTop:        &option.KeepTopOptions{Count: count, Batch: 5},
	}, outbounds...)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))
	return m
}

// Fewer answer than are kept: the one that searches goes on, used beside the kept ones, and once
// it is through and answers it takes the free place.
func TestH_KeepTopLetsASearcherGoOn(t *testing.T) {
	link, addr := slowServer(t)
	fast := newTopLazy("vless", addr, 10)
	dead := newTopLazy("trojan", addr, -1)
	warp := newSearchLazy("warp", addr)
	m := searchTestMonitor(t, link, 2, fast, dead, warp)
	require.Eventually(t, func() bool { return keptLazies(m) != nil }, 20*time.Second, 2*time.Millisecond, "the pick ends")
	require.Equal(t, []string{"vless"}, keptLazies(m), "only one answers")
	require.Eventually(t, func() bool { return !m.Parked("warp") }, 5*time.Second, 5*time.Millisecond, "it searches while there is a place: it is used")
	require.True(t, warp.Loaded(), "and goes on")
	require.True(t, m.Parked("trojan"), "a dead one that does not search rests")

	warp.status.Store(uint32(adapter.StatusReady))
	require.Eventually(t, func() bool { return slices.Equal(keptLazies(m), []string{"vless", "warp"}) }, 10*time.Second, 5*time.Millisecond,
		"through, it answers its test and takes the free place")
	require.False(t, m.Parked("warp"))
}

// Enough answer: the one that searches rests, which stops its search.
func TestH_KeepTopRestsASearcherWhenFull(t *testing.T) {
	link, addr := slowServer(t)
	fast := newTopLazy("vless", addr, 10)
	other := newTopLazy("trojan", addr, 20)
	warp := newSearchLazy("warp", addr)
	m := searchTestMonitor(t, link, 2, fast, other, warp)
	require.Eventually(t, func() bool { return keptLazies(m) != nil }, 20*time.Second, 2*time.Millisecond, "the pick ends")
	require.Equal(t, []string{"trojan", "vless"}, keptLazies(m))
	require.Eventually(t, func() bool { return !warp.Loaded() }, 5*time.Second, 5*time.Millisecond, "no place for it: unloaded, its search stops")
	require.True(t, m.Parked("warp"))
}

// heldLazy is a lazy outbound something holds (a DNS server its endpoint).
type heldLazy struct {
	*topLazy
}

func (h heldLazy) Hold() (adapter.Outbound, func(), error) { return h, func() {}, nil }
func (h heldLazy) Held() bool                              { return true }

// What a proxy in use goes through is in use too, and what an outbound that runs anyway goes
// through; one held runs whatever its ping, as a pinned one.
func TestH_KeepTopKeepsDetoursAndHeld(t *testing.T) {
	link, addr := slowServer(t)
	fast := newTopLazy("vless", addr, 10)
	fast.deps = []string{"hop"}
	hop := newTopLazy("hop", addr, -1)
	hop2 := newTopLazy("hop2", addr, -1)
	dead := newTopLazy("trojan", addr, -1)
	held := heldLazy{newTopLazy("ovpn", addr, -1)}
	plain := &fakeOutbound{tag: "plain", dial: dialTo(addr, nil), deps: []string{"hop2"}}
	m := searchTestMonitor(t, link, 1, fast, hop, hop2, dead, held, plain)
	require.Eventually(t, func() bool { return keptLazies(m) != nil }, 20*time.Second, 2*time.Millisecond, "the pick ends")
	require.Contains(t, keptLazies(m), "vless")
	require.False(t, m.Parked("hop"), "the detour of one in use")
	require.False(t, m.Parked("hop2"), "the detour of one that runs anyway")
	require.False(t, m.Parked("ovpn"), "held: it runs")
	require.True(t, m.Parked("trojan"))
}
