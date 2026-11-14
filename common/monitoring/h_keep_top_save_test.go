package monitoring

import (
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/htest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

type countingCache struct {
	fakeCache
	saves atomic.Int32
}

func (c *countingCache) SaveBinary(tag string, set *adapter.SavedBinary) error {
	c.saves.Add(1)
	return c.fakeCache.SaveBinary(tag, set)
}

// A pick steps once for each outbound it tests. Each step used to save every ping, a write of
// them all and a sync of the disk, hundreds of times in a test of a big profile: they are saved
// now and then while the pick goes on, and when it is over.
func TestH_KeepTopPickDoesNotSaveAtEveryStep(t *testing.T) {
	link, addr := slowServer(t)
	cache := &countingCache{fakeCache: fakeCache{data: map[string]*adapter.SavedBinary{}}}
	const total = 40
	var outbounds []adapter.Outbound
	for i := 0; i < total; i++ {
		// the last one is far faster than the rest, so which one is kept does not hang on a
		// millisecond of the scheduler's
		delay := int64(40 + i%5)
		if i == total-1 {
			delay = 2
		}
		outbounds = append(outbounds, newTopLazy(fmt.Sprint("p", i), addr, delay))
	}
	m := newTestMonitor(t, cache, option.MonitoringOptions{
		URLs:           []string{link},
		Interval:       badoption.Duration(time.Hour),
		URLTestTimeout: badoption.Duration(2 * time.Second),
		KeepTop:        &option.KeepTopOptions{Count: 1, Batch: 2},
	}, outbounds...)
	require.NoError(t, htest.Start(m, adapter.StartStateInitialize))
	require.NoError(t, htest.Start(m, adapter.StartStatePostStart))
	require.Eventually(t, func() bool {
		return slices.Equal(keptLazies(m), []string{fmt.Sprint("p", total-1)})
	}, 30*time.Second, 5*time.Millisecond)
	require.NotNil(t, cache.LoadBinary("outbound_monitoring_history"), "saved when the pick is over")
	require.Less(t, int(cache.saves.Load()), total/2, "not a save for each outbound tested")
}
