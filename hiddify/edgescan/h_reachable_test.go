package edgescan

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// hPause is a pause manager whose network the test pauses and wakes.
type hPause struct {
	pause.Manager
	paused    atomic.Bool
	access    sync.Mutex
	callbacks list.List[pause.Callback]
}

func (p *hPause) IsDevicePaused() bool  { return false }
func (p *hPause) IsNetworkPaused() bool { return p.paused.Load() }
func (p *hPause) RegisterCallback(callback pause.Callback) *list.Element[pause.Callback] {
	p.access.Lock()
	defer p.access.Unlock()
	return p.callbacks.PushBack(callback)
}

func (p *hPause) UnregisterCallback(element *list.Element[pause.Callback]) {
	p.access.Lock()
	defer p.access.Unlock()
	p.callbacks.Remove(element)
}

func (p *hPause) set(paused bool) {
	p.paused.Store(paused)
	p.access.Lock()
	callbacks := p.callbacks.Array()
	p.access.Unlock()
	for _, callback := range callbacks {
		callback(pause.EventNetworkWake)
	}
}

// Without a network a search does not probe: it waits for one, on the network's event, and the
// wait does not count toward its time.
func TestH_SearchWaitsForNetwork(t *testing.T) {
	defer func(saved time.Duration) { minRound = saved }(minRound)
	minRound = 10 * time.Millisecond
	manager := &hPause{}
	manager.paused.Store(true)
	ctx := service.ContextWith[pause.Manager](context.Background(), manager)
	require.False(t, Reachable(ctx))
	var rounds atomic.Int32
	done := make(chan error, 1)
	go func() {
		_, err := Search(ctx, log.NewNOPFactory().Logger(), 200*time.Millisecond, func(ctx context.Context) ([]Result, error) {
			rounds.Add(1)
			return nil, errors.New("nothing")
		})
		done <- err
	}()
	time.Sleep(400 * time.Millisecond)
	require.Zero(t, rounds.Load(), "no probe without a network")
	select {
	case <-done:
		t.Fatal("the time without a network counted")
	default:
	}
	manager.set(false)
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrSearchExhausted)
	case <-time.After(5 * time.Second):
		t.Fatal("the search did not go on with the network")
	}
	require.Positive(t, rounds.Load())

	cancelled, cancel := context.WithCancel(ctx)
	manager.paused.Store(true)
	cancel()
	_, ok := WaitReachable(cancelled, nil)
	require.False(t, ok)
}
