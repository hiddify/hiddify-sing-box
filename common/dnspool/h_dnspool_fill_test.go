package dnspool

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/stretchr/testify/require"
)

// closedUDPAddr is a loopback UDP address nothing listens on.
func closedUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := pc.LocalAddr().String()
	require.NoError(t, pc.Close())
	return addr
}

// Fill probes the candidates in order until Want of them joined, leaves the rest, and probes
// the next ones once resolvers in the pool go down.
func TestH_DnspoolFill(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	dial, err := DialFunc(context.Background(), option.DialerOptions{})
	require.NoError(t, err)
	pool, err := StartPool(logger, "test", PoolOptions{DownAfter: 1, PerAttempt: 200 * time.Millisecond, Deadline: 300 * time.Millisecond, ProbeInterval: time.Hour}, dial)
	require.NoError(t, err)
	defer pool.Close()

	// the first two that pass the probe have nothing behind them, so they go down at the first
	// queries; the spare one is a working resolver
	dead1, dead2 := closedUDPAddr(t), closedUDPAddr(t)
	gone1, gone2 := closedUDPAddr(t), closedUDPAddr(t)
	spare := startLocalDNS(t)
	candidates := []Candidate{{Address: dead1}, {Address: gone1}, {Address: dead2}, {Address: gone2}, {Address: spare}}

	var mu sync.Mutex
	var probed []string
	first := make(chan struct{})
	cache := &memoryCache{data: map[string]*adapter.SavedBinary{}}
	history := NewHistory()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	go func() {
		done <- pool.Fill(ctx, logger, FillOptions{
			Candidates: candidates,
			Probe: func(ctx context.Context, address string) error {
				mu.Lock()
				probed = append(probed, address)
				mu.Unlock()
				if address == dead1 || address == dead2 {
					return E.New("no answer")
				}
				return nil
			},
			Want:        2,
			Concurrency: 1,
			Recheck:     50 * time.Millisecond,
			History:     history,
			Cache:       cache,
			HistoryKey:  "k",
			OnFirst:     func() { close(first) },
		})
	}()

	<-first
	require.Eventually(t, func() bool { return len(pool.Manager().Resolvers()) == 2 }, 5*time.Second, 10*time.Millisecond)
	mu.Lock()
	require.Equal(t, []string{dead1, gone1, dead2, gone2}, probed)
	mu.Unlock()
	require.Equal(t, 2, pool.Working())

	// queries through the pool fail on both, which go down, and the spare is probed and added
	require.Eventually(t, func() bool {
		_, _ = Probe(ctx, logger, pool.Addr(), "found.test", dns.TypeA, option.DialerOptions{})
		return len(pool.Manager().Resolvers()) == 3
	}, 10*time.Second, 20*time.Millisecond)
	resp, err := Probe(ctx, logger, pool.Addr(), "found.test", dns.TypeA, option.DialerOptions{})
	require.NoError(t, CheckAnswer(pool.Addr(), resp, err))

	// every candidate used: Fill returns
	select {
	case added := <-done:
		require.Equal(t, 3, added)
	case <-time.After(5 * time.Second):
		t.Fatal("Fill did not return after the candidates were used up")
	}
	cancel()
	require.Equal(t, -3, history.Score(dead1))
	require.Equal(t, 1, history.Score(spare))
	require.Equal(t, 1, LoadHistory(cache, "k").ResolverRate[spare])
}

// A canceled Fill returns at once without probing.
func TestH_DnspoolFillCanceled(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	pool, err := StartPool(logger, "test", PoolOptions{}, nil)
	require.NoError(t, err)
	defer pool.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probe := func(context.Context, string) error {
		t.Error("probed after cancel")
		return nil
	}
	require.Equal(t, 0, pool.Fill(ctx, logger, FillOptions{Candidates: []Candidate{{Address: closedUDPAddr(t)}}, Probe: probe}))
}
