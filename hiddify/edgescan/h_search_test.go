package edgescan

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/hiddify/rating"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// A search goes on round after round until one finds something, and is exhausted when its time
// is up; without a time, it goes on until it is stopped.
func TestH_Search(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	defer func(saved time.Duration) { minRound = saved }(minRound)
	minRound = 10 * time.Millisecond
	rounds := 0
	results, err := Search(context.Background(), logger, time.Minute, func(ctx context.Context) ([]Result, error) {
		rounds++
		if rounds < 3 {
			return nil, errors.New("nothing")
		}
		return []Result{{}}, nil
	})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, 3, rounds)

	_, err = Search(context.Background(), logger, 50*time.Millisecond, func(ctx context.Context) ([]Result, error) {
		return nil, errors.New("nothing")
	})
	require.ErrorIs(t, err, ErrSearchExhausted)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	rounds = 0
	_, err = Search(ctx, logger, 0, func(ctx context.Context) ([]Result, error) {
		rounds++
		return nil, errors.New("nothing")
	})
	require.ErrorIs(t, err, context.DeadlineExceeded, "no limit: it goes on until it is stopped")
	require.Greater(t, rounds, 2)
	rounds = 0
	_, err = Search(context.Background(), logger, -1, func(ctx context.Context) ([]Result, error) {
		rounds++
		return nil, errors.New("nothing")
	})
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrSearchExhausted)
	require.Equal(t, 1, rounds, "behind another proxy: one round")
}

// search_timeout is the one setting: 1 minute by default; a deep search has no limit, or a long
// one (above 3 minutes).
func TestH_SearchLimit(t *testing.T) {
	limit := func(timeout time.Duration, asked bool) (time.Duration, bool) {
		return SearchLimit(&option.EdgeSearchOptions{SearchTimeout: badoption.Duration(timeout)}, asked)
	}
	check := func(timeout time.Duration, asked bool, want time.Duration, wantDeep bool) {
		got, deep := limit(timeout, asked)
		require.Equal(t, want, got, "%s asked=%v", timeout, asked)
		require.Equal(t, wantDeep, deep, "%s asked=%v", timeout, asked)
	}
	require.Equal(t, time.Minute, DefaultSearchTimeout)
	check(0, false, DefaultSearchTimeout, false)
	check(0, true, 0, true)
	check(time.Minute, false, time.Minute, false)
	check(time.Minute, true, 0, true)
	check(3*time.Minute, false, 3*time.Minute, false)
	check(3*time.Minute+time.Second, false, 3*time.Minute+time.Second, true)
	check(2*time.Hour, false, 2*time.Hour, true)
	check(2*time.Hour, true, 2*time.Hour, true)
	check(-1, false, 0, true)
	got, deep := SearchLimit(nil, false)
	require.Equal(t, DefaultSearchTimeout, got)
	require.False(t, deep)
	require.True(t, ConfiguredDeep(&option.EdgeSearchOptions{SearchTimeout: -1}))
	require.False(t, ConfiguredDeep(nil))
}

// The book is saved compactly and read back whole; the format before it is still read.
func TestH_BookCompact(t *testing.T) {
	book := NewBook()
	now := time.Now().Truncate(time.Second)
	target := Target{AddrPort: netip.MustParseAddrPort("162.159.192.1:2408"), ServerName: "a.example"}
	book.SuccessTarget("wifi/IR/2.176.0.0/16", target, 42*time.Millisecond, now)
	book.MethodSuccess("wifi/IR/2.176.0.0/16", ServerNameMethod("a.example"), now)
	book.BlockSuccess("wifi/IR/2.176.0.0/16", netip.MustParsePrefix("162.159.192.0/24"), now)
	s := newSpace([]Set{{CIDRs: []netip.Prefix{netip.MustParsePrefix("162.159.192.0/24")}}}, []uint16{2408}, 0, 0)
	book.draw("wifi/IR/2.176.0.0/16", s, 2, func(Target) bool { return true }, nil)

	content, err := json.Marshal(book)
	require.NoError(t, err)
	require.Less(t, len(content), 400, string(content))
	loaded := NewBook()
	require.NoError(t, json.Unmarshal(content, loaded))
	score, known := loaded.TargetScore("wifi/IR/2.176.0.0/16", target)
	require.True(t, known)
	require.Equal(t, rating.Score(1), score)
	require.Equal(t, 42*time.Millisecond, loaded.networks["wifi/IR/2.176.0.0/16"].Records[target.String()].RTT)
	require.Equal(t, rating.Score(1), loaded.BlockScore("wifi/IR/2.176.0.0/16", netip.MustParsePrefix("162.159.192.0/24")))
	methodScore, _ := loaded.MethodScore("wifi/IR/2.176.0.0/16", ServerNameMethod("a.example"))
	require.Equal(t, rating.Score(1), methodScore)
	for key, saved := range book.networks["wifi/IR/2.176.0.0/16"].Walks {
		require.Equal(t, saved.Next, loaded.networks["wifi/IR/2.176.0.0/16"].Walks[key].Next)
		require.Equal(t, saved.Seed, loaded.networks["wifi/IR/2.176.0.0/16"].Walks[key].Seed)
	}

	legacy := NewBook()
	require.NoError(t, legacy.UnmarshalJSON([]byte(`{"home":{"last_seen":"2026-11-01T00:00:00Z","records":{"10.0.0.2:2408":{"score":2,"last_success":"2026-11-01T00:00:00Z"}}}}`)))
	score, _ = legacy.Score("home", netip.MustParseAddrPort("10.0.0.2:2408"))
	require.Equal(t, rating.Score(2), score)
}

// What was not seen for 30 days is forgotten, and blocks without a score are not kept.
func TestH_BookLifetime(t *testing.T) {
	book := NewBook()
	now := time.Now()
	old := now.Add(-Lifetime - time.Hour)
	book.Success("home", netip.MustParseAddrPort("10.0.0.1:1"), time.Millisecond, old)
	book.BlockSuccess("home", netip.MustParsePrefix("10.0.0.0/24"), old)
	book.Success("home", netip.MustParseAddrPort("10.0.0.2:1"), time.Millisecond, now)
	book.Success("gone", netip.MustParseAddrPort("10.0.0.3:1"), time.Millisecond, old)
	book.networks["gone"].LastSeen = old
	book.prune(now)
	_, known := book.Score("home", netip.MustParseAddrPort("10.0.0.1:1"))
	require.False(t, known)
	_, known = book.Score("home", netip.MustParseAddrPort("10.0.0.2:1"))
	require.True(t, known)
	require.Empty(t, book.networks["home"].Blocks)
	require.NotContains(t, book.networks, "gone")
}

// A failed probe costs its block a point when another answered; blocks that keep failing are
// drawn less.
func TestH_ScanRatesBlocks(t *testing.T) {
	book := NewBook()
	answering := netip.MustParsePrefix("192.0.2.0/24")
	probe := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		if answering.Contains(addrPort.Addr()) {
			return time.Millisecond, nil
		}
		return 0, errors.New("no answer")
	}
	request := Request{
		Options: &option.WARPScannerOptions{Concurrency: 1, Count: 16, CIDRs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("192.0.2.0/23")}, Ports: badoption.Listable[uint16]{1}},
		IPv4:    true,
		Book:    book,
		Network: "home",
		Probe:   probe,
		Enough:  16,
	}
	_, err := Scan(context.Background(), log.NewNOPFactory().Logger(), request)
	require.NoError(t, err)
	require.Positive(t, book.BlockScore("home", answering))
	require.Negative(t, book.BlockScore("home", netip.MustParsePrefix("192.0.3.0/24")))
}
