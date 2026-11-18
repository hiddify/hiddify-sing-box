package edgescan

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// The permutation is one to one, whatever the size and seed.
func TestH_Permute(t *testing.T) {
	for _, size := range []uint64{1, 2, 3, 10, 256, 1000, 4096 * 3} {
		for _, seed := range []uint64{0, 1, 0x9e3779b97f4a7c15, ^uint64(0)} {
			seen := make(map[uint64]bool, size)
			for k := range size {
				x := permute(k, size, seed)
				require.Less(t, x, size)
				require.False(t, seen[x], "size %d seed %d: %d twice", size, seed, x)
				seen[x] = true
			}
		}
	}
}

// A walk gives every address and port of a set once, inside its ranges, and starts over in
// another order once the set is walked; the sets are drawn alike while none is rated.
func TestH_WalkCoversSpace(t *testing.T) {
	narrow := netip.MustParsePrefix("192.0.2.8/30")
	wide := netip.MustParsePrefix("198.51.100.0/28")
	names := []string{"", "a.example"}
	s := newSpace([]Set{{CIDRs: []netip.Prefix{narrow}, ServerNames: names}, {CIDRs: []netip.Prefix{wide}, ServerNames: names}}, []uint16{1, 2}, 0, 0)
	book := NewBook()
	seen := map[netip.AddrPort]bool{}
	sets := map[string]int{}
	for len(seen) < 4*2+16*2 {
		setOf := map[Target]string{}
		drawn := book.draw("home", s, 8, func(target Target) bool { return !seen[target.AddrPort] }, setOf)
		require.NotEmpty(t, drawn)
		for _, target := range drawn {
			require.True(t, narrow.Contains(target.AddrPort.Addr()) || wide.Contains(target.AddrPort.Addr()), target)
			require.Contains(t, names, target.ServerName)
			seen[target.AddrPort] = true
			sets[setOf[target]]++
		}
	}
	require.Len(t, sets, 2)
	all := func(Target) bool { return true }
	require.Len(t, book.draw("home", s, 4, all, nil), 4, "a walked space starts over")
}

// A set, a server name or a block that answered on the network is drawn most of the time; the
// others are still drawn.
func TestH_DrawWeighted(t *testing.T) {
	good := netip.MustParsePrefix("192.0.2.0/24")
	other := netip.MustParsePrefix("198.51.100.0/24")
	s := newSpace([]Set{
		{Name: "good", CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.0.0/16")}, ServerNames: []string{"a.example", "b.example", "c.example"}},
		{Name: "other", CIDRs: []netip.Prefix{other}},
	}, []uint16{443}, 0, 0)
	book := NewBook()
	now := time.Now()
	for range 3 {
		book.MethodSuccess("home", SetMethod("good"), now)
		book.MethodSuccess("home", ServerNameMethod("b.example"), now)
		book.BlockSuccess("home", good, now)
	}
	counts := map[string]int{}
	for range 400 {
		setOf := map[Target]string{}
		for _, target := range book.draw("home", s, 1, func(Target) bool { return true }, setOf) {
			counts[setOf[target]]++
			if setOf[target] == "good" {
				counts["name "+target.ServerName]++
				if good.Contains(target.AddrPort.Addr()) {
					counts["block"]++
				}
			}
		}
	}
	require.Greater(t, counts["good"], 220)
	require.Positive(t, counts["other"])
	require.Greater(t, counts["name b.example"], counts["good"]/2)
	require.Positive(t, counts["name a.example"])
	require.Greater(t, counts["block"], counts["good"]/2, "the /24 that answered, out of a /16")
}

// A scan goes on where the last one stopped: the candidates it tried are not drawn again.
func TestH_ScanContinuesWalk(t *testing.T) {
	book := NewBook()
	tried := map[netip.AddrPort]int{}
	probe := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		tried[addrPort]++
		return 0, errors.New("no answer")
	}
	request := Request{
		Options: &option.WARPScannerOptions{Concurrency: 1, Count: 16, CIDRs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("192.0.2.0/27")}, Ports: badoption.Listable[uint16]{1, 2}},
		IPv4:    true,
		Book:    book,
		Network: "home",
		Probe:   probe,
	}
	for range 4 {
		_, err := Scan(context.Background(), log.NewNOPFactory().Logger(), request)
		require.Error(t, err)
	}
	require.Len(t, tried, 64, "four scans of 16 walk the 64 candidates")
	for addrPort, count := range tried {
		require.Equal(t, 1, count, addrPort)
	}
	content, err := book.MarshalJSON()
	require.NoError(t, err)
	loaded := NewBook()
	require.NoError(t, loaded.UnmarshalJSON(content))
	for key, saved := range book.networks["home"].Walks {
		require.Equal(t, saved.Seed, loaded.networks["home"].Walks[key].Seed, "the walk is kept in the cache file")
		require.Equal(t, saved.Next, loaded.networks["home"].Walks[key].Next)
	}
}

// Targets with a server name are probed and scored with it, apart from the same address alone.
func TestH_ScanServerNames(t *testing.T) {
	book := NewBook()
	edge := netip.MustParseAddr("192.0.2.1")
	probe := func(ctx context.Context, target Target) (time.Duration, error) {
		if target.ServerName == "good.example" {
			return time.Millisecond, nil
		}
		return 0, errors.New("reset")
	}
	results, err := Scan(context.Background(), log.NewNOPFactory().Logger(), Request{
		Options:     &option.WARPScannerOptions{Concurrency: 1, Count: 8},
		Defaults:    Defaults{CIDRs: []netip.Prefix{netip.PrefixFrom(edge, 32)}, Ports: []uint16{443}, ServerNames: []string{"", "bad.example", "good.example"}},
		IPv4:        true,
		Book:        book,
		Network:     "home",
		TargetProbe: probe,
	})
	require.NoError(t, err)
	require.Len(t, results, 1)
	good := Target{AddrPort: netip.AddrPortFrom(edge, 443), ServerName: "good.example"}
	require.Equal(t, good, results[0].Target)
	_, known := book.Score("home", good.AddrPort)
	require.False(t, known, "the address alone is another target")
	preferred, _ := book.CandidateTargets("home")
	require.Equal(t, []Target{good}, preferred)
	parsed, err := ParseTarget(good.String())
	require.NoError(t, err)
	require.Equal(t, good, parsed)
}

// With ConfirmedOnly, an answer is not scored; a confirmed target comes first and ends the scan.
func TestH_ScanConfirmedOnly(t *testing.T) {
	book := NewBook()
	edge := netip.MustParseAddr("192.0.2.1")
	probe := func(ctx context.Context, target Target) (time.Duration, error) { return time.Millisecond, nil }
	request := Request{
		Options:       &option.WARPScannerOptions{Concurrency: 1, Count: 8},
		Defaults:      Defaults{CIDRs: []netip.Prefix{netip.PrefixFrom(edge, 30)}, Ports: []uint16{443}},
		IPv4:          true,
		Book:          book,
		Network:       "home",
		TargetProbe:   probe,
		ConfirmedOnly: true,
	}
	results, err := Scan(context.Background(), log.NewNOPFactory().Logger(), request)
	require.NoError(t, err)
	require.Len(t, results, enoughResults)
	preferred, _ := book.CandidateTargets("home")
	require.Empty(t, preferred, "answers are not scored")

	confirmed := results[2].Target
	for range stableScore {
		book.SuccessTarget("home", confirmed, 0, time.Now())
	}
	results, err = Scan(context.Background(), log.NewNOPFactory().Logger(), request)
	require.NoError(t, err)
	require.Equal(t, confirmed, results[0].Target, "the confirmed target is tried first and ends the scan")
	require.Len(t, results, 1)
}

// Seeds come after the known targets and before new ones.
func TestH_ScanSeeds(t *testing.T) {
	book := NewBook()
	known := Target{AddrPort: netip.MustParseAddrPort("192.0.2.1:443")}
	seed := Target{AddrPort: netip.MustParseAddrPort("198.51.100.7:443"), ServerName: "cdn.example"}
	book.SuccessTarget("home", known, time.Millisecond, time.Now())
	var order []Target
	probe := func(ctx context.Context, target Target) (time.Duration, error) {
		order = append(order, target)
		return 0, errors.New("no answer")
	}
	_, err := Scan(context.Background(), log.NewNOPFactory().Logger(), Request{
		Options:     &option.WARPScannerOptions{Concurrency: 1, Count: 4},
		Defaults:    Defaults{CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Ports: []uint16{443}},
		IPv4:        true,
		Book:        book,
		Network:     "home",
		TargetProbe: probe,
		Seeds:       []Target{seed},
	})
	require.Error(t, err)
	require.Equal(t, []Target{known, seed}, order[:2])
	require.Len(t, order, 4)
}

// With EnoughPerSet, the answers of a fast set beyond its share do not end the scan.
func TestH_ScanEnoughPerSet(t *testing.T) {
	fast := netip.MustParsePrefix("192.0.2.0/24")
	slow := netip.MustParsePrefix("198.51.100.0/24")
	probe := func(ctx context.Context, target Target) (time.Duration, error) {
		if slow.Contains(target.AddrPort.Addr()) && target.AddrPort.Addr().As4()[3] != 7 {
			return 0, errors.New("no answer")
		}
		return time.Millisecond, nil
	}
	var seeds []Target
	for i := range 10 {
		seeds = append(seeds, Target{AddrPort: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), 443)})
	}
	seeds = append(seeds, Target{AddrPort: netip.MustParseAddrPort("198.51.100.7:443")})
	results, err := Scan(context.Background(), log.NewNOPFactory().Logger(), Request{
		Options:      &option.WARPScannerOptions{Concurrency: 1, Count: 16},
		Defaults:     Defaults{Ports: []uint16{443}, Sets: []Set{{Name: "fast", CIDRs: []netip.Prefix{fast}}, {Name: "slow", CIDRs: []netip.Prefix{slow}}}},
		IPv4:         true,
		Book:         NewBook(),
		Network:      "home",
		TargetProbe:  probe,
		Seeds:        seeds,
		Enough:       2,
		EnoughPerSet: 1,
		SetOf: func(target Target) string {
			if slow.Contains(target.AddrPort.Addr()) {
				return "slow"
			}
			return "fast"
		},
		ConfirmedOnly: true,
	})
	require.NoError(t, err)
	var slowAnswered bool
	for _, result := range results {
		slowAnswered = slowAnswered || slow.Contains(result.AddrPort.Addr())
	}
	require.True(t, slowAnswered, "the slow set had its turn: %v", results)
}

// Ranges of different sizes waste no turns: every turn of a walk is an address, and each range is
// walked whole.
func TestH_WalkUnevenRanges(t *testing.T) {
	ranges := []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("198.51.100.0/28"), netip.MustParsePrefix("203.0.113.0/30")}
	s := newSpace([]Set{{CIDRs: ranges}}, []uint16{443}, 0, 0)
	set := &s.sets[0]
	require.Equal(t, uint64(1+16+4), set.total)
	seen := map[netip.AddrPort]bool{}
	for index := range set.total {
		addrPort, ok := set.at(index, 7, s.ports)
		require.True(t, ok, index)
		require.False(t, seen[addrPort], "twice: %s", addrPort)
		seen[addrPort] = true
	}
	_, ok := set.at(set.total, 7, s.ports)
	require.False(t, ok)
	for _, prefix := range ranges {
		count := 0
		for addrPort := range seen {
			if prefix.Contains(addrPort.Addr()) {
				count++
			}
		}
		require.Equal(t, 1<<(32-prefix.Bits()), count, prefix)
	}
	// the first round gives each range a turn
	first := map[netip.Prefix]bool{}
	for index := range uint64(3) {
		addrPort, _ := set.at(index, 7, s.ports)
		for _, prefix := range ranges {
			if prefix.Contains(addrPort.Addr()) {
				first[prefix] = true
			}
		}
	}
	require.Len(t, first, 3)
}
