package warpscan

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

var (
	hA = netip.MustParseAddrPort("10.0.0.1:2408")
	hB = netip.MustParseAddrPort("10.0.0.2:2408")
	hC = netip.MustParseAddrPort("[2001:db8::1]:2408")
)

func TestH_BookScores(t *testing.T) {
	book := NewBook()
	now := time.Now()
	for range 20 {
		book.Success("home", hA, time.Millisecond, now)
	}
	score, _ := book.Score("home", hA)
	require.Equal(t, MaxScore, score, "20 successes reach the top")

	// one penalty per hour, however many failures
	for range 5 {
		book.Failure("home", hA, now)
	}
	score, _ = book.Score("home", hA)
	require.Equal(t, MaxScore-1, score)
	for hour := 1; hour <= 30; hour++ {
		book.Failure("home", hA, now.Add(time.Duration(hour)*time.Hour))
	}
	score, _ = book.Score("home", hA)
	require.Equal(t, RecentScoreFloor, score, "an endpoint that worked this week stays at or above -5")

	// past the week, it falls to the bottom; one success brings it back to 1
	later := now.Add(RecentWindow + time.Hour)
	for hour := range 20 {
		book.Failure("home", hA, later.Add(time.Duration(hour)*time.Hour))
	}
	score, _ = book.Score("home", hA)
	require.Equal(t, MinScore, score)
	book.Success("home", hA, time.Millisecond, later.Add(30*time.Hour))
	score, _ = book.Score("home", hA)
	require.Equal(t, 1, score)

	// scores are per network
	_, known := book.Score("mobile", hA)
	require.False(t, known)
}

func TestH_BookCandidates(t *testing.T) {
	book := NewBook()
	now := time.Now()
	book.Success("home", hA, 50*time.Millisecond, now)
	book.Success("home", hB, 10*time.Millisecond, now)
	book.Success("home", hB, 10*time.Millisecond, now)
	book.Success("mobile", hC, 10*time.Millisecond, now)
	dead := netip.MustParseAddrPort("10.0.0.9:2408")
	for hour := range 20 {
		book.Failure("home", dead, now.Add(time.Duration(hour)*time.Hour))
	}
	preferred, last := book.Candidates("home")
	require.Equal(t, []netip.AddrPort{hB, hA, hC}, preferred, "own endpoints by score, then other networks' good ones")
	require.Equal(t, []netip.AddrPort{dead}, last)
}

func TestH_BookJSON(t *testing.T) {
	book := NewBook()
	book.Success("home", hA, time.Millisecond, time.Now())
	content, err := book.MarshalJSON()
	require.NoError(t, err)
	loaded := NewBook()
	require.NoError(t, loaded.UnmarshalJSON(content))
	score, known := loaded.Score("home", hA)
	require.True(t, known)
	require.Equal(t, 1, score)
	require.Error(t, NewBook().UnmarshalJSON([]byte(`["10.0.0.1:2408"]`)), "the old list format is not a book")
}

func hRequest(book *Book, probe Probe) Request {
	return Request{
		Options:  &option.WARPScannerOptions{Concurrency: 1, Count: 10, CIDRs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8:1::/64")}, Ports: badoption.Listable[uint16]{1}},
		IPv4:     true,
		IPv6:     true,
		Book:     book,
		Network:  "home",
		Probe:    probe,
	}
}

// The best scored endpoints are probed first; answers and failures are recorded; the result is
// ordered by score, then RTT.
func TestH_ScanUsesScores(t *testing.T) {
	book := NewBook()
	now := time.Now()
	book.Success("home", hA, 50*time.Millisecond, now)
	book.Success("mobile", hB, time.Millisecond, now) // a hint from another network
	var access sync.Mutex
	var order []netip.AddrPort
	probe := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		access.Lock()
		order = append(order, addrPort)
		access.Unlock()
		switch addrPort {
		case hA:
			return 40 * time.Millisecond, nil
		case hB:
			return 5 * time.Millisecond, nil
		}
		return 0, errors.New("no answer")
	}
	results, err := Scan(context.Background(), log.NewNOPFactory().Logger(), hRequest(book, probe))
	require.NoError(t, err)
	require.Equal(t, []netip.AddrPort{hA, hB}, order[:2])
	require.Equal(t, hA, results[0].AddrPort, "the proven endpoint wins over a faster new one")
	require.Equal(t, 2, results[0].Score)
	require.Equal(t, hB, results[1].AddrPort)
	require.Equal(t, 1, results[1].Score)
	score, known := book.Score("home", order[2])
	require.True(t, known)
	require.Equal(t, -1, score, "a random endpoint that failed is recorded")
}

// Excluded endpoints are not probed, and only the families the network has are drawn.
func TestH_ScanExcludeAndFamilies(t *testing.T) {
	book := NewBook()
	book.Success("home", hA, time.Millisecond, time.Now())
	var probed []netip.AddrPort
	probe := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		probed = append(probed, addrPort)
		return 0, errors.New("no answer")
	}
	request := hRequest(book, probe)
	request.Exclude = []netip.AddrPort{hA}
	request.IPv6 = false
	_, err := Scan(context.Background(), log.NewNOPFactory().Logger(), request)
	require.Error(t, err)
	require.NotContains(t, probed, hA)
	for _, addrPort := range probed {
		require.True(t, addrPort.Addr().Is4(), addrPort)
	}
}

// When the network cannot reach a family, its other candidates are skipped.
func TestH_ScanSkipsUnreachableFamily(t *testing.T) {
	probes := map[bool]int{}
	probe := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		probes[addrPort.Addr().Is6()]++
		if addrPort.Addr().Is6() {
			return 0, syscall.ENETUNREACH
		}
		return 0, errors.New("no answer")
	}
	request := hRequest(NewBook(), probe)
	request.Options.Count = 40
	_, err := Scan(context.Background(), log.NewNOPFactory().Logger(), request)
	require.Error(t, err)
	require.Equal(t, 1, probes[true])
	require.Greater(t, probes[false], 1)
}

// A scan stops once enough endpoints answered.
func TestH_ScanStopsEarly(t *testing.T) {
	probes := 0
	probe := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		probes++
		return time.Millisecond, nil
	}
	request := hRequest(NewBook(), probe)
	request.Options.Count = 64
	results, err := Scan(context.Background(), log.NewNOPFactory().Logger(), request)
	require.NoError(t, err)
	require.Len(t, results, enoughResults)
	require.Equal(t, enoughResults, probes)
}

// Random addresses stay inside their range.
func TestH_RandomAddress(t *testing.T) {
	for _, prefix := range []netip.Prefix{netip.MustParsePrefix("162.159.192.0/24"), netip.MustParsePrefix("2606:4700:103::/64"), netip.MustParsePrefix("10.1.2.3/32")} {
		for range 100 {
			require.True(t, prefix.Contains(randomAddress(prefix)), prefix)
		}
	}
}

// An endpoint with a record on this network ends the scan as soon as it answers.
func TestH_ScanStopsAtStableEndpoint(t *testing.T) {
	book := NewBook()
	for range stableScore - 1 {
		book.Success("home", hA, time.Millisecond, time.Now())
	}
	probes := 0
	probe := func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		probes++
		if addrPort == hA {
			return time.Millisecond, nil
		}
		return 0, errors.New("no answer")
	}
	results, err := Scan(context.Background(), log.NewNOPFactory().Logger(), hRequest(book, probe))
	require.NoError(t, err)
	require.Equal(t, 1, probes)
	require.Equal(t, hA, results[0].AddrPort)
}
