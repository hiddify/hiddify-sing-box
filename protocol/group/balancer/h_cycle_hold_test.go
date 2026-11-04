package balancer

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type hHistory = map[string]*adapter.URLTestHistory

// the tests switch at once; TestH_LowestDelayStaysAfterASwitch sets its own stay
func init() { minStay = 0 }

// step is what Balancer.update does with a strategy: it holds while a cycle runs and the members
// in use answer, else it takes the results. The cycle is taken to have started after every
// result given: none is of this cycle.
func step(s Strategy, cycle bool, history hHistory) {
	stepSince(s, cycle, time.Now().Add(time.Hour), history)
}

// stepSince is step with the cycle started at since.
func stepSince(s Strategy, cycle bool, since time.Time, history hHistory) {
	if !holdsDuringCycle(cycle, since, s, history) {
		s.UpdateOutboundsInfo(history)
	}
}

// During a test cycle, lowest-delay no longer jumps to whichever member just answered fastest: a
// member in use without a result of this run is replaced by the best one known so far, that one
// is kept while it answers, and the best of all is chosen when the cycle ends. A member that fails
// during the cycle is left at once.
func TestH_LowestDelayHoldsDuringCycle(t *testing.T) {
	s := NewLowestDelay(outs(newFake("a"), newFake("b"), newFake("c"), newFake("d")), option.BalancerOutboundOptions{})
	step(s, true, hHistory{"a": cached(80), "b": his(400)})
	require.Equal(t, "b", s.Now(), "the cached member has no result of this run: the first that answered, for now")
	step(s, true, hHistory{"a": timeout(), "b": his(400)})
	require.Equal(t, "b", s.Now())
	step(s, true, hHistory{"a": timeout(), "b": his(400), "c": his(150)})
	require.Equal(t, "b", s.Now(), "kept during the cycle while it answers")
	step(s, true, hHistory{"a": timeout(), "b": his(400), "c": his(150), "d": his(90)})
	require.Equal(t, "b", s.Now())
	step(s, false, hHistory{"a": timeout(), "b": his(400), "c": his(150), "d": his(90)})
	require.Equal(t, "d", s.Now(), "the cycle ended: the best of all")

	step(s, true, hHistory{"a": his(60), "b": his(400), "c": his(150), "d": his(90)})
	require.Equal(t, "d", s.Now(), "the next cycle: kept, though a is faster")
	step(s, true, hHistory{"a": his(60), "b": his(400), "c": his(150), "d": timeout()})
	require.Equal(t, "a", s.Now(), "the member in use failed: left at once")
}

// The hold ends for the member in use once this cycle has tested it: a member chosen while the
// fast one did not answer is not kept for the whole cycle after the fast one answers again.
func TestH_LowestDelayHoldEndsOnceTheMemberInUseIsTested(t *testing.T) {
	s := NewLowestDelay(outs(newFake("nl"), newFake("pl")), option.BalancerOutboundOptions{})
	step(s, false, hHistory{"nl": his(17), "pl": his(91)})
	require.Equal(t, "nl", s.Now())
	step(s, true, hHistory{"nl": timeout(), "pl": his(91)})
	require.Equal(t, "pl", s.Now(), "the member in use failed: left for the one that answers")
	cycleStart := time.Now().Add(time.Second) // pl's result is of before this cycle
	stepSince(s, true, cycleStart, hHistory{"nl": his(17), "pl": his(91)})
	require.Equal(t, "pl", s.Now(), "held while this cycle has not tested it")
	time.Sleep(time.Millisecond)
	stepSince(s, true, time.Now().Add(-time.Second), hHistory{"nl": his(17), "pl": his(91)})
	require.Equal(t, "nl", s.Now(), "this cycle tested the member in use: the faster one takes the selection")
}

// Round robin keeps the members it rotates through, and the one it ranks first (what the app
// shows), while a cycle runs and they answer; it ranks again when the cycle ends. It rotates
// through members that answer only.
func TestH_RoundRobinHoldsDuringCycle(t *testing.T) {
	s := NewRoundRobin(outs(newFake("a"), newFake("b"), newFake("c"), newFake("d")), option.BalancerOutboundOptions{})
	step(s, true, hHistory{"a": his(300), "b": his(200)})
	require.Equal(t, "b", s.representative())
	rotation := func() []string {
		seen := map[string]bool{}
		for range 8 {
			seen[s.Select(adapter.InboundContext{}, "tcp", true).Tag()] = true
		}
		var tags []string
		for _, tag := range []string{"a", "b", "c", "d"} {
			if seen[tag] {
				tags = append(tags, tag)
			}
		}
		return tags
	}
	require.Equal(t, []string{"a", "b"}, rotation(), "only the members that answered")
	step(s, true, hHistory{"a": his(300), "b": his(200), "c": his(90)})
	require.Equal(t, "b", s.representative(), "kept during the cycle")
	require.Equal(t, []string{"a", "b"}, rotation())
	step(s, false, hHistory{"a": his(300), "b": his(200), "c": his(90), "d": timeout()})
	require.Equal(t, "c", s.representative(), "ranked again when the cycle ended")
	require.NotContains(t, rotation(), "d", "a failed member is not used")
	step(s, true, hHistory{"a": his(300), "b": his(200), "c": timeout(), "d": timeout()})
	require.Equal(t, "b", s.representative(), "a member in use failed during the cycle: ranked again at once")
	require.NotContains(t, rotation(), "c")
}

// Only a balancer that sends every connection through one member tells monitoring when its
// members change: each telling tests its parents and its pick again, and a spreading one changes
// its members with almost every result.
func TestH_OnlyLowestDelaySignalsItsSelection(t *testing.T) {
	require.True(t, signalsSelection(StrategyLowestDelay))
	for _, strategy := range []string{StrategyRoundRobin, StrategyConsistentHashing, StrategyStickySessions, "pool"} {
		require.False(t, signalsSelection(strategy), strategy)
	}
}

// A ping cached from the previous run decides nothing: it only orders the members until the real
// pings arrive. A cached pick is left for a better cached one, with no tolerance, and for the
// first real ping that works, however slow; a cached ping never takes a member whose real ping
// answers; with no real ping that works, the best cached one is the pick.
func TestH_LowestDelayCachedResultsOnlyOrder(t *testing.T) {
	s := NewLowestDelay(outs(newFake("a"), newFake("b"), newFake("c"), newFake("d")), option.BalancerOutboundOptions{})
	step(s, false, hHistory{"a": cached(100), "b": cached(60)})
	require.Equal(t, "b", s.Now(), "the best cached")
	step(s, false, hHistory{"a": cached(100), "b": cached(60), "c": cached(50)})
	require.Equal(t, "c", s.Now(), "a better cached one, with no tolerance: it is only an order")
	step(s, false, hHistory{"a": cached(100), "b": cached(60), "c": cached(50), "d": his(300)})
	require.Equal(t, "d", s.Now(), "the first real ping that works takes a cached pick, however slow")
	step(s, false, hHistory{"a": his(280), "b": cached(60), "c": cached(50), "d": his(300)})
	require.Equal(t, "d", s.Now(), "between real pings, the tolerance")
	step(s, false, hHistory{"a": his(280), "b": cached(5), "c": cached(50), "d": his(300)})
	require.Equal(t, "d", s.Now(), "a cached ping never takes a real one")
	step(s, false, hHistory{"a": his(280), "b": cached(5), "c": cached(50), "d": timeout()})
	require.Equal(t, "a", s.Now(), "the pick failed: the real ping that works")
	step(s, false, hHistory{"a": timeout(), "b": cached(5), "c": cached(50), "d": timeout()})
	require.Equal(t, "b", s.Now(), "no real ping works: the best cached")
}

// A member that took the selection with a real ping stays for minStay while it answers, whatever
// faster result comes in, then the best known takes it: one hop, not one per result.
func TestH_LowestDelayStaysAfterASwitch(t *testing.T) {
	s := NewLowestDelay(outs(newFake("a"), newFake("b"), newFake("c")), option.BalancerOutboundOptions{})
	s.stay = 150 * time.Millisecond
	step(s, false, hHistory{"a": his(439)})
	require.Equal(t, "a", s.Now())
	step(s, false, hHistory{"a": his(439), "b": his(170)})
	require.Equal(t, "b", s.Now(), "the first switch")
	step(s, false, hHistory{"a": his(439), "b": his(170), "c": his(112)})
	require.Equal(t, "b", s.Now(), "faster, but b stays for now")
	step(s, false, hHistory{"a": his(18), "b": his(170), "c": his(112)})
	require.Equal(t, "b", s.Now())
	time.Sleep(200 * time.Millisecond)
	step(s, false, hHistory{"a": his(18), "b": his(170), "c": his(112)})
	require.Equal(t, "a", s.Now(), "the stay is over: the best known, in one hop")
	step(s, false, hHistory{"a": timeout(), "b": his(170), "c": his(112)})
	require.Equal(t, "c", s.Now(), "a failed pick is left at once, stay or not")
}

// representative is the member round robin ranks first, as of the results it took: the fastest,
// which stays while a cycle runs. A test helper.
func (s *RoundRobin) representative() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if outs := s.sortedOutbounds[N.NetworkTCP]; len(outs) > 0 {
		return outs[0].Tag()
	}
	return ""
}
