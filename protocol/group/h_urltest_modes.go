package group

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Hiddify additions to the URL test group, after sing-box-lx (SPEC 054 and 116):
//
//   - urls: more test URLs. A member is up when any of them answers, so one test URL blocked on a
//     network does not mark every member dead.
//   - Penalties: a dial that fails because the path is dead (a timeout or an unreachable network)
//     gives the member a penalty and makes one more try through the best other member. When that
//     works, the group moves to it without closing live connections. A penalty is cleared only by
//     proof of life: a dial or a test that works. When the fastest member has
//     penaltyThreshold penalties, members are ranked by penalties first, then by delay; when every
//     member has them, a test of all members runs at once, at most every penaltyForcedRetestGap.
//   - mode failover: keep the selected member until it fails. Each interval tests only the
//     selected members; when one fails, all members are tested and the fastest is selected.
//     A member that slowed down to more than degradeRatio times the fastest other member, and
//     still is on a second test, is left too (SPEC 126): all members are tested and the group
//     moves when one is more than degradeMoveRatio times faster.

const (
	penaltyThreshold       = 3
	penaltyForcedRetestGap = 2 * time.Minute
	degradeRatio           = 2.0
	degradeMoveRatio       = 1.5
)

// isPathDeadDialError tells a dead path (penalty and one more try) from a refused destination,
// which another member would meet too, and from a canceled dial.
func isPathDeadDialError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ETIMEDOUT) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (g *URLTestGroup) penaltyOf(tag string) int64 {
	value, loaded := g.penalties.Load(tag)
	if !loaded {
		return 0
	}
	return value.(*atomic.Int64).Load()
}

func (g *URLTestGroup) penaltyAdd(tag string) {
	value, _ := g.penalties.LoadOrStore(tag, new(atomic.Int64))
	value.(*atomic.Int64).Add(1)
}

func (g *URLTestGroup) penaltyReset(tag string) {
	if value, loaded := g.penalties.Load(tag); loaded {
		value.(*atomic.Int64).Store(0)
	}
}

func (g *URLTestGroup) historyOf(detour adapter.Outbound, network string) *adapter.URLTestHistory {
	history := g.history.LoadURLTestHistory(RealTag(detour, network))
	if history == nil || history.Delay == urltest.FailedDelay {
		return nil
	}
	return history
}

// fastestByDelay returns the member with the lowest delay, without tolerance.
func (g *URLTestGroup) fastestByDelay(network string) adapter.Outbound {
	var minDelay uint16
	var minOutbound adapter.Outbound
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		history := g.historyOf(detour, network)
		if history == nil {
			continue
		}
		if minOutbound == nil || history.Delay < minDelay {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	return minOutbound
}

func (g *URLTestGroup) penaltyEmergency(network string) bool {
	fastest := g.fastestByDelay(network)
	return fastest != nil && g.penaltyOf(fastest.Tag()) >= penaltyThreshold
}

// penaltyBest ranks the members with history by penalties, then by delay, leaving out exclude.
func (g *URLTestGroup) penaltyBest(network string, exclude adapter.Outbound) adapter.Outbound {
	var best adapter.Outbound
	var bestPenalty int64
	var bestDelay uint16
	for _, detour := range g.outbounds {
		if detour == exclude || !common.Contains(detour.Network(), network) {
			continue
		}
		history := g.historyOf(detour, network)
		if history == nil {
			continue
		}
		penalty := g.penaltyOf(detour.Tag())
		if best == nil || penalty < bestPenalty || (penalty == bestPenalty && history.Delay < bestDelay) {
			best, bestPenalty, bestDelay = detour, penalty, history.Delay
		}
	}
	return best
}

// selectForUpdate is the selection of performUpdateCheck: failover keeps the selected member,
// and penalties rank first when the fastest member has too many.
func (g *URLTestGroup) selectForUpdate(network string) (adapter.Outbound, bool) {
	if g.penaltyEmergency(network) {
		if best := g.penaltyBest(network, nil); best != nil {
			return best, true
		}
	}
	if g.failover {
		current := g.selectedOutboundTCP
		if network == N.NetworkUDP {
			current = g.selectedOutboundUDP
		}
		if current != nil && g.historyOf(current, network) != nil {
			if _, degraded := g.degraded.LoadAndDelete(network); degraded {
				if fastest := g.fastestByDelay(network); fastest != nil && fastest != current &&
					float64(g.historyOf(fastest, network).Delay)*degradeMoveRatio < float64(g.historyOf(current, network).Delay) {
					return fastest, true
				}
			}
			return current, true
		}
		if fastest := g.fastestByDelay(network); fastest != nil {
			return fastest, true
		}
	}
	return g.Select(network)
}

// pickForDial is the member for a new connection: the selected one, unless penalties rank first.
func (g *URLTestGroup) pickForDial(network string) adapter.Outbound {
	if g.penaltyEmergency(network) {
		if best := g.penaltyBest(network, nil); best != nil {
			return best
		}
	}
	selected := g.selectedOutboundTCP
	if network == N.NetworkUDP {
		selected = g.selectedOutboundUDP
	}
	if selected != nil {
		return selected
	}
	outbound, _ := g.Select(network)
	return outbound
}

// moveSelection moves the group to a member that just proved it works, without closing live
// connections.
func (g *URLTestGroup) moveSelection(network string, detour adapter.Outbound) {
	g.updateAccess.Lock()
	var changed bool
	switch network {
	case N.NetworkTCP:
		changed = g.selectedOutboundTCP != detour
		g.selectedOutboundTCP = detour
	case N.NetworkUDP:
		changed = g.selectedOutboundUDP != detour
		g.selectedOutboundUDP = detour
	}
	g.updateAccess.Unlock()
	if changed {
		g.logger.Info("selection moved to ", detour.Tag(), " after a failed dial")
		g.history.NotifyUpdated()
	}
}

// penaltyFailoverDial handles a failed dial: a penalty for a dead path, and one more try through
// the best other member. ok is false when there was no other try or it failed too; the caller
// then returns the first error.
func (g *URLTestGroup) penaltyFailoverDial(ctx context.Context, network string, destination M.Socksaddr, failed adapter.Outbound, dialErr error) (conn net.Conn, ok bool) {
	if !isPathDeadDialError(dialErr) {
		return nil, false
	}
	g.penaltyAdd(failed.Tag())
	g.maybeForceRetest()
	fallback := g.penaltyBest(network, failed)
	if fallback == nil {
		return nil, false
	}
	conn, err := fallback.DialContext(ctx, network, destination)
	if err != nil {
		g.logger.Error(E.Cause(err, "fallback dial via ", fallback.Tag()))
		g.history.DeleteURLTestHistory(fallback.Tag())
		if isPathDeadDialError(err) {
			g.penaltyAdd(fallback.Tag())
			g.maybeForceRetest()
		}
		return nil, false
	}
	g.penaltyReset(fallback.Tag())
	g.moveSelection(network, fallback)
	return conn, true
}

// maybeForceRetest tests all members at once when every member with history has too many
// penalties, at most every penaltyForcedRetestGap from the end of the last such test.
func (g *URLTestGroup) maybeForceRetest() {
	if !g.penaltyTotal(N.NetworkTCP) {
		return
	}
	if last, _ := g.lastForcedRetest.Load().(time.Time); !last.IsZero() && time.Since(last) < penaltyForcedRetestGap {
		return
	}
	if !g.forcedRetestRunning.CompareAndSwap(false, true) {
		return
	}
	g.logger.Warn("all members have failed dials, testing them now")
	go func() {
		defer g.forcedRetestRunning.Store(false)
		g.CheckOutbounds(g.ctx, true)
		g.lastForcedRetest.Store(time.Now())
	}()
}

func (g *URLTestGroup) penaltyTotal(network string) bool {
	var sawCandidate bool
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) || g.historyOf(detour, network) == nil {
			continue
		}
		sawCandidate = true
		if g.penaltyOf(detour.Tag()) < penaltyThreshold {
			return false
		}
	}
	return sawCandidate
}

// failoverHeld returns the selected members, TCP first.
func (g *URLTestGroup) failoverHeld() []adapter.Outbound {
	held := make([]adapter.Outbound, 0, 2)
	if g.selectedOutboundTCP != nil {
		held = append(held, g.selectedOutboundTCP)
	}
	if g.selectedOutboundUDP != nil && g.selectedOutboundUDP != g.selectedOutboundTCP {
		held = append(held, g.selectedOutboundUDP)
	}
	return held
}

// testMembers tests outbounds with every test URL and clears the penalty of each that answered.
func (g *URLTestGroup) testMembers(ctx context.Context, outbounds []adapter.Outbound, force bool) map[string]uint16 {
	result := urlTestOutbounds(ctx, g.outbound, g.history, g.logger, outbounds, g.links, g.interval, force)
	for tag := range result {
		g.penaltyReset(tag)
	}
	return result
}

// failoverCheck is the regular test of a failover group: the selected members only, and all
// members when one of them failed or none is selected yet.
func (g *URLTestGroup) failoverCheck(ctx context.Context) map[string]uint16 {
	held := g.failoverHeld()
	result := make(map[string]uint16)
	if len(held) > 0 {
		result = g.testMembers(ctx, held, true)
		if ctx.Err() != nil {
			return result
		}
		var failed bool
		for _, detour := range held {
			if g.history.LoadURLTestHistory(RealTag(detour, N.NetworkTCP)) == nil {
				failed = true
			}
		}
		if !failed && !g.failoverDegraded(ctx) {
			return result
		}
	}
	others := make([]adapter.Outbound, 0, len(g.outbounds))
	for _, detour := range g.outbounds {
		if !common.Contains(held, detour) {
			others = append(others, detour)
		}
	}
	for tag, delay := range g.testMembers(ctx, others, false) {
		result[tag] = delay
	}
	return result
}

// failoverDegraded reports whether a selected member is more than degradeRatio times slower than
// the fastest other member of its network, on a second test too, and marks that network so the
// next selection may move.
func (g *URLTestGroup) failoverDegraded(ctx context.Context) bool {
	var degraded bool
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		current := g.selectedOutboundTCP
		if network == N.NetworkUDP {
			current = g.selectedOutboundUDP
		}
		if current == nil || !g.slowerThanBest(current, network) {
			continue
		}
		g.testMembers(ctx, []adapter.Outbound{current}, true) // one slow test is not enough
		if ctx.Err() != nil {
			return false
		}
		if g.slowerThanBest(current, network) {
			g.degraded.Store(network, struct{}{})
			degraded = true
		}
	}
	return degraded
}

// slowerThanBest reports whether current is more than degradeRatio times slower than the fastest
// other member of network.
func (g *URLTestGroup) slowerThanBest(current adapter.Outbound, network string) bool {
	history := g.historyOf(current, network)
	if history == nil {
		return false
	}
	var best uint16
	for _, detour := range g.outbounds {
		if detour == current || !common.Contains(detour.Network(), network) {
			continue
		}
		if other := g.historyOf(detour, network); other != nil && (best == 0 || other.Delay < best) {
			best = other.Delay
		}
	}
	return best > 0 && float64(history.Delay) > degradeRatio*float64(best)
}

// urlTestLinks tests detour with every link at once; the first that answers gives the delay.
func urlTestLinks(ctx context.Context, links []string, detour adapter.Outbound) (uint16, error) {
	if len(links) <= 1 {
		var link string
		if len(links) == 1 {
			link = links[0]
		}
		return urltest.URLTest(ctx, link, detour)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan urlTestResult, len(links))
	for _, link := range links {
		go func() {
			delay, err := urltest.URLTest(ctx, link, detour)
			results <- urlTestResult{delay, err}
		}()
	}
	var errs []error
	for range links {
		result := <-results
		if result.err == nil {
			return result.delay, nil
		}
		errs = append(errs, result.err)
	}
	return 0, E.Errors(errs...)
}

// testLinks joins url and urls without repeats; an empty result tests the default URL.
func testLinks(link string, links []string) []string {
	var result []string
	for _, candidate := range append([]string{link}, links...) {
		if candidate != "" && !common.Contains(result, candidate) {
			result = append(result, candidate)
		}
	}
	if len(result) == 0 {
		return []string{""}
	}
	return result
}

// signalSelection tells monitoring that the group moved to another member, as a selector does:
// what follows the group (a tunnel through it, the app's list) learns it at once, not at the next
// monitoring test.
func (g *URLTestGroup) signalSelection() {
	if mon := monitoring.Get(g.ctx); mon != nil && g.tag != "" {
		if err := mon.SignalChange(g.tag); err != nil {
			g.logger.Debug("signal selection change: ", err)
		}
	}
}
