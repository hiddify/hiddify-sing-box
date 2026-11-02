package monitoring

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

// How the monitoring knows an outbound's IPv6: from what the router saw on the connections it
// carried (route option ipv6_fallback), never from a probe of its own. A probe is traffic to a
// public address that a filtered network breaks, and a dial through VLESS, Trojan or VMess says
// nothing about the exit anyway. The user's own traffic says it all: a connection to an IPv6
// address that the destination answered shows IPv6 carried; one that got nothing while the same
// destination answered over IPv4 shows it is not.
const (
	// ipv6FailuresToConclude is how many IPv6 connections in a row must get nothing, while
	// IPv4 answered, before the outbound counts as having no IPv6. One is a site whose IPv6 is
	// broken; two is the exit.
	ipv6FailuresToConclude = 2
	// ipv6Forget is how long an outbound found without IPv6 stays so. No IPv6 reaches it
	// meanwhile (no AAAA answers, IPv6 refused), so nothing else can tell when its exit gains
	// IPv6; after this the next IPv6 connection is let through and carried over IPv4 if needed.
	ipv6Forget = 10 * time.Minute
)

type ipv6Knowledge struct {
	failures   int       // IPv6 connections in a row that got nothing while IPv4 answered
	carriedAt  time.Time // when an IPv6 connection last answered
	observedAt time.Time // the last observation
}

func (k *ipv6Knowledge) observe(carried bool, now time.Time) {
	k.observedAt = now
	if carried {
		k.failures = 0
		k.carriedAt = now
	} else {
		k.failures++
	}
}

// answer is what the knowledge says: supported, and whether anything is known at all.
func (k ipv6Knowledge) answer(now time.Time) (supported bool, known bool) {
	if k.failures >= ipv6FailuresToConclude {
		if now.Sub(k.observedAt) < ipv6Forget {
			return false, true
		}
		return false, false // long enough: let an IPv6 connection through and see
	}
	if !k.carriedAt.IsZero() {
		return true, true
	}
	return false, false
}

// ObserveIPv6 implements adapter.IPv6Capability: the router saw a connection to an IPv6 address
// through the outbound answered (carried), or answered only once carried over IPv4 (not). A
// group's observation goes to the member it leads to.
func (m *OutboundMonitoring) ObserveIPv6(tag string, carried bool) {
	reg := m.reg()
	if reg == nil || tag == "" {
		return
	}
	leaf := m.ipv6Leaf(reg, tag)
	now := time.Now()
	m.ipv6Access.Lock()
	knowledge := m.ipv6[leaf]
	if knowledge == nil {
		knowledge = &ipv6Knowledge{}
		m.ipv6[leaf] = knowledge
	}
	knowledge.observe(carried, now)
	supported, known := knowledge.answer(now)
	failures := knowledge.failures
	m.ipv6Access.Unlock()
	if carried {
		m.logger.Debug("outbound ", leaf, " carried IPv6")
	} else if known && !supported {
		m.logger.Info("outbound ", leaf, " has no IPv6: ", failures, " IPv6 connections got nothing while IPv4 answered; no AAAA answers and no IPv6 through it for ", ipv6Forget)
	} else {
		m.logger.Info("outbound ", leaf, " did not carry an IPv6 connection that IPv4 then carried")
	}
	// shown to the app, and fresh: no need to verify it again this run
	if state, ok := reg.outbounds[leaf]; ok {
		state.mu.Lock()
		if known {
			state.history.IPv6 = &supported
		} else {
			state.history.IPv6 = nil
		}
		state.history.IPv6FromCache = false
		state.mu.Unlock()
	}
}

// OutboundIPv6 implements adapter.IPv6Capability: what the connections showed for the outbound;
// for a group, for the member it leads to, or, when it has no single selection (a balancer that
// hashes or rotates), for all its live members together. Not known before any observation.
func (m *OutboundMonitoring) OutboundIPv6(tag string) (supported bool, known bool) {
	reg := m.reg()
	if reg == nil {
		return false, false
	}
	return m.ipv6OfTag(reg, tag, 0)
}

// ipv6Leaf is the outbound a connection through tag went through: a group's selected member,
// down the chain; a group without a single selection stands for itself.
func (m *OutboundMonitoring) ipv6Leaf(reg *monitoringRegistry, tag string) string {
	for range 8 {
		state, ok := reg.outbounds[tag]
		if !ok {
			return tag
		}
		if _, isGroup := reg.groups[tag]; !isGroup {
			return tag
		}
		selected := RealTag(state.outbound)
		if selected == "" || selected == tag {
			return tag
		}
		tag = selected
	}
	return tag
}

func (m *OutboundMonitoring) ipv6Knowledge(tag string) (supported bool, known bool) {
	m.ipv6Access.Lock()
	defer m.ipv6Access.Unlock()
	knowledge := m.ipv6[tag]
	if knowledge == nil {
		return false, false
	}
	return knowledge.answer(time.Now())
}

func (m *OutboundMonitoring) ipv6OfTag(reg *monitoringRegistry, tag string, depth int) (supported bool, known bool) {
	if depth > 8 { // a group leads to its selected member, which may be a group too
		return false, false
	}
	state, ok := reg.outbounds[tag]
	if !ok {
		return m.ipv6Knowledge(tag)
	}
	grp, isGroup := reg.groups[tag]
	if !isGroup {
		return m.ipv6Knowledge(tag)
	}
	if selected := RealTag(state.outbound); selected != "" && selected != tag {
		return m.ipv6OfTag(reg, selected, depth+1)
	}
	// No single selection: a connection may go to any live member, so IPv6 is carried only when
	// every one of them is known to carry it, and lacking as soon as one is known to lack it.
	// What was observed on the group itself (a member the router could not name) counts too.
	if supported, known = m.ipv6Knowledge(tag); known && !supported {
		return false, true
	}
	live, allKnown := 0, true
	for member := range grp.outbounds {
		memberState, ok := reg.outbounds[member]
		if !ok || !memberState.answered() {
			continue
		}
		live++
		memberSupported, memberKnown := m.ipv6OfTag(reg, member, depth+1)
		if memberKnown && !memberSupported {
			return false, true
		}
		if !memberKnown {
			allKnown = false
		}
	}
	if live == 0 || !allKnown {
		return false, false
	}
	return true, true
}

// answered reports whether the outbound has a URL test result that is not a timeout, of this run
// or a cached one: a member a group may give a connection to.
func (s *outboundState) answered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.history.Delay > 0 && s.history.Delay < TimeoutDelay
}

var _ adapter.IPv6Capability = (*OutboundMonitoring)(nil)

// recordIPv6 sets what is known outright: a verification at the URL test, a declaration from the
// link, or an answer cached from an earlier run. Traffic observations build on it from there.
func (m *OutboundMonitoring) recordIPv6(tag string, carried bool) {
	now := time.Now()
	m.ipv6Access.Lock()
	knowledge := m.ipv6[tag]
	if knowledge == nil {
		knowledge = &ipv6Knowledge{}
		m.ipv6[tag] = knowledge
	}
	knowledge.observedAt = now
	if carried {
		knowledge.failures = 0
		knowledge.carriedAt = now
	} else {
		knowledge.failures = ipv6FailuresToConclude
		knowledge.carriedAt = time.Time{}
	}
	m.ipv6Access.Unlock()
}

// seedIPv6Knowledge starts the run with what is already known: the answers cached with the URL
// test results of earlier runs, and the links' declarations, which win. Both are verified again
// at the outbound's first URL test when the verification is on.
func (m *OutboundMonitoring) seedIPv6Knowledge() {
	reg := m.reg()
	if reg == nil {
		return
	}
	for tag, state := range reg.outbounds {
		state.mu.Lock()
		cached := state.history.IPv6
		state.mu.Unlock()
		if cached != nil {
			m.recordIPv6(tag, *cached)
		}
	}
	for tag, carried := range m.ipv6Declared {
		m.recordIPv6(tag, carried)
		if state, ok := reg.outbounds[tag]; ok {
			state.mu.Lock()
			declared := carried
			state.history.IPv6 = &declared
			state.mu.Unlock()
		} else {
			m.logger.Warn("ipv6_declared names an outbound that is not monitored: ", tag)
		}
	}
}

// verifyIPv6Of is the URL test over IPv6 through the outbound (urltest.URLTestIPv6), with the
// box's own DNS for the test host's IPv6 address; nil when nothing could be verified, which
// leaves what is known as it is.
func (m *OutboundMonitoring) verifyIPv6Of(ctx context.Context, out *outboundState, link string) *bool {
	resolve := func(ctx context.Context, host string) ([]netip.Addr, error) {
		router := service.FromContext[adapter.DNSRouter](m.ctx)
		if router == nil {
			return nil, E.New("no DNS router")
		}
		return router.Lookup(ctx, host, adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv6Only})
	}
	verifyContext, cancel := context.WithTimeout(ctx, m.urlTestTimeout)
	defer cancel()
	carried, err := urltest.URLTestIPv6(verifyContext, link, out.outbound, resolve)
	if err != nil {
		m.logger.Debug("outbound ", out.outbound.Tag(), ": IPv6 not verified: ", err)
		return nil
	}
	if carried {
		m.logger.Debug("outbound ", out.outbound.Tag(), " carries IPv6, verified at the URL test")
	} else {
		m.logger.Info("outbound ", out.outbound.Tag(), " has no IPv6, verified at the URL test: no AAAA answers and no IPv6 through it")
	}
	return &carried
}
