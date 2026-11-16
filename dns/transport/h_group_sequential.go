package transport

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// defaultSequentialMemberFloor is the least a server is waited for when the query's time is
// shared among the servers still to ask.
const defaultSequentialMemberFloor = 2 * time.Second

// The score of a server in sequential mode: servers are asked from the highest score down. //H
const (
	sequentialScoreMin = -10
	sequentialScoreMax = 10
)

// groupSequential keeps what the sequential mode learnt: a score per server from -10 to 10, which
// orders the servers. A server that answers gains a point and is at least 1 after it, so one
// answer puts a server that kept failing ahead of every server that did not answer; a server
// that failed loses a point, but only when another server answered that query, as a query no
// server answers says more about the network than about the servers, and only when its detour
// was ready, as a server cannot answer through an outbound that is not. Each server also gets a
// bounded share of the query's time, so one that hangs cannot spend the whole of it: before, a
// TCP server whose port was black-holed took the full DNS timeout and the query failed without
// the servers behind it ever being asked.
type groupSequential struct {
	memberTimeout time.Duration

	access sync.Mutex
	scores map[string]int
}

func newGroupSequential(options option.GroupDNSServerOptions) *groupSequential {
	return &groupSequential{
		memberTimeout: time.Duration(options.MemberTimeout),
		scores:        make(map[string]int),
	}
}

func (s *groupSequential) reset() {
	s.access.Lock()
	defer s.access.Unlock()
	clear(s.scores)
}

// order is the servers to ask, in order: the highest score first, servers with the same score as
// listed, so every server is still asked when the ones before it fail.
func (s *groupSequential) order(tags []string) []string {
	s.access.Lock()
	defer s.access.Unlock()
	ordered := slices.Clone(tags)
	slices.SortStableFunc(ordered, func(a, b string) int {
		return s.scores[b] - s.scores[a]
	})
	return ordered
}

// record scores a query: answered is the server whose answer was used, "" when none answered;
// failed are the servers that failed before it. Servers that answered without an address do not
// move.
func (s *groupSequential) record(answered string, failed []string) {
	if answered == "" {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.scores[answered] = max(min(s.scores[answered]+1, sequentialScoreMax), 1)
	for _, tag := range failed {
		s.scores[tag] = max(s.scores[tag]-1, sequentialScoreMin)
	}
}

// detourReady reports whether the outbounds and endpoints a server goes through are ready, and
// for a group the outbound it uses now (outboundReady). A
// server whose detour is not ready yet, such as WARP still connecting or Psiphon without a
// tunnel, is not asked, and when it fails because its detour went down during the query, it
// loses no point. //H
func (t *GroupTransport) detourReady(transportManager adapter.DNSTransportManager, tag string) bool {
	transport, loaded := transportManager.Transport(tag)
	if !loaded {
		return true
	}
	referrer, isReferrer := transport.(adapter.Referrer)
	if !isReferrer {
		return true
	}
	outboundManager := service.FromContext[adapter.OutboundManager](t.ctx)
	if outboundManager == nil {
		return true
	}
	network := N.NetworkTCP
	if transport.Type() == C.DNSTypeUDP {
		network = N.NetworkUDP
	}
	visited := make(map[string]bool)
	for _, detour := range referrer.References() {
		if !outboundReady(outboundManager, detour, network, visited) {
			return false
		}
	}
	return true
}

// outboundReady reports whether the outbound tag is ready and, for a group (selector, urltest,
// fallback, balancer), whether the outbound it uses now for network is, down to the last group:
// a selector is always ready itself, while the proxy selected in it may still be connecting. A
// group that has not picked one yet counts as ready. //H
func outboundReady(outboundManager adapter.OutboundManager, tag string, network string, visited map[string]bool) bool {
	if visited[tag] {
		return true
	}
	visited[tag] = true
	outbound, loaded := outboundManager.Outbound(tag)
	if !loaded {
		return true
	}
	if !adapter.IsReady(outbound) {
		return false
	}
	group, isGroup := outbound.(adapter.OutboundGroup)
	if !isGroup {
		return true
	}
	selected := group.Selected(network)
	if selected == nil {
		return true
	}
	return outboundReady(outboundManager, selected.Tag(), network, visited)
}

// score is a server's current score, for tests and the log. //H
func (s *groupSequential) score(tag string) int {
	s.access.Lock()
	defer s.access.Unlock()
	return s.scores[tag]
}

// budget is how long the next server is waited for, with left servers still to ask: member_timeout
// when set, else the time left shared among them, at least the floor; never past the deadline.
func (s *groupSequential) budget(ctx context.Context, left int) time.Duration {
	remaining := C.DNSTimeout
	if deadline, loaded := ctx.Deadline(); loaded {
		remaining = time.Until(deadline)
	}
	budget := s.memberTimeout
	if budget <= 0 {
		budget = max(remaining/time.Duration(max(left, 1)), defaultSequentialMemberFloor)
	}
	return min(budget, remaining)
}

func (t *GroupTransport) exchangeSequential(ctx context.Context, transportManager adapter.DNSTransportManager, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	collector := groupCollector{transport: t}
	// a server whose detour is not ready is not asked: it would only fail, or hang for its share
	var order []string
	for _, tag := range t.sequential.order(t.serverTags) {
		if t.detourReady(transportManager, tag) {
			order = append(order, tag)
		}
	}
	if len(order) == 0 {
		callback(nil, E.New("no DNS server of ", t.Tag(), " has a ready detour"))
		return
	}
	var failed []string
	for i, tag := range order {
		memberContext, cancel := context.WithTimeout(ctx, t.sequential.budget(ctx, len(order)-i))
		result := t.exchangeOne(memberContext, transportManager, tag, message)
		cancel()
		if result.err != nil && ctx.Err() != nil {
			t.finishCanceled(ctx, &collector, callback)
			return
		}
		if result.err != nil && memberContext.Err() != nil {
			result.err = E.Cause(result.err, "waiting for ", tag)
		}
		response, outcome := collector.classify(ctx, result, false)
		switch outcome {
		case groupAccepted:
			t.sequential.record(tag, failed)
			callback(response, nil)
			return
		case groupFailed:
			if t.detourReady(transportManager, tag) { // it may have gone down during the query
				failed = append(failed, tag)
			}
		}
	}
	callback(collector.finish())
}
