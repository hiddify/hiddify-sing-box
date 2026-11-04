package balancer

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/contrab/maphash"
)

// StrategyPool keeps a fixed number of slots filled with working members and sends each
// connection to a slot by a hash of what the connection is (sticky_hash), as lx's round_robin.
const StrategyPool = "pool"

const defaultPoolSize = 3

// Pool fills min(pool, members) slots with working members and keeps them there:
//   - a member stays in its slot while it answers, so the keys of the other slots never move;
//   - a dead member is replaced in its slot by a working member outside the pool; while none is
//     available the slot is skipped, its keys spread over the working slots, and they come back
//     when it answers again;
//   - with tolerance, a member outside the pool replaces a slot member only when it is
//     faster by more than that many milliseconds; with 0, slots keep the first working members
//     in config order.
//
// A connection goes to slot hash(sticky key) % slots; with sticky_hash ["none"] connections go
// round-robin over the working slots. Refilling a slot does not interrupt connections.
type Pool struct {
	outbounds  map[string][]adapter.Outbound
	size       int
	tolerance  uint16
	ratio      float64 // with tolerance: a share of the slot member's delay, see switchThreshold
	stickyHash []string
	hash       maphash.Hasher[string]

	access sync.Mutex
	slots  map[string][]string // per network: the member tag of each slot, "" while empty
	delays map[string]uint16
	next   map[string]int
}

var _ Strategy = (*Pool)(nil)

func NewPool(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) (*Pool, error) {
	size := options.Pool
	if size < 0 {
		return nil, E.New("pool must not be negative")
	}
	if size == 0 {
		size = defaultPoolSize
	}
	stickyHash, err := parseStickyHash(options.StickyHash, defaultStickyHash)
	if err != nil {
		return nil, err
	}
	ratio := options.ToleranceRatio
	if ratio <= 0 {
		ratio = defaultToleranceRatio
	}
	pool := &Pool{
		outbounds:  convertOutbounds(outbounds),
		size:       size,
		tolerance:  options.Tolerance,
		ratio:      ratio,
		stickyHash: stickyHash,
		hash:       maphash.NewHasher[string](),
		slots:      make(map[string][]string),
		delays:     make(map[string]uint16),
		next:       make(map[string]int),
	}
	for network, members := range pool.outbounds {
		pool.slots[network] = make([]string, min(size, len(members)))
	}
	return pool, nil
}

func (p *Pool) alive(tag string) bool {
	delay, loaded := p.delays[tag]
	return loaded && delay < monitoring.TimeoutDelay
}

// UpdateOutboundsInfo refills the slots from the test results. It never asks to interrupt
// connections: a slot that is refilled was dead, and the other slots keep their members.
func (p *Pool) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) bool {
	p.access.Lock()
	defer p.access.Unlock()
	p.delays = getDelayMap(history)
	for network, members := range p.outbounds {
		p.refill(network, members)
	}
	return false
}

func (p *Pool) refill(network string, members []adapter.Outbound) {
	slots := p.slots[network]
	inPool := make(map[string]bool, len(slots))
	for _, tag := range slots {
		if tag != "" {
			inPool[tag] = true
		}
	}
	// the working members outside the pool, in config order
	var spare []string
	for _, member := range members {
		if tag := member.Tag(); !inPool[tag] && p.alive(tag) {
			spare = append(spare, tag)
		}
	}
	takeSpare := func(better func(tag string) bool) string {
		for i, tag := range spare {
			if better == nil || better(tag) {
				spare = append(spare[:i], spare[i+1:]...)
				return tag
			}
		}
		return ""
	}
	for i, tag := range slots {
		if tag == "" || !p.alive(tag) {
			// an empty or dead slot takes the first working spare; a dead member keeps its slot
			// while there is none, so its keys come back when it answers again
			if replacement := takeSpare(nil); replacement != "" {
				slots[i] = replacement
			}
			continue
		}
		if p.tolerance > 0 { // unset: the first working members keep their slots
			current := p.delays[tag]
			threshold := switchThreshold(current, p.tolerance, p.ratio)
			if replacement := takeSpare(func(candidate string) bool {
				return uint32(p.delays[candidate])+threshold < uint32(current)
			}); replacement != "" {
				spare = append(spare, tag)
				slots[i] = replacement
			}
		}
	}
}

// key is what makes connections stick to a slot.
func (p *Pool) key(metadata *adapter.InboundContext) string {
	return stickyKey(metadata, p.stickyHash)
}

func (p *Pool) Select(metadata adapter.InboundContext, network string, touch bool) adapter.Outbound {
	if network != N.NetworkTCP && network != N.NetworkUDP {
		network = N.NetworkTCP
	}
	p.access.Lock()
	defer p.access.Unlock()
	slots := p.slots[network]
	var working []int
	for i, tag := range slots {
		if tag != "" && p.alive(tag) {
			working = append(working, i)
		}
	}
	if len(working) == 0 {
		// nothing tested yet, or nothing works: the first member, as the other strategies
		if members := p.outbounds[network]; len(members) > 0 {
			return members[0]
		}
		return nil
	}
	var slot int
	if len(p.stickyHash) == 0 {
		slot = working[p.next[network]%len(working)]
		if touch {
			p.next[network]++
		}
	} else {
		hash := p.hash.Hash(p.key(&metadata))
		slot = int(hash % uint64(len(slots)))
		if tag := slots[slot]; tag == "" || !p.alive(tag) {
			// the slot is down: spread its keys over the working slots, the same way each time
			slot = working[int(hash%uint64(len(working)))]
		}
	}
	return p.member(network, slots[slot])
}

func (p *Pool) member(network string, tag string) adapter.Outbound {
	for _, member := range p.outbounds[network] {
		if member.Tag() == tag {
			return member
		}
	}
	return nil
}

// Now is the member of the first working TCP slot.
func (p *Pool) Now() string {
	p.access.Lock()
	defer p.access.Unlock()
	for _, tag := range p.slots[N.NetworkTCP] {
		if tag != "" && p.alive(tag) {
			return tag
		}
	}
	return ""
}

// Slots returns the member tag of each slot of network, "" for an empty one.
func (p *Pool) Slots(network string) []string {
	p.access.Lock()
	defer p.access.Unlock()
	return append([]string(nil), p.slots[network]...)
}
