package edgescan

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"math/bits"
	mrand "math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/sagernet/sing-box/hiddify/rating"
)

// maxHostBits bounds the addresses walked in one range: an IPv6 /64 is walked in its first 2^32
// addresses, more than any scan reaches.
const maxHostBits = 32

// The default size of a rated block: an IPv4 /24, and an IPv6 /48, the units networks are
// routed and filtered by.
const (
	DefaultBlockBitsV4 = 24
	DefaultBlockBitsV6 = 48
)

// Method keys of the choices a scan draws by their rating on the network.
const (
	setMethodPrefix  = "set/"
	nameMethodPrefix = "sni/"
)

// SetMethod is the method key of a set, rated by the targets of it that answered (or that the
// caller confirmed, see Request.ConfirmedOnly).
func SetMethod(name string) string { return setMethodPrefix + name }

// ServerNameMethod is the method key of a server name, rated by the targets that answered with it.
func ServerNameMethod(name string) string { return nameMethodPrefix + name }

// Set is a group of ranges that share their server names, such as the edges of one CDN.
type Set struct {
	Name        string
	CIDRs       []netip.Prefix
	ServerNames []string
}

// space is the candidate space of a scan: the ranges of each set, with each port, and a server
// name of the set. Each draw picks a set, then a block that answered or a new address of the
// set, then a server name, each by weighted random (see pick): the choices that answered on this
// network come up most, and the others still get their turn, so a scan does not try every name
// or every set in turn. New addresses come from a walk of the set's addresses and ports, in an
// order of the network's own, that goes on where the last scan stopped: an address that failed
// is not tried again until the set was walked.
type space struct {
	ports      []uint16
	sets       []spaceSet
	blockBits4 int
	blockBits6 int
}

type spaceSet struct {
	name   string // the rating key of the set
	walk   string // the key of its walk
	ranges []netip.Prefix
	sizes  []uint64 // addresses × ports per range
	names  []string
	total  uint64 // turns until every range of the set was walked: the sum of the sizes
}

func newSpace(sets []Set, ports []uint16, blockBits4, blockBits6 int) *space {
	if blockBits4 <= 0 || blockBits4 > 32 {
		blockBits4 = DefaultBlockBitsV4
	}
	if blockBits6 <= 0 || blockBits6 > 128 {
		blockBits6 = DefaultBlockBitsV6
	}
	s := &space{ports: ports, blockBits4: blockBits4, blockBits6: blockBits6}
	if len(ports) == 0 {
		return s
	}
	for _, set := range sets {
		names := set.ServerNames
		if len(names) == 0 {
			names = []string{""}
		}
		walked := spaceSet{names: names}
		seen := map[netip.Prefix]bool{}
		hash := sha256.New()
		for _, port := range ports {
			hash.Write(binary.BigEndian.AppendUint16(nil, port))
		}
		for _, prefix := range set.CIDRs {
			prefix = prefix.Masked()
			if !prefix.IsValid() || seen[prefix] {
				continue
			}
			seen[prefix] = true
			hostBits := min(prefix.Addr().BitLen()-prefix.Bits(), maxHostBits)
			size := uint64(1) << hostBits * uint64(len(ports))
			walked.ranges = append(walked.ranges, prefix)
			walked.sizes = append(walked.sizes, size)
			hash.Write([]byte(prefix.String() + ","))
		}
		if len(walked.ranges) == 0 {
			continue
		}
		// the largest first: the ranges still unwalked in a round are the first ones (see at)
		order := make([]int, len(walked.ranges))
		for i := range order {
			order[i] = i
		}
		slices.SortStableFunc(order, func(a, b int) int { return cmp.Compare(walked.sizes[b], walked.sizes[a]) })
		ranges, sizes := make([]netip.Prefix, len(order)), make([]uint64, len(order))
		for i, j := range order {
			ranges[i], sizes[i] = walked.ranges[j], walked.sizes[j]
		}
		walked.ranges, walked.sizes = ranges, sizes
		for _, size := range sizes {
			walked.total = saturatingAdd(walked.total, size)
		}
		walked.walk = hex.EncodeToString(hash.Sum(nil)[:6])
		walked.name = set.Name
		if walked.name == "" {
			walked.name = walked.ranges[0].String()
		}
		s.sets = append(s.sets, walked)
	}
	return s
}

func saturatingMul(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return ^uint64(0)
	}
	return lo
}

// block is the rated block of address.
func (s *space) block(address netip.Addr) netip.Prefix {
	address = address.Unmap()
	bits := s.blockBits6
	if address.Is4() {
		bits = s.blockBits4
	}
	prefix, _ := address.Prefix(min(bits, address.BitLen()))
	return prefix
}

func saturatingAdd(a, b uint64) uint64 {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return ^uint64(0)
	}
	return sum
}

// turnsBefore is the number of turns before round of a set: each range takes one turn a round
// until it is walked, so a small range drops out of the rounds instead of wasting turns.
func (set *spaceSet) turnsBefore(round uint64) uint64 {
	var turns uint64
	for _, size := range set.sizes {
		turns = saturatingAdd(turns, min(size, round))
	}
	return turns
}

// at returns the address and port of turn index of set under seed, or false past the walk. Turn
// index is in round k, the k-th address of each range not walked yet, which are the first ones of
// the ranges ordered by size.
func (set *spaceSet) at(index uint64, seed uint64, ports []uint16) (netip.AddrPort, bool) {
	if index >= set.total {
		return netip.AddrPort{}, false
	}
	// the round: the last k with turnsBefore(k) <= index
	low, high := uint64(0), set.sizes[0]
	for low+1 < high {
		middle := low + (high-low)/2
		if set.turnsBefore(middle) <= index {
			low = middle
		} else {
			high = middle
		}
	}
	k := low
	r := index - set.turnsBefore(k)
	size := set.sizes[r]
	x := permute(k, size, seed^r*0x9e3779b97f4a7c15)
	port := ports[x%uint64(len(ports))]
	x /= uint64(len(ports))
	return netip.AddrPortFrom(addressAt(set.ranges[r], x), port), true
}

// permute maps k in [0, size) to a position in [0, size), one to one for a given seed: an affine
// map with a multiplier coprime to size.
func permute(k, size, seed uint64) uint64 {
	if size <= 1 {
		return 0
	}
	a := (seed | 1) % size
	if a == 0 {
		a = 1
	}
	for gcd(a, size) != 1 {
		a++
	}
	b := (seed >> 17) % size
	hi, lo := bits.Mul64(a, k)
	_, product := bits.Div64(hi%size, lo, size)
	sum, carry := bits.Add64(product, b, 0)
	if carry != 0 || sum >= size {
		sum -= size
	}
	return sum
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// addressAt is the offset-th address of prefix.
func addressAt(prefix netip.Prefix, offset uint64) netip.Addr {
	address := prefix.Addr().AsSlice()
	for i := len(address) - 1; i >= 0 && offset > 0; i-- {
		sum := uint64(address[i]) + offset&0xff
		address[i] = byte(sum)
		offset = offset>>8 + sum>>8
	}
	result, _ := netip.AddrFromSlice(address)
	return result
}

// randomAddressIn is a random address of prefix, within its first 2^maxHostBits.
func randomAddressIn(prefix netip.Prefix) netip.Addr {
	hostBits := min(prefix.Addr().BitLen()-prefix.Bits(), maxHostBits)
	if hostBits <= 0 {
		return prefix.Addr()
	}
	return addressAt(prefix.Masked(), randomUint64()&(1<<hostBits-1))
}

// walk is where the scans of one network stand in the walk of one set.
type walk struct {
	Seed     uint64
	Next     uint64
	LastUsed time.Time
}

// maxWalksPerNetwork bounds the walks a network keeps; the least recently used goes.
const maxWalksPerNetwork = 64

func newSeed() uint64 {
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		value, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		return value.Uint64()
	}
	return binary.LittleEndian.Uint64(data[:])
}

// randFloat and randomUint64 are the randomness of the draws; tests may replace them.
var (
	randFloat    = mrand.Float64
	randomUint64 = mrand.Uint64
)

// pick draws one of n choices: with the chance of their weights (rating.Score.Weight), one of
// the choices with a positive score, or else any choice, all alike, with the weight of one or a
// quarter of the others' (a fifth of the draws at least). A choice that answered on this network
// comes up more the better it scored, and the rest are still explored: one choice at 3 points is
// drawn about 70% of the time.
func pick(n int, score func(i int) rating.Score) int {
	if n <= 1 {
		return 0
	}
	var (
		good   []int
		weight []float64
		total  float64
	)
	for i := range n {
		if s := score(i); s > 0 {
			good = append(good, i)
			weight = append(weight, s.Weight())
			total += s.Weight()
		}
	}
	explore := max(1, total/4) // the untried keep at least a fifth of the draws
	r := randFloat() * (total + explore)
	for j, i := range good {
		if r < weight[j] {
			return i
		}
		r -= weight[j]
	}
	return int(randomUint64() % uint64(n))
}

// walkShare is the least share of the draws a set's walk gets next to the blocks that answered:
// new addresses are still tried when many blocks work.
const walkShare = 0.25

// draw returns up to want new candidates of space that allowed accepts, and records the set of
// each in setOf. See space.
func (b *Book) draw(networkName string, s *space, want int, allowed func(Target) bool, setOf map[Target]string) []Target {
	if len(s.sets) == 0 || want <= 0 {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	now := time.Now()
	n := b.network(networkName, now)
	methodScore := func(key string) rating.Score {
		if record := n.Methods[key]; record != nil {
			return record.Score
		}
		return 0
	}
	// the blocks that answered here, for each set: the ones its ranges overlap, narrowed to the
	// range when it is the narrower
	type goodBlock struct {
		prefix netip.Prefix
		score  rating.Score
	}
	goodBlocks := make([][]goodBlock, len(s.sets))
	for block, record := range n.Blocks {
		if record.Score <= 0 {
			continue
		}
		for i := range s.sets {
			for _, prefix := range s.sets[i].ranges {
				if !prefix.Overlaps(block) {
					continue
				}
				narrower := block
				if prefix.Bits() > block.Bits() {
					narrower = prefix
				}
				goodBlocks[i] = append(goodBlocks[i], goodBlock{narrower, record.Score})
			}
		}
	}
	walkOf := func(set *spaceSet) *walk {
		current := n.Walks[set.walk]
		if current == nil {
			current = &walk{Seed: newSeed()}
			n.Walks[set.walk] = current
			if len(n.Walks) > maxWalksPerNetwork {
				keys := make([]string, 0, len(n.Walks))
				for key := range n.Walks {
					keys = append(keys, key)
				}
				slices.SortFunc(keys, func(a, b string) int { return n.Walks[a].LastUsed.Compare(n.Walks[b].LastUsed) })
				for _, key := range keys[:len(n.Walks)-maxWalksPerNetwork] {
					if key != set.walk {
						delete(n.Walks, key)
					}
				}
			}
		}
		current.LastUsed = now
		return current
	}
	var drawn []Target
	taken := map[Target]bool{} // a space smaller than want wraps within one draw
	// a bound on the turns looked at, for spaces that are mostly excluded or walked
	for steps := 0; len(drawn) < want && steps < want*64+len(s.sets); steps++ {
		index := pick(len(s.sets), func(i int) rating.Score { return methodScore(SetMethod(s.sets[i].name)) })
		set := &s.sets[index]
		blocks := goodBlocks[index]
		var addrPort netip.AddrPort
		// a block that answered, or a new address of the walk, at least a quarter of the draws
		var weights float64
		for _, block := range blocks {
			weights += block.score.Weight()
		}
		if len(blocks) > 0 && randFloat() >= max(walkShare, 1/(weights+1)) {
			choice := pick(len(blocks), func(i int) rating.Score { return blocks[i].score })
			addrPort = netip.AddrPortFrom(randomAddressIn(blocks[choice].prefix), s.ports[randomUint64()%uint64(len(s.ports))])
		} else {
			current := walkOf(set)
			if current.Next >= set.total {
				current.Next = 0
				current.Seed = newSeed()
			}
			var ok bool
			addrPort, ok = set.at(current.Next, current.Seed, s.ports)
			current.Next++
			if !ok {
				continue
			}
			// an address of a block that did not answer here is drawn as often as its weight
			if record := n.Blocks[s.block(addrPort.Addr())]; record != nil && record.Score < 0 && randFloat() >= record.Score.Weight() {
				continue
			}
		}
		name := set.names[pick(len(set.names), func(i int) rating.Score { return methodScore(ServerNameMethod(set.names[i])) })]
		target := Target{AddrPort: addrPort, ServerName: name}
		if taken[target] || !allowed(target) {
			continue
		}
		taken[target] = true
		drawn = append(drawn, target)
		if setOf != nil {
			setOf[target] = set.name
		}
	}
	return drawn
}
