package warpscan

import (
	"cmp"
	"encoding/json"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/hiddify/rating"
)

// Scores (see rating) rank endpoints per network: an endpoint that works on one network (a home
// Wi-Fi) may be blocked on another (a mobile carrier), so each network keeps its own record of
// every endpoint tried on it. Each network also rates the methods tried on it, such as the noises
// and the tunnels (see Book.OrderMethods).
const (
	MaxScore = rating.Max
	MinScore = rating.Min
	// RecentScoreFloor is the lowest score of an endpoint that succeeded within RecentWindow.
	RecentScoreFloor rating.Score = -5
	RecentWindow                  = 7 * 24 * time.Hour
	// FailurePeriod is the shortest time between two penalties of one endpoint, so a burst of
	// failures (one outage) costs a single point.
	FailurePeriod = time.Hour
	// records kept per network, and networks forgotten after
	maxRecordsPerNetwork = 128
	networkLifetime      = 90 * 24 * time.Hour
)

// EndpointPolicy tempers the failures of endpoints and methods alike.
var EndpointPolicy = rating.Policy{FailureGap: FailurePeriod, RecentWindow: RecentWindow, RecentFloor: RecentScoreFloor}

// Record is what is known about one endpoint on one network.
type Record struct {
	rating.Record
	RTT time.Duration `json:"rtt,omitempty"`
}

// Book holds the records of every network. It is safe for concurrent use.
type Book struct {
	access   sync.Mutex
	networks map[string]*network
}

type network struct {
	LastSeen time.Time                  `json:"last_seen"`
	Records  map[netip.AddrPort]*Record `json:"records"`
	// Methods rates the ways of getting through tried on this network, by a key the caller
	// names (NoiseMethod).
	Methods map[string]*rating.Record `json:"methods,omitempty"`
	// LegacyNoise is the noise preset that got through, as saved before methods were rated; it
	// is read once into Methods.
	LegacyNoise string `json:"noise,omitempty"`
}

// NoiseMethod is the method key of a noise preset, "" for the configured noise.
func NoiseMethod(preset string) string {
	return "noise/" + preset
}

func NewBook() *Book {
	return &Book{networks: make(map[string]*network)}
}

func (b *Book) network(name string, now time.Time) *network {
	n := b.networks[name]
	if n == nil {
		n = &network{}
		b.networks[name] = n
	}
	if n.Records == nil {
		n.Records = make(map[netip.AddrPort]*Record)
	}
	if n.Methods == nil {
		n.Methods = make(map[string]*rating.Record)
	}
	n.LastSeen = now
	return n
}

// MethodScore returns the score of method on network, and whether it was rated there.
func (b *Book) MethodScore(networkName string, method string) (rating.Score, bool) {
	b.access.Lock()
	defer b.access.Unlock()
	if n := b.networks[networkName]; n != nil {
		if record := n.Methods[method]; record != nil {
			return record.Score, true
		}
	}
	return 0, false
}

// OrderMethods returns methods in a weighted random order by their score on network (see
// rating.Order); a method not rated there counts as prior gives it (nil for 0).
func (b *Book) OrderMethods(networkName string, methods []string, prior func(method string) rating.Score) []string {
	b.access.Lock()
	defer b.access.Unlock()
	var records map[string]*rating.Record
	if n := b.networks[networkName]; n != nil {
		records = n.Methods
	}
	return rating.Order(methods, func(method string) rating.Score {
		if record := records[method]; record != nil {
			return record.Score
		}
		if prior != nil {
			return prior(method)
		}
		return 0
	})
}

// SettleMethods scores one attempt over several methods on network: winner got through, the
// methods in failed did not before it. Without a winner nothing is recorded (see
// rating.Table.Settle).
func (b *Book) SettleMethods(networkName string, winner string, failed []string, now time.Time) {
	b.access.Lock()
	defer b.access.Unlock()
	methods := b.network(networkName, now).Methods
	method(methods, winner).Success(now)
	for _, key := range failed {
		if key != winner {
			method(methods, key).Failure(now, EndpointPolicy)
		}
	}
}

// MethodFailure records that method did not get through on network although it looked like it
// would (a tunnel that answered a handshake but did not connect).
func (b *Book) MethodFailure(networkName string, key string, now time.Time) {
	b.access.Lock()
	defer b.access.Unlock()
	method(b.network(networkName, now).Methods, key).Failure(now, EndpointPolicy)
}

func method(methods map[string]*rating.Record, key string) *rating.Record {
	record := methods[key]
	if record == nil {
		record = &rating.Record{}
		methods[key] = record
	}
	return record
}

// Success records that addrPort answered on network: +1, or 1 when it was negative.
func (b *Book) Success(networkName string, addrPort netip.AddrPort, rtt time.Duration, now time.Time) {
	b.access.Lock()
	defer b.access.Unlock()
	records := b.network(networkName, now).Records
	record := records[addrPort]
	if record == nil {
		record = &Record{}
		records[addrPort] = record
	}
	record.Success(now)
	if rtt > 0 {
		record.RTT = rtt
	}
}

// Failure records that addrPort did not answer on network (see EndpointPolicy): -1, at most once
// per FailurePeriod, never below RecentScoreFloor when it succeeded within RecentWindow. Only an
// endpoint that answered there before is marked down: the ranges hold millions of address and
// port pairs, so a random one that failed is all but never drawn again, and its record would
// only push the endpoints that work out of the book.
func (b *Book) Failure(networkName string, addrPort netip.AddrPort, now time.Time) {
	b.access.Lock()
	defer b.access.Unlock()
	n := b.networks[networkName]
	if n == nil {
		return
	}
	if record := n.Records[addrPort]; record != nil && !record.LastSuccess.IsZero() {
		n.LastSeen = now
		record.Failure(now, EndpointPolicy)
	}
}

// Score returns the score of addrPort on network, and whether it is known there.
func (b *Book) Score(networkName string, addrPort netip.AddrPort) (rating.Score, bool) {
	b.access.Lock()
	defer b.access.Unlock()
	if n := b.networks[networkName]; n != nil {
		if record := n.Records[addrPort]; record != nil {
			return record.Score, true
		}
	}
	return 0, false
}

type ranked struct {
	addrPort netip.AddrPort
	record   Record
}

func rank(records map[netip.AddrPort]*Record) []ranked {
	list := make([]ranked, 0, len(records))
	for addrPort, record := range records {
		list = append(list, ranked{addrPort, *record})
	}
	slices.SortFunc(list, func(a, b ranked) int {
		if c := cmp.Compare(b.record.Score, a.record.Score); c != 0 {
			return c
		}
		if c := cmp.Compare(a.record.RTT, b.record.RTT); c != 0 {
			return c
		}
		return a.addrPort.Compare(b.addrPort)
	})
	return list
}

// Candidates returns the endpoints to try on network, best first: the network's own endpoints
// above MinScore by score, then endpoints with a positive score on other networks (not yet tried
// on this one). Endpoints at MinScore on this network are returned separately, to try last.
func (b *Book) Candidates(networkName string) (preferred []netip.AddrPort, last []netip.AddrPort) {
	b.access.Lock()
	defer b.access.Unlock()
	local := map[netip.AddrPort]*Record{}
	if n := b.networks[networkName]; n != nil {
		local = n.Records
	}
	for _, entry := range rank(local) {
		if entry.record.Score <= MinScore {
			last = append(last, entry.addrPort)
		} else {
			preferred = append(preferred, entry.addrPort)
		}
	}
	others := map[netip.AddrPort]*Record{}
	for name, n := range b.networks {
		if name == networkName {
			continue
		}
		for addrPort, record := range n.Records {
			if record.Score <= 0 || local[addrPort] != nil {
				continue
			}
			if current := others[addrPort]; current == nil || record.Score > current.Score {
				others[addrPort] = record
			}
		}
	}
	for _, entry := range rank(others) {
		preferred = append(preferred, entry.addrPort)
	}
	return preferred, last
}

// prune drops old networks and the worst records past the limit.
func (b *Book) prune(now time.Time) {
	for name, n := range b.networks {
		if now.Sub(n.LastSeen) > networkLifetime {
			delete(b.networks, name)
			continue
		}
		if len(n.Records) <= maxRecordsPerNetwork {
			continue
		}
		list := rank(n.Records)
		for _, entry := range list[maxRecordsPerNetwork:] {
			delete(n.Records, entry.addrPort)
		}
	}
}

// legacyNoiseScore is the score of the noise saved before methods were rated.
const legacyNoiseScore rating.Score = 3

func (b *Book) MarshalJSON() ([]byte, error) {
	b.access.Lock()
	defer b.access.Unlock()
	b.prune(time.Now())
	return json.Marshal(b.networks)
}

func (b *Book) UnmarshalJSON(content []byte) error {
	networks := make(map[string]*network)
	if err := json.Unmarshal(content, &networks); err != nil {
		return err
	}
	for name, n := range networks {
		if n == nil {
			delete(networks, name)
			continue
		}
		if n.Records == nil {
			n.Records = make(map[netip.AddrPort]*Record)
		}
		for addrPort, record := range n.Records {
			if record == nil || record.LastSuccess.IsZero() {
				delete(n.Records, addrPort) // a failure of an endpoint that never answered, saved before
			}
		}
		if n.Methods == nil {
			n.Methods = make(map[string]*rating.Record)
		}
		if n.LegacyNoise != "" {
			// the noise that got through, before methods were rated: as a few successes
			key := NoiseMethod(n.LegacyNoise)
			if n.Methods[key] == nil {
				n.Methods[key] = &rating.Record{Score: legacyNoiseScore, LastSuccess: n.LastSeen}
			}
			n.LegacyNoise = ""
		}
	}
	b.access.Lock()
	b.networks = networks
	b.access.Unlock()
	return nil
}
