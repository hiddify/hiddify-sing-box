package edgescan

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// A Store holds the score books of the scanners that share it, for the whole process: the WARP
// endpoint scanner (WARP over WireGuard, AmneziaWG and MASQUE) and the Psiphon CDN edge scanner,
// of every outbound that reaches
// the network directly (no detour, or a direct one), share SharedKey. They see the same network,
// so what one learned the others use at once, a search one of them runs serves the others that
// ask for the same while it runs, and the network is named once for all. The Store outlives a
// box: a hot reload or a restart in the same process goes on with what it knew, without reading
// the cache file again. A scanner behind another detour sees that detour's network instead, and
// keeps a store of its own, under its own key.
type Store struct {
	key string

	access    sync.Mutex
	cacheFile adapter.CacheFile
	books     map[string]*Book
	legacy    *Book // a single book saved before stores, given to the first kind that asks
	merged    map[string]bool
	flights   map[string]*flight
	lastWays  map[string]LastWay // see LastWay

	networkAccess sync.Mutex
	network       *NetworkInfo
	networkAt     time.Time
	networkFlight *flight
	changedAt     time.Time
}

// SharedKey is the cache key of the store of the scanners that reach the network directly.
const SharedKey = "edge-scanner"

// Kinds of book in a store: the targets of each are of their own (WARP's WireGuard endpoints,
// Psiphon's CDN edges), and so are their ratings.
const (
	KindWARP        = "warp"
	KindWARPTunnels = "warp-tunnels"
	KindWARPMASQUE  = "warp-masque" // WARP over MASQUE: its endpoints are other servers
	KindPsiphon     = "psiphon"
)

var stores struct {
	access sync.Mutex
	byKey  map[string]*Store
}

// OpenStore returns the store kept under key in cacheFile, the same for every caller of the
// process while the cache file is the same (a hot reload keeps it), loaded from it the first time.
// A box started again opens its cache file again, and the store is loaded from what was saved.
// Without a cache file, each call has a store of its own, which nothing keeps.
func OpenStore(cacheFile adapter.CacheFile, key string) *Store {
	newStore := func() *Store {
		store := &Store{key: key, cacheFile: cacheFile, books: make(map[string]*Book), merged: make(map[string]bool), flights: make(map[string]*flight)}
		store.load(cacheFile)
		return store
	}
	if cacheFile == nil {
		return newStore()
	}
	stores.access.Lock()
	defer stores.access.Unlock()
	if stores.byKey == nil {
		stores.byKey = make(map[string]*Store)
	}
	store := stores.byKey[key]
	if store == nil || store.cacheFile != cacheFile {
		store = newStore() // the store of an earlier cache file is forgotten: it was saved
		stores.byKey[key] = store
	}
	return store
}

// OpenScannerStore is the store of a scanner that dials through detour: the shared one when it
// reaches the network directly (see Direct), or else one of its own under privateKey.
func OpenScannerStore(ctx context.Context, detour string, privateKey string) *Store {
	cacheFile := service.FromContext[adapter.CacheFile](ctx)
	if Direct(ctx, detour) {
		return OpenStore(cacheFile, SharedKey)
	}
	return OpenStore(cacheFile, privateKey)
}

// Direct reports whether a dialer with detour reaches the network directly: no detour, or a
// direct outbound.
func Direct(ctx context.Context, detour string) bool {
	if detour == "" {
		return true
	}
	manager := service.FromContext[adapter.OutboundManager](ctx)
	if manager == nil {
		return false
	}
	outbound, loaded := manager.Outbound(detour)
	return loaded && outbound.Type() == C.TypeDirect
}

// storeVersion marks a saved store: books by kind.
const storeVersion = 3

type savedStore struct {
	Version int                        `json:"v"`
	Books   map[string]json.RawMessage `json:"k"`
	// Adopted are the keys whose books joined the store (see Adopt), not read again
	Adopted []string `json:"a,omitempty"`
	// LastWays are the ways through that worked last, by key (see LastWay)
	LastWays map[string]LastWay `json:"g,omitempty"`
}

func (s *Store) load(cacheFile adapter.CacheFile) {
	if cacheFile == nil {
		return
	}
	saved := cacheFile.LoadBinary(s.key)
	if saved == nil {
		return
	}
	var content savedStore
	if json.Unmarshal(saved.Content, &content) == nil && content.Version == storeVersion {
		for _, key := range content.Adopted {
			s.merged[key] = true
		}
		s.lastWays = content.LastWays
		for kind, raw := range content.Books {
			book := NewBook()
			if book.UnmarshalJSON(raw) == nil {
				s.books[kind] = book
			}
		}
		return
	}
	// a single book, saved before stores
	book := NewBook()
	if book.UnmarshalJSON(saved.Content) == nil {
		s.legacy = book
	}
}

// Book returns the book of kind.
func (s *Store) Book(kind string) *Book {
	s.access.Lock()
	defer s.access.Unlock()
	book := s.books[kind]
	if book == nil {
		book = s.legacy
		s.legacy = nil
		if book == nil {
			book = NewBook()
		}
		s.books[kind] = book
	}
	return book
}

// Adopt merges into the book of kind what a scanner saved before stores under its own key, once:
// the scores of every endpoint of a WARP profile join the shared ones. The store remembers the
// keys it adopted, so what it pruned since does not come back.
func (s *Store) Adopt(kind string, legacyKey string) {
	if legacyKey == "" || legacyKey == s.key {
		return
	}
	s.access.Lock()
	cacheFile := s.cacheFile
	done := s.merged[legacyKey]
	s.merged[legacyKey] = true
	s.access.Unlock()
	if done || cacheFile == nil {
		return
	}
	saved := cacheFile.LoadBinary(legacyKey)
	if saved == nil {
		return
	}
	legacy := NewBook()
	if legacy.UnmarshalJSON(saved.Content) == nil {
		s.Book(kind).Merge(legacy)
	}
}

// Save keeps every book of the store in the cache file, in one entry.
func (s *Store) Save() error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.cacheFile == nil {
		return nil
	}
	content := savedStore{Version: storeVersion, Books: make(map[string]json.RawMessage, len(s.books))}
	for key, way := range s.lastWays {
		if time.Since(way.At) > Lifetime {
			delete(s.lastWays, key)
		}
	}
	if len(s.lastWays) > 0 {
		content.LastWays = s.lastWays
	}
	for key := range s.merged {
		content.Adopted = append(content.Adopted, key)
	}
	for kind, book := range s.books {
		raw, err := json.Marshal(book)
		if err != nil {
			return err
		}
		content.Books[kind] = raw
	}
	raw, err := json.Marshal(content)
	if err != nil {
		return err
	}
	return s.cacheFile.SaveBinary(s.key, &adapter.SavedBinary{LastUpdated: time.Now(), Content: raw})
}

type flight struct {
	done   chan struct{}
	value  any
	err    error
	cancel context.CancelFunc
	users  int
}

// errFlightLeft is the error a waiter sees when every caller of a flight left before it ended.
var errFlightLeft = errors.New("search abandoned")

// Do runs fn once for every caller with the same key at the same time: the WARP endpoints that
// look for an endpoint on the same network, with the same probe, share one search, so the
// network is not probed twice as hard. The search runs while any caller still waits for it; a
// caller that leaves (its ctx ends) does not stop it for the others.
func (s *Store) Do(ctx context.Context, key string, fn func(ctx context.Context) (any, error)) (any, error) {
	s.access.Lock()
	current := s.flights[key]
	if current == nil {
		flightCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		current = &flight{done: make(chan struct{}), cancel: cancel}
		s.flights[key] = current
		go func() {
			value, err := fn(flightCtx)
			s.access.Lock()
			current.value, current.err = value, err
			if s.flights[key] == current {
				delete(s.flights, key)
			}
			s.access.Unlock()
			cancel()
			close(current.done)
		}()
	}
	current.users++
	s.access.Unlock()
	select {
	case <-current.done:
		s.leave(current)
		return current.value, current.err
	case <-ctx.Done():
		s.leave(current)
		return nil, ctx.Err()
	}
}

// leave counts a caller out of a flight, and stops the flight when no caller waits for it.
func (s *Store) leave(current *flight) {
	s.access.Lock()
	current.users--
	idle := current.users == 0
	if idle {
		// a caller that comes now starts a search of its own, not this stopping one
		for key, other := range s.flights {
			if other == current {
				delete(s.flights, key)
			}
		}
	}
	s.access.Unlock()
	if idle {
		current.cancel()
	}
}

// networkMaxAge is how long a named network is taken as current without a network change.
const networkMaxAge = 10 * time.Minute

// Network names the network the box is on (see DetectNetwork), once for every scanner of the
// store: the name found within networkMaxAge, and since the last NetworkChanged, is kept, and the
// scanners that ask while it is being found wait for it.
func (s *Store) Network(ctx context.Context, logger logger.ContextLogger, dialer N.Dialer) NetworkInfo {
	s.networkAccess.Lock()
	if s.network != nil && time.Since(s.networkAt) < networkMaxAge {
		network := *s.network
		s.networkAccess.Unlock()
		return network
	}
	current := s.networkFlight
	if current == nil {
		current = &flight{done: make(chan struct{})}
		s.networkFlight = current
		go func() {
			network := DetectNetwork(context.WithoutCancel(ctx), logger, dialer)
			s.networkAccess.Lock()
			if s.networkFlight == current { // not changed meanwhile
				s.network, s.networkAt = &network, time.Now()
				s.networkFlight = nil
			}
			s.networkAccess.Unlock()
			current.value = network
			close(current.done)
		}()
	}
	s.networkAccess.Unlock()
	select {
	case <-current.done:
		return current.value.(NetworkInfo)
	case <-ctx.Done():
		return NetworkInfo{Name: "default", IPv4: true, IPv6: true}
	}
}

// networkChangeWindow is how long one network change is: the scanners of a shared store are each
// told of it, and the first forgets the name; the others' calls, within this time, do not throw
// away the name found meanwhile.
const networkChangeWindow = 5 * time.Second

// NetworkChanged forgets the network name: the next Network names it again.
func (s *Store) NetworkChanged() {
	s.networkAccess.Lock()
	defer s.networkAccess.Unlock()
	if !s.changedAt.IsZero() && time.Since(s.changedAt) < networkChangeWindow {
		return
	}
	s.changedAt = time.Now()
	s.network = nil
	s.networkFlight = nil
}

// Merge adds to b what other knows that b does not: the records, methods and blocks b has no
// record of, and the walks it has not started. A record both have keeps b's.
func (b *Book) Merge(other *Book) {
	if other == nil || other == b {
		return
	}
	other.access.Lock()
	networks := other.networks
	other.networks = make(map[string]*network) // other is not used after
	other.access.Unlock()
	b.access.Lock()
	defer b.access.Unlock()
	for name, from := range networks {
		to := b.networks[name]
		if to == nil {
			b.networks[name] = from
			continue
		}
		to.ensureMaps()
		if from.LastSeen.After(to.LastSeen) {
			to.LastSeen = from.LastSeen
		}
		for key, record := range from.Records {
			if to.Records[key] == nil {
				to.Records[key] = record
			}
		}
		for key, record := range from.Methods {
			if to.Methods[key] == nil {
				to.Methods[key] = record
			}
		}
		for key, record := range from.Blocks {
			if to.Blocks[key] == nil {
				to.Blocks[key] = record
			}
		}
		for key, walk := range from.Walks {
			if to.Walks[key] == nil {
				to.Walks[key] = walk
			}
		}
	}
}
