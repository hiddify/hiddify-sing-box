package warp

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/cloudflare"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// The devices WARP registered, WireGuard, AmneziaWG and MASQUE ones, are kept in one pool in the
// cache file, shared by every warp endpoint, and used again instead of registering new ones. Each
// endpoint leases its own: two endpoints on one device would push each other off Cloudflare. An
// endpoint takes the device it used before, else a free one, and registers a new one only when
// none is free. A device is only given up when Cloudflare says it cannot be used (it is gone,
// disabled, or its account used up its quota); a network that blocks WARP leaves it in use, since
// a new device would be blocked the same way.

const (
	kindWireGuard = "wireguard"
	kindAWG       = "awg" // a WireGuard device of its own, so auto mode can race it next to WireGuard
	kindMASQUE    = "masque"

	// poolKey is the cache key of the device pool.
	poolKey = "warp-profiles"
	// endpointPoolSuffix is where an endpoint kept its devices before the pool, after its
	// unique_identifier.
	endpointPoolSuffix = "/warp-profiles"
	// legacyMASQUESuffix is where one MASQUE device was saved before.
	legacyMASQUESuffix = "/masque"

	// profileCheckTimeout bounds one question to the WARP API about a device.
	profileCheckTimeout = 20 * time.Second
)

// warpProfile is one registered device.
type warpProfile struct {
	Kind  string `json:"kind"`
	ID    string `json:"id,omitempty"`
	Token string `json:"token,omitempty"`
	// WireGuard is the device's WireGuard config, for kindWireGuard and kindAWG.
	WireGuard *C.WARPConfig `json:"wireguard,omitempty"`
	// MASQUE is the device's MASQUE config (masque.Config), for kindMASQUE.
	MASQUE  json.RawMessage `json:"masque,omitempty"`
	Created time.Time       `json:"created,omitzero"`
	// Owner is the unique_identifier of the endpoint that used the device last; it takes it
	// first next time.
	Owner string `json:"owner,omitempty"`
	// Retired says why the device cannot be used any more; empty while it can.
	Retired string `json:"retired,omitempty"`
	// inline is the profile written in the config: never pooled nor retired.
	inline bool
}

// checkable reports whether the device can be asked about: an id and a token.
func (p *warpProfile) checkable() bool {
	return !p.inline && p.ID != "" && p.Token != ""
}

// warpPool is the devices of every warp endpoint on one cache file, with the endpoint each is
// leased to. It is read from the cache file when first used: the cache file is not open yet when
// the endpoints are created.
type warpPool struct {
	access    sync.Mutex
	cacheFile adapter.CacheFile
	loaded    bool
	migrated  map[string]bool // endpoints whose devices of before were taken in
	profiles  []*warpProfile
	leases    map[*warpProfile]string // the endpoint that has the device now
}

var (
	poolsAccess sync.Mutex
	pools       = make(map[adapter.CacheFile]*warpPool) // nil: no cache file, the pool lives in memory
)

func poolFor(cacheFile adapter.CacheFile) *warpPool {
	if cacheFile != nil && !cacheFile.StoreWARPConfig() {
		cacheFile = nil
	}
	poolsAccess.Lock()
	defer poolsAccess.Unlock()
	pool := pools[cacheFile]
	if pool == nil {
		pool = &warpPool{cacheFile: cacheFile, migrated: make(map[string]bool), leases: make(map[*warpProfile]string)}
		pools[cacheFile] = pool
	}
	return pool
}

// loadLocked reads the pool, once, and takes in the devices owner kept before the pool.
func (p *warpPool) loadLocked(ctx context.Context, logger log.ContextLogger, owner string) {
	if p.cacheFile == nil {
		return
	}
	changed := false
	if !p.loaded {
		p.loaded = true
		if saved := p.cacheFile.LoadBinary(poolKey); saved != nil {
			if err := json.Unmarshal(saved.Content, &p.profiles); err != nil {
				logger.WarnContext(ctx, "WARP: unreadable saved devices, starting over: ", err)
				p.profiles = nil
			}
		}
	}
	if !p.migrated[owner] {
		p.migrated[owner] = true
		var found []*warpProfile
		if saved := p.cacheFile.LoadBinary(owner + endpointPoolSuffix); saved != nil {
			var profiles []*warpProfile
			if json.Unmarshal(saved.Content, &profiles) == nil {
				found = append(found, profiles...)
			}
		} else {
			if saved := p.cacheFile.LoadBinary(owner); saved != nil {
				var config C.WARPConfig
				if json.Unmarshal(saved.Content, &config) == nil && config.PrivateKey != "" {
					found = append(found, &warpProfile{Kind: kindWireGuard, WireGuard: &config})
				}
			}
			if saved := p.cacheFile.LoadBinary(owner + legacyMASQUESuffix); saved != nil {
				var device struct {
					ID          string `json:"id"`
					AccessToken string `json:"access_token"`
				}
				if json.Unmarshal(saved.Content, &device) == nil && device.ID != "" {
					found = append(found, &warpProfile{Kind: kindMASQUE, ID: device.ID, Token: device.AccessToken, MASQUE: saved.Content})
				}
			}
		}
		for _, profile := range found {
			if !p.containsLocked(profile) {
				profile.Owner = owner
				p.profiles = append(p.profiles, profile)
				changed = true
			}
		}
	}
	if changed {
		p.saveLocked()
	}
}

func (p *warpPool) containsLocked(profile *warpProfile) bool {
	for _, existing := range p.profiles {
		if profile.ID != "" && existing.ID == profile.ID ||
			profile.WireGuard != nil && existing.WireGuard != nil && existing.WireGuard.PrivateKey == profile.WireGuard.PrivateKey {
			return true
		}
	}
	return false
}

func (p *warpPool) saveLocked() {
	if p.cacheFile == nil {
		return
	}
	if content, err := json.Marshal(p.profiles); err == nil {
		p.cacheFile.SaveBinary(poolKey, &adapter.SavedBinary{LastUpdated: time.Now(), Content: content})
	}
}

// warpProfiles are the devices of one endpoint, leased from the pool.
type warpProfiles struct {
	ctx    context.Context
	logger log.ContextLogger
	owner  string
	pool   *warpPool
	once   sync.Once
}

func newWARPProfiles(ctx context.Context, logger log.ContextLogger, owner string) *warpProfiles {
	return &warpProfiles{ctx: ctx, logger: logger, owner: owner}
}

// loadWARPProfiles returns the endpoint's devices, with the pool read at once.
func loadWARPProfiles(ctx context.Context, logger log.ContextLogger, owner string) *warpProfiles {
	profiles := newWARPProfiles(ctx, logger, owner)
	profiles.ensureLoaded()
	return profiles
}

func (s *warpProfiles) ensureLoaded() {
	s.once.Do(func() {
		s.pool = poolFor(service.FromContext[adapter.CacheFile](s.ctx))
	})
	s.pool.access.Lock()
	s.pool.loadLocked(s.ctx, s.logger, s.owner)
	s.pool.access.Unlock()
}

// usable returns the device of kind this endpoint leases, leasing one when it has none: the one
// it used before, else a free one. nil when none is free.
func (s *warpProfiles) usable(kind string) *warpProfile {
	s.ensureLoaded()
	pool := s.pool
	pool.access.Lock()
	defer pool.access.Unlock()
	var free *warpProfile
	for _, profile := range pool.profiles {
		if profile.Kind != kind || profile.Retired != "" {
			continue
		}
		holder, leased := pool.leases[profile]
		switch {
		case leased && holder == s.owner:
			return profile
		case leased:
			continue // another endpoint's
		case profile.Owner == s.owner:
			free = profile // the one it used before comes first
		case free == nil || free.Owner != s.owner:
			free = profile
		}
	}
	if free == nil {
		return nil
	}
	pool.leases[free] = s.owner
	if free.Owner != s.owner {
		free.Owner = s.owner
		pool.saveLocked()
	}
	return free
}

// isRetired reports whether the device id was retired.
func (s *warpProfiles) isRetired(id string) bool {
	s.ensureLoaded()
	s.pool.access.Lock()
	defer s.pool.access.Unlock()
	for _, profile := range s.pool.profiles {
		if profile.ID == id && profile.Retired != "" {
			return true
		}
	}
	return false
}

// add puts a newly registered device in the pool, leased to this endpoint, and saves.
func (s *warpProfiles) add(profile *warpProfile) {
	s.ensureLoaded()
	s.pool.access.Lock()
	defer s.pool.access.Unlock()
	profile.Owner = s.owner
	s.pool.profiles = append(s.pool.profiles, profile)
	s.pool.leases[profile] = s.owner
	s.pool.saveLocked()
}

// retire records why profile cannot be used any more, frees it, and saves.
func (s *warpProfiles) retire(profile *warpProfile, reason string) {
	if profile.inline {
		return
	}
	s.ensureLoaded()
	s.pool.access.Lock()
	defer s.pool.access.Unlock()
	profile.Retired = reason
	delete(s.pool.leases, profile)
	s.pool.saveLocked()
}

// release gives the endpoint's devices back to the pool, when it closes.
func (s *warpProfiles) release() {
	if s.pool == nil {
		return
	}
	s.pool.access.Lock()
	defer s.pool.access.Unlock()
	for profile, holder := range s.pool.leases {
		if holder == s.owner {
			delete(s.pool.leases, profile)
		}
	}
}

// profileProblem asks the WARP API whether profile can still be used. known is false when the
// API could not be reached, or the device cannot be asked about: then nothing is known about it,
// and it stays in use.
func (w *WARPEndpoint) profileProblem(profile *warpProfile) (problem string, known bool) {
	if !profile.checkable() {
		return "", false
	}
	ctx, cancel := context.WithTimeout(w.ctx, profileCheckTimeout)
	defer cancel()
	var device *cloudflare.CloudflareProfile
	var gone error
	err := withWARPAPI(ctx, &w.options.Profile, func(dialer N.Dialer) error {
		var err error
		device, err = cloudflare.NewCloudflareApiDetour(dialer).GetProfile(ctx, profile.Token, profile.ID)
		if cloudflare.DeviceGone(err) {
			gone = err
			return nil // Cloudflare answered: no other path will say otherwise
		}
		return err
	})
	switch {
	case gone != nil:
		return E.Cause(gone, "the device is no longer registered").Error(), true
	case err != nil:
		return "", false
	}
	if problem := device.Problem(); problem != "" {
		return problem, true
	}
	return "", true
}

// DevicePrivateKey is the WireGuard private key of the device in use, empty for MASQUE; it tells
// which device an endpoint runs on.
func (w *WARPEndpoint) DevicePrivateKey() string {
	if profile := w.currentProfile(); profile != nil && profile.WireGuard != nil {
		return profile.WireGuard.PrivateKey
	}
	return ""
}
