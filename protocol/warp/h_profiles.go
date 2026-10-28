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

// WARP keeps the devices it registered, WireGuard and MASQUE ones, in the cache file, and uses
// them again instead of registering new ones. A device is only given up when Cloudflare says it
// cannot be used (it is gone, disabled, or its account used up its quota); a network that blocks
// WARP leaves it in use, since a new device would be blocked the same way.

const (
	kindWireGuard = "wireguard"
	kindAWG       = "awg" // a WireGuard device of its own, so auto mode can race it next to WireGuard
	kindMASQUE    = "masque"

	// profilesSuffix is the cache key of the devices, after the endpoint's unique_identifier.
	profilesSuffix = "/warp-profiles"
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
	// Retired says why the device cannot be used any more; empty while it can.
	Retired string `json:"retired,omitempty"`
	// inline is the profile written in the config: never saved nor retired.
	inline bool
}

// checkable reports whether the device can be asked about: an id and a token.
func (p *warpProfile) checkable() bool {
	return !p.inline && p.ID != "" && p.Token != ""
}

// warpProfiles are the devices of one warp endpoint, read from the cache file when first used:
// the cache file is not open yet when the endpoint is created.
type warpProfiles struct {
	access    sync.Mutex
	cacheFile adapter.CacheFile
	key       string
	profiles  []*warpProfile

	loadOnce sync.Once
	load     func()
}

func newWARPProfiles(ctx context.Context, logger log.ContextLogger, uniqueID string) *warpProfiles {
	store := &warpProfiles{key: uniqueID + profilesSuffix}
	store.load = func() { store.read(ctx, logger, uniqueID) }
	return store
}

func (s *warpProfiles) ensureLoaded() {
	s.loadOnce.Do(s.load)
}

// loadWARPProfiles reads the devices at once.
func loadWARPProfiles(ctx context.Context, logger log.ContextLogger, uniqueID string) *warpProfiles {
	store := newWARPProfiles(ctx, logger, uniqueID)
	store.ensureLoaded()
	return store
}

func (s *warpProfiles) read(ctx context.Context, logger log.ContextLogger, uniqueID string) {
	store := s
	cacheFile := service.FromContext[adapter.CacheFile](ctx)
	if cacheFile == nil || !cacheFile.StoreWARPConfig() {
		return
	}
	store.cacheFile = cacheFile
	if saved := cacheFile.LoadBinary(store.key); saved != nil {
		if err := json.Unmarshal(saved.Content, &store.profiles); err != nil {
			logger.WarnContext(ctx, "WARP: unreadable saved devices, starting over: ", err)
			store.profiles = nil
		}
		return
	}
	// the devices saved one per key before
	if saved := cacheFile.LoadBinary(uniqueID); saved != nil {
		var config C.WARPConfig
		if json.Unmarshal(saved.Content, &config) == nil && config.PrivateKey != "" {
			store.profiles = append(store.profiles, &warpProfile{Kind: kindWireGuard, WireGuard: &config})
		}
	}
	if saved := cacheFile.LoadBinary(uniqueID + legacyMASQUESuffix); saved != nil {
		var device struct {
			ID          string `json:"id"`
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal(saved.Content, &device) == nil {
			store.profiles = append(store.profiles, &warpProfile{Kind: kindMASQUE, ID: device.ID, Token: device.AccessToken, MASQUE: saved.Content})
		}
	}
	if len(store.profiles) > 0 {
		store.save()
	}
}

// usable returns the first device of kind that is not retired, or nil.
func (s *warpProfiles) usable(kind string) *warpProfile {
	s.ensureLoaded()
	s.access.Lock()
	defer s.access.Unlock()
	for _, profile := range s.profiles {
		if profile.Kind == kind && profile.Retired == "" {
			return profile
		}
	}
	return nil
}

// isRetired reports whether the device id was retired.
func (s *warpProfiles) isRetired(id string) bool {
	s.ensureLoaded()
	s.access.Lock()
	defer s.access.Unlock()
	for _, profile := range s.profiles {
		if profile.ID == id && profile.Retired != "" {
			return true
		}
	}
	return false
}

// add puts a newly registered device first and saves.
func (s *warpProfiles) add(profile *warpProfile) {
	s.ensureLoaded()
	s.access.Lock()
	s.profiles = append([]*warpProfile{profile}, s.profiles...)
	s.access.Unlock()
	s.save()
}

// retire records why profile cannot be used any more, and saves.
func (s *warpProfiles) retire(profile *warpProfile, reason string) {
	if profile.inline {
		return
	}
	s.access.Lock()
	profile.Retired = reason
	s.access.Unlock()
	s.save()
}

func (s *warpProfiles) save() {
	if s.cacheFile == nil {
		return
	}
	s.access.Lock()
	content, err := json.Marshal(s.profiles)
	s.access.Unlock()
	if err == nil {
		s.cacheFile.SaveBinary(s.key, &adapter.SavedBinary{LastUpdated: time.Now(), Content: content})
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
