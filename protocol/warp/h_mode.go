package warp

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/wireguard-go/hiddify"
)

// The tunnels of a warp endpoint (option mode). In auto mode the endpoint makes one handshake
// with each at once and runs the fastest that answers; while it is not connected it tries again,
// and moves to another tunnel that answers.
const (
	modeWireGuard = "wireguard"
	modeAWG       = "awg"
	modeMASQUE    = "masque"
	modeAuto      = "auto"

	// defaultAWGPreset gives the AmneziaWG settings of awg and auto mode without an awg block.
	defaultAWGPreset = "dns-google"

	// raceTimeout bounds the handshakes of auto mode, and raceAttempts is how many each tunnel
	// gets: a single lost packet must not lose the race.
	raceTimeout  = 5 * time.Second
	raceAttempts = 2

	// While the endpoint is not connected, it is checked every healthInterval: after
	// healthAfter, its device is asked about (at most every profileCheckInterval), and in auto
	// mode the tunnels race again.
	healthInterval       = time.Minute
	healthAfter          = 3 * time.Minute
	profileCheckInterval = 10 * time.Minute

	// autoConfirmWait is how long the tunnel auto mode chose has to connect: an answer to one
	// handshake does not make a tunnel that carries traffic, so a tunnel that does not connect
	// is left for the next.
	autoConfirmWait = 20 * time.Second
)

// warpMode returns the tunnel of options: mode, or without it the masque or awg block. awg and auto
// without awg settings get those of defaultAWGPreset.
func warpMode(options *option.WARPEndpointOptions) (string, error) {
	var mode string
	switch strings.ToLower(options.Mode) {
	case "":
		switch {
		case options.MASQUE.IsEnabled() && options.AWG.IsAvailble():
			return "", E.New("warp: masque and awg are two tunnels, set one, or mode auto")
		case options.MASQUE.IsEnabled():
			return modeMASQUE, nil
		case options.AWG.IsAvailble():
			return modeAWG, nil
		}
		return modeWireGuard, nil
	case "wg", modeWireGuard:
		mode = modeWireGuard
	case modeAWG:
		mode = modeAWG
	case modeMASQUE:
		mode = modeMASQUE
	case modeAuto:
		mode = modeAuto
	default:
		return "", E.New("warp: unknown mode: ", options.Mode, ` (expected "wg", "awg", "masque" or "auto")`)
	}
	if (mode == modeAWG || mode == modeAuto) && !options.AWG.IsAvailble() {
		preset, _ := warpscan.NoisePresetByName(defaultAWGPreset)
		options.AWG = preset.AWG(options.AWG)
	}
	return mode, nil
}

// activeMode is the tunnel in use: the mode, or in auto mode the one chosen, empty before.
func (w *WARPEndpoint) activeMode() string {
	if w.mode != modeAuto {
		return w.mode
	}
	active, _ := w.active.Load().(string)
	return active
}

// warpSession is one start of the endpoint: it ends when the endpoint starts again (another
// device or tunnel) or closes, and its background work stops with it.
type warpSession struct {
	done chan struct{}
	once sync.Once
}

func (s *warpSession) end() {
	s.once.Do(func() { close(s.done) })
}

// session returns the channel that closes when the current start ends.
func (w *WARPEndpoint) session() <-chan struct{} {
	w.sessionAccess.Lock()
	defer w.sessionAccess.Unlock()
	if w.current == nil {
		w.current = &warpSession{done: make(chan struct{})}
	}
	return w.current.done
}

// beginSession ends the current start and begins a new one.
func (w *WARPEndpoint) beginSession() <-chan struct{} {
	w.sessionAccess.Lock()
	defer w.sessionAccess.Unlock()
	if w.current != nil {
		w.current.end()
	}
	w.current = &warpSession{done: make(chan struct{})}
	select {
	case <-w.done:
		w.current.end()
	default:
		if w.discarded.Load() {
			w.current.end()
		}
	}
	return w.current.done
}

func (w *WARPEndpoint) endSession() {
	w.sessionAccess.Lock()
	defer w.sessionAccess.Unlock()
	if w.current != nil {
		w.current.end()
	}
}

// start registers or loads a device and runs the tunnel of the mode, choosing it in auto mode.
func (w *WARPEndpoint) start() {
	done := w.beginSession()
	mode := w.mode
	if mode == modeAuto {
		w.selecting.Store(true)
		mode = w.chooseMode(done)
		w.selecting.Store(false)
		if mode == "" {
			return
		}
		w.active.Store(mode)
	}
	profile := w.obtainProfile(done, modeKind(mode))
	if profile == nil {
		return
	}
	w.mtx.Lock()
	w.profile = profile
	w.mtx.Unlock()
	if !w.candidate {
		// before connecting: a start that keeps failing (the tunnel cannot open through the
		// detour) blocks in connect, and must be left as well
		w.followDetourMoves(done)
	}
	if w.mode == modeAuto {
		go w.confirmAuto(done, mode)
	}
	if mode == modeMASQUE {
		w.connectMASQUE(done, profile)
	} else {
		w.connect(done, profile.WireGuard)
	}
	select {
	case <-done:
		return
	default:
	}
	if !w.candidate {
		w.runChecks(done)
	}
}

// confirmAuto leaves the tunnel auto mode chose when it does not connect within
// autoConfirmWait: the race runs again without it.
func (w *WARPEndpoint) confirmAuto(done <-chan struct{}, mode string) {
	select {
	case <-done:
		return
	case <-time.After(autoConfirmWait):
	}
	if adapter.IsReady(w) {
		return
	}
	w.failedModes.Store(mode, struct{}{})
	w.restart("auto mode: " + mode + " did not connect")
}

// clearFailedModes forgets the tunnels that did not connect: on a new path or network they may.
func (w *WARPEndpoint) clearFailedModes() {
	w.failedModes.Range(func(key, _ any) bool {
		w.failedModes.Delete(key)
		return true
	})
}

func (w *WARPEndpoint) modeFailed(mode string) bool {
	_, failed := w.failedModes.Load(mode)
	return failed
}

// modeKind is the kind of device a tunnel runs on: each has its own, so the tunnels of auto mode
// do not share a key.
func modeKind(mode string) string {
	switch mode {
	case modeAWG:
		return kindAWG
	case modeMASQUE:
		return kindMASQUE
	}
	return kindWireGuard
}

// restart ends the current start, with its inner endpoint, and starts again.
func (w *WARPEndpoint) restart(reason string) {
	w.logger.InfoContext(w.ctx, "WARP: ", reason, ", starting again")
	w.endSession()
	w.mtx.Lock()
	old := w.endpoint
	w.endpoint = nil
	w.scanStatusOf = nil
	w.failover = nil // WireGuard's, of the start that ends
	w.mtx.Unlock()
	if old != nil {
		adapter.CloseLate(w.scope, old)
	}
	go w.start()
}

// obtainProfile returns the device of kind: the profile in the config, a saved one that can be
// used, or a new one, registered until it works or the start ends.
func (w *WARPEndpoint) obtainProfile(done <-chan struct{}, kind string) *warpProfile {
	if kind != kindMASQUE && w.options.WARPConfig != nil && w.options.WARPConfig.PrivateKey != "" {
		return &warpProfile{Kind: kind, WireGuard: w.options.WARPConfig, inline: true}
	}
	_, recreated := w.recreated.Load(kind)
	if !w.options.Profile.Recreate || recreated {
		if profile := w.profiles.usable(kind); profile != nil {
			return profile
		}
		if kind == kindAWG && w.mode == modeAWG {
			// awg mode alone may run on the WireGuard device saved before; only auto mode needs
			// one of each
			if profile := w.profiles.usable(kindWireGuard); profile != nil {
				return profile
			}
		}
	}
	var profile *warpProfile
	w.registering.Store(true)
	registered := w.retry(done, "register WARP "+kind+" device", func() error { // a cold detour fails the first attempts
		var err error
		profile, err = w.register(kind)
		return err
	})
	w.registering.Store(false)
	if !registered {
		return nil
	}
	w.recreated.Store(kind, struct{}{})
	w.profiles.add(profile)
	return profile
}

// register registers a device of kind. The device of profile.id and profile.auth_token is only
// taken while it is not retired; after, a new one is registered.
func (w *WARPEndpoint) register(kind string) (*warpProfile, error) {
	profileOptions := w.options.Profile
	if profileOptions.ID != "" && w.profiles.isRetired(profileOptions.ID) {
		profileOptions.ID, profileOptions.AuthToken, profileOptions.PrivateKey = "", "", ""
	}
	if kind == kindMASQUE {
		return registerMASQUEProfile(w.ctx, &profileOptions)
	}
	if kind == kindAWG && w.mode == modeAuto && profileOptions.ID != "" {
		// the device of profile.id is the WireGuard one; AmneziaWG races it with its own key
		profileOptions.ID, profileOptions.AuthToken, profileOptions.PrivateKey = "", "", ""
	}
	device, err := GetWarpProfile(w.ctx, &profileOptions)
	if err != nil {
		return nil, err
	}
	token := device.Token
	if token == "" {
		token = profileOptions.AuthToken
	}
	config := device.Config
	return &warpProfile{Kind: kind, ID: device.ID, Token: token, WireGuard: &config, Created: time.Now()}, nil
}

// currentProfile is the device in use.
func (w *WARPEndpoint) currentProfile() *warpProfile {
	w.mtx.Lock()
	defer w.mtx.Unlock()
	return w.profile
}

// watchHealth checks the endpoint while it is not connected: its device may no longer be
// usable (then a usable or new one replaces it), and in auto mode another tunnel may answer.
func (w *WARPEndpoint) watchHealth(done <-chan struct{}) {
	ticker := time.NewTicker(healthInterval)
	defer ticker.Stop()
	var notReadySince, lastCheck time.Time
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		now := time.Now()
		if adapter.IsReady(w) {
			notReadySince = time.Time{}
			continue
		}
		if notReadySince.IsZero() {
			notReadySince = now
		}
		if now.Sub(notReadySince) < healthAfter || now.Sub(lastCheck) < profileCheckInterval {
			continue
		}
		lastCheck = now
		if profile := w.currentProfile(); profile != nil {
			problem, known := w.profileProblem(profile)
			switch {
			case known && problem != "":
				w.profiles.retire(profile, problem)
				w.restart("device " + profile.ID + ": " + problem)
				return
			case known:
				w.logger.InfoContext(w.ctx, "WARP: device ", profile.ID, " is fine, the network does not let it through")
			}
		}
		if w.mode == modeAuto {
			if best := w.raceModes(done); best != "" && best != w.activeMode() {
				w.restart("auto mode: " + best + " gets through")
				return
			}
		}
	}
}

// chooseMode gets the devices auto mode needs and races the tunnels; WireGuard when none
// answers, so the scanner and the port rotation can still look for a way. Empty when the start
// ends first.
func (w *WARPEndpoint) chooseMode(done <-chan struct{}) string {
	for _, kind := range []string{kindWireGuard, kindAWG} {
		if w.obtainProfile(done, kind) == nil {
			return ""
		}
	}
	if masqueIncluded {
		if w.obtainProfile(done, kindMASQUE) == nil {
			return ""
		}
	}
	if best := w.raceModes(done); best != "" {
		return best
	}
	select {
	case <-done:
		return ""
	default:
	}
	for _, mode := range []string{modeWireGuard, modeAWG, modeMASQUE} {
		if !w.modeFailed(mode) && (mode != modeMASQUE || masqueIncluded) {
			w.logger.WarnContext(w.ctx, "WARP auto mode: no tunnel answered, using ", mode)
			return mode
		}
	}
	w.clearFailedModes() // each was tried: start over
	w.logger.WarnContext(w.ctx, "WARP auto mode: no tunnel connected, starting over with WireGuard")
	return modeWireGuard
}

// raceModes makes a handshake with each tunnel at once and returns the fastest that answered,
// or empty.
func (w *WARPEndpoint) raceModes(done <-chan struct{}) string {
	ctx, cancel := context.WithTimeout(w.ctx, raceTimeout)
	defer cancel()
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()
	probes := make(map[string]func(ctx context.Context) (time.Duration, error))
	probeDialer, err := dialer.NewWithOptions(dialer.Options{Context: w.ctx, Options: w.options.DialerOptions, ResolverOnDetour: true})
	if err != nil {
		w.logger.ErrorContext(w.ctx, err)
		return ""
	}
	for mode, noise := range map[string]hiddify.NoiseOptions{
		modeWireGuard: w.options.Noise,
		modeAWG:       warpscan.AWGProbeNoise(w.options.AWG),
	} {
		config := w.options.WARPConfig // the profile in the config, for both
		if profile := w.profiles.usable(modeKind(mode)); profile != nil && (config == nil || config.PrivateKey == "") {
			config = profile.WireGuard
		}
		if config == nil || config.PrivateKey == "" || len(config.Peers) == 0 {
			continue
		}
		address, port, err := warpPeerEndpoint(config, w.options.ServerOptions)
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddr(address)
		if err != nil {
			continue
		}
		probe, err := warpscan.WireGuardProbe(probeDialer, config.PrivateKey, config.Peers[0].PublicKey, noise)
		if err != nil {
			continue
		}
		peer := netip.AddrPortFrom(addr, port)
		probes[mode] = func(ctx context.Context) (time.Duration, error) { return probe(ctx, peer) }
	}
	if masqueIncluded {
		if profile := w.profiles.usable(kindMASQUE); profile != nil {
			probes[modeMASQUE] = func(ctx context.Context) (time.Duration, error) { return w.probeMASQUE(ctx, profile) }
		}
	}
	type answer struct {
		mode string
		rtt  time.Duration
	}
	answers := make(chan answer, len(probes))
	for mode := range probes {
		if w.modeFailed(mode) {
			delete(probes, mode) // it answered a handshake before, but did not connect
		}
	}
	for mode, probe := range probes {
		go func() {
			var err error
			for range raceAttempts {
				var rtt time.Duration
				if rtt, err = probe(ctx); err == nil {
					answers <- answer{mode, rtt}
					return
				}
				if ctx.Err() != nil {
					break
				}
			}
			w.logger.DebugContext(w.ctx, "WARP auto mode: ", mode, ": ", err)
			answers <- answer{mode: mode, rtt: -1}
		}()
	}
	var best answer
	for range probes {
		got := <-answers
		if got.rtt >= 0 && (best.mode == "" || got.rtt < best.rtt) {
			best = got
		}
	}
	if best.mode != "" {
		w.logger.InfoContext(w.ctx, "WARP auto mode: using ", best.mode, " (", best.rtt, ")")
	}
	return best.mode
}
