package warp

import (
	"context"
	"errors"
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
//
// What a start makes belongs to its session: the scans and probes run on its context, and the
// inner endpoint, the failover and the device are published only while it is the current one
// (publish). A session ends with w.mtx held, so "is it over" and "publish" cannot interleave: a
// start that was replaced while it scanned or connected published its inner endpoint next to the
// new start's, a second device with the same key that nothing closed, or its failover over the
// new one's.
type warpSession struct {
	done     chan struct{}
	once     sync.Once
	ctx      context.Context // ends with the session
	cancel   context.CancelFunc
	finished chan struct{} // closed when the start that runs in the session has returned
	failover *warpFailover // the scanner's, of this start; guarded by w.mtx
	// network is the network auto mode named for its tunnel ratings, which the scanner of the
	// start takes over; guarded by w.mtx
	network *warpscan.NetworkInfo
}

// end ends the session; w.mtx is held.
func (s *warpSession) end() {
	s.once.Do(func() {
		close(s.done)
		s.cancel()
	})
}

func (w *WARPEndpoint) newSession() *warpSession {
	ctx, cancel := context.WithCancel(w.ctx)
	return &warpSession{done: make(chan struct{}), ctx: ctx, cancel: cancel, finished: make(chan struct{})}
}

// session returns the current start.
func (w *WARPEndpoint) session() *warpSession {
	w.sessionAccess.Lock()
	defer w.sessionAccess.Unlock()
	if w.current == nil {
		w.current = w.newSession()
		close(w.current.finished) // no start runs in it
	}
	return w.current
}

// beginSession ends the current start and begins a new one; previous is the one it ended.
func (w *WARPEndpoint) beginSession() (session *warpSession, previous *warpSession) {
	w.sessionAccess.Lock()
	defer w.sessionAccess.Unlock()
	w.mtx.Lock()
	defer w.mtx.Unlock()
	previous = w.current
	if previous != nil {
		previous.end()
	}
	w.current = w.newSession()
	select {
	case <-w.done:
		w.current.end()
	default:
		if w.discarded.Load() {
			w.current.end()
		}
	}
	return w.current, previous
}

func (w *WARPEndpoint) endSession() {
	w.sessionAccess.Lock()
	defer w.sessionAccess.Unlock()
	w.mtx.Lock()
	defer w.mtx.Unlock()
	if w.current != nil {
		w.current.end()
	}
}

// publish runs set with w.mtx held, and reports false without running it when the start that
// done belongs to is over.
func (w *WARPEndpoint) publish(done <-chan struct{}, set func()) bool {
	w.mtx.Lock()
	defer w.mtx.Unlock()
	select {
	case <-done:
		return false
	default:
	}
	set()
	return true
}

// start registers or loads a device and runs the tunnel of the mode, choosing it in auto mode.
func (w *WARPEndpoint) start() {
	w.starting.Store(true)        //H: see Status
	defer w.starting.Store(false) //H: also when it ends before connecting
	session, previous := w.beginSession()
	defer close(session.finished)
	done := session.done
	if previous != nil {
		// one start at a time: the one this replaces has been told to end, and has left before
		// this one registers, scans or connects. Side by side they dialed with one key.
		<-previous.finished
	}
	mode := w.mode
	if mode == modeAuto {
		w.selecting.Store(true)
		mode = w.chooseMode(session)
		w.selecting.Store(false)
		if mode == "" || !w.publish(done, func() { w.active.Store(mode) }) {
			return
		}
	}
	profile := w.obtainProfile(done, modeKind(mode))
	if profile == nil || !w.publish(done, func() { w.profile = profile }) {
		return
	}
	if !w.candidate {
		// before connecting: a start that keeps failing (the tunnel cannot open through the
		// detour) blocks in connect, and must be left as well
		w.followDetourMoves(done)
	}
	if w.mode == modeAuto {
		go w.confirmAuto(done, mode)
	}
	if mode == modeMASQUE {
		w.connectMASQUE(session, profile)
	} else {
		w.connect(session, profile.WireGuard)
	}
	w.starting.Store(false) //H: connected; the checks run from here on
	select {
	case <-done:
		return
	default:
	}
	if !w.candidate {
		w.runChecks(session)
	}
}

// confirmAuto leaves the tunnel auto mode chose when it does not connect within
// autoConfirmWait: the race runs again without it. Either way the tunnel is rated (see
// h_tunnel_rating.go).
func (w *WARPEndpoint) confirmAuto(done <-chan struct{}, mode string) {
	select {
	case <-done:
		return
	case <-time.After(autoConfirmWait):
	}
	if adapter.IsReady(w) {
		w.tunnelConnected(mode)
		return
	}
	if !w.paused() { // a paused device connects nothing: no tunnel is to blame
		w.tunnelsFailed(mode)
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
	// the session ends and what it published is taken back in one step: the start that ends
	// cannot publish in between
	w.sessionAccess.Lock()
	w.mtx.Lock()
	if w.current != nil {
		w.current.end()
	}
	old := w.endpoint
	w.endpoint = nil
	w.scanStatusOf = nil
	w.failover = nil // WireGuard's, of the start that ends
	w.mtx.Unlock()
	w.sessionAccess.Unlock()
	if old != nil {
		adapter.CloseLate(w.scope, old)
	}
	go w.start() // which waits for the start that ends
}

// obtainProfile returns the device of kind: the profile in the config, a saved one that can be
// used, or a new one, registered until it works or the start ends.
func (w *WARPEndpoint) obtainProfile(done <-chan struct{}, kind string) *warpProfile {
	if kind != kindMASQUE && w.options.WARPConfig != nil && w.options.WARPConfig.PrivateKey != "" {
		return &warpProfile{Kind: kind, WireGuard: w.options.WARPConfig, inline: true}
	}
	if kind == kindMASQUE {
		if profile := w.linkMASQUEProfile(); profile != nil { // a masque:// link's device, until Cloudflare refuses it
			return profile
		}
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
	var (
		profile *warpProfile
		invalid error
	)
	w.registering.Store(true)
	registered := w.retry(done, "register WARP "+kind+" device", func() error { // a cold detour fails the first attempts
		var err error
		profile, err = w.registerDevice(kind)
		if errors.As(err, new(invalidDeviceError)) {
			invalid = err // the API answered, with a device that cannot work: trying again does not help
			return nil
		}
		return err
	})
	w.registering.Store(false)
	if !registered {
		return nil
	}
	if invalid != nil {
		w.fail(E.Cause(invalid, "register WARP "+kind+" device"))
		return nil
	}
	w.recreated.Store(kind, struct{}{})
	w.profiles.add(profile)
	return profile
}

// hRegister registers a device of a kind.
type hRegister func(kind string) (*warpProfile, error)

// registerDevice is register, or what a test put in its place.
func (w *WARPEndpoint) registerDevice(kind string) (*warpProfile, error) {
	if w.registerWith != nil {
		return w.registerWith(kind)
	}
	return w.register(kind)
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
	if err = validateWARPConfig(&config, w.options.ServerOptions); err != nil { // before it is saved
		return nil, err
	}
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
			if best := w.pickTunnel(w.raceModes(done)); best != "" && best != w.activeMode() {
				w.restart("auto mode: " + best + " gets through")
				return
			}
		}
	}
}

// chooseMode gets the devices auto mode needs, races the tunnels, and draws one of those that
// answered by their rating on the network (pickTunnel). When none answers, it draws one of those
// that did not fail to connect yet, so the scanner and the port rotation can still look for a
// way. Empty when the start ends first. The network is named meanwhile, for the ratings.
func (w *WARPEndpoint) chooseMode(session *warpSession) string {
	done := session.done
	detected := w.detectNetwork(session.ctx)
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
	race := w.raceModes(done)
	select {
	case network, ok := <-detected:
		if ok && !w.publish(done, func() { session.network = &network }) {
			return ""
		}
	case <-done:
		return ""
	}
	if best := w.pickTunnel(race); best != "" {
		return best
	}
	select {
	case <-done:
		return ""
	default:
	}
	modes := []string{modeWireGuard, modeAWG}
	if masqueIncluded {
		modes = append(modes, modeMASQUE)
	}
	var left []string
	for _, mode := range modes {
		if !w.modeFailed(mode) {
			left = append(left, mode)
		}
	}
	if len(left) > 0 {
		mode := w.orderTunnels(left)[0]
		w.logger.WarnContext(w.ctx, "WARP auto mode: no tunnel answered, using ", mode, " (score ", w.tunnelScore(mode), ")")
		return mode
	}
	w.clearFailedModes() // each was tried: start over
	mode := w.orderTunnels(modes)[0]
	w.logger.WarnContext(w.ctx, "WARP auto mode: no tunnel connected, starting over with ", mode)
	return mode
}

// tunnelRace is the outcome of raceModes: the handshake time of each tunnel that answered, and
// the tunnels that did not.
type tunnelRace struct {
	answered map[string]time.Duration
	silent   []string
}

// pickTunnel draws one of the tunnels that answered race by their rating on the network (see
// h_tunnel_rating.go), and counts the silent ones as failed when another answered; empty when
// none answered.
func (w *WARPEndpoint) pickTunnel(race tunnelRace) string {
	if len(race.answered) == 0 {
		return ""
	}
	w.tunnelsFailed(race.silent...)
	answered := make([]string, 0, len(race.answered))
	for _, mode := range []string{modeWireGuard, modeAWG, modeMASQUE} {
		if _, ok := race.answered[mode]; ok {
			answered = append(answered, mode)
		}
	}
	best := w.orderTunnels(answered)[0]
	w.logger.InfoContext(w.ctx, "WARP auto mode: using ", best, " (", race.answered[best], ", score ", w.tunnelScore(best), "; answered: ", strings.Join(answered, ", "), ")")
	return best
}

// raceModes makes a handshake with each tunnel at once. A start that ends meanwhile gets no
// answers and no silent tunnels.
func (w *WARPEndpoint) raceModes(done <-chan struct{}) tunnelRace {
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
		return tunnelRace{}
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
	race := tunnelRace{answered: make(map[string]time.Duration)}
	for range probes {
		got := <-answers
		if got.rtt >= 0 {
			race.answered[got.mode] = got.rtt
		} else {
			race.silent = append(race.silent, got.mode)
		}
	}
	select {
	case <-done:
		return tunnelRace{}
	default:
	}
	return race
}
