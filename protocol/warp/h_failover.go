package warp

import (
	"bufio"
	"context"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/hiddify/rating"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/hiddify"
)

// With the scanner enabled, WARP keeps a score for each endpoint on each network (see
// warpscan.Book), connects to the best one that answers, and replaces the inner endpoint when the
// one in use stops working: after a network change, or when traffic goes out but no handshake
// completes for staleHandshake. The replacement is started before the old endpoint is closed.

const (
	failoverInterval = time.Minute
	staleHandshake   = 3 * time.Minute
	// networkSettle waits for the network environment to be updated after a change
	networkSettle = 2 * time.Second
	probeAttempts = 2
)

type warpFailover struct {
	config      *C.WARPConfig
	store       *edgescan.Store // shared with the other scanners on the network, see scanStore
	book        *warpscan.Book
	probeDialer N.Dialer
	dialer      N.Dialer // resolves domains, for network detection
	logger      log.ContextLogger

	networkAccess sync.Mutex
	network       warpscan.NetworkInfo

	noiseAccess sync.Mutex
	noise       string                    // the noise preset in use, empty for the configured noise
	probes      map[string]warpscan.Probe // by noise preset

	access      sync.Mutex // one check at a time
	current     netip.AddrPort
	connectedAt time.Time
	recorded    bool // the current endpoint's first handshake is counted
	lastTx      uint64
}

func (w *WARPEndpoint) scannerEnabled() bool {
	return w.options.Scanner != nil && w.options.Scanner.Enabled && w.options.Server == ""
}

// connect starts the first inner endpoint. Network work runs without w.mtx, which is taken
// only to publish the inner endpoint: a dial during the start must not wait for a scan.
func (w *WARPEndpoint) connect(session *warpSession, config *C.WARPConfig) {
	done := session.done
	peerAddr, peerPort, err := warpPeerEndpoint(config, w.options.ServerOptions) //H: a config without peers or ports crashed the process
	if err != nil {
		w.fail(err)
		return
	}
	var (
		current     netip.AddrPort
		failover    *warpFailover
		deepPending bool // a deep search from the start goes on once the endpoint runs
	)
	if w.scannerEnabled() {
		w.mtx.Lock()
		network := session.network // named by auto mode
		w.mtx.Unlock()
		failover, err = w.newFailover(session.ctx, config, network)
		if err != nil {
			failover = nil
			w.logger.WarnContext(w.ctx, "WARP scanner: ", err)
		} else {
			if !w.publish(done, func() { w.failover, session.failover = failover, failover }) {
				return
			}
			results, err := w.searchWithin(session.ctx, failover, nil, true, false)
			deepPending = err != nil && edgescan.ConfiguredDeep(searchOptions(w.options.Scanner))
			if err != nil {
				w.logger.WarnContext(w.ctx, err, ", using the profile's endpoint")
			} else {
				current = results[0].AddrPort
				peerAddr, peerPort = current.Addr().String(), current.Port()
				w.logger.InfoContext(w.ctx, "WARP scanner: using ", current, " (score ", results[0].Score, ", ", results[0].RTT, ")")
			}
		}
	}
	var inner adapter.Endpoint
	if !w.retry(done, "WARP", func() error { // AmneziaWG fails its start when the detour does not work yet
		inner, err = w.newInner(config, peerAddr, peerPort)
		return err
	}) {
		return
	}
	if !w.publish(done, func() {
		w.endpoint = inner
		w.peerAddr, w.peerPort = peerAddr, peerPort
		if failover != nil {
			if !current.IsValid() {
				if address, err := netip.ParseAddr(peerAddr); err == nil {
					current = netip.AddrPortFrom(address, peerPort)
				}
			}
			failover.current = current
			failover.connectedAt = time.Now()
		}
	}) {
		adapter.CloseLate(w.scope, inner) // the start ended meanwhile
		return
	}
	if deepPending {
		if err := w.StartDeepSearch(); err != nil {
			w.logger.WarnContext(w.ctx, err)
		}
	}
}

// replaceInner starts a new inner endpoint for the peer and closes the old one once it is in
// place, so dials keep working during the switch. It reports whether the endpoint was replaced:
// it is not, and that is no error, when the start that done belongs to ended meanwhile.
func (w *WARPEndpoint) replaceInner(done <-chan struct{}, config *C.WARPConfig, peerAddr string, peerPort uint16) (bool, error) {
	w.replaceAccess.Lock()
	defer w.replaceAccess.Unlock()
	replacement, err := w.newInner(config, peerAddr, peerPort)
	if err != nil {
		select {
		case <-done:
			return false, nil // closed meanwhile: nothing to replace
		default:
		}
		return false, E.Cause(err, "WARP: replace endpoint")
	}
	var old adapter.Endpoint
	if !w.publish(done, func() {
		old = w.endpoint
		w.endpoint = replacement
		w.peerAddr, w.peerPort = peerAddr, peerPort
	}) {
		adapter.CloseLate(w.scope, replacement)
		return false, nil
	}
	adapter.CloseLate(w.scope, old)
	return true, nil
}

// newInner creates and starts a WireGuard or AmneziaWG endpoint for the given peer.
func (w *WARPEndpoint) newInner(config *C.WARPConfig, peerAddr string, peerPort uint16) (adapter.Endpoint, error) {
	var (
		inner adapter.Endpoint
		err   error
	)
	mode := w.activeMode()          // read once: auto mode may choose another tunnel meanwhile, and the options are the tunnel's
	options := w.innerOptions(mode) // with the noise the scanner found
	if mode == modeAWG {
		inner, err = createWARPAwgEndpoint(w.ctx, w.router, w.logger, w.tag, options, config, peerAddr, peerPort, config.Peers[0].PublicKey)
	} else {
		inner, err = createWARPWireGuardEndpoint(w.ctx, w.router, w.logger, w.tag, options, config, peerAddr, peerPort, config.Peers[0].PublicKey)
	}
	if err != nil {
		return nil, err
	}
	// run every start stage: the WireGuard device is only created in StartStateInitialize,
	// so skipping it panics in Start (nil tun device); a failed start is closed again
	if err = adapter.StartLate(w.scope, "endpoint/"+inner.Type()+"["+w.tag+"]", inner); err != nil {
		return nil, E.Cause(err, "start WARP endpoint")
	}
	return inner, nil
}

// newFailover sets up the scanner of a start; network is the network auto mode named for it, nil
// to name it here.
func (w *WARPEndpoint) newFailover(ctx context.Context, config *C.WARPConfig, network *warpscan.NetworkInfo) (*warpFailover, error) {
	probeDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          w.ctx,
		Options:          w.options.DialerOptions,
		ResolverOnDetour: true,
	})
	if err != nil {
		return nil, err
	}
	if _, err = warpscan.WireGuardProbe(probeDialer, config.PrivateKey, config.Peers[0].PublicKey, w.options.Noise); err != nil {
		return nil, err // the keys are checked once here
	}
	traceDialer, err := dialer.NewWithOptions(dialer.Options{ // the trace URLs are named by domain
		Context:          w.ctx,
		Options:          w.options.DialerOptions,
		RemoteIsDomain:   true,
		ResolverOnDetour: true,
	})
	if err != nil {
		return nil, err
	}
	store := w.scanStore()
	failover := &warpFailover{
		config:      config,
		store:       store,
		book:        store.Book(edgescan.KindWARP),
		probeDialer: probeDialer,
		dialer:      traceDialer,
		logger:      w.logger,
		probes:      make(map[string]warpscan.Probe),
	}
	if network != nil {
		failover.network = *network
	} else {
		failover.detectNetwork(ctx)
		detected := failover.currentNetwork()
		w.ratedNetwork.Store(&detected)
	}
	return failover, nil
}

// detectNetwork names the network the box is on now (see warpscan.DetectNetwork).
func (f *warpFailover) detectNetwork(ctx context.Context) {
	var network warpscan.NetworkInfo
	if f.store != nil {
		network = f.store.Network(ctx, f.logger, f.dialer)
	} else {
		network = warpscan.DetectNetwork(ctx, f.logger, f.dialer)
	}
	f.networkAccess.Lock()
	f.network = network
	f.networkAccess.Unlock()
}

func (f *warpFailover) currentNetwork() warpscan.NetworkInfo {
	f.networkAccess.Lock()
	defer f.networkAccess.Unlock()
	return f.network
}

// noiseSearchCount is the most endpoints one noise preset is tried on: the endpoints known to
// answer come first, so a few are enough to tell whether the noise gets through.
const noiseSearchCount = 16

// innerOptions are the endpoint's options with the noise in use: a preset the scanner found
// replaces the noise (WireGuard) or the junk and special packets (AmneziaWG).
func (w *WARPEndpoint) innerOptions(mode string) option.WARPEndpointOptions {
	options := w.options
	if mode != modeAWG {
		options.AWG = nil // the WireGuard endpoint refuses an awg block; auto mode has one
	}
	failover := w.currentFailover()
	if failover == nil {
		return options
	}
	if preset, found := warpscan.NoisePresetByName(failover.currentNoise()); found {
		if mode == modeAWG {
			options.AWG = preset.AWG(options.AWG)
		} else {
			options.Noise = preset.WireGuard()
		}
	}
	return options
}

// probeNoise is what the device sends before a handshake with the noise preset (empty for the
// configured noise), for the probe: the WireGuard noise, or AmneziaWG's special and junk packets.
func (w *WARPEndpoint) probeNoise(presetName string) hiddify.NoiseOptions {
	preset, isPreset := warpscan.NoisePresetByName(presetName)
	if w.activeMode() == modeAWG {
		awg := w.options.AWG
		if isPreset {
			awg = preset.AWG(awg)
		}
		return warpscan.AWGProbeNoise(awg)
	}
	if isPreset {
		return preset.WireGuard()
	}
	return w.options.Noise
}

func (w *WARPEndpoint) probe(failover *warpFailover, presetName string) (warpscan.Probe, error) {
	failover.noiseAccess.Lock()
	defer failover.noiseAccess.Unlock()
	if probe, loaded := failover.probes[presetName]; loaded {
		return probe, nil
	}
	probe, err := warpscan.WireGuardProbe(failover.probeDialer, failover.config.PrivateKey, failover.config.Peers[0].PublicKey, w.probeNoise(presetName))
	if err != nil {
		return nil, err
	}
	failover.probes[presetName] = probe
	return probe, nil
}

func (f *warpFailover) currentNoise() string {
	f.noiseAccess.Lock()
	defer f.noiseAccess.Unlock()
	return f.noise
}

// configuredNoisePrior is the score the configured noise counts as on a network where it was
// never tried: the user chose it, so it comes first more often than an untried preset.
const configuredNoisePrior rating.Score = 2

// noiseCandidates are the noises a scan tries on network (the configured one, then the presets of
// noise_presets), in a weighted random order by their score there (see warpscan.Book.OrderMethods):
// the noise that gets through most is tried first most of the time, and the others now and then,
// so a noise that stopped working is replaced, and one that works again is found. Without
// search_noise, the configured noise alone.
func (w *WARPEndpoint) noiseCandidates(failover *warpFailover, networkName string) []string {
	scanner := w.options.Scanner
	if scanner == nil || !scanner.SearchNoise {
		return []string{""}
	}
	presets := []string(scanner.NoisePresets)
	if len(presets) == 0 {
		for _, preset := range warpscan.NoisePresets {
			presets = append(presets, preset.Name)
		}
	}
	byMethod := map[string]string{warpscan.NoiseMethod(""): ""}
	methods := []string{warpscan.NoiseMethod("")}
	for _, preset := range presets {
		if _, isWireGuard := warpscan.NoisePresetByName(preset); !isWireGuard {
			continue // a MASQUE noise (a server name), for the MASQUE tunnel
		}
		method := warpscan.NoiseMethod(preset)
		if _, seen := byMethod[method]; !seen {
			byMethod[method] = preset
			methods = append(methods, method)
		}
	}
	ordered := failover.book.OrderMethods(networkName, methods, func(method string) rating.Score {
		if method == warpscan.NoiseMethod("") {
			return configuredNoisePrior
		}
		return 0
	})
	candidates := make([]string, len(ordered))
	for i, method := range ordered {
		candidates[i] = byMethod[method]
	}
	return candidates
}

// noiseCount is the most endpoints a scan with the i-th noise of candidates probes: the full count
// for the first when it got through on the network before, or when none did yet (the first scan
// there); noiseSearchCount for the others, as the endpoints known to answer come first.
func noiseCount(book *warpscan.Book, networkName string, candidates []string, i int, count int) int {
	if count > 0 && count <= noiseSearchCount {
		return count
	}
	if i == 0 {
		if score, _ := book.MethodScore(networkName, warpscan.NoiseMethod(candidates[0])); score > 0 {
			return count
		}
		known := false
		for _, candidate := range candidates {
			if score, _ := book.MethodScore(networkName, warpscan.NoiseMethod(candidate)); score > 0 {
				known = true
				break
			}
		}
		if !known {
			return count
		}
	}
	return noiseSearchCount
}

// scan looks for endpoints on the current network, without exclude, with the failover in use, in
// one round.
func (w *WARPEndpoint) scan(exclude []netip.AddrPort) ([]warpscan.Result, error) {
	failover := w.currentFailover()
	if failover == nil {
		return nil, errNoFailover
	}
	results, noise, err := w.scanWith(w.ctx, failover, exclude, false)
	if err == nil {
		w.useNoise(failover, noise)
	}
	return results, err
}

// scanWith looks for endpoints on the current network, without exclude, and saves the scores.
// With search_noise, it tries the noises in the order of noiseCandidates and keeps the first that
// gets an answer; the next inner endpoint uses it. That noise gains a point on the network, and
// the ones tried before it lose one; when no noise gets through, none is marked down.
// It works on failover to the end: a restart clears the endpoint's while a scan of the start that
// ends still runs. ctx is the session's: the scan of a start that ended stops, where it went on
// for as long as its probes took.
// It returns the noise that got through; the caller puts it in use (see search).
func (w *WARPEndpoint) scanWith(ctx context.Context, failover *warpFailover, exclude []netip.AddrPort, deep bool) ([]warpscan.Result, string, error) {
	defaults := warpscan.Defaults{CIDRs: warpscan.WireGuardCIDRs, Ports: warpscan.WireGuardPorts}
	if ports := failover.config.Peers[0].Endpoint.Ports; len(ports) > 0 {
		defaults.Ports = make([]uint16, 0, len(ports))
		for _, port := range ports {
			defaults.Ports = append(defaults.Ports, uint16(port))
		}
	}
	network := failover.currentNetwork()
	var (
		lastErr error
		failed  []string // the noises no endpoint answered
	)
	candidates := w.noiseCandidates(failover, network.Name)
	for i, noise := range candidates {
		probe, err := w.probe(failover, noise)
		if err != nil {
			lastErr = err
			continue
		}
		options := *w.options.Scanner
		if len(candidates) > 1 {
			options.Count = noiseCount(failover.book, network.Name, candidates, i, options.Count)
		}
		results, err := warpscan.Scan(ctx, w.logger, warpscan.Request{
			Deep:     deep,
			Options:  &options,
			Defaults: defaults,
			IPv4:     network.IPv4,
			IPv6:     network.IPv6,
			Book:     failover.book,
			Network:  network.Name,
			Exclude:  exclude,
			Probe:    probe,
		})
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			failed = append(failed, warpscan.NoiseMethod(noise))
			continue
		}
		if len(candidates) > 1 {
			failover.book.SettleMethods(network.Name, warpscan.NoiseMethod(noise), failed, time.Now())
		}
		w.saveScores(failover)
		return results, noise, nil
	}
	w.saveScores(failover)
	return nil, "", lastErr
}

// useNoise puts noise in use for the next inner endpoint.
func (w *WARPEndpoint) useNoise(failover *warpFailover, noise string) {
	failover.noiseAccess.Lock()
	changed := failover.noise != noise
	failover.noise = noise
	failover.noiseAccess.Unlock()
	if changed {
		score, _ := failover.book.MethodScore(failover.currentNetwork().Name, warpscan.NoiseMethod(noise))
		w.logger.InfoContext(w.ctx, "WARP scanner: noise ", noiseName(noise), " gets through (score ", score, ")")
	}
}

// noiseName names a noise of noiseCandidates for the log.
func noiseName(noise string) string {
	if noise == "" {
		return "configured"
	}
	return noise
}

// currentFailover is the scanner's failover of the start in use, or nil: a restart clears it, so
// a check reads it once and keeps it.
func (w *WARPEndpoint) currentFailover() *warpFailover {
	w.mtx.Lock()
	defer w.mtx.Unlock()
	return w.failover
}

var errNoFailover = E.New("WARP scanner: not set up")

func (w *WARPEndpoint) saveScores(failover *warpFailover) {
	if failover.store == nil {
		return
	}
	if err := failover.store.Save(); err != nil {
		w.logger.WarnContext(w.ctx, "WARP scanner: save scores: ", err)
	}
}

// InterfaceUpdated passes the network change to the inner endpoint (which rebinds its socket)
// and checks the endpoint in use on the new network.
func (w *WARPEndpoint) InterfaceUpdated(ctx context.Context) {
	w.clearFailedModes()      //H: auto mode: on a new network every tunnel may connect again
	w.ratedNetwork.Store(nil) // the tunnel ratings wait for the new network's name
	w.mtx.Lock()
	inner := w.endpoint
	w.mtx.Unlock()
	if listener, isListener := inner.(adapter.InterfaceUpdateListener); isListener {
		listener.InterfaceUpdated(ctx)
	}
	session := w.session()
	w.mtx.Lock()
	failover := session.failover
	w.mtx.Unlock()
	if failover == nil {
		return
	}
	go func() {
		select {
		case <-time.After(networkSettle):
		case <-session.done:
			return
		}
		if failover.store != nil {
			failover.store.NetworkChanged()
		}
		failover.detectNetwork(session.ctx)
		detected := failover.currentNetwork()
		w.ratedNetwork.Store(&detected)
		w.check(session, true)
	}()
}

func (w *WARPEndpoint) watch(session *warpSession) {
	ticker := time.NewTicker(failoverInterval)
	defer ticker.Stop()
	for {
		select {
		case <-session.done:
			return
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.check(session, false)
		}
	}
}

// check counts the first handshake of the endpoint in use as a success, and replaces the
// endpoint when it no longer answers: always checked after a network change, otherwise only
// when traffic goes out without a recent handshake. It works for session, with its failover:
// the endpoint's may be another start's by now.
func (w *WARPEndpoint) check(session *warpSession, networkChanged bool) {
	w.mtx.Lock()
	failover := session.failover
	w.mtx.Unlock()
	if failover == nil { // a start without the scanner
		return
	}
	if !failover.access.TryLock() {
		return
	}
	defer failover.access.Unlock()
	if pauseManager := service.FromContext[pause.Manager](w.ctx); pauseManager != nil && (pauseManager.IsDevicePaused() || pauseManager.IsNetworkPaused()) {
		return
	}
	var inner adapter.Endpoint
	if !w.publish(session.done, func() { inner = w.endpoint }) { // the start ended: the endpoint is not its
		return
	}
	if inner == nil || !failover.current.IsValid() {
		return
	}
	network := failover.currentNetwork().Name
	lastHandshake, tx := peerStatus(inner)
	if !failover.recorded && lastHandshake.After(failover.connectedAt) {
		failover.recorded = true
		failover.book.Success(network, failover.current, 0, time.Now())
		w.saveScores(failover)
	}
	stuck := tx > failover.lastTx && (lastHandshake.IsZero() || time.Since(lastHandshake) > staleHandshake)
	failover.lastTx = tx
	if !networkChanged && !stuck {
		return
	}
	probe, err := w.probe(failover, failover.currentNoise())
	if err != nil {
		w.logger.ErrorContext(w.ctx, err)
		return
	}
	for range probeAttempts {
		ctx, cancel := context.WithTimeout(session.ctx, 3*time.Second)
		rtt, err := probe(ctx, failover.current)
		cancel()
		if err == nil {
			failover.book.Success(network, failover.current, rtt, time.Now())
			w.saveScores(failover)
			return
		}
		if session.ctx.Err() != nil {
			return
		}
	}
	w.logger.WarnContext(w.ctx, "WARP: endpoint ", failover.current, " does not answer, looking for another")
	results, err := w.search(session.ctx, failover, []netip.AddrPort{failover.current})
	if err != nil {
		// no endpoint answers: the network is down, not the endpoint in use
		w.logger.WarnContext(w.ctx, err, ", keeping ", failover.current)
		return
	}
	failover.book.Failure(network, failover.current, time.Now()) // another answers: this one is the problem
	w.saveScores(failover)
	best := results[0].AddrPort
	replaced, err := w.replaceInner(session.done, failover.config, best.Addr().String(), best.Port())
	if err != nil {
		w.logger.ErrorContext(w.ctx, err)
		return
	}
	if !replaced { // the start ended while it scanned: the endpoint in use is the next start's
		return
	}
	failover.current = best
	failover.connectedAt = time.Now()
	failover.recorded = true // the scan counted its answer
	failover.lastTx = 0
	w.logger.InfoContext(w.ctx, "WARP: switched to ", best, " (score ", results[0].Score, ", ", results[0].RTT, ")")
}

// peerStatus reads the latest handshake and the bytes sent from the inner device.
func peerStatus(inner adapter.Endpoint) (lastHandshake time.Time, tx uint64) {
	getter, isGetter := inner.(interface{ IpcGet() (string, error) })
	if !isGetter {
		return
	}
	status, err := getter.IpcGet()
	if err != nil {
		return
	}
	var seconds, nanoseconds int64
	scanner := bufio.NewScanner(strings.NewReader(status))
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		switch key {
		case "last_handshake_time_sec":
			seconds, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nanoseconds, _ = strconv.ParseInt(value, 10, 64)
		case "tx_bytes":
			bytes, _ := strconv.ParseUint(value, 10, 64)
			tx += bytes
		}
	}
	if seconds > 0 || nanoseconds > 0 {
		lastHandshake = time.Unix(seconds, nanoseconds)
	}
	return
}
