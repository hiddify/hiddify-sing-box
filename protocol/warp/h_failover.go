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
func (w *WARPEndpoint) connect(done <-chan struct{}, config *C.WARPConfig) {
	peerAddr, peerPort, err := warpPeerEndpoint(config, w.options.ServerOptions) //H: a config without peers or ports crashed the process
	if err != nil {
		w.fail(err)
		return
	}
	var current netip.AddrPort
	if w.scannerEnabled() {
		failover, err := w.newFailover(config)
		if err != nil {
			w.logger.WarnContext(w.ctx, "WARP scanner: ", err)
		} else {
			w.failover = failover
			results, err := w.scan(nil)
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
	select {
	case <-done: // the start ended meanwhile
		adapter.CloseLate(w.scope, inner)
		return
	default:
	}
	w.mtx.Lock()
	w.endpoint = inner
	w.peerAddr, w.peerPort = peerAddr, peerPort
	if w.failover != nil {
		if !current.IsValid() {
			if address, err := netip.ParseAddr(peerAddr); err == nil {
				current = netip.AddrPortFrom(address, peerPort)
			}
		}
		w.failover.current = current
		w.failover.connectedAt = time.Now()
	}
	w.mtx.Unlock()
}

// replaceInner starts a new inner endpoint for the peer and closes the old one once it is in
// place, so dials keep working during the switch.
func (w *WARPEndpoint) replaceInner(done <-chan struct{}, config *C.WARPConfig, peerAddr string, peerPort uint16) error {
	w.replaceAccess.Lock()
	defer w.replaceAccess.Unlock()
	replacement, err := w.newInner(config, peerAddr, peerPort)
	if err != nil {
		select {
		case <-done:
			return nil // closed meanwhile: nothing to replace
		default:
		}
		return E.Cause(err, "WARP: replace endpoint")
	}
	select {
	case <-done:
		adapter.CloseLate(w.scope, replacement)
		return nil
	default:
	}
	w.mtx.Lock()
	old := w.endpoint
	w.endpoint = replacement
	w.peerAddr, w.peerPort = peerAddr, peerPort
	w.mtx.Unlock()
	adapter.CloseLate(w.scope, old)
	return nil
}

// newInner creates and starts a WireGuard or AmneziaWG endpoint for the given peer.
func (w *WARPEndpoint) newInner(config *C.WARPConfig, peerAddr string, peerPort uint16) (adapter.Endpoint, error) {
	var (
		inner adapter.Endpoint
		err   error
	)
	options := w.innerOptions() // with the noise the scanner found
	if w.activeMode() == modeAWG {
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

func (w *WARPEndpoint) newFailover(config *C.WARPConfig) (*warpFailover, error) {
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
	failover := &warpFailover{
		config:      config,
		book:        warpscan.Load(service.FromContext[adapter.CacheFile](w.ctx), w.uniqueID),
		probeDialer: probeDialer,
		dialer:      traceDialer,
		logger:      w.logger,
		probes:      make(map[string]warpscan.Probe),
	}
	failover.detectNetwork(w.ctx)
	return failover, nil
}

// detectNetwork names the network the box is on now (see warpscan.DetectNetwork).
func (f *warpFailover) detectNetwork(ctx context.Context) {
	network := warpscan.DetectNetwork(ctx, f.logger, f.dialer)
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
func (w *WARPEndpoint) innerOptions() option.WARPEndpointOptions {
	options := w.options
	if w.activeMode() != modeAWG {
		options.AWG = nil // the WireGuard endpoint refuses an awg block; auto mode has one
	}
	if w.failover == nil {
		return options
	}
	if preset, found := warpscan.NoisePresetByName(w.failover.currentNoise()); found {
		if w.activeMode() == modeAWG {
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

func (w *WARPEndpoint) probe(presetName string) (warpscan.Probe, error) {
	failover := w.failover
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

// noiseCandidates are the noises a scan tries on network, in order: with search_noise, the one
// that got through there before; the configured one; then the presets.
func (w *WARPEndpoint) noiseCandidates(networkName string) []string {
	scanner := w.options.Scanner
	if scanner == nil || !scanner.SearchNoise {
		return []string{""}
	}
	candidates := []string{w.failover.book.Noise(networkName), ""}
	presets := []string(scanner.NoisePresets)
	if len(presets) == 0 {
		for _, preset := range warpscan.NoisePresets {
			presets = append(presets, preset.Name)
		}
	}
	candidates = append(candidates, presets...)
	seen := make(map[string]bool)
	unique := candidates[:0]
	for _, candidate := range candidates {
		if !seen[candidate] {
			seen[candidate] = true
			unique = append(unique, candidate)
		}
	}
	return unique
}

// scan looks for endpoints on the current network, without exclude, and saves the scores. With
// search_noise, when none answers with the noise in use, it tries the others (noiseCandidates)
// and keeps the first that gets an answer; the next inner endpoint uses it.
func (w *WARPEndpoint) scan(exclude []netip.AddrPort) ([]warpscan.Result, error) {
	failover := w.failover
	defaults := warpscan.Defaults{CIDRs: warpscan.WireGuardCIDRs, Ports: warpscan.WireGuardPorts}
	if ports := failover.config.Peers[0].Endpoint.Ports; len(ports) > 0 {
		defaults.Ports = make([]uint16, 0, len(ports))
		for _, port := range ports {
			defaults.Ports = append(defaults.Ports, uint16(port))
		}
	}
	network := failover.currentNetwork()
	w.scanStatus.Begin()
	var lastErr error
	for i, noise := range w.noiseCandidates(network.Name) {
		probe, err := w.probe(noise)
		if err != nil {
			lastErr = err
			continue
		}
		options := *w.options.Scanner
		if i > 0 && (options.Count == 0 || options.Count > noiseSearchCount) {
			options.Count = noiseSearchCount
		}
		results, err := warpscan.Scan(w.ctx, w.logger, warpscan.Request{
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
			if w.ctx.Err() != nil {
				break
			}
			continue
		}
		failover.noiseAccess.Lock()
		changed := failover.noise != noise
		failover.noise = noise
		failover.noiseAccess.Unlock()
		if changed || failover.book.Noise(network.Name) != noise {
			failover.book.SetNoise(network.Name, noise)
			if noise != "" {
				w.logger.InfoContext(w.ctx, "WARP scanner: noise ", noise, " gets through")
			}
		}
		w.saveScores()
		w.scanStatus.Found(results[0].AddrPort)
		return results, nil
	}
	w.saveScores()
	w.scanStatus.NotFound()
	return nil, lastErr
}

func (w *WARPEndpoint) saveScores() {
	if err := warpscan.Save(service.FromContext[adapter.CacheFile](w.ctx), w.uniqueID, w.failover.book); err != nil {
		w.logger.WarnContext(w.ctx, "WARP scanner: save scores: ", err)
	}
}

// InterfaceUpdated passes the network change to the inner endpoint (which rebinds its socket)
// and checks the endpoint in use on the new network.
func (w *WARPEndpoint) InterfaceUpdated(ctx context.Context) {
	w.clearFailedModes() //H: auto mode: on a new network every tunnel may connect again
	w.mtx.Lock()
	inner := w.endpoint
	w.mtx.Unlock()
	if listener, isListener := inner.(adapter.InterfaceUpdateListener); isListener {
		listener.InterfaceUpdated(ctx)
	}
	if w.failover == nil {
		return
	}
	done := w.session()
	go func() {
		select {
		case <-time.After(networkSettle):
		case <-done:
			return
		}
		w.failover.detectNetwork(w.ctx)
		w.check(done, true)
	}()
}

func (w *WARPEndpoint) watch(done <-chan struct{}) {
	ticker := time.NewTicker(failoverInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.check(done, false)
		}
	}
}

// check counts the first handshake of the endpoint in use as a success, and replaces the
// endpoint when it no longer answers: always checked after a network change, otherwise only
// when traffic goes out without a recent handshake.
func (w *WARPEndpoint) check(done <-chan struct{}, networkChanged bool) {
	failover := w.failover
	if !failover.access.TryLock() {
		return
	}
	defer failover.access.Unlock()
	if pauseManager := service.FromContext[pause.Manager](w.ctx); pauseManager != nil && (pauseManager.IsDevicePaused() || pauseManager.IsNetworkPaused()) {
		return
	}
	w.mtx.Lock()
	inner := w.endpoint
	w.mtx.Unlock()
	if inner == nil || !failover.current.IsValid() {
		return
	}
	network := failover.currentNetwork().Name
	lastHandshake, tx := peerStatus(inner)
	if !failover.recorded && lastHandshake.After(failover.connectedAt) {
		failover.recorded = true
		failover.book.Success(network, failover.current, 0, time.Now())
		w.saveScores()
	}
	stuck := tx > failover.lastTx && (lastHandshake.IsZero() || time.Since(lastHandshake) > staleHandshake)
	failover.lastTx = tx
	if !networkChanged && !stuck {
		return
	}
	probe, err := w.probe(failover.currentNoise())
	if err != nil {
		w.logger.ErrorContext(w.ctx, err)
		return
	}
	for range probeAttempts {
		ctx, cancel := context.WithTimeout(w.ctx, 3*time.Second)
		rtt, err := probe(ctx, failover.current)
		cancel()
		if err == nil {
			failover.book.Success(network, failover.current, rtt, time.Now())
			w.saveScores()
			return
		}
		if w.ctx.Err() != nil {
			return
		}
	}
	w.logger.WarnContext(w.ctx, "WARP: endpoint ", failover.current, " does not answer, looking for another")
	failover.book.Failure(network, failover.current, time.Now())
	results, err := w.scan([]netip.AddrPort{failover.current})
	if err != nil {
		w.logger.WarnContext(w.ctx, err, ", keeping ", failover.current)
		return
	}
	best := results[0].AddrPort
	if err = w.replaceInner(done, failover.config, best.Addr().String(), best.Port()); err != nil {
		w.logger.ErrorContext(w.ctx, err)
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
