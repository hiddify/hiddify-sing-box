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
	"github.com/sagernet/sing-box/common/monitoring"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
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
	config *C.WARPConfig
	book   *warpscan.Book
	probe  warpscan.Probe
	dialer N.Dialer // resolves domains, for network detection
	logger log.ContextLogger

	networkAccess sync.Mutex
	network       warpscan.NetworkInfo

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
func (w *WARPEndpoint) connect(config *C.WARPConfig) {
	peerAddr, peerPort, err := warpPeerEndpoint(config, w.options.ServerOptions) //H: a config without peers or ports crashed the process
	if err != nil {
		w.logger.ErrorContext(w.ctx, err)
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
	if !w.retry("WARP", func() error { // AmneziaWG fails its start when the detour does not work yet
		inner, err = w.newInner(config, peerAddr, peerPort)
		return err
	}) {
		return
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
	w.followDetour(config)
	if w.failover != nil {
		go w.watch()
	} else if w.options.ServerPort == 0 && len(config.Peers[0].Endpoint.Ports) > 1 {
		ports := make([]uint16, 0, len(config.Peers[0].Endpoint.Ports))
		current := 0
		for i, port := range config.Peers[0].Endpoint.Ports {
			ports = append(ports, uint16(port))
			if uint16(port) == peerPort {
				current = i
			}
		}
		go w.rotatePorts(config, peerAddr, ports, current)
	}
}

// replaceInner starts a new inner endpoint for the peer and closes the old one once it is in
// place, so dials keep working during the switch.
func (w *WARPEndpoint) replaceInner(config *C.WARPConfig, peerAddr string, peerPort uint16) error {
	w.replaceAccess.Lock()
	defer w.replaceAccess.Unlock()
	replacement, err := w.newInner(config, peerAddr, peerPort)
	if err != nil {
		select {
		case <-w.done:
			return nil // closed meanwhile: nothing to replace
		default:
		}
		return E.Cause(err, "WARP: replace endpoint")
	}
	select {
	case <-w.done:
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

// followDetour reconnects when a group detour moves to another member: the WireGuard socket
// stays on the member it was opened through, which the group may have left because it failed.
func (w *WARPEndpoint) followDetour(config *C.WARPConfig) {
	if w.options.Detour == "" {
		return
	}
	outboundManager := service.FromContext[adapter.OutboundManager](w.ctx)
	if outboundManager == nil {
		return
	}
	detour, loaded := outboundManager.Outbound(w.options.Detour)
	if !loaded {
		return
	}
	monitoring.FollowDetour(w.ctx, w.done, detour, N.NetworkUDP, func(from string, to string) {
		w.mtx.Lock()
		peerAddr, peerPort := w.peerAddr, w.peerPort
		w.mtx.Unlock()
		w.logger.InfoContext(w.ctx, "WARP: detour moved from ", from, " to ", to, ", reconnecting")
		if err := w.replaceInner(config, peerAddr, peerPort); err != nil {
			w.logger.ErrorContext(w.ctx, err)
		}
	})
}

// newInner creates and starts a WireGuard or AmneziaWG endpoint for the given peer.
func (w *WARPEndpoint) newInner(config *C.WARPConfig, peerAddr string, peerPort uint16) (adapter.Endpoint, error) {
	var (
		inner adapter.Endpoint
		err   error
	)
	if w.options.AWG != nil && w.options.AWG.IsAvailble() {
		inner, err = createWARPAwgEndpoint(w.ctx, w.router, w.logger, w.tag, w.options, config, peerAddr, peerPort, config.Peers[0].PublicKey)
	} else {
		inner, err = createWARPWireGuardEndpoint(w.ctx, w.router, w.logger, w.tag, w.options, config, peerAddr, peerPort, config.Peers[0].PublicKey)
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
	probe, err := warpscan.WireGuardProbe(probeDialer, config.PrivateKey, config.Peers[0].PublicKey, w.options.Noise)
	if err != nil {
		return nil, err
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
		config: config,
		book:   warpscan.Load(service.FromContext[adapter.CacheFile](w.ctx), w.uniqueID),
		probe:  probe,
		dialer: traceDialer,
		logger: w.logger,
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

// scan looks for endpoints on the current network, without exclude, and saves the scores.
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
	w.scanStatus.Scanning()
	results, err := warpscan.Scan(w.ctx, w.logger, warpscan.Request{
		Options:  w.options.Scanner,
		Defaults: defaults,
		IPv4:     network.IPv4,
		IPv6:     network.IPv6,
		Book:     failover.book,
		Network:  network.Name,
		Exclude:  exclude,
		Probe:    failover.probe,
	})
	w.saveScores()
	if err != nil {
		w.scanStatus.NotFound()
	} else {
		w.scanStatus.Found(results[0].AddrPort)
	}
	return results, err
}

func (w *WARPEndpoint) saveScores() {
	if err := warpscan.Save(service.FromContext[adapter.CacheFile](w.ctx), w.uniqueID, w.failover.book); err != nil {
		w.logger.WarnContext(w.ctx, "WARP scanner: save scores: ", err)
	}
}

// InterfaceUpdated passes the network change to the inner endpoint (which rebinds its socket)
// and checks the endpoint in use on the new network.
func (w *WARPEndpoint) InterfaceUpdated(ctx context.Context) {
	w.mtx.Lock()
	inner := w.endpoint
	w.mtx.Unlock()
	if listener, isListener := inner.(adapter.InterfaceUpdateListener); isListener {
		listener.InterfaceUpdated(ctx)
	}
	if w.failover == nil {
		return
	}
	go func() {
		select {
		case <-time.After(networkSettle):
		case <-w.done:
			return
		}
		w.failover.detectNetwork(w.ctx)
		w.check(true)
	}()
}

func (w *WARPEndpoint) watch() {
	ticker := time.NewTicker(failoverInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.check(false)
		}
	}
}

// check counts the first handshake of the endpoint in use as a success, and replaces the
// endpoint when it no longer answers: always checked after a network change, otherwise only
// when traffic goes out without a recent handshake.
func (w *WARPEndpoint) check(networkChanged bool) {
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
	for range probeAttempts {
		ctx, cancel := context.WithTimeout(w.ctx, 3*time.Second)
		rtt, err := failover.probe(ctx, failover.current)
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
	if err = w.replaceInner(failover.config, best.Addr().String(), best.Port()); err != nil {
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
