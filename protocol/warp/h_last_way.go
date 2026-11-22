package warp

import (
	"context"
	"slices"
	"time"

	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/hiddify/warpscan"
)

// With the scanner on, WARP remembers the way through that worked last (see edgescan.LastWay):
// the endpoint and the noise of each tunnel, and in auto mode the tunnel. The next start tries it
// first: auto mode takes the tunnel without racing, and the tunnel checks the endpoint with the
// noise in two handshakes, before the network is named or anything is scanned. When it answers,
// the endpoint connects at once, and is ready as soon as the handshake completes; the network is
// named and one scan round runs after, in the background, and WARP moves to an endpoint that is
// clearly better (see edgescan.Better). When it does not answer, the start searches as before, and
// auto mode races the tunnels.

// The keys of the ways in the store: one per tunnel (wayKey), and the tunnel of auto mode.
const autoWayKey = "warp/auto"

func wayKey(mode string) string { return "warp/" + mode }

// The methods of a way.
const (
	wayNoise  = "noise"
	wayTunnel = "tunnel"
)

// lastWay is the way through of mode that worked last, when the scanner can use it: its noise
// is one the scanner may try.
func (w *WARPEndpoint) lastWay(mode string) (edgescan.LastWay, bool) {
	way, found := w.scanStore().LastWay(wayKey(mode))
	if !found || !way.Target.AddrPort.IsValid() || !w.noiseAllowed(way.Method(wayNoise)) {
		return edgescan.LastWay{}, false
	}
	return way, true
}

// noiseAllowed reports whether the scanner may use noise: the configured noise, or with
// search_noise a preset of noise_presets.
func (w *WARPEndpoint) noiseAllowed(noise string) bool {
	if noise == "" {
		return true
	}
	scanner := w.options.Scanner
	if scanner == nil || !scanner.SearchNoise {
		return false
	}
	if len(scanner.NoisePresets) > 0 {
		return slices.Contains([]string(scanner.NoisePresets), noise)
	}
	_, found := warpscan.NoisePresetByName(noise)
	return found
}

// lastTunnel is the tunnel auto mode connected with last, unless it failed to connect on this
// network, or the race was asked for (see raceNext); empty for none.
func (w *WARPEndpoint) lastTunnel() string {
	if w.raceNext.Swap(false) {
		return ""
	}
	way, found := w.scanStore().LastWay(autoWayKey)
	if !found {
		return ""
	}
	tunnel := way.Method(wayTunnel)
	switch tunnel {
	case modeWireGuard, modeAWG:
	case modeMASQUE:
		if !masqueIncluded {
			return ""
		}
	default:
		return ""
	}
	if w.modeFailed(tunnel) {
		return ""
	}
	return tunnel
}

// rememberTunnel keeps mode as the tunnel auto mode connects with.
func (w *WARPEndpoint) rememberTunnel(mode string) {
	if w.mode != modeAuto || !w.scannerEnabled() {
		return
	}
	store := w.scanStore()
	store.RememberWay(autoWayKey, edgescan.LastWay{Network: w.tunnelNetwork(), Methods: map[string]string{wayTunnel: mode}})
	if err := store.Save(); err != nil {
		w.logger.WarnContext(w.ctx, "WARP scanner: save the last way: ", err)
	}
}

// rememberWay keeps the endpoint and the noise in use as the way through of the tunnel.
func (w *WARPEndpoint) rememberWay(failover *warpFailover) {
	if !failover.current.IsValid() {
		return
	}
	mode := w.activeMode()
	if mode == "" || mode == modeMASQUE {
		return
	}
	way := edgescan.LastWay{
		Network: failover.currentNetwork().Name,
		Target:  edgescan.Target{AddrPort: failover.current},
		Methods: map[string]string{wayNoise: failover.currentNoise()},
	}
	if failover.store != nil {
		failover.store.RememberWay(wayKey(mode), way)
	}
	w.saveScores(failover)
}

// tryLastWay checks the last way of the tunnel; on an answer it is put in use: the noise, for
// the inner endpoint the start creates. It returns the handshake time.
func (w *WARPEndpoint) tryLastWay(ctx context.Context, failover *warpFailover, way edgescan.LastWay) (time.Duration, bool) {
	noise := way.Method(wayNoise)
	probe, err := w.probe(failover, noise)
	if err != nil {
		return 0, false
	}
	rtt, err := edgescan.TryLastWay(ctx, probe, way.Target.AddrPort)
	if err != nil {
		w.logger.InfoContext(w.ctx, "WARP scanner: the last way, ", way.Target.AddrPort, " with noise ", noiseName(noise), ", does not answer: ", err, "; searching")
		return 0, false
	}
	failover.noiseAccess.Lock()
	failover.noise = noise
	failover.noiseAccess.Unlock()
	w.logger.InfoContext(w.ctx, "WARP scanner: the last way answers, ", way.Target.AddrPort, " with noise ", noiseName(noise), " (", rtt, "); connecting, and looking for a better one")
	return rtt, true
}

// nameNetwork names the network of failover when the start did not (it took the last way).
func (w *WARPEndpoint) nameNetwork(ctx context.Context, failover *warpFailover) {
	if failover.currentNetwork().Name != "" {
		return
	}
	failover.detectNetwork(ctx)
	detected := failover.currentNetwork()
	w.ratedNetwork.Store(&detected)
}

// searchBetter runs after a start that connected with the last way, which answered in rtt: it
// names the network, counts the answer there, and runs one scan round; WARP moves to an endpoint
// it found when it is clearly better (see edgescan.Better). The endpoint stays ready meanwhile:
// the round does not show as a search.
func (w *WARPEndpoint) searchBetter(session *warpSession, failover *warpFailover, rtt time.Duration) {
	w.nameNetwork(session.ctx, failover)
	if session.ctx.Err() != nil {
		return
	}
	failover.access.Lock() // no check meanwhile, and the check after it sees the endpoint in use
	defer failover.access.Unlock()
	network := failover.currentNetwork().Name
	current := failover.current
	if !current.IsValid() {
		return
	}
	failover.book.Success(network, current, rtt, time.Now()) // it answered at the start
	w.saveScores(failover)
	if _, reachable := edgescan.WaitReachable(session.ctx, w.logger); !reachable {
		return
	}
	results, noise, err := w.scanWith(session.ctx, failover, nil, false)
	if err != nil {
		if session.ctx.Err() == nil {
			w.logger.DebugContext(w.ctx, "WARP scanner: no better endpoint: ", err)
		}
		return
	}
	score, _ := failover.book.Score(network, current)
	for _, result := range results {
		if result.AddrPort == current && result.RTT > 0 {
			rtt = result.RTT // fresher than the start's
		}
	}
	best := results[0]
	if !edgescan.Better(best, current, score, rtt) {
		w.logger.DebugContext(w.ctx, "WARP scanner: ", current, " stays (score ", score, ", ", rtt, "; best found ", best.AddrPort, ", score ", best.Score, ", ", best.RTT, ")")
		return
	}
	previousNoise := failover.currentNoise()
	w.useNoise(failover, noise) // the replacement starts with the noise it answered with
	replaced, err := w.replaceInner(session.done, failover.config, best.AddrPort.Addr().String(), best.AddrPort.Port())
	if err != nil || !replaced {
		w.useNoise(failover, previousNoise) // the endpoint in use keeps its noise
		if err != nil {
			w.logger.ErrorContext(w.ctx, err)
		}
		return
	}
	failover.current = best.AddrPort
	failover.connectedAt = time.Now()
	failover.recorded = true // the scan counted its answer
	failover.lastTx = 0
	w.rememberWay(failover)
	w.logger.InfoContext(w.ctx, "WARP scanner: moved to a better endpoint, ", best.AddrPort, " (score ", best.Score, ", ", best.RTT, "; was ", current, ", score ", score, ", ", rtt, ")")
}
