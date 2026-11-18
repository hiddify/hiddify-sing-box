package warp

import (
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// detourReadyWait is how long a start waits for a detour that is connecting, and detourReadyPoll
// how often it looks. A variable for the tests.
var (
	detourReadyWait = 30 * time.Second
	detourReadyPoll = 250 * time.Millisecond
)

// Everything a start does goes through the detour: naming the network, the race of auto mode, the
// scanner, the handshakes. When the detour is not carrying traffic yet (warp in warp starts the
// inner WARP together with this one, and the inner one is still choosing its tunnel), each of
// them failed at once: the network was named by its interface alone, and the ratings and scores
// went under that name, auto mode drew its tunnel without a race ("no tunnel answered"), the
// scanner found nothing, and confirmAuto then blamed the tunnel. So a start first waits for the
// detour (waitDetour), and the checks that blame a tunnel or a port leave it alone while the
// detour is down (detourReady).

// detourNetwork is the network the tunnel uses the detour for: UDP, but TCP for MASQUE over
// HTTP/2.
func (w *WARPEndpoint) detourNetwork() string {
	mode := w.mode
	if mode == modeAuto {
		mode = w.activeMode()
	}
	if mode == modeMASQUE && w.options.MASQUE != nil && strings.EqualFold(w.options.MASQUE.VHTTP, "h2") {
		return N.NetworkTCP
	}
	return N.NetworkUDP
}

// detourPath is the detour and, through its groups, the outbound that carries the traffic now;
// nil without a detour or when it is not known.
func (w *WARPEndpoint) detourPath() []adapter.Outbound {
	if w.options.Detour == "" {
		return nil
	}
	manager := service.FromContext[adapter.OutboundManager](w.ctx)
	if manager == nil {
		return nil
	}
	detour, loaded := manager.Outbound(w.options.Detour)
	if !loaded {
		return nil
	}
	return adapter.GroupPath(detour, w.detourNetwork())
}

// detourReady reports whether the detour carries traffic now; true without one. A lazy detour at
// rest counts as ready: the first dial creates it.
func (w *WARPEndpoint) detourReady() bool {
	status, _ := adapter.PathStatus(w.detourPath())
	return status == adapter.StatusReady
}

// waitDetour waits until the detour carries traffic. A lazy outbound on the way is held meanwhile,
// so it is created and connects now instead of at the first dial, which would fail. While the
// detour registers or searches (adapter.IsWarming: a WARP getting its device or choosing its
// tunnel), nothing can get through it, however long that takes, so there is no limit: a WARP
// registration took 33 s on a real start, and racing through it then lost the race again. Time
// spent connecting counts up to detourReadyWait: a detour that does not become ready by itself (a
// proxy that connects only at its first connection) is dialed through as it is. It stops waiting
// when the detour failed or is not known. It reports false when the start ended.
func (w *WARPEndpoint) waitDetour(done <-chan struct{}) bool {
	if w.options.Detour == "" {
		return !ended(done)
	}
	held := make(map[string]func())
	defer func() {
		for _, release := range held {
			release()
		}
	}()
	defer w.waitingDetour.Store(nil)
	ticker := time.NewTicker(detourReadyPoll)
	defer ticker.Stop()
	var waiting adapter.Outbound
	var connecting time.Duration // time the detour spent not warming and not ready
	for {
		if ended(done) {
			return false
		}
		path := w.detourPath() // again each time: a group may move, and a reload replaces outbounds
		for _, outbound := range path {
			lazy, isLazy := outbound.(adapter.HeldLazy)
			if !isLazy || held[outbound.Tag()] != nil {
				continue
			}
			if _, release, err := lazy.Hold(); err == nil {
				held[outbound.Tag()] = release
			}
		}
		status, notReady := adapter.PathStatus(path)
		switch status {
		case adapter.StatusReady:
			if waiting != nil {
				w.logger.InfoContext(w.ctx, "WARP: detour ", waiting.Tag(), " is ready")
			}
			return true
		case adapter.StatusFailed:
			w.logger.WarnContext(w.ctx, "WARP: detour ", notReady.Tag(), " failed, connecting through it anyway")
			return true
		}
		if waiting == nil || waiting.Tag() != notReady.Tag() {
			w.logger.InfoContext(w.ctx, "WARP: waiting for detour ", notReady.Tag(), " (", status, ")")
			tag := notReady.Tag()
			w.waitingDetour.Store(&tag)
		}
		waiting = notReady
		if !adapter.IsWarming(status) {
			if connecting >= detourReadyWait {
				w.logger.WarnContext(w.ctx, "WARP: detour ", notReady.Tag(), " is still ", status, " after ", detourReadyWait, ", connecting through it anyway")
				return true
			}
			connecting += detourReadyPoll
		}
		select {
		case <-done:
			return false
		case <-ticker.C:
		}
	}
}

func ended(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}
