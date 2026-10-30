package warp

import (
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// A group detour moves to another member either because the user selected it (a selector), or
// by itself (a URL test, a balancer). A move the user made applies at once: the tunnel is opened
// again through the new member, and in auto mode the tunnels race again. A move the group made
// by itself applies at most every detourSettle, at once when the member left had failed or WARP
// does not work: a new tunnel is opened through the new member next to the one in use, and
// replaces it only once it connects (switchInner).
const (
	detourSettle = 30 * time.Second
	// switchWait is how long the new tunnel of switchInner has to connect.
	switchWait = autoConfirmWait + raceTimeout
	switchPoll = 500 * time.Millisecond
)

// followDetourMoves follows a group detour for the current start.
func (w *WARPEndpoint) followDetourMoves(done <-chan struct{}) {
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
	network := N.NetworkUDP
	if w.activeMode() == modeMASQUE && w.options.MASQUE != nil && strings.EqualFold(w.options.MASQUE.VHTTP, "h2") {
		network = N.NetworkTCP
	}
	monitoring.FollowDetourSettled(w.ctx, done, detour, network, detourSettle, func() bool { return !adapter.IsReady(w) }, func(change monitoring.DetourChange) {
		moved := "the detour moved from " + change.From + " to " + change.To
		if change.Automatic {
			w.switchInner(done, moved)
			return
		}
		w.clearFailedModes() // the new path may carry a tunnel that failed on the old one
		w.mtx.Lock()
		inner, peerAddr, peerPort, profile := w.endpoint, w.peerAddr, w.peerPort, w.profile
		w.mtx.Unlock()
		if w.mode == modeAuto || w.activeMode() == modeMASQUE || inner == nil || profile == nil || profile.WireGuard == nil {
			w.restart(moved)
			return
		}
		w.logger.InfoContext(w.ctx, "WARP: ", moved, ", reconnecting")
		if err := w.replaceInner(done, profile.WireGuard, peerAddr, peerPort); err != nil {
			w.logger.ErrorContext(w.ctx, err)
		}
	})
}

// switchInner opens a new tunnel through the detour next to the one in use (in auto mode after a
// new race) and moves to it once it connects; the tunnel in use stays when it does not. When the
// tunnel in use does not work, it starts again instead.
func (w *WARPEndpoint) switchInner(done <-chan struct{}, reason string) {
	if w.mode == modeAuto {
		w.clearFailedModes()
	}
	if !adapter.IsReady(w) {
		w.restart(reason)
		return
	}
	w.logger.InfoContext(w.ctx, "WARP: ", reason, ", opening a new tunnel next to the one in use")
	candidate := w.newCandidate()
	go candidate.start()
	ticker := time.NewTicker(switchPoll)
	defer ticker.Stop()
	deadline := time.NewTimer(switchWait)
	defer deadline.Stop()
	for {
		select {
		case <-done:
			candidate.discard()
			return
		case <-deadline.C:
			candidate.discard()
			w.logger.WarnContext(w.ctx, "WARP: the new tunnel did not connect, keeping the one in use")
			return
		case <-ticker.C:
			if adapter.IsReady(candidate) {
				if err := w.adopt(candidate); err != nil {
					w.logger.WarnContext(w.ctx, err)
				}
				return
			}
		}
	}
}

// newCandidate is a WARP endpoint for switchInner: the same options, devices and scope, closed
// with this one; it runs one start, without following the detour or its health.
func (w *WARPEndpoint) newCandidate() *WARPEndpoint {
	return &WARPEndpoint{
		Adapter:   w.Adapter,
		scope:     w.scope,
		ctx:       w.ctx,
		router:    w.router,
		logger:    w.logger,
		tag:       w.tag,
		uniqueID:  w.uniqueID,
		options:   w.options,
		done:      w.done,
		mode:      w.mode,
		profiles:  w.profiles,
		candidate: true,
	}
}

// discard ends the start of a candidate and closes its tunnel.
func (w *WARPEndpoint) discard() {
	w.discarded.Store(true) // a start it began meanwhile ends at once
	w.endSession()
	w.replaceAccess.Lock()
	w.mtx.Lock()
	inner := w.endpoint
	w.endpoint = nil
	w.mtx.Unlock()
	w.replaceAccess.Unlock()
	if inner != nil {
		adapter.CloseLate(w.scope, inner)
	}
}

// adopt moves the connected tunnel of candidate into w, closes the one in use, and follows the
// detour and the health of the new one.
func (w *WARPEndpoint) adopt(candidate *WARPEndpoint) error {
	candidate.endSession() // its own checks stop; w runs them from now on
	candidate.replaceAccess.Lock()
	defer candidate.replaceAccess.Unlock()
	candidate.mtx.Lock()
	inner, peerAddr, peerPort := candidate.endpoint, candidate.peerAddr, candidate.peerPort
	failover, profile, scanStatusOf := candidate.failover, candidate.profile, candidate.scanStatusOf
	candidate.endpoint = nil
	candidate.mtx.Unlock()
	if inner == nil {
		return E.New("WARP: the new tunnel closed")
	}
	done := w.beginSession()
	select {
	case <-done: // closed meanwhile
		adapter.CloseLate(w.scope, inner)
		return nil
	default:
	}
	w.replaceAccess.Lock()
	w.mtx.Lock()
	old := w.endpoint
	w.endpoint = inner
	w.peerAddr, w.peerPort = peerAddr, peerPort
	w.failover, w.profile, w.scanStatusOf = failover, profile, scanStatusOf
	w.mtx.Unlock()
	w.replaceAccess.Unlock()
	if mode := candidate.activeMode(); w.mode == modeAuto {
		w.active.Store(mode)
	}
	if failover != nil && failover.current.IsValid() {
		w.scanStatus.Found(failover.current)
	}
	if old != nil {
		adapter.CloseLate(w.scope, old)
	}
	w.logger.InfoContext(w.ctx, "WARP: moved to the new tunnel (", w.activeMode(), ")")
	w.followDetourMoves(done)
	w.runChecks(done)
	return nil
}

// runChecks starts the checks of the tunnel in use: the scanner's failover or the port rotation
// (WireGuard and AmneziaWG), and the health of the device.
func (w *WARPEndpoint) runChecks(done <-chan struct{}) {
	w.mtx.Lock()
	failover, profile, peerAddr, peerPort := w.failover, w.profile, w.peerAddr, w.peerPort
	w.mtx.Unlock()
	switch {
	case w.activeMode() == modeMASQUE: // the MASQUE tunnel checks itself
	case failover != nil:
		go w.watch(done)
	case (w.options.RotatePorts == nil || *w.options.RotatePorts) && profile != nil && profile.WireGuard != nil && w.options.ServerPort == 0 && len(profile.WireGuard.Peers) > 0 && len(profile.WireGuard.Peers[0].Endpoint.Ports) > 1:
		config := profile.WireGuard
		ports := make([]uint16, 0, len(config.Peers[0].Endpoint.Ports))
		current := 0
		for i, port := range config.Peers[0].Endpoint.Ports {
			ports = append(ports, uint16(port))
			if uint16(port) == peerPort {
				current = i
			}
		}
		go w.rotatePorts(done, config, peerAddr, ports, current)
	}
	go w.watchHealth(done)
}
