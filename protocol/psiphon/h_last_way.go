package psiphon

import (
	"slices"
	"strings"
	"time"

	"github.com/sagernet/sing-box/hiddify/edgescan"
)

// As the first hop, Psiphon remembers the way through that worked last (see edgescan.LastWay):
// the tunnel protocol of the tunnel that came up, the CDN edge it fronted through when the
// protocol is a fronted one, and the network. The first attempt of a search tries it first:
// the tunnel core starts at once, with that protocol first and a dial override for that edge,
// for at most lastWayAttempt, while the scanner names the network and scans the edges in the
// background. When the tunnel comes up, the outbound is ready, and the scan's scores serve the
// next attempts. When it does not, the attempt ends and the search goes on as before, with the
// scan that ran meanwhile. A working tunnel is not dropped for a better edge: the tunnel core
// takes it at its next connect.

const (
	lastWayKey  = edgescan.KindPsiphon
	wayProtocol = "protocol"
	// lastWayAttempt is how long the tunnel core has to come up with the last way
	lastWayAttempt = 30 * time.Second
)

// frontedProtocol reports whether protocol fronts through a CDN edge.
func frontedProtocol(protocol string) bool {
	return strings.Contains(protocol, "FRONTED")
}

// tryLastWay runs the first attempt of a search with the last way, and reports whether the tunnel
// came up; false also when there is none, or it is not the first attempt of the search.
func (h *Outbound) tryLastWay() bool {
	if h.scanner == nil || h.scanner.store == nil || !h.lastWayPending {
		return false
	}
	h.lastWayPending = false
	restore, ok := h.useLastWay()
	if !ok {
		return false
	}
	h.scanner.beginAttempt()
	go h.scanner.Scan() // names the network and scores the edges, for the tunnel and the next attempts
	if err := h.psiphon.Start(); err == nil {
		return true
	} else if h.ctx.Err() == nil {
		h.logger.Info(scannerName, ": the last way did not come up: ", err, "; searching")
	}
	h.psiphon.stop()
	restore()
	return false
}

// useLastWay sets the tunnel core up for the last way: its network, its protocol first, a dial
// override for its edge, and at most lastWayAttempt. restore sets back what the attempt changed.
func (h *Outbound) useLastWay() (restore func(), ok bool) {
	way, found := h.scanner.store.LastWay(lastWayKey)
	protocol := way.Method(wayProtocol)
	config := h.psiphon.config
	if !found || protocol == "" || (len(config.LimitTunnelProtocols) > 0 && !slices.Contains(config.LimitTunnelProtocols, protocol)) {
		return nil, false
	}
	networkID, timeout := config.NetworkID, config.EstablishTunnelTimeoutSeconds
	initial, initialCount := config.InitialLimitTunnelProtocols, config.InitialLimitTunnelProtocolsCandidateCount
	overrides, builtInCDNScan := config.FrontedMeekDialOverrides, config.FrontedMeekCDNScanUseBuiltInSpec
	restore = func() {
		config.NetworkID, config.EstablishTunnelTimeoutSeconds = networkID, timeout
		config.InitialLimitTunnelProtocols, config.InitialLimitTunnelProtocolsCandidateCount = initial, initialCount
		config.FrontedMeekDialOverrides, config.FrontedMeekCDNScanUseBuiltInSpec = overrides, builtInCDNScan
	}
	if !h.fixedNetworkID && way.Network != "" {
		config.NetworkID = way.Network
	}
	config.InitialLimitTunnelProtocols = []string{protocol}
	config.InitialLimitTunnelProtocolsCandidateCount = preferredCandidates
	config.FrontedMeekDialOverrides = nil
	if frontedProtocol(protocol) && way.Target.AddrPort.IsValid() {
		config.FrontedMeekDialOverrides = frontingOverrides([]edgescan.Result{{Target: way.Target}}, 1, h.scanner.setOf)
	}
	config.FrontedMeekCDNScanUseBuiltInSpec = len(config.FrontedMeekDialOverrides) == 0
	if attempt := durationToSecondsPtr(lastWayAttempt); timeout == nil || *timeout <= 0 || *attempt < *timeout {
		config.EstablishTunnelTimeoutSeconds = attempt
	}
	edge := "no edge"
	if len(config.FrontedMeekDialOverrides) > 0 {
		edge = way.Target.String()
	}
	h.logger.Info(scannerName, ": trying the last way first, ", protocol, " (", edge, "); scanning meanwhile")
	return restore, true
}

// beginAttempt forgets the edge of the last attempt: the way kept when a tunnel comes up names
// the edge of its own attempt.
func (s *edgeScanner) beginAttempt() {
	s.access.Lock()
	s.lastEdge = edgescan.Target{}
	s.access.Unlock()
}

// rememberWay keeps the way of a tunnel that came up with protocol.
func (s *edgeScanner) rememberWay(protocol string) {
	if s.store == nil {
		return
	}
	s.access.Lock()
	way := edgescan.LastWay{Network: s.network.Name, Methods: map[string]string{wayProtocol: protocol}}
	if frontedProtocol(protocol) {
		way.Target = s.lastEdge
	}
	s.access.Unlock()
	s.store.RememberWay(lastWayKey, way)
	s.save()
}
