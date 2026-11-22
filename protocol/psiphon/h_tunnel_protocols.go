package psiphon

import (
	"context"
	"net/netip"
	"runtime"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// The tunnel core's own connections always go through an upstream proxy (the outbound's SOCKS
// bridge, see Start), which carries TCP only: the QUIC and in-proxy (WebRTC) protocols are left
// out by the core then. They are named, and in-proxy turned off, so the core does not spend its
// candidates on them.
var (
	// firstHopProtocols are tried when Psiphon is the first hop: every protocol that is not
	// in-proxy, the fork's CDN fronted ones included.
	firstHopProtocols = []string{
		"SSH",
		"OSSH",
		"TLS-OSSH",
		"UNFRONTED-MEEK-OSSH",
		"UNFRONTED-MEEK-HTTPS-OSSH",
		"UNFRONTED-MEEK-SESSION-TICKET-OSSH",
		"QUIC-OSSH",
		"SHADOWSOCKS-OSSH",
		"FRONTED-MEEK-OSSH",
		"FRONTED-MEEK-CDN-OSSH",
		"FRONTED-MEEK-HTTP-OSSH",
		"FRONTED-MEEK-CDN-HTTP-OSSH",
		"FRONTED-MEEK-QUIC-OSSH",
		"FRONTED-MEEK-CDN-QUIC-OSSH",
	}
	// chainedProtocols are tried behind another proxy: the TCP ones.
	chainedProtocols = []string{
		"SSH",
		"OSSH",
		"TLS-OSSH",
		"UNFRONTED-MEEK-OSSH",
		"UNFRONTED-MEEK-HTTPS-OSSH",
		"UNFRONTED-MEEK-SESSION-TICKET-OSSH",
		"SHADOWSOCKS-OSSH",
		"FRONTED-MEEK-OSSH",
		"FRONTED-MEEK-CDN-OSSH",
		"FRONTED-MEEK-HTTP-OSSH",
		"FRONTED-MEEK-CDN-HTTP-OSSH",
	}
)

// defaultClientPlatform names the system the way Psiphon's own clients do (it chooses tactics
// by it); the example app's name it had before told Psiphon nothing.
var defaultClientPlatform = func() string {
	switch runtime.GOOS {
	case "android":
		return "Android_hiddify"
	case "ios":
		return "iOS_hiddify"
	case "darwin":
		return "macOS_hiddify"
	case "windows":
		return "Windows_hiddify"
	default:
		return "Linux_hiddify"
	}
}()

// applyTunnelProtocols sets what the tunnel core tries, where config leaves it unset. As the
// first hop: every TCP and QUIC protocol, and the fork's CDN fronting scan of its built-in edges
// after the ones the scanner found. Behind another proxy, which already gets out: the TCP
// protocols, without tactics, whose requests only slow the start there.
func applyTunnelProtocols(config *psiphon.Config, options option.PsiphonOutboundOptions) {
	zero := 0.0
	if config.InproxyTunnelProtocolSelectionProbability == nil {
		config.InproxyTunnelProtocolSelectionProbability = &zero
	}
	if config.InproxyTunnelProtocolPreferProbability == nil {
		config.InproxyTunnelProtocolPreferProbability = &zero
	}
	if !scannerEnabled(options) {
		if len(config.LimitTunnelProtocols) == 0 {
			config.LimitTunnelProtocols = chainedProtocols
			config.DisableTactics = true
		}
		return
	}
	if len(config.LimitTunnelProtocols) == 0 {
		config.LimitTunnelProtocols = firstHopProtocols
	}
	config.FrontedMeekCDNScanUseBuiltInSpec = true
	if options.Scanner != nil && len(options.Scanner.Sets) > 0 {
		config.FrontedMeekCDNScanBuiltInSets = options.Scanner.Sets
	}
	// the core reports the edge it connected over in a diagnostic notice (see edgeScanner)
	config.EmitDiagnosticNotices = true
}

// scanEdges runs the scanner before the tunnel core starts, and puts the edges that answered
// first in the core's CDN fronting scan. The network it detected names the core's network too,
// so the core keeps what worked on each network apart, unless network_id fixes it.
func (h *Outbound) scanEdges() {
	if h.scanner == nil {
		return
	}
	h.scanner.beginAttempt()
	network, results, err := h.scanner.Scan()
	if !h.fixedNetworkID && network.Name != "" {
		h.psiphon.config.NetworkID = network.Name
	}
	// the protocols that came up on this network first, the others after them
	if first := h.scanner.firstProtocols(network.Name, h.psiphon.config.LimitTunnelProtocols); len(first) > 0 {
		h.psiphon.config.InitialLimitTunnelProtocols = first
		h.psiphon.config.InitialLimitTunnelProtocolsCandidateCount = preferredCandidates
	} else {
		h.psiphon.config.InitialLimitTunnelProtocols = nil
		h.psiphon.config.InitialLimitTunnelProtocolsCandidateCount = 0
	}
	if err != nil {
		h.logger.Warn(scannerName, ": ", err, "; Psiphon scans the built-in edges itself")
		h.psiphon.config.FrontedMeekDialOverrides = nil
		h.psiphon.config.FrontedMeekCDNScanUseBuiltInSpec = true
		return
	}
	overrides := frontingOverrides(results, h.scanner.candidates(), h.scanner.setOf)
	h.logger.Info(scannerName, ": ", len(results), " edges answered, best ", results[0].Target, " in ", results[0].RTT, ", ", len(overrides), " CDN routes for Psiphon")
	h.psiphon.config.FrontedMeekDialOverrides = overrides
	// The core numbers its CDN candidates across all its servers: with its own scan on, an
	// override is only tried by the first few dials, whatever server they are for, and the rest
	// go to the scan, which pairs every edge with every server. With it off, each server of a CDN
	// that answered cycles through that CDN's edges, and the scanner, round after round, does the
	// searching. Without an override, the core scans by itself.
	h.psiphon.config.FrontedMeekCDNScanUseBuiltInSpec = len(overrides) == 0
}

// useScanner gives the outbound its scanner: the first hop.
func (h *Outbound) useScanner() {
	h.scanner = newEdgeScanner(h.ctx, h.logger, h.dialer, h.options.Scanner, h.Tag(), h.options.Detour)
	h.psiphon.onInfo = h.scanner.onNotice
	if h.dnsRouter != nil {
		dnsRouter := h.dnsRouter
		h.scanner.resolve = func(ctx context.Context, name string) ([]netip.Addr, error) {
			return dnsRouter.Lookup(ctx, name, adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
		}
	}
}

// firstHopByDetour makes Psiphon the first hop when its detour is a direct outbound: the config is
// built again as for no detour (every protocol, the CDN scan), and the scanner runs.
func (h *Outbound) firstHopByDetour() error {
	options := h.options
	options.Detour = ""
	config, err := buildConfig(options, h.establishTimeout, h.Tag())
	if err != nil {
		return err
	}
	config.UpstreamProxyURL = h.psiphon.config.UpstreamProxyURL
	h.psiphon.config = config
	h.logger.Debug("psiphon: the detour is direct: the first hop")
	h.useScanner()
	return nil
}
