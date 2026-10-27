package warp

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// scanWARPEndpoint finds a WARP endpoint that completes a WireGuard handshake with the profile's
// keys, trying the endpoints that answered last time first, and remembers the ones that answer.
// Probes go through the endpoint's own dialer, so detour and interface binding apply.
func scanWARPEndpoint(ctx context.Context, logger log.ContextLogger, key string, options option.WARPEndpointOptions, config *C.WARPConfig) (netip.AddrPort, error) {
	probeDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		ResolverOnDetour: true,
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	probe, err := warpscan.WireGuardProbe(probeDialer, config.PrivateKey, config.Peers[0].PublicKey, options.Noise)
	if err != nil {
		return netip.AddrPort{}, err
	}
	defaults := warpscan.Defaults{CIDRs: warpscan.WireGuardCIDRs, Ports: warpscan.WireGuardPorts}
	if ports := config.Peers[0].Endpoint.Ports; len(ports) > 0 {
		defaults.Ports = make([]uint16, 0, len(ports))
		for _, port := range ports {
			defaults.Ports = append(defaults.Ports, uint16(port))
		}
	}
	cacheFile := service.FromContext[adapter.CacheFile](ctx)
	results, err := warpscan.Scan(ctx, logger, options.Scanner, defaults, warpscan.Load(cacheFile, key), probe)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if err = warpscan.Save(cacheFile, key, warpscan.Kept(results)); err != nil {
		logger.WarnContext(ctx, "WARP scanner: save endpoints: ", err)
	}
	logger.InfoContext(ctx, "WARP scanner: using ", results[0].AddrPort, " (", results[0].RTT, ")")
	return results[0].AddrPort, nil
}
