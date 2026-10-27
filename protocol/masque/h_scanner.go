package masque

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// scanMASQUEEndpoint finds a WARP MASQUE endpoint that completes the tunnel's handshake (QUIC,
// or TLS over TCP with HTTP/2), trying the endpoints that answered last time first, and
// remembers the ones that answer.
func scanMASQUEEndpoint(ctx context.Context, logger log.ContextLogger, key string, options option.MASQUEOutboundOptions, dialer N.Dialer, tlsConfig tls.Config) (net.Addr, error) {
	defaults := warpscan.Defaults{CIDRs: warpscan.MASQUECIDRs, Ports: warpscan.MASQUEPorts}
	if options.UseIPv6 {
		defaults.CIDRs = warpscan.MASQUECIDRsIPv6
	}
	if options.UseHTTP2 {
		key += "/h2"
	}
	cacheFile := service.FromContext[adapter.CacheFile](ctx)
	probe := warpscan.MASQUEProbe(dialer, tlsConfig, options.UseHTTP2)
	results, err := warpscan.Scan(ctx, logger, options.Scanner, defaults, warpscan.Load(cacheFile, key), probe)
	if err != nil {
		return nil, err
	}
	if err = warpscan.Save(cacheFile, key, warpscan.Kept(results)); err != nil {
		logger.WarnContext(ctx, "WARP scanner: save endpoints: ", err)
	}
	best := results[0].AddrPort
	logger.InfoContext(ctx, "WARP scanner: using ", best, " (", results[0].RTT, ")")
	if options.UseHTTP2 {
		return net.TCPAddrFromAddrPort(best), nil
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(best.Addr(), best.Port())), nil
}
