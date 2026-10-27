package masque

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// scanMASQUEEndpoint finds a WARP MASQUE endpoint that completes the tunnel's handshake (QUIC,
// or TLS over TCP with HTTP/2), using and updating the endpoint scores of the current network
// (see warpscan.Book).
func scanMASQUEEndpoint(ctx context.Context, logger log.ContextLogger, key string, options option.MASQUEOutboundOptions, dialer N.Dialer, tlsConfig tls.Config) (net.Addr, error) {
	if options.UseHTTP2 {
		key += "/h2"
	}
	traceDialer, err := outboundDialerWithDomains(ctx, options) // the trace URLs are named by domain
	if err != nil {
		return nil, err
	}
	network := warpscan.DetectNetwork(ctx, logger, traceDialer)
	ipv4, ipv6 := network.IPv4, network.IPv6
	if options.UseIPv6 {
		ipv4, ipv6 = false, true
	}
	defaults := warpscan.Defaults{CIDRs: warpscan.MASQUEQUICCIDRs, Ports: warpscan.MASQUEPorts}
	if options.UseHTTP2 {
		defaults.CIDRs = warpscan.MASQUEHTTP2CIDRs
	}
	cacheFile := service.FromContext[adapter.CacheFile](ctx)
	book := warpscan.Load(cacheFile, key)
	results, err := warpscan.Scan(ctx, logger, warpscan.Request{
		Options:  options.Scanner,
		Defaults: defaults,
		IPv4:     ipv4,
		IPv6:     ipv6,
		Book:     book,
		Network:  network.Name,
		Probe:    warpscan.MASQUEProbe(dialer, tlsConfig, options.UseHTTP2),
	})
	if saveErr := warpscan.Save(cacheFile, key, book); saveErr != nil {
		logger.WarnContext(ctx, "WARP scanner: save scores: ", saveErr)
	}
	if err != nil {
		return nil, err
	}
	best := results[0]
	logger.InfoContext(ctx, "WARP scanner: using ", best.AddrPort, " (score ", best.Score, ", ", best.RTT, ")")
	if options.UseHTTP2 {
		return net.TCPAddrFromAddrPort(best.AddrPort), nil
	}
	return net.UDPAddrFromAddrPort(best.AddrPort), nil
}

func outboundDialerWithDomains(ctx context.Context, options option.MASQUEOutboundOptions) (N.Dialer, error) {
	return dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   true,
		ResolverOnDetour: true,
	})
}
