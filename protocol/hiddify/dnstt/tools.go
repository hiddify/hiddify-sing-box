package dnstt

import (
	"fmt"
	"strings"

	dnstt "github.com/net2share/vaydns/client"
	"github.com/sagernet/sing-box/common/dnspool"
	"github.com/sagernet/sing-box/option"
)

type ResolverS struct {
	Resolver dnstt.Resolver
	Auto     bool
	Tier     int
}

// getConfigResolvers turns the resolver entries into VayDNS resolvers; "auto" is the built-in
// list shared by the DNS tunnels (common/dnspool), Soar's discovery candidates for
// smart_pool.discovery first.
func getConfigResolvers(options option.DnsttOptions) ([]ResolverS, error) {
	resolvers := []ResolverS{}
	for _, candidate := range dnspool.ExpandWith(options.Resolvers, options.SmartPool.DiscoveryOptions()) {
		resolver, err := getResolver(options, candidate.Address)
		if err != nil {
			return nil, fmt.Errorf("invalid resolver address %s: %w", candidate.Address, err)
		}
		resolvers = append(resolvers, ResolverS{Resolver: resolver, Auto: candidate.Auto, Tier: candidate.Tier})
	}
	return resolvers, nil
}
func getResolver(options option.DnsttOptions, s string) (dnstt.Resolver, error) {
	var resolver dnstt.Resolver
	var err error
	if _, ok := strings.CutPrefix(s, "https://"); ok {
		resolver, err = dnstt.NewResolver(dnstt.ResolverTypeDOH, s)
	} else if dot, ok := strings.CutPrefix(s, "dot://"); ok {
		resolver, err = dnstt.NewResolver(dnstt.ResolverTypeDOT, dot)
	} else {
		resolver, err = dnstt.NewResolver(dnstt.ResolverTypeUDP, s)
	}
	if err != nil {
		return resolver, err
	}
	resolver.UDPAcceptErrors = options.UdpAcceptErrors
	resolver.UDPSharedSocket = options.UdpSharedSocket
	if options.UdpTimeout != nil {
		resolver.UDPTimeout = options.UdpTimeout.Build()
	}
	if options.UdpWorkers != nil {
		resolver.UDPWorkers = *options.UdpWorkers
	}
	if options.UTLSClientHelloID != "" {
		resolver.UTLSClientHelloID = dnstt.UTLSLookup(options.UTLSClientHelloID)
	}
	return resolver, nil
}
