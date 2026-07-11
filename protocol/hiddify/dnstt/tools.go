package dnstt

import (
	"encoding/json"
	"fmt"
	"strings"

	_ "embed"

	dnstt "github.com/net2share/vaydns/client"
	"github.com/sagernet/sing-box/option"
)

var (
	//go:embed resolvers_by_country.json
	resolvers_bytes  []byte
	countryResolvers map[string][]string
	resolverCountry  map[string]string
)

func loadResolvers() {
	json.Unmarshal(resolvers_bytes, &countryResolvers)
	resolverCountry = make(map[string]string)
	for country, resolvers := range countryResolvers {
		for _, resolver := range resolvers {
			resolverCountry[resolver] = country
		}
	}
}

type ResolverS struct {
	Resolver dnstt.Resolver
	Auto     bool
}

func getConfigResolvers(options option.DnsttOptions) ([]ResolverS, error) {
	resolvers := []ResolverS{}
	for _, resolverAddr := range options.Resolvers {
		if resolverAddr == "" || resolverAddr == "auto" {
			for ip, _ := range resolverCountry {
				resolver, err := getResolver(options, fmt.Sprint(ip, ":53"))

				if err != nil {
					return nil, fmt.Errorf("invalid resolver address %s: %w", ip, err)
				}
				resolvers = append(resolvers, ResolverS{
					Resolver: resolver,
					Auto:     true,
				})
			}
			continue
		}
		resolver, err := getResolver(options, resolverAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid resolver address %s: %w", resolverAddr, err)
		}
		resolvers = append(resolvers, ResolverS{
			Resolver: resolver,
			Auto:     false,
		})

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
