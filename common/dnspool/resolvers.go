// Package dnspool is what the DNS tunnel outbounds share: the built-in list of public resolvers,
// the saved score of each resolver, a plain DNS probe that tells whether a resolver answers, and
// the resolver pool (github.com/hiddify/hmrd_multi_resolver_dns) each outbound runs for itself
// to spread its queries over many resolvers. The dnstt, masterdns and soar outbounds are built on it,
// so every DNS tunnel has the same resolver handling and the same smart_pool options.
package dnspool

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"

	"github.com/getlantern/soar"
	"github.com/sagernet/sing-box/option"
)

//go:embed resolvers_by_country.json
var builtinResolversJSON []byte

var (
	loadBuiltin = sync.OnceFunc(func() {
		_ = json.Unmarshal(builtinResolversJSON, &countryResolvers)
		resolverCountry = make(map[string]string)
		for country, resolvers := range countryResolvers {
			for _, resolver := range resolvers {
				resolverCountry[resolver] = country
			}
		}
	})
	countryResolvers map[string][]string
	resolverCountry  map[string]string
)

// AutoResolver is the resolver entry that stands for the built-in list; an empty entry means
// the same.
const AutoResolver = "auto"

// BuiltinResolvers returns the built-in public resolvers by IP, with the country of each. The
// list is loaded once, on first use.
func BuiltinResolvers() map[string]string {
	loadBuiltin()
	return resolverCountry
}

// BuiltinResolversByCountry returns the built-in public resolvers grouped by country code.
func BuiltinResolversByCountry() map[string][]string {
	loadBuiltin()
	return countryResolvers
}

// Country returns the country code of a built-in resolver IP, or "".
func Country(ip string) string {
	loadBuiltin()
	return resolverCountry[ip]
}

// The tiers of "auto" candidates, the order History.Sort keeps among equal scores: the
// candidates of Soar's discovery, then the built-in list.
const (
	TierDiscovery = iota
	TierBuiltin
)

// Candidate is one resolver an outbound may use: the address as the pool and the probe read it
// ("1.1.1.1:53", "dot://1.1.1.1:853", "https://dns.google/dns-query"), whether it came from
// "auto", and for those, its tier.
type Candidate struct {
	Address string
	Auto    bool
	Tier    int
}

// Expand reads an outbound's resolver entries with the default discovery.
func Expand(entries []string) []Candidate {
	return ExpandWith(entries, option.ResolverDiscoveryOptions{})
}

// ExpandWith reads an outbound's resolver entries. "auto" and "" add, once, the candidates of
// Soar's discovery for the discovery settings (the device's own resolvers, the country's bundled
// list, global public resolvers, sampled addresses of the country's ranges), then every built-in
// resolver on port 53; every other entry is kept as written. Entries are trimmed; nothing is
// validated here, each tunnel checks the forms it supports.
func ExpandWith(entries []string, discovery option.ResolverDiscoveryOptions) []Candidate {
	var candidates []Candidate
	autoAdded := false
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.EqualFold(entry, AutoResolver) {
			if !autoAdded {
				autoAdded = true
				candidates = append(candidates, autoCandidates(discovery)...)
			}
			continue
		}
		candidates = append(candidates, Candidate{Address: entry})
	}
	return candidates
}

// autoCandidates is what "auto" stands for, each address once.
func autoCandidates(discovery option.ResolverDiscoveryOptions) []Candidate {
	seen := make(map[string]bool)
	var candidates []Candidate
	add := func(address string, tier int) {
		if !seen[address] {
			seen[address] = true
			candidates = append(candidates, Candidate{Address: address, Auto: true, Tier: tier})
		}
	}
	for _, address := range SoarDiscovery(discovery).List() {
		add(address, TierDiscovery)
	}
	for ip := range BuiltinResolvers() {
		add(ip+":53", TierBuiltin)
	}
	return candidates
}

// SoarDiscovery is a Soar discovery configuration for the discovery settings, unset ones left to
// Soar's defaults.
func SoarDiscovery(discovery option.ResolverDiscoveryOptions) soar.Discovery {
	return soar.Discovery{
		Enabled:      true,
		Country:      discovery.Country,
		SampleRanges: discovery.SampleRanges,
		Want:         discovery.Want,
		Concurrency:  discovery.Concurrency,
		Pace:         discovery.Pace.Build(),
	}
}

// HasAuto reports whether the entries ask for the built-in list.
func HasAuto(entries []string) bool {
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.EqualFold(entry, AutoResolver) {
			return true
		}
	}
	return false
}
