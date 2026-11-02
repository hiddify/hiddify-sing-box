// Package dnspool is what the DNS tunnel outbounds share: the built-in list of public resolvers,
// the saved score of each resolver, a plain DNS probe that tells whether a resolver answers, and
// the resolver pool (github.com/hiddify/hmrd_multi_resolver_dns) each outbound runs for itself
// to spread its queries over many resolvers. The dnstt and masterdns outbounds are built on it,
// so every DNS tunnel has the same resolver handling and the same smart_pool options.
package dnspool

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
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

// Candidate is one resolver an outbound may use: the address as the pool and the probe read it
// ("1.1.1.1:53", "dot://1.1.1.1:853", "https://dns.google/dns-query"), and whether it came from
// the built-in list.
type Candidate struct {
	Address string
	Auto    bool
}

// Expand reads an outbound's resolver entries. "auto" and "" add every built-in resolver on
// port 53; every other entry is kept as written. Entries are trimmed; nothing is validated here,
// each tunnel checks the forms it supports.
func Expand(entries []string) []Candidate {
	var candidates []Candidate
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.EqualFold(entry, AutoResolver) {
			for ip := range BuiltinResolvers() {
				candidates = append(candidates, Candidate{Address: ip + ":53", Auto: true})
			}
			continue
		}
		candidates = append(candidates, Candidate{Address: entry})
	}
	return candidates
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
