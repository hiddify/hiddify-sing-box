package finalmask

import (
	"encoding/json"
	"slices"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"google.golang.org/protobuf/proto"
)

// xdnsSettings is the xdns mask with the settings of earlier Xray versions still accepted, so
// links and profiles made for them keep loading:
//
//   - v26.7 to v26.9: "domains": ["t.example.com"] for a server and
//     "resolvers": ["t.example.com+udp://8.8.8.8:53"] for a client;
//   - v26.9.30: domains as {"name": ...} and resolvers as {"type": "udp", "addr": ...}.
//
// Both become the current form, {"names": [...]} and {"addrs": [...]}. The client sends through
// every resolver for every domain, so a resolver string's domain joins the domains.
type xdnsSettings struct {
	XDNS
}

func (c *xdnsSettings) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var domainNames []string
	var domains, resolvers []json.RawMessage
	if err := unmarshalOptional(raw["domains"], &domains); err != nil {
		return E.Cause(err, "domains")
	}
	if err := unmarshalOptional(raw["resolvers"], &resolvers); err != nil {
		return E.Cause(err, "resolvers")
	}
	newDomains := make([]json.RawMessage, 0, len(domains))
	for _, domain := range domains {
		var name string
		if json.Unmarshal(domain, &name) == nil {
			domainNames = appendUnique(domainNames, name)
			continue
		}
		newDomains = append(newDomains, renameField(domain, "name", "names"))
	}
	newResolvers := make([]json.RawMessage, 0, len(resolvers))
	for _, resolver := range resolvers {
		var value string
		if json.Unmarshal(resolver, &value) == nil {
			name, addr, found := strings.Cut(value, "+")
			if !found || !strings.Contains(addr, "://") {
				return E.New("invalid resolver ", value)
			}
			domainNames = appendUnique(domainNames, name)
			newResolvers = append(newResolvers, mustMarshal(map[string]any{"addrs": []string{addr}}))
			continue
		}
		newResolvers = append(newResolvers, legacyResolverObject(resolver))
	}
	if len(domainNames) > 0 {
		newDomains = append(newDomains, mustMarshal(map[string]any{"names": domainNames}))
	}
	if len(newDomains) == 0 && len(newResolvers) == 0 {
		return E.New("empty domains & empty resolvers")
	}
	raw["domains"] = mustMarshal(newDomains)
	raw["resolvers"] = mustMarshal(newResolvers)
	return json.Unmarshal(mustMarshal(raw), &c.XDNS)
}

func (c *xdnsSettings) Build() (proto.Message, error) {
	return c.XDNS.Build()
}

// legacyResolverObject turns {"type": "udp", "addr": "8.8.8.8:53"} into
// {"addrs": ["udp://8.8.8.8:53"]}; a resolver that already has addrs is left as it is.
func legacyResolverObject(resolver json.RawMessage) json.RawMessage {
	var object map[string]json.RawMessage
	if json.Unmarshal(resolver, &object) != nil {
		return resolver
	}
	if _, hasAddrs := object["addrs"]; hasAddrs {
		return resolver
	}
	var addr, resolverType string
	if json.Unmarshal(object["addr"], &addr) != nil || addr == "" {
		return resolver
	}
	_ = json.Unmarshal(object["type"], &resolverType)
	if resolverType != "" && !strings.Contains(addr, "://") {
		addr = resolverType + "://" + addr
	}
	delete(object, "addr")
	delete(object, "type")
	object["addrs"] = mustMarshal([]string{addr})
	return mustMarshal(object)
}

// renameField turns {"name": "x"} into {"names": ["x"]}.
func renameField(object json.RawMessage, from, to string) json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(object, &fields) != nil {
		return object
	}
	if _, hasNew := fields[to]; hasNew {
		return object
	}
	value, hasOld := fields[from]
	if !hasOld {
		return object
	}
	delete(fields, from)
	fields[to] = mustMarshal([]json.RawMessage{value})
	return mustMarshal(fields)
}

func unmarshalOptional(data json.RawMessage, value any) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	return json.Unmarshal(data, value)
}

func appendUnique(list []string, value string) []string {
	if value == "" || slices.Contains(list, value) {
		return list
	}
	return append(list, value)
}

func mustMarshal(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}
