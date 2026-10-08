package box

import (
	"bytes"
	"context"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
)

// H: hot reload: apply new options to a running box without restarting it.
//
// Reloadable: outbounds, endpoints, inbounds (TUN too: closed, then opened again), DNS
// servers/rules/final and route rules/rule_set/final. Anything else must stay the same (see
// CheckHotReload).

// HotReloadChanges lists the tags a hot reload touched.
type HotReloadChanges struct {
	Created  []string // new tags
	Replaced []string // changed, or depending on a changed or removed tag
	Removed  []string
}

func (c HotReloadChanges) IsEmpty() bool {
	return len(c.Created) == 0 && len(c.Replaced) == 0 && len(c.Removed) == 0
}

type HotReloadResult struct {
	Outbounds  HotReloadChanges // outbounds and endpoints
	DNSServers HotReloadChanges
	Inbounds   HotReloadChanges
	RouteRules bool // route rules or rule-sets were reloaded
	DNSRules   bool
	RouteFinal bool
	DNSFinal   bool
}

func (r HotReloadResult) IsEmpty() bool {
	return r.Outbounds.IsEmpty() && r.DNSServers.IsEmpty() && r.Inbounds.IsEmpty() &&
		!r.RouteRules && !r.DNSRules && !r.RouteFinal && !r.DNSFinal
}

// HotReload applies options to the running box without restarting it. It returns an error,
// changing nothing, when options differ in anything that cannot be reloaded.
func (s *Box) HotReload(ctx context.Context, options *option.Options) error {
	_, err := s.HotReloadWithResult(ctx, options)
	return err
}

// HotReloadWithResult is HotReload, also reporting what was changed.
func (s *Box) HotReloadWithResult(ctx context.Context, options *option.Options) (HotReloadResult, error) {
	if options == nil {
		return HotReloadResult{}, E.New("missing options")
	}
	s.reloadAccess.Lock()
	defer s.reloadAccess.Unlock()
	plan, err := planHotReload(s.ctx, s.runningOptions, *options)
	if err != nil {
		return HotReloadResult{}, err
	}
	if !plan.result.IsEmpty() {
		if err = s.applyHotReload(ctx, plan); err != nil {
			return plan.result, err
		}
		s.logger.Info("hot reloaded: outbounds ", changesSummary(plan.result.Outbounds),
			", dns servers ", changesSummary(plan.result.DNSServers),
			", inbounds ", changesSummary(plan.result.Inbounds),
			", route rules ", plan.result.RouteRules, ", dns rules ", plan.result.DNSRules)
	}
	s.runningOptions = *options
	return plan.result, nil
}

func changesSummary(changes HotReloadChanges) string {
	return F.ToString(len(changes.Created), " created, ", len(changes.Replaced), " replaced, ", len(changes.Removed), " removed")
}

// CheckHotReload returns an error unless newOptions differ from oldOptions only in what a hot
// reload can change.
func CheckHotReload(ctx context.Context, oldOptions, newOptions option.Options) error {
	var changed []string
	oldRest, newRest := oldOptions, newOptions
	for _, options := range []*option.Options{&oldRest, &newRest} {
		options.Inbounds, options.Outbounds, options.Endpoints, options.DNS, options.Route = nil, nil, nil, nil, nil
	}
	keys, err := changedKeys(ctx, &oldRest, &newRest)
	if err != nil {
		return err
	}
	changed = append(changed, keys...)

	oldRoute, newRoute := common.PtrValueOrDefault(oldOptions.Route), common.PtrValueOrDefault(newOptions.Route)
	for _, route := range []*option.RouteOptions{&oldRoute, &newRoute} {
		route.Rules, route.RuleSet, route.Final = nil, nil, ""
	}
	keys, err = changedKeys(ctx, &oldRoute, &newRoute)
	if err != nil {
		return err
	}
	for _, key := range keys {
		changed = append(changed, "route."+key)
	}

	oldDNS, newDNS := common.PtrValueOrDefault(oldOptions.DNS), common.PtrValueOrDefault(newOptions.DNS)
	for _, dns := range []*option.DNSOptions{&oldDNS, &newDNS} {
		dns.Servers, dns.Rules, dns.Final = nil, nil, ""
	}
	keys, err = changedKeys(ctx, &oldDNS, &newDNS)
	if err != nil {
		return err
	}
	for _, key := range keys {
		changed = append(changed, "dns."+key)
	}
	if len(changed) > 0 {
		return E.New("hot reload cannot change: ", strings.Join(changed, ", "))
	}
	return nil
}

// IsTunChanged reports whether options differ from the running options in their TUN inbounds,
// which a hot reload recreates (re-opening the TUN device).
func (s *Box) IsTunChanged(ctx context.Context, options *option.Options) (bool, error) {
	if options == nil {
		return false, E.New("missing options")
	}
	s.reloadAccess.Lock()
	running := s.runningOptions
	s.reloadAccess.Unlock()
	oldTUN, err := tunInbounds(s.ctx, running)
	if err != nil {
		return false, err
	}
	newTUN, err := tunInbounds(s.ctx, *options)
	if err != nil {
		return false, err
	}
	return !bytes.Equal(oldTUN, newTUN), nil
}

// changedKeys returns the top-level JSON fields that differ.
func changedKeys(ctx context.Context, oldValue, newValue any) ([]string, error) {
	oldContent, err := json.MarshalContext(ctx, oldValue)
	if err != nil {
		return nil, err
	}
	newContent, err := json.MarshalContext(ctx, newValue)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(oldContent, newContent) {
		return nil, nil
	}
	var oldFields, newFields map[string]json.RawMessage
	_ = json.Unmarshal(oldContent, &oldFields)
	_ = json.Unmarshal(newContent, &newFields)
	var keys []string
	for key, value := range newFields {
		if !bytes.Equal(value, oldFields[key]) {
			keys = append(keys, key)
		}
	}
	for key := range oldFields {
		if _, ok := newFields[key]; !ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func tunInbounds(ctx context.Context, options option.Options) ([]byte, error) {
	var tun []option.Inbound
	for i, inbound := range options.Inbounds {
		if inbound.Type == C.TypeTun {
			if inbound.Tag == "" {
				inbound.Tag = F.ToString(i)
			}
			tun = append(tun, inbound)
		}
	}
	return json.MarshalContext(ctx, tun)
}

const (
	hotReloadOutbound = "outbound"
	hotReloadEndpoint = "endpoint"
	hotReloadDNS      = "dns"
	hotReloadInbound  = "inbound"
)

type hotReloadItem struct {
	kind         string
	tag          string
	typ          string
	options      any
	content      []byte
	dependencies []string
	index        int
}

type hotReloadItems map[string]*hotReloadItem

func (items hotReloadItems) add(ctx context.Context, item *hotReloadItem, value any) error {
	if item.tag == "" {
		item.tag = F.ToString(item.index) // as New does
	}
	if _, loaded := items[item.tag]; loaded {
		return E.New("duplicate ", item.kind, " tag: ", item.tag)
	}
	content, err := json.MarshalContext(ctx, value)
	if err != nil {
		return E.Cause(err, "marshal ", item.kind, " ", item.tag)
	}
	item.content = content
	switch item.kind {
	case hotReloadOutbound, hotReloadEndpoint:
		item.dependencies = outboundDependencies(content)
	case hotReloadDNS:
		item.dependencies = stringList(content, "servers")
	}
	items[item.tag] = item
	return nil
}

func outboundItems(ctx context.Context, options option.Options) (hotReloadItems, error) {
	items := make(hotReloadItems)
	for i := range options.Outbounds {
		outbound := &options.Outbounds[i]
		if err := items.add(ctx, &hotReloadItem{kind: hotReloadOutbound, tag: outbound.Tag, typ: outbound.Type, options: outbound.Options, index: i}, outbound); err != nil {
			return nil, err
		}
	}
	for i := range options.Endpoints {
		endpoint := &options.Endpoints[i]
		if err := items.add(ctx, &hotReloadItem{kind: hotReloadEndpoint, tag: endpoint.Tag, typ: endpoint.Type, options: endpoint.Options, index: i}, endpoint); err != nil {
			return nil, err
		}
	}
	return items, nil
}

func dnsServerItems(ctx context.Context, options option.Options) (hotReloadItems, error) {
	items := make(hotReloadItems)
	if options.DNS == nil {
		return items, nil
	}
	for i := range options.DNS.Servers {
		server := &options.DNS.Servers[i]
		if err := items.add(ctx, &hotReloadItem{kind: hotReloadDNS, tag: server.Tag, typ: server.Type, options: server.Options, index: i}, server); err != nil {
			return nil, err
		}
	}
	return items, nil
}

func inboundItems(ctx context.Context, options option.Options) (hotReloadItems, error) {
	items := make(hotReloadItems)
	for i := range options.Inbounds {
		inbound := &options.Inbounds[i]
		if err := items.add(ctx, &hotReloadItem{kind: hotReloadInbound, tag: inbound.Tag, typ: inbound.Type, options: inbound.Options, index: i}, inbound); err != nil {
			return nil, err
		}
	}
	return items, nil
}

// outboundDependencies returns the tags an outbound/endpoint uses: every "detour" (also nested,
// e.g. a WARP profile's) and a group's "outbounds".
func outboundDependencies(content []byte) []string {
	var value any
	if json.Unmarshal(content, &value) != nil {
		return nil
	}
	var dependencies []string
	var walk func(value any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for key, field := range v {
				if detour, ok := field.(string); ok && key == "detour" && detour != "" {
					dependencies = append(dependencies, detour)
				} else {
					walk(field)
				}
			}
		case []any:
			for _, field := range v {
				walk(field)
			}
		}
	}
	walk(value)
	return append(dependencies, stringList(content, "outbounds")...)
}

// stringList returns a top-level string list field (a group's members).
func stringList(content []byte, key string) []string {
	var fields map[string]any
	if json.Unmarshal(content, &fields) != nil {
		return nil
	}
	values, _ := fields[key].([]any)
	var list []string
	for _, value := range values {
		if tag, ok := value.(string); ok {
			list = append(list, tag)
		}
	}
	return list
}

type hotReloadDiff struct {
	oldItems, newItems hotReloadItems
	order              []string // tags to create or replace, dependencies first
}

// diffItems finds the created, changed and removed tags; an item that depends on a changed or
// removed one is replaced too, as it holds the old instance.
func diffItems(oldItems, newItems hotReloadItems, changes *HotReloadChanges) (*hotReloadDiff, error) {
	recreate := make(map[string]bool)
	dirty := make(map[string]bool)
	for tag, item := range newItems {
		old, existed := oldItems[tag]
		switch {
		case !existed:
			changes.Created = append(changes.Created, tag)
		case old.kind != item.kind || !bytes.Equal(old.content, item.content):
			changes.Replaced = append(changes.Replaced, tag)
		default:
			continue
		}
		recreate[tag] = true
		dirty[tag] = true
	}
	for tag := range oldItems {
		if _, kept := newItems[tag]; !kept {
			changes.Removed = append(changes.Removed, tag)
			dirty[tag] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for tag, item := range newItems {
			if recreate[tag] {
				continue
			}
			for _, dependency := range item.dependencies {
				if dirty[dependency] {
					recreate[tag] = true
					dirty[tag] = true
					changes.Replaced = append(changes.Replaced, tag)
					changed = true
					break
				}
			}
		}
	}
	sort.Strings(changes.Created)
	sort.Strings(changes.Replaced)
	sort.Strings(changes.Removed)
	order, err := hotReloadOrder(newItems, recreate)
	if err != nil {
		return nil, err
	}
	return &hotReloadDiff{oldItems: oldItems, newItems: newItems, order: order}, nil
}

// hotReloadOrder sorts the tags to recreate so that each comes after the recreated tags it uses
// (a group starts by looking up its members).
func hotReloadOrder(items hotReloadItems, recreate map[string]bool) ([]string, error) {
	tags := make([]string, 0, len(recreate))
	for tag := range recreate {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	const (
		unvisited = iota
		visiting
		done
	)
	state := make(map[string]int)
	order := make([]string, 0, len(tags))
	var visit func(tag string) error
	visit = func(tag string) error {
		switch state[tag] {
		case visiting:
			return E.New("dependency cycle at ", tag)
		case done:
			return nil
		}
		state[tag] = visiting
		for _, dependency := range items[tag].dependencies {
			if recreate[dependency] {
				if err := visit(dependency); err != nil {
					return err
				}
			}
		}
		state[tag] = done
		order = append(order, tag)
		return nil
	}
	for _, tag := range tags {
		if err := visit(tag); err != nil {
			return nil, err
		}
	}
	return order, nil
}

type hotReloadPlan struct {
	result      HotReloadResult
	outbounds   *hotReloadDiff
	dnsServers  *hotReloadDiff
	inbounds    *hotReloadDiff
	newOptions  option.Options
	ruleSetsNew bool // the route rule-sets changed, so DNS rules must be rebuilt too
}

func planHotReload(ctx context.Context, oldOptions, newOptions option.Options) (*hotReloadPlan, error) {
	if err := CheckHotReload(ctx, oldOptions, newOptions); err != nil {
		return nil, err
	}
	plan := &hotReloadPlan{newOptions: newOptions}
	diff := func(collect func(context.Context, option.Options) (hotReloadItems, error), changes *HotReloadChanges) (*hotReloadDiff, error) {
		oldItems, err := collect(ctx, oldOptions)
		if err != nil {
			return nil, E.Cause(err, "running options")
		}
		newItems, err := collect(ctx, newOptions)
		if err != nil {
			return nil, err
		}
		return diffItems(oldItems, newItems, changes)
	}
	var err error
	if plan.outbounds, err = diff(outboundItems, &plan.result.Outbounds); err != nil {
		return nil, err
	}
	if plan.dnsServers, err = diff(dnsServerItems, &plan.result.DNSServers); err != nil {
		return nil, err
	}
	if plan.inbounds, err = diff(inboundItems, &plan.result.Inbounds); err != nil {
		return nil, err
	}

	oldRoute, newRoute := common.PtrValueOrDefault(oldOptions.Route), common.PtrValueOrDefault(newOptions.Route)
	ruleSetsChanged, err := contentChanged(ctx, oldRoute.RuleSet, newRoute.RuleSet)
	if err != nil {
		return nil, err
	}
	rulesChanged, err := contentChanged(ctx, oldRoute.Rules, newRoute.Rules)
	if err != nil {
		return nil, err
	}
	plan.ruleSetsNew = ruleSetsChanged
	plan.result.RouteRules = ruleSetsChanged || rulesChanged
	plan.result.RouteFinal = oldRoute.Final != newRoute.Final

	oldDNS, newDNS := common.PtrValueOrDefault(oldOptions.DNS), common.PtrValueOrDefault(newOptions.DNS)
	dnsRulesChanged, err := contentChanged(ctx, oldDNS.Rules, newDNS.Rules)
	if err != nil {
		return nil, err
	}
	// DNS rules hold the route rule-sets they use
	plan.result.DNSRules = dnsRulesChanged || (ruleSetsChanged && len(newDNS.Rules) > 0)
	plan.result.DNSFinal = oldDNS.Final != newDNS.Final
	return plan, nil
}

func contentChanged(ctx context.Context, oldValue, newValue any) (bool, error) {
	oldContent, err := json.MarshalContext(ctx, oldValue)
	if err != nil {
		return false, err
	}
	newContent, err := json.MarshalContext(ctx, newValue)
	if err != nil {
		return false, err
	}
	return !bytes.Equal(oldContent, newContent), nil
}

type hotReloadSelector interface {
	Selected(network string) adapter.Outbound
	SelectOutbound(tag string) bool
}

func (s *Box) applyHotReload(ctx context.Context, plan *hotReloadPlan) error {
	outbounds := plan.outbounds
	// a tag that moves between outbound and endpoint first leaves its old manager
	for tag, old := range outbounds.oldItems {
		if item, kept := outbounds.newItems[tag]; kept && item.kind != old.kind {
			s.hotReloadRemove(old)
		}
	}
	selections := make(map[string]string)
	for _, tag := range outbounds.order {
		if outbound, loaded := s.outbound.Outbound(tag); loaded {
			if selector, isSelector := outbound.(hotReloadSelector); isSelector {
				if selected := selector.Selected(N.NetworkTCP); selected != nil {
					selections[tag] = selected.Tag()
				}
			}
		}
	}
	for _, tag := range outbounds.order {
		if err := s.hotReloadCreate(outbounds.newItems[tag]); err != nil {
			return err
		}
	}
	for _, tag := range plan.dnsServers.order {
		if err := s.hotReloadCreate(plan.dnsServers.newItems[tag]); err != nil {
			return err
		}
	}
	newDNS := common.PtrValueOrDefault(plan.newOptions.DNS)
	newRoute := common.PtrValueOrDefault(plan.newOptions.Route)
	if plan.result.DNSFinal {
		if err := s.dnsTransport.SetDefaultTag(newDNS.Final); err != nil {
			return err
		}
	}
	if plan.result.RouteRules {
		if err := s.router.ReloadRules(ctx, newRoute.Rules, newRoute.RuleSet); err != nil {
			return E.Cause(err, "reload route rules")
		}
	}
	if plan.result.DNSRules {
		if err := s.dnsRouter.ReloadRules(newDNS.Rules); err != nil {
			return err
		}
	}
	if plan.result.RouteFinal {
		if err := s.outbound.SetDefaultTag(newRoute.Final); err != nil {
			return err
		}
	}
	for _, tag := range plan.result.Outbounds.Removed {
		s.hotReloadRemove(outbounds.oldItems[tag])
	}
	for _, tag := range plan.result.DNSServers.Removed {
		s.hotReloadRemove(plan.dnsServers.oldItems[tag])
	}
	// inbounds: the old one goes first, so a changed inbound can listen on the same port
	inbounds := plan.inbounds
	for _, tag := range append(append([]string(nil), plan.result.Inbounds.Removed...), plan.result.Inbounds.Replaced...) {
		s.hotReloadRemove(inbounds.oldItems[tag])
	}
	for _, tag := range inbounds.order {
		if err := s.hotReloadCreate(inbounds.newItems[tag]); err != nil {
			return err
		}
	}
	for tag, selected := range selections {
		if outbound, loaded := s.outbound.Outbound(tag); loaded {
			if selector, isSelector := outbound.(hotReloadSelector); isSelector {
				selector.SelectOutbound(selected)
			}
		}
	}
	if !plan.result.Outbounds.IsEmpty() {
		if monitor := monitoring.Get(s.ctx); monitor != nil {
			if err := monitor.Reload(); err != nil {
				return E.Cause(err, "reload outbound monitoring")
			}
		}
	}
	return nil
}

// hotReloadCreate creates (or replaces) an item the way New does, including the invalid
// placeholder for an outbound/endpoint that fails.
func (s *Box) hotReloadCreate(item *hotReloadItem) error {
	name := F.ToString(item.kind, "/", item.typ, "[", item.tag, "]")
	logger := s.logFactory.NewLogger(name)
	var err error
	switch item.kind {
	case hotReloadDNS:
		err = s.dnsTransport.Create(s.ctx, logger, item.tag, item.typ, item.options)
	case hotReloadInbound:
		err = s.inbound.Create(s.ctx, s.router, logger, item.tag, item.typ, item.options)
	}
	if item.kind == hotReloadDNS || item.kind == hotReloadInbound {
		if err != nil {
			return E.Cause(err, "hot reload ", name)
		}
		return nil
	}
	ctx := adapter.WithContext(s.ctx, &adapter.InboundContext{Outbound: item.tag})
	create := s.outbound.Create
	if item.kind == hotReloadEndpoint {
		create = s.endpoint.Create
	}
	err = create(ctx, s.router, logger, item.tag, item.typ, item.options)
	if err == nil {
		return nil
	}
	s.logger.Error(E.Cause(err, "hot reload ", name))
	err = create(ctx, s.router, logger, item.tag, C.TypeHInvalidConfig,
		&option.HInvalidOptions{InvalidConfig: item.options, OriginalType: item.typ, Err: E.Cause(err, "initialize ", name)})
	if err != nil {
		return E.Cause(err, "hot reload ", name)
	}
	return nil
}

func (s *Box) hotReloadRemove(item *hotReloadItem) {
	var err error
	switch item.kind {
	case hotReloadOutbound:
		err = s.outbound.RemoveForReload(item.tag)
	case hotReloadEndpoint:
		err = s.endpoint.Remove(item.tag)
	case hotReloadDNS:
		err = s.dnsTransport.RemoveForReload(item.tag)
	case hotReloadInbound:
		err = s.inbound.Remove(item.tag)
	}
	if err != nil {
		s.logger.Warn(E.Cause(err, "hot reload: remove ", item.kind, " ", item.tag))
	}
}
