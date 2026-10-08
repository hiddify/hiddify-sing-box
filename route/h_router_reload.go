package route

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
)

// H: hot reload of the route rules and rule-sets.

func ruleSetContent(options option.RuleSet) []byte {
	content, _ := json.Marshal(options)
	return content
}

// ReloadRules replaces the route rules and rule-sets of a started router. A rule-set whose
// options did not change is kept as it is (no new download); new and changed ones are started
// before anything is switched, and on an error the router keeps its current rules.
func (r *Router) ReloadRules(ctx context.Context, ruleOptions []option.Rule, ruleSetOptions []option.RuleSet) error {
	r.rulesAccess.RLock()
	oldRuleSets := r.ruleSets
	oldRuleSetMap := r.ruleSetMap
	oldContents := r.ruleSetContents
	oldRules := r.rules
	r.rulesAccess.RUnlock()

	newRuleSetMap := make(map[string]adapter.RuleSet)
	newContents := make(map[string][]byte)
	var newRuleSets, createdRuleSets []adapter.RuleSet
	closeCreated := func() {
		for _, ruleSet := range createdRuleSets {
			_ = ruleSet.Close()
		}
	}
	for i, options := range ruleSetOptions {
		content := ruleSetContent(options)
		for _, tag := range options.Tag {
			if _, exists := newRuleSetMap[tag]; exists {
				closeCreated()
				return E.New("duplicate rule-set tag: ", tag)
			}
			ruleSet, loaded := oldRuleSetMap[tag]
			if !loaded || !bytes.Equal(oldContents[tag], content) {
				var err error
				ruleSet, err = R.NewRuleSet(r.ctx, r.logger, tag, options)
				if err != nil {
					closeCreated()
					return E.Cause(err, "parse rule-set[", i, "]")
				}
				createdRuleSets = append(createdRuleSets, ruleSet)
			}
			newRuleSets = append(newRuleSets, ruleSet)
			newRuleSetMap[tag] = ruleSet
			newContents[tag] = content
		}
	}
	if len(createdRuleSets) > 0 {
		startContext := adapter.NewHTTPStartContext()
		for _, ruleSet := range createdRuleSets {
			if err := ruleSet.StartContext(ctx, startContext); err != nil {
				startContext.Close()
				closeCreated()
				return E.Cause(err, "initialize rule-set ", ruleSet.Name())
			}
		}
		startContext.Close()
	}

	// rules find their rule-sets through RuleSet(tag), so the new rule-sets go in first
	r.rulesAccess.Lock()
	r.ruleSets, r.ruleSetMap, r.ruleSetContents = newRuleSets, newRuleSetMap, newContents
	r.rulesAccess.Unlock()
	restoreRuleSets := func() {
		r.rulesAccess.Lock()
		r.ruleSets, r.ruleSetMap, r.ruleSetContents = oldRuleSets, oldRuleSetMap, oldContents
		r.rulesAccess.Unlock()
		closeCreated()
	}
	newRules := make([]adapter.Rule, 0, len(ruleOptions))
	closeNewRules := func() {
		for _, rule := range newRules {
			_ = rule.Close()
		}
	}
	for i, options := range ruleOptions {
		if err := R.ValidateNoNestedRuleActions(options); err != nil {
			closeNewRules()
			restoreRuleSets()
			return E.Cause(err, "parse rule[", i, "]")
		}
		rule, err := R.NewRule(r.ctx, r.logger, options, false)
		if err != nil {
			closeNewRules()
			restoreRuleSets()
			return E.Cause(err, "parse rule[", i, "]")
		}
		newRules = append(newRules, rule)
	}
	for i, rule := range newRules {
		if err := rule.Start(); err != nil {
			closeNewRules()
			restoreRuleSets()
			return E.Cause(err, "initialize rule[", i, "]")
		}
	}

	r.rulesAccess.Lock()
	r.rules = newRules
	r.rulesAccess.Unlock()
	for _, rule := range oldRules {
		_ = rule.Close()
	}
	for tag, ruleSet := range oldRuleSetMap {
		if newRuleSetMap[tag] != ruleSet {
			_ = ruleSet.Close()
		}
	}
	if r.ruleSetUpdater != nil {
		_ = r.ruleSetUpdater.Close()
	}
	r.ruleSetUpdater = R.NewRuleSetUpdater(r.ctx, newRuleSets)
	if r.ruleSetUpdater != nil { // nil without remote rule-sets
		r.ruleSetUpdater.Start()
	}
	r.network.Initialize(newRuleSets)
	for _, ruleSet := range createdRuleSets {
		ruleSet.Cleanup()
		if ruleSet.Metadata().ContainsProcessRule {
			r.needFindProcess = true
		}
	}
	if hasRule(ruleOptions, isProcessRule) {
		r.needFindProcess = true
	}
	r.initProcessSearcher(taskmonitor.New(r.logger, C.StartTimeout))
	r.logger.Info("reloaded ", len(newRules), " rules and ", len(newRuleSets), " rule-sets (", len(createdRuleSets), " new)")
	return nil
}
