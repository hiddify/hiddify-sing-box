package dns

import (
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// ReloadRules replaces the DNS rules of a started router (hot reload) and clears the cache; on an
// error the current rules stay. //H
func (r *Router) ReloadRules(rules []option.DNSRule) error {
	r.rulesAccess.Lock()
	oldRawRules := r.rawRules
	r.rawRules = append([]option.DNSRule(nil), rules...)
	r.rulesAccess.Unlock()
	newRules, legacyDNSMode, _, err := r.buildRules(true)
	if err != nil {
		r.rulesAccess.Lock()
		r.rawRules = oldRawRules
		r.rulesAccess.Unlock()
		return E.Cause(err, "reload DNS rules")
	}
	r.rulesAccess.Lock()
	if r.closing {
		r.rulesAccess.Unlock()
		closeRules(newRules)
		return nil
	}
	oldRules := r.rules
	r.rules = newRules
	r.legacyDNSMode = legacyDNSMode
	r.rulesAccess.Unlock()
	closeRules(oldRules)
	r.ClearCache()
	r.logger.Info("reloaded ", len(newRules), " DNS rules")
	return nil
}
