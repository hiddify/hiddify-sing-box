package option

import "github.com/sagernet/sing/common/json/badoption"

type MonitoringOptions struct {
	Interval       badoption.Duration `json:"interval,omitempty"`
	URLs           []string           `json:"urls,omitempty"`       //H
	IpInfoURL      string             `json:"ipinfo_url,omitempty"` //H subscription `ipinfo-url`
	Workers        int                `json:"workers,omitempty"`
	DebounceWindow badoption.Duration `json:"debounce_window,omitempty"`
	URLTestTimeout badoption.Duration `json:"url_test_timeout,omitempty"`
	IdleTimeout    badoption.Duration `json:"idle_timeout,omitempty"`
	// H: a test asked for (a tap, a selection) with no answer by the first of these shows as
	// unavailable for now and is tried again beside the running attempt, again at each next one;
	// the last is its final timeout. An answer from any attempt shows at once. Empty is 1s, 3s, 10s.
	OnDemandTimeouts badoption.Listable[badoption.Duration] `json:"on_demand_timeouts,omitempty"` //H
	// H: retired, no effect. The monitoring no longer probes an IPv6 address through the
	// outbounds: it learns their IPv6 from the connections the router carries, see the route
	// option ipv6_fallback. Kept so a config that set it still loads.
	IPv6Probe badoption.Listable[string] `json:"ipv6_probe,omitempty"` //H
	// H: after an outbound's URL test answers, the same URL is fetched once more over the test
	// host's IPv6 address through the outbound, to learn whether it carries IPv6, once per
	// outbound per run; the answer is cached with its URL test results (adapter.URLTestHistory.IPv6)
	// and serves dns rule ipv6_by_outbound and rule ipv6_unavailable_via. Off by default: only
	// worth it when the apps get IPv6 at all.
	VerifyIPv6 bool `json:"verify_ipv6,omitempty"` //H
	// H: outbounds whose IPv6 is declared, by tag (a link's ipv6=1 or ipv6=0): known from the
	// start, until a verification or their own connections say otherwise.
	IPv6Declared map[string]bool `json:"ipv6_declared,omitempty"` //H
	// H: of the lazy outbounds ("lazy": true), use only the fastest few, found a few at a time;
	// the others rest: not tested, not used by a group, and so never created. See KeepTopOptions.
	KeepTop *KeepTopOptions `json:"keep_top,omitempty"` //H
}

// KeepTopOptions are the options of keep top (common/monitoring/h_keep_top.go). //H
type KeepTopOptions struct {
	// Count is how many lazy outbounds to keep in use: the fastest. 0, with answering or
	// countries, is all that fit those.
	Count int `json:"count,omitempty"`
	// Answering keeps every lazy outbound that answers, and puts one that stops answering to
	// rest; count is not used.
	Answering bool `json:"answering,omitempty"`
	// Countries keeps only the outbounds whose exit is in one of these countries (two-letter
	// codes), by the IP lookup of their test, or the flag in their tag before it.
	Countries badoption.Listable[string] `json:"countries,omitempty"`
	// Batch is how many outbounds are tested at a time, beside the best found so far: 10 when
	// 0, all of them at once below 0.
	Batch int `json:"batch,omitempty"`
	// Quick ends the pick once the outbounds still to test were slower at their last test than
	// the ones found, instead of testing all of them.
	Quick bool `json:"quick,omitempty"`
	// Pinned are the tags of lazy outbounds that are always in use, whatever their ping, as the
	// one a selector has selected is, beside the count fastest.
	Pinned badoption.Listable[string] `json:"pinned,omitempty"`
}
