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
}
