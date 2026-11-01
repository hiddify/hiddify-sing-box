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
	// H: the IPv6 address and port a connection is opened to through each outbound that answered
	// its URL test, once per outbound per run, to learn whether that outbound carries IPv6 (dns
	// rule ipv6_by_outbound, rule ipv6_unavailable_via). Empty is [2606:4700:4700::1111]:443; "none"
	// turns the probe off.
	IPv6Probe string `json:"ipv6_probe,omitempty"` //H
}
