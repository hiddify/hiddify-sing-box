package monitoring

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// defaultIPv6Probe is Cloudflare's resolver over DNS-over-TLS: an address any IPv6 route
// reaches, on a port the connection is only opened to, never spoken on.
const defaultIPv6Probe = "[2606:4700:4700::1111]:443"

// ipv6ProbeTimeout bounds the probe: a dead IPv6 path through a proxy answers nothing.
const ipv6ProbeTimeout = 3 * time.Second

// ipv6ProbeAddress is the probe to use for the option's value: the default when empty, none
// for "none".
func ipv6ProbeAddress(option string) string {
	switch option {
	case "":
		return defaultIPv6Probe
	case "none", "off", "false":
		return ""
	}
	return option
}

// ipv6Of is what the test records about IPv6 for the one outbound that answered its URL test:
// once per outbound per run (and once more after a cached result), a connection to the probe
// address through that outbound, closed as soon as it is open; otherwise what was known of it.
// Each outbound and endpoint has its own answer: one proxy carries IPv6, the next may not.
func (m *OutboundMonitoring) ipv6Of(ctx context.Context, out *outboundState) *bool {
	out.mu.Lock()
	known, fromCache := out.history.IPv6, out.from_cache
	out.mu.Unlock()
	if m.ipv6Probe == "" {
		return known
	}
	if known != nil && !fromCache {
		return known
	}
	probeContext, cancel := context.WithTimeout(ctx, ipv6ProbeTimeout)
	defer cancel()
	conn, err := out.outbound.DialContext(probeContext, N.NetworkTCP, M.ParseSocksaddr(m.ipv6Probe))
	supported := err == nil
	if conn != nil {
		conn.Close()
	}
	if supported {
		m.logger.Debug("outbound ", out.outbound.Tag(), " carries IPv6")
	} else {
		m.logger.Info("outbound ", out.outbound.Tag(), " does not carry IPv6: ", err)
	}
	return &supported
}

// OutboundIPv6 implements adapter.IPv6Capability: what the probe found for the outbound, or
// for the member a group leads to; not known before the probe.
func (m *OutboundMonitoring) OutboundIPv6(tag string) (supported bool, known bool) {
	if m.reg() == nil {
		return false, false
	}
	his := m.getUrlTest(tag)
	if his == nil || his.IPv6 == nil {
		return false, false
	}
	return *his.IPv6, true
}

var _ adapter.IPv6Capability = (*OutboundMonitoring)(nil)
