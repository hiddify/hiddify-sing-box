package monitoring

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// dnsTunnelTypes carry their traffic inside DNS queries through recursive resolvers: a request
// takes several DNS exchanges each way, and the server looks up the test URL's host on top, so a
// working one can need longer than the URL test timeout.
var dnsTunnelTypes = map[string]bool{
	C.TypeDNSTT:     true,
	C.TypeMasterDNS: true,
	C.TypeSoar:      true,
}

// dnsTunnelTimeoutFactor scales every timeout of a test that goes over a DNS tunnel.
const dnsTunnelTimeoutFactor = 3

// timeoutFactor is dnsTunnelTimeoutFactor when the outbound's traffic goes over a DNS tunnel:
// it is one, a group selects one, or it dials through one; else 1.
func (m *OutboundMonitoring) timeoutFactor(out adapter.Outbound) time.Duration {
	if m.overDNSTunnel(out, m.reg().outbounds, maxGroupDepth) {
		return dnsTunnelTimeoutFactor
	}
	return 1
}

func (m *OutboundMonitoring) overDNSTunnel(out adapter.Outbound, outbounds map[string]*outboundState, depth int) bool {
	if out == nil || depth == 0 {
		return false
	}
	if dnsTunnelTypes[out.Type()] {
		return true
	}
	if group, isGroup := out.(adapter.OutboundGroup); isGroup {
		return m.overDNSTunnel(group.Selected(N.NetworkTCP), outbounds, depth-1)
	}
	for _, dependency := range out.Dependencies() {
		if state, ok := outbounds[dependency]; ok && m.overDNSTunnel(state.outbound, outbounds, depth-1) {
			return true
		}
	}
	return false
}
