package dialer

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type DirectDialer interface {
	IsEmpty() bool
}

type DetourDialer struct {
	outboundManager         adapter.OutboundManager
	detour                  string
	defaultOutbound         bool
	disableEmptyDirectCheck bool
	legacyDNSDialer         bool
	// H: the last resolution; redone when another outbound is registered under the tag
	// (hot reload replaces outbounds), instead of keeping the first one forever
	resolved atomic.Pointer[detourResolution]
}

type detourResolution struct {
	outbound adapter.Outbound
	dialer   N.Dialer
	err      error
}

func NewDetour(outboundManager adapter.OutboundManager, detour string, disableEmptyDirectCheck bool) N.Dialer {
	return &DetourDialer{
		outboundManager:         outboundManager,
		detour:                  detour,
		disableEmptyDirectCheck: disableEmptyDirectCheck,
	}
}

func NewLegacyDNSDetour(outboundManager adapter.OutboundManager, detour string) N.Dialer {
	return &DetourDialer{
		outboundManager: outboundManager,
		detour:          detour,
		legacyDNSDialer: true,
	}
}

func NewDefaultOutboundDetour(outboundManager adapter.OutboundManager) N.Dialer {
	return &DetourDialer{
		outboundManager: outboundManager,
		defaultOutbound: true,
	}
}

func InitializeDetour(dialer N.Dialer) error {
	detourDialer, isDetour := common.Cast[*DetourDialer](dialer)
	if !isDetour {
		return nil
	}
	return common.Error(detourDialer.Dialer())
}

func (d *DetourDialer) Dialer() (N.Dialer, error) {
	var current adapter.Outbound
	if d.detour != "" {
		current, _ = d.outboundManager.Outbound(d.detour)
	} else {
		current = d.outboundManager.Default()
	}
	if last := d.resolved.Load(); last != nil && last.outbound == current {
		return last.dialer, last.err
	}
	resolution := &detourResolution{outbound: current}
	resolution.dialer, resolution.err = d.check(current)
	d.resolved.Store(resolution)
	return resolution.dialer, resolution.err
}

func (d *DetourDialer) check(dialer adapter.Outbound) (N.Dialer, error) {
	if dialer == nil {
		if d.detour != "" {
			return nil, E.New("outbound detour not found: ", d.detour)
		}
		return nil, E.New("missing default outbound")
	}
	if !d.defaultOutbound && !d.disableEmptyDirectCheck && !d.legacyDNSDialer {
		if directDialer, isDirect := dialer.(DirectDialer); isDirect {
			if directDialer.IsEmpty() {
				return nil, E.New("detour to an empty direct outbound makes no sense")
			}
		}
	}
	return dialer, nil
}

func (d *DetourDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dialer, err := d.Dialer()
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, destination)
}

func (d *DetourDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	dialer, err := d.Dialer()
	if err != nil {
		return nil, err
	}
	return dialer.ListenPacket(ctx, destination)
}

func (d *DetourDialer) Upstream() any {
	detour, _ := d.Dialer()
	return detour
}
