//go:build with_kcp

package v2raykcp

import (
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/sagernet/sing-box/transport/v2raykcp/kcp"
)

// newConfig builds Xray's mKCP config with Xray's defaults and checks.
func newConfig(options option.V2RayKCPOptions) (*kcp.Config, error) {
	config := &kcp.Config{
		Mtu:              1350,
		Tti:              50,
		UplinkCapacity:   5,
		DownlinkCapacity: 20,
		CwndMultiplier:   1,
		MaxSendingWindow: 2 * 1024 * 1024,
	}
	if options.MTU != 0 {
		config.Mtu = options.MTU
	}
	if options.TTI != 0 {
		config.Tti = options.TTI
	}
	if options.UplinkCapacity != 0 {
		config.UplinkCapacity = options.UplinkCapacity
	}
	if options.DownlinkCapacity != 0 {
		config.DownlinkCapacity = options.DownlinkCapacity
	}
	if options.CwndMultiplier != 0 {
		config.CwndMultiplier = options.CwndMultiplier
	}
	if options.MaxSendingWindow != 0 {
		config.MaxSendingWindow = options.MaxSendingWindow
	}
	if config.Mtu < 21 {
		return nil, E.New("mKCP mtu must be at least 21")
	}
	if config.Tti < 10 || config.Tti > 1000 {
		return nil, E.New("mKCP tti must be between 10 and 1000")
	}
	if config.GetSendingBufferSize() == 0 {
		return nil, E.New("mKCP max_sending_window must be at least the mtu")
	}
	return config, nil
}
