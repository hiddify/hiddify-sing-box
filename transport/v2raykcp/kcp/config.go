// Hiddify: Xray's mKCP config as a plain struct (Xray's is generated from protobuf), with the
// same fields and helpers. Under the Mozilla Public License 2.0, as Xray.

package kcp

// Config is the mKCP configuration, as Xray's kcp.Config.
type Config struct {
	Mtu              uint32
	Tti              uint32
	UplinkCapacity   uint32
	DownlinkCapacity uint32
	CwndMultiplier   uint32
	MaxSendingWindow uint32
}

func (c *Config) GetSendingInFlightSize() uint32 {
	size := c.UplinkCapacity * 1024 * 1024 / c.Mtu / (1000 / c.Tti)
	if size < 8 {
		size = 8
	}
	return size
}

func (c *Config) GetSendingBufferSize() uint32 {
	return c.MaxSendingWindow / c.Mtu
}

func (c *Config) GetReceivingInFlightSize() uint32 {
	size := c.DownlinkCapacity * 1024 * 1024 / c.Mtu / (1000 / c.Tti)
	if size < 8 {
		size = 8
	}
	return size
}
