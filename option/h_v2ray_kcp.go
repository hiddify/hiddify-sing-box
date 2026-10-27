package option

// V2RayKCPOptions configures the mKCP transport, as Xray 26's kcpSettings. The header and seed of
// older mKCP are finalmask UDP masks now (mkcp-original, mkcp-aes128gcm, header-*), as in Xray.
type V2RayKCPOptions struct {
	MTU              uint32 `json:"mtu,omitempty"`
	TTI              uint32 `json:"tti,omitempty"`
	UplinkCapacity   uint32 `json:"uplink_capacity,omitempty"`
	DownlinkCapacity uint32 `json:"downlink_capacity,omitempty"`
	CwndMultiplier   uint32 `json:"cwnd_multiplier,omitempty"`
	MaxSendingWindow uint32 `json:"max_sending_window,omitempty"`
}
