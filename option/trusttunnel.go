package option

type TrustTunnelInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Users                   []TrustTunnelUser `json:"users,omitempty"`
	Network                 NetworkList       `json:"network,omitempty"`
	CongestionController    string            `json:"congestion_controller,omitempty"`
	CWND                    int               `json:"cwnd,omitempty"`
	DisablePathMTUDiscovery bool              `json:"disable_path_mtu_discovery,omitempty"`
}

type TrustTunnelUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type TrustTunnelMultiplexOptions struct {
	Enabled        bool `json:"enabled,omitempty"`
	MaxConnections int  `json:"max_connections,omitempty"`
	MinStreams     int  `json:"min_streams,omitempty"`
	MaxStreams     int  `json:"max_streams,omitempty"`
}

type TrustTunnelOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Username                string                       `json:"username,omitempty"`
	Password                string                       `json:"password,omitempty"`
	Network                 NetworkList                  `json:"network,omitempty"`
	HealthCheck             bool                         `json:"health_check,omitempty"`
	QUIC                    bool                         `json:"quic,omitempty"`
	CongestionController    string                       `json:"congestion_controller,omitempty"`
	CWND                    int                          `json:"cwnd,omitempty"`
	DisablePathMTUDiscovery bool                         `json:"disable_path_mtu_discovery,omitempty"`
	Multiplex               *TrustTunnelMultiplexOptions `json:"multiplex,omitempty"`
}
