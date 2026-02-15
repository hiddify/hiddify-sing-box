package option

type MieruOutboundOptions struct {
	DialerOptions
	ServerOptions
	TransportInfo []MieruTransportPort `json:"transport_info,omitempty"`
	UserName      string               `json:"username,omitempty"`
	Password      string               `json:"password,omitempty"`
	Multiplexing  string               `json:"multiplexing,omitempty"`
	Network       NetworkList          `json:"network,omitempty"`
}

type MieruInboundOptions struct {
	ListenOptions
	Users         []MieruUser          `json:"users,omitempty"`
	TransportInfo []MieruTransportPort `json:"transport_info,omitempty"`
	Network       NetworkList          `json:"network,omitempty"`
}

type MieruTransportPort struct {
	Transport string `json:"transport,omitempty"`
	PortRange string `json:"port_range,omitempty"`
	Port      uint16 `json:"port,omitempty"`
}

type MieruUser struct {
	Name     string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}
