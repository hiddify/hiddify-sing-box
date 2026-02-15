package option

type MieruOutboundOptions struct {
	DialerOptions
	ServerOptions
	Network       NetworkList        `json:"network,omitempty"`
	PortBindings  []MieruPortBinding `json:"portBindings,omitempty"`
	UserName      string             `json:"username,omitempty"`
	Password      string             `json:"password,omitempty"`
	Multiplexing  string             `json:"multiplexing,omitempty"`
	HandshakeMode string             `json:"handshake_mode,omitempty"`
}

type MieruInboundOptions struct {
	ListenOptions
	Users        []MieruUser        `json:"users,omitempty"`
	PortBindings []MieruPortBinding `json:"portBindings,omitempty"`
	Network      NetworkList        `json:"network,omitempty"`
}

type MieruPortBinding struct {
	Protocol  string `json:"protocol,omitempty"`
	PortRange string `json:"portRange,omitempty"`
	Port      uint16 `json:"port,omitempty"`
}

type MieruUser struct {
	Name     string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}
