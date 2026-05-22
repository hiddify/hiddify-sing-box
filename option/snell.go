package option

// SnellUser is one entry in a multi-user Snell inbound configuration.
type SnellUser struct {
	Name string `json:"name"`
	PSK  string `json:"psk"`
}

type SnellInboundOptions struct {
	ListenOptions
	// PSK is the pre-shared key for single-user mode.
	// Mutually exclusive with Users.
	PSK     string `json:"psk,omitempty"`
	Version int    `json:"version,omitempty"`
	// Users enables multi-user mode.  When set, PSK must be empty.
	Users    []SnellUser `json:"users,omitempty"`
	ObfsMode string      `json:"obfs_mode,omitempty"`
	ObfsHost string      `json:"obfs_host,omitempty"`
}

type SnellOutboundOptions struct {
	DialerOptions
	ServerOptions
	PSK      string      `json:"psk"`
	Version  int         `json:"version,omitempty"`
	Reuse    bool        `json:"reuse,omitempty"`
	Network  NetworkList `json:"network,omitempty"`
	ObfsMode string      `json:"obfs_mode,omitempty"`
	ObfsHost string      `json:"obfs_host,omitempty"`
}
