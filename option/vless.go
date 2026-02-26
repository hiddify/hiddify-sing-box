package option

type VLESSInboundOptions struct {
	ListenOptions
	Users      []VLESSUser `json:"users,omitempty"`
	Decryption string      `json:"decryption,omitempty"`
	InboundTLSOptionsContainer
	Multiplex *InboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport *V2RayTransportOptions   `json:"transport,omitempty"`
}

type VLESSUser struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
}

type VLESSOutboundOptions struct {
	DialerOptions
	ServerOptions
	UUID       string      `json:"uuid"`
	Flow       string      `json:"flow,omitempty"`
	Encryption string      `json:"encryption,omitempty"`
	Network    NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	Multiplex      *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport      *V2RayTransportOptions    `json:"transport,omitempty"`
	PacketEncoding *string                   `json:"packet_encoding,omitempty"`
}
