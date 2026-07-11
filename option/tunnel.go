package option

import "github.com/sagernet/sing/common/json/badoption"

type TunnelClientEndpointOptions struct {
	UUID     string   `json:"uuid"`
	Key      string   `json:"key"`
	Outbound Outbound `json:"outbound"`
}

type TunnelServerEndpointOptions struct {
	UUID           string             `json:"uuid"`
	Users          []TunnelUser       `json:"users"`
	Inbound        Inbound            `json:"inbound"`
	ConnectTimeout badoption.Duration `json:"connect_timeout,omitempty"`
}

type TunnelUser struct {
	UUID string `json:"uuid"`
	Key  string `json:"key"`
}
