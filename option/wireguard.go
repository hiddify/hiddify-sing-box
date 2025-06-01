package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type WireGuardEndpointOptions struct {
	System       bool                             `json:"system,omitempty"`
	Name         string                           `json:"name,omitempty"`
	MTU          uint32                           `json:"mtu,omitempty"`
	Address      badoption.Listable[netip.Prefix] `json:"address"`
	PrivateKey   string                           `json:"private_key"`
	ListenPort   uint16                           `json:"listen_port,omitempty"`
	Peers        []WireGuardPeer                  `json:"peers,omitempty"`
	UDPTimeout   badoption.Duration               `json:"udp_timeout,omitempty"`
	UDPMapping   UDPNATBehavior                   `json:"udp_mapping,omitempty"`
	UDPFiltering UDPNATBehavior                   `json:"udp_filtering,omitempty"`
	UDPNATMax    uint32                           `json:"udp_nat_max,omitempty"`
	Workers      int                              `json:"workers,omitempty"`
	OnDemand     bool                             `json:"on_demand,omitempty"`
	Amnezia      *WireGuardAmnezia                `json:"amnezia,omitempty"`
	DialerOptions
}

type WireGuardPeer struct {
	Address                     string                           `json:"address,omitempty"`
	Port                        uint16                           `json:"port,omitempty"`
	PublicKey                   string                           `json:"public_key,omitempty"`
	PreSharedKey                string                           `json:"pre_shared_key,omitempty"`
	AllowedIPs                  badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	PersistentKeepaliveInterval uint16                           `json:"persistent_keepalive_interval,omitempty"`
	Reserved                    []uint8                          `json:"reserved,omitempty"`

	FakePackets      string `json:"fake_packets,omitempty"`
	FakePacketsSize  string `json:"fake_packets_size,omitempty"`
	FakePacketsDelay string `json:"fake_packets_delay,omitempty"`
	FakePacketsMode  string `json:"fake_packets_mode,omitempty"`
}

type WireGuardWarpEndpointOptions struct {
	System     bool                  `json:"system,omitempty"`
	Name       string                `json:"name,omitempty"`
	ListenPort uint16                `json:"listen_port,omitempty"`
	UDPTimeout badoption.Duration    `json:"udp_timeout,omitempty"`
	Workers    int                   `json:"workers,omitempty"`
	Amnezia    *WireGuardAmnezia     `json:"amnezia,omitempty"`
	Profile    *WireGuardWarpProfile `json:"profile,omitempty"`
	DialerOptions
}

type WireGuardWarpProfile struct {
	Detour   string `json:"detour,omitempty"`
	Recreate bool   `json:"recreate,omitempty"`
}

type LegacyWireGuardOutboundOptions struct {
	DialerOptions
	SystemInterface bool                             `json:"system_interface,omitempty"`
	GSO             bool                             `json:"gso,omitempty"`
	InterfaceName   string                           `json:"interface_name,omitempty"`
	LocalAddress    badoption.Listable[netip.Prefix] `json:"local_address"`
	PrivateKey      string                           `json:"private_key"`
	Peers           []LegacyWireGuardPeer            `json:"peers,omitempty"`
	ServerOptions
	PeerPublicKey string            `json:"peer_public_key"`
	PreSharedKey  string            `json:"pre_shared_key,omitempty"`
	Reserved      []uint8           `json:"reserved,omitempty"`
	Workers       int               `json:"workers,omitempty"`
	MTU           uint32            `json:"mtu,omitempty"`
	Network       NetworkList       `json:"network,omitempty"`
	Amnezia       *WireGuardAmnezia `json:"amnezia,omitempty"`
}

type LegacyWireGuardPeer struct {
	ServerOptions
	PublicKey    string                           `json:"public_key,omitempty"`
	PreSharedKey string                           `json:"pre_shared_key,omitempty"`
	AllowedIPs   badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	Reserved     []uint8                          `json:"reserved,omitempty"`
}

type WireGuardAmnezia struct {
	JC   int    `json:"jc,omitempty"`
	JMin int    `json:"jmin,omitempty"`
	JMax int    `json:"jmax,omitempty"`
	S1   int    `json:"s1,omitempty"`
	S2   int    `json:"s2,omitempty"`
	H1   uint32 `json:"h1,omitempty"`
	H2   uint32 `json:"h2,omitempty"`
	H3   uint32 `json:"h3,omitempty"`
	H4   uint32 `json:"h4,omitempty"`
}
