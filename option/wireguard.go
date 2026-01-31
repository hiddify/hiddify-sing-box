package option

import (
	"net/netip"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json/badoption"
)

type WireGuardEndpointOptions struct {
	System                     bool                             `json:"system,omitempty"`
	Name                       string                           `json:"name,omitempty"`
	MTU                        uint32                           `json:"mtu,omitempty"`
	Address                    badoption.Listable[netip.Prefix] `json:"address"`
	PrivateKey                 string                           `json:"private_key"`
	ListenPort                 uint16                           `json:"listen_port,omitempty"`
	Peers                      []WireGuardPeer                  `json:"peers,omitempty"`
	UDPTimeout                 badoption.Duration               `json:"udp_timeout,omitempty"`
	UDPMapping                 UDPNATBehavior                   `json:"udp_mapping,omitempty"`
	UDPFiltering               UDPNATBehavior                   `json:"udp_filtering,omitempty"`
	UDPNATMax                  uint32                           `json:"udp_nat_max,omitempty"`
	Workers                    int                              `json:"workers,omitempty"`
	OnDemand                   bool                             `json:"on_demand,omitempty"`
	PreallocatedBuffersPerPool uint32                           `json:"preallocated_buffers_per_pool,omitempty"`
	DisablePauses              bool                             `json:"disable_pauses,omitempty"`
	Amnezia                    *WireGuardAmnezia                `json:"amnezia,omitempty"`
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
	WireGuardHiddify
}

type WireGuardWARPEndpointOptions struct {
	System                     bool               `json:"system,omitempty"`
	Name                       string             `json:"name,omitempty"`
	ListenPort                 uint16             `json:"listen_port,omitempty"`
	UDPTimeout                 badoption.Duration `json:"udp_timeout,omitempty"`
	Workers                    int                `json:"workers,omitempty"`
	PreallocatedBuffersPerPool uint32             `json:"preallocated_buffers_per_pool,omitempty"`
	DisablePauses              bool               `json:"disable_pauses,omitempty"`
	Amnezia                    *WireGuardAmnezia  `json:"amnezia,omitempty"`
	Profile                    WARPProfile        `json:"profile,omitempty"`
	DialerOptions

	UniqueIdentifier string `json:"unique_identifier,omitempty"` //h
	ServerOptions           //H
	WireGuardHiddify        //H
	*C.WARPConfig           //H
}

type WARPProfile struct {
	ID         string `json:"id,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	AuthToken  string `json:"auth_token,omitempty"`
	Recreate   bool   `json:"recreate,omitempty"`
	Detour     string `json:"detour,omitempty"`
	License    string `json:"license,omitempty"`
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
	PeerPublicKey              string            `json:"peer_public_key"`
	PreSharedKey               string            `json:"pre_shared_key,omitempty"`
	Reserved                   []uint8           `json:"reserved,omitempty"`
	Workers                    int               `json:"workers,omitempty"`
	PreallocatedBuffersPerPool uint32            `json:"preallocated_buffers_per_pool,omitempty"`
	DisablePauses              bool              `json:"disable_pauses,omitempty"`
	MTU                        uint32            `json:"mtu,omitempty"`
	Network                    NetworkList       `json:"network,omitempty"`
	Amnezia                    *WireGuardAmnezia `json:"amnezia,omitempty"`

	WireGuardHiddify
}

type LegacyWireGuardPeer struct {
	ServerOptions
	PublicKey    string                           `json:"public_key,omitempty"`
	PreSharedKey string                           `json:"pre_shared_key,omitempty"`
	AllowedIPs   badoption.Listable[netip.Prefix] `json:"allowed_ips,omitempty"`
	Reserved     []uint8                          `json:"reserved,omitempty"`
}

type WireGuardAmnezia struct {
	JC    int    `json:"jc,omitempty"`
	JMin  int    `json:"jmin,omitempty"`
	JMax  int    `json:"jmax,omitempty"`
	S1    int    `json:"s1,omitempty"`
	S2    int    `json:"s2,omitempty"`
	S3    int    `json:"s3,omitempty"`
	S4    int    `json:"s4,omitempty"`
	H1    uint32 `json:"h1,omitempty"`
	H2    uint32 `json:"h2,omitempty"`
	H3    uint32 `json:"h3,omitempty"`
	H4    uint32 `json:"h4,omitempty"`
	I1    string `json:"i1,omitempty"`
	I2    string `json:"i2,omitempty"`
	I3    string `json:"i3,omitempty"`
	I4    string `json:"i4,omitempty"`
	I5    string `json:"i5,omitempty"`
	J1    string `json:"j1,omitempty"`
	J2    string `json:"j2,omitempty"`
	J3    string `json:"j3,omitempty"`
	ITime int64  `json:"itime,omitempty"`
}
type WireGuardHiddify struct {
	FakePackets      string `json:"fake_packets,omitempty"`
	FakePacketsSize  string `json:"fake_packets_size,omitempty"`
	FakePacketsDelay string `json:"fake_packets_delay,omitempty"`
	FakePacketsMode  string `json:"fake_packets_mode,omitempty"`
}
