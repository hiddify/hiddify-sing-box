package wireguard

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	hiddify "github.com/sagernet/wireguard-go/hiddify"
)

type EndpointOptions struct {
	Context      context.Context
	Logger       logger.ContextLogger
	System       bool
	Handler      tun.Handler
	UDPTimeout   time.Duration
	ICMPTimeout  time.Duration
	UDPMapping   tun.NATMapping
	UDPFiltering tun.NATFiltering
	UDPNATMax    uint32

	InterfaceFinder            control.InterfaceFinder
	EgressPoolOptions          tun.UDPEgressPoolOptions
	Dialer                     N.Dialer
	CreateDialer               func(interfaceName string) N.Dialer
	Tag                        string
	Name                       string
	MTU                        uint32
	Address                    []netip.Prefix
	PrivateKey                 string
	ListenPort                 uint16
	ResolvePeer                func(domain string) ([]netip.Addr, error)
	Peers                      []PeerOptions
	Workers                    int
	PreallocatedBuffersPerPool uint32
	DisablePauses              bool
	Amnezia                    *AmneziaOptions
	Noise                      hiddify.NoiseOptions
}

type PeerOptions struct {
	Endpoint                    M.Socksaddr
	PublicKey                   string
	PreSharedKey                string
	AllowedIPs                  []netip.Prefix
	PersistentKeepaliveInterval uint16
	Reserved                    []uint8
}

type AmneziaOptions struct {
	JC    int
	JMin  int
	JMax  int
	S1    int
	S2    int
	S3    int
	S4    int
	H1    uint32
	H2    uint32
	H3    uint32
	H4    uint32
	I1    string
	I2    string
	I3    string
	I4    string
	I5    string
	J1    string
	J2    string
	J3    string
	ITime int64
}
