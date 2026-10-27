package masque

import (
	"net"
	"net/netip"
	"time"

	tun "github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/tls"
)

type TunnelOptions struct {
	Handler              tun.Handler
	Dialer               N.Dialer
	Address              []netip.Prefix
	Endpoint             net.Addr
	TLSConfig            tls.Config
	UseHTTP2             bool
	UDPTimeout           time.Duration
	UDPKeepalivePeriod   time.Duration
	UDPInitialPacketSize uint16
	MTU                  uint32 // H: 0 is DefaultMTU
	ReconnectDelay       time.Duration
	// Mode is the HTTP version (ModeHTTP3, ModeHTTP2 or ModeAuto); empty follows UseHTTP2.
	Mode string
	// H2Endpoint is the HTTP/2 endpoint of ModeAuto (Endpoint is the HTTP/3 one).
	H2Endpoint net.Addr
	// OnConnected reports an endpoint that connected, and how long it took.
	OnConnected func(endpoint net.Addr, http2 bool, elapsed time.Duration)
	// NextEndpoint is asked for another endpoint after failed connects; nil keeps the endpoint.
	NextEndpoint func(failed net.Addr, http2 bool) net.Addr
}
