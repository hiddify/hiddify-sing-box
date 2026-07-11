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
	ReconnectDelay       time.Duration
}
