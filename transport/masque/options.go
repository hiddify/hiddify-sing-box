package masque

import (
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/tls"
)

type TunnelOptions struct {
	System               bool
	Name                 string
	CreateDialer         func(interfaceName string) N.Dialer
	Dialer               N.Dialer
	Address              []netip.Prefix
	AllowedAddress       []netip.Prefix
	Endpoint             net.Addr
	TLSConfig            tls.Config
	UseHTTP2             bool
	UDPTimeout           time.Duration
	UDPKeepalivePeriod   time.Duration
	UDPInitialPacketSize uint16
	ReconnectDelay       time.Duration
	HandshakeTimeout     time.Duration
	CongestionControl    func(conn *quic.Conn) congestion.CongestionControl
}
