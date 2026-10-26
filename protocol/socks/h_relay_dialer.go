package socks

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func newClient(dialer N.Dialer, serverAddr M.Socksaddr, version socks.Version, username string, password string) *socks.Client {
	return socks.NewClient(&relayDialer{Dialer: dialer, serverAddr: serverAddr}, serverAddr, version, username, password)
}

// relayDialer dials the UDP relay of a UDP ASSOCIATE. Many SOCKS5 servers answer with an
// unspecified BND.ADDR (0.0.0.0 or ::) to mean "the address you reached me on"; dialing it
// as is reaches the local machine instead, so use the server's address with the given port.
type relayDialer struct {
	N.Dialer
	serverAddr M.Socksaddr
}

func (d *relayDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP && destination.IsIP() && destination.Addr.IsUnspecified() {
		destination = M.Socksaddr{Addr: d.serverAddr.Addr, Fqdn: d.serverAddr.Fqdn, Port: destination.Port}
	}
	return d.Dialer.DialContext(ctx, network, destination)
}

func (d *relayDialer) Upstream() any {
	return d.Dialer
}
