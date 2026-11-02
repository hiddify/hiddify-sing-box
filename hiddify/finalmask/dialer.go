package finalmask

import (
	"context"
	"net"
	"slices"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	xnet "github.com/xtls/xray-core/common/net"
	xfinalmask "github.com/xtls/xray-core/transport/internet/finalmask"
)

// DialFunc and ListenPacketFunc open the sockets under the masks: those of the connection, and
// those a mask opens itself, such as the resolvers of xdns.
type (
	DialFunc         func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacketFunc func(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
)

// finalMask makes Xray's FinalMask over the given sockets. NewFinalMask reverses its slices, so
// it gets copies.
func (m *Masks) finalMask(
	dialTCP func(context.Context, xnet.Destination) (net.Conn, error),
	dialUDP func(context.Context, xnet.Destination) (net.PacketConn, net.Addr, error),
	listenPacket func(context.Context, net.Addr) (net.PacketConn, error),
) *xfinalmask.FinalMask {
	listen := func(context.Context, net.Addr) (net.Listener, error) {
		return nil, E.New("final mask: listen is not supported")
	}
	if listenPacket == nil {
		listenPacket = func(context.Context, net.Addr) (net.PacketConn, error) {
			return nil, E.New("final mask: listen is not supported")
		}
	}
	return xfinalmask.NewFinalMask(slices.Clone(m.tcp), slices.Clone(m.udp), dialTCP, listen, dialUDP, listenPacket)
}

// DialContext opens a TCP connection, or a connected UDP one, through the masks, with dial for
// every TCP socket and listen for every UDP one.
func (m *Masks) DialContext(ctx context.Context, network string, destination M.Socksaddr, dial DialFunc, listen ListenPacketFunc) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		if !m.HasTCP() {
			return dial(ctx, network, destination)
		}
		return m.finalMask(dialTCPFunc(dial), dialUDPFunc(dial, listen), nil).DialTCP(ctx, xrayDestination(xnet.Network_TCP, destination))
	case N.NetworkUDP:
		if !m.HasUDP() {
			return dial(ctx, network, destination)
		}
		conn, err := m.finalMask(dialTCPFunc(dial), dialUDPFunc(dial, listen), nil).DialUDP(ctx, xrayDestination(xnet.Network_UDP, destination))
		if err != nil {
			return nil, err
		}
		wrapper := conn.(*xnet.PacketConnWrapper)
		return bufio.NewBindPacketConn(wrapper.PacketConn, wrapper.Dest), nil
	}
	return dial(ctx, network, destination)
}

// ListenPacket opens an unconnected UDP socket through the udp masks, with listen for the socket
// itself and dial for the TCP ones a mask opens.
func (m *Masks) ListenPacket(ctx context.Context, destination M.Socksaddr, dial DialFunc, listen ListenPacketFunc) (net.PacketConn, error) {
	if !m.HasUDP() {
		return listen(ctx, destination)
	}
	conn, err := m.finalMask(dialTCPFunc(dial), dialUDPFunc(dial, listen), nil).DialUDP(ctx, xrayDestination(xnet.Network_UDP, destination))
	if err != nil {
		return nil, err
	}
	return conn.(*xnet.PacketConnWrapper).PacketConn, nil
}

// WrapConnServer applies the tcp masks to an accepted connection, as an Xray server does.
func (m *Masks) WrapConnServer(conn net.Conn) (net.Conn, error) {
	for i := len(m.tcp) - 1; i >= 0; i-- {
		masked, err := m.tcp[i].WrapConnServer(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = masked
	}
	return conn, nil
}

// WrapPacketConnServer applies the udp masks to a listening socket, as an Xray server does.
func (m *Masks) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	if !m.HasUDP() {
		return conn, nil
	}
	listenPacket := func(context.Context, net.Addr) (net.PacketConn, error) {
		return conn, nil
	}
	return m.finalMask(nil, nil, listenPacket).ListenPacket(context.Background(), conn.LocalAddr())
}

func dialTCPFunc(dial DialFunc) func(context.Context, xnet.Destination) (net.Conn, error) {
	return func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		return dial(ctx, N.NetworkTCP, socksaddr(dest))
	}
}

// dialUDPFunc opens the UDP sockets Xray asks for. As in Xray, a socket to an IP address is not
// connected, so a mask can send to another address on it (udphop moves to another port that way),
// and its address is a *net.UDPAddr (udphop needs one). A domain, which only a mask's own setting
// gives (an xdns resolver), is dialed connected instead.
func dialUDPFunc(dial DialFunc, listen ListenPacketFunc) func(context.Context, xnet.Destination) (net.PacketConn, net.Addr, error) {
	return func(ctx context.Context, dest xnet.Destination) (net.PacketConn, net.Addr, error) {
		address := socksaddr(dest)
		if address.IsIP() {
			conn, err := listen(ctx, address)
			if err != nil {
				return nil, nil, err
			}
			return conn, address.UDPAddr(), nil
		}
		conn, err := dial(ctx, N.NetworkUDP, address)
		if err != nil {
			return nil, nil, err
		}
		remoteAddr := conn.RemoteAddr()
		if remote := M.SocksaddrFromNet(remoteAddr); remote.IsIP() {
			remoteAddr = remote.UDPAddr()
		}
		return bufio.NewUnbindPacketConnWithAddr(conn, address), remoteAddr, nil
	}
}

func xrayDestination(network xnet.Network, destination M.Socksaddr) xnet.Destination {
	dest := xnet.Destination{Network: network, Port: xnet.Port(destination.Port)}
	switch {
	case destination.IsFqdn():
		dest.Address = xnet.DomainAddress(destination.Fqdn)
	case destination.IsIP():
		dest.Address = xnet.IPAddress(destination.Addr.Unmap().AsSlice())
	default:
		dest.Address = xnet.AnyIP
	}
	return dest
}

func socksaddr(dest xnet.Destination) M.Socksaddr {
	if dest.Address == nil {
		return M.Socksaddr{Port: uint16(dest.Port)}
	}
	if dest.Address.Family().IsDomain() {
		return M.ParseSocksaddrHostPort(dest.Address.Domain(), uint16(dest.Port))
	}
	return M.SocksaddrFrom(M.AddrFromIP(dest.Address.IP()), uint16(dest.Port))
}

// XrayFinalMask is an Xray FinalMask with the masks of m, nil for none, that opens every socket
// with dial and listen: Xray code that dials through a FinalMask (XDRIVE) then uses the sing-box
// dialer.
func (m *Masks) XrayFinalMask(dial DialFunc, listen ListenPacketFunc) *xfinalmask.FinalMask {
	if m == nil {
		m = &Masks{}
	}
	return m.finalMask(dialTCPFunc(dial), dialUDPFunc(dial, listen), nil)
}
