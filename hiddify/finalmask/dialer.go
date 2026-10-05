package finalmask

import (
	"net"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// WrapConn applies the tcp masks to a TCP connection and the udp masks to a connected UDP one.
func (m *Masks) WrapConn(conn net.Conn, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		if m.TCP == nil {
			return conn, nil
		}
		masked, err := m.TCP.WrapConnClient(conn)
		if err != nil {
			conn.Close()
			return nil, E.Cause(err, "final mask")
		}
		return masked, nil
	case N.NetworkUDP:
		if m.UDP == nil {
			return conn, nil
		}
		masked, err := m.UDP.WrapPacketConnClient(bufio.NewUnbindPacketConnWithAddr(conn, destination))
		if err != nil {
			conn.Close()
			return nil, E.Cause(err, "final mask")
		}
		return bufio.NewBindPacketConn(masked, conn.RemoteAddr()), nil
	}
	return conn, nil
}

// WrapPacketConn applies the udp masks.
func (m *Masks) WrapPacketConn(conn net.PacketConn) (net.PacketConn, error) {
	if m.UDP == nil {
		return conn, nil
	}
	masked, err := m.UDP.WrapPacketConnClient(conn)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "final mask")
	}
	return masked, nil
}
