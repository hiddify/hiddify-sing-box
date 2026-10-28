package masque

import (
	"net"

	"github.com/sagernet/sing-box/common/wholepacket"
)

// WholePacketConn lets QUIC read through a proxy's packet connection (see wholepacket).
func WholePacketConn(conn net.PacketConn) net.PacketConn {
	return wholepacket.Wrap(conn)
}
