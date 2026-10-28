package masque

import (
	"net"
	"sync"
)

// maxUDPPacket is the largest UDP payload.
const maxUDPPacket = 65535

var packetBuffers = sync.Pool{New: func() any { return make([]byte, maxUDPPacket) }}

// WholePacketConn lets QUIC read through a proxy's packet connection. QUIC reads each packet
// into a buffer of about one packet, but a proxy that decrypts in place (Shadowsocks) needs room
// for its own header and tag too: a full packet was cut off and failed to decrypt, which ended
// the QUIC connection. Each packet is read whole here, then copied.
func WholePacketConn(conn net.PacketConn) net.PacketConn {
	if _, isUDP := conn.(*net.UDPConn); isUDP {
		return conn
	}
	return &wholePacketConn{PacketConn: conn}
}

type wholePacketConn struct {
	net.PacketConn
}

func (c *wholePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(p) >= maxUDPPacket {
		return c.PacketConn.ReadFrom(p)
	}
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	n, addr, err := c.PacketConn.ReadFrom(buffer)
	return copy(p, buffer[:n]), addr, err
}
