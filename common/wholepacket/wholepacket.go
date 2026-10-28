// Package wholepacket reads each packet of a proxy's packet connection whole.
//
// QUIC reads each packet into a buffer of about one packet. A proxy that decrypts in place in
// the caller's buffer (Shadowsocks) needs room for its own header and tag too, so a full packet
// was cut off, failed to decrypt ("cipher: message authentication failed"), and the read error
// ended the QUIC connection. Wrap reads each packet into a buffer large enough for any UDP
// payload, then copies it.
package wholepacket

import (
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// maxUDPPacket is the largest UDP payload.
const maxUDPPacket = 65535

var buffers = sync.Pool{New: func() any { return make([]byte, maxUDPPacket) }}

// Wrap returns conn reading whole packets in ReadFrom. A UDP socket, or a connection already
// wrapped, is returned as it is; the buffer-based packet methods are kept.
func Wrap(conn net.PacketConn) net.PacketConn {
	switch conn.(type) {
	case *net.UDPConn, *packetConn, *netPacketConn:
		return conn
	}
	if netConn, isNet := conn.(N.NetPacketConn); isNet {
		return &netPacketConn{NetPacketConn: netConn}
	}
	return &packetConn{PacketConn: conn}
}

func readWhole(conn net.PacketConn, p []byte) (int, net.Addr, error) {
	if len(p) >= maxUDPPacket {
		return conn.ReadFrom(p)
	}
	buffer := buffers.Get().([]byte)
	defer buffers.Put(buffer)
	n, addr, err := conn.ReadFrom(buffer)
	return copy(p, buffer[:n]), addr, err
}

type packetConn struct {
	net.PacketConn
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return readWhole(c.PacketConn, p)
}

func (c *packetConn) Upstream() any {
	return c.PacketConn
}

type netPacketConn struct {
	N.NetPacketConn
}

func (c *netPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return readWhole(c.NetPacketConn, p)
}

// ReadPacket reads the packet whole too, for readers that use the buffer-based methods.
func (c *netPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if buffer.FreeLen() >= maxUDPPacket {
		return c.NetPacketConn.ReadPacket(buffer)
	}
	whole := buf.NewSize(maxUDPPacket)
	defer whole.Release()
	destination, err := c.NetPacketConn.ReadPacket(whole)
	if err != nil {
		return destination, err
	}
	_, err = buffer.Write(whole.Bytes()[:min(whole.Len(), buffer.FreeLen())])
	return destination, err
}

func (c *netPacketConn) Upstream() any {
	return c.NetPacketConn
}
