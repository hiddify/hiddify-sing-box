package wholepacket

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// hInPlacePacketConn decrypts in the caller's buffer like a Shadowsocks client: a buffer too
// small for the packet with its overhead fails, as a cut-off ciphertext fails to authenticate.
type hInPlacePacketConn struct {
	net.PacketConn
	packet   []byte
	overhead int
}

func (c *hInPlacePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(p) < len(c.packet)+c.overhead {
		return 0, nil, errors.New("cipher: message authentication failed")
	}
	return copy(p, c.packet), &net.UDPAddr{IP: net.IPv4(162, 159, 198, 1), Port: 443}, nil
}

func TestH_Wrap(t *testing.T) {
	packet := bytes.Repeat([]byte{0x42}, 1452) // a full QUIC packet
	conn := &hInPlacePacketConn{packet: packet, overhead: 39}
	buffer := make([]byte, 1452) // what QUIC reads into

	_, _, err := conn.ReadFrom(buffer)
	require.Error(t, err, "the packet does not fit with the proxy's overhead")

	n, addr, err := Wrap(conn).ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, packet, buffer[:n])
	require.Equal(t, "162.159.198.1:443", addr.String())

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer udpConn.Close()
	require.Same(t, udpConn, Wrap(udpConn), "a UDP socket needs no copy")
	wrapped := Wrap(conn)
	require.Same(t, wrapped, Wrap(wrapped), "wrapped once")
}
