package socks

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

// hRecordingDialer dials TCP for real and records the UDP addresses it is asked to dial.
type hRecordingDialer struct {
	access sync.Mutex
	udp    []M.Socksaddr
}

func (d *hRecordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		d.access.Lock()
		d.udp = append(d.udp, destination)
		d.access.Unlock()
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (d *hRecordingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}

// hSOCKS5Server accepts one UDP ASSOCIATE and answers with BND.ADDR 0.0.0.0, as many servers
// do to mean "the address you reached me on".
func hSOCKS5Server(t *testing.T, relayPort uint16) M.Socksaddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		greeting := make([]byte, 3)
		if _, err = io.ReadFull(conn, greeting); err != nil {
			return
		}
		conn.Write([]byte{5, 0})
		request := make([]byte, 10)
		if _, err = io.ReadFull(conn, request); err != nil {
			return
		}
		reply := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(reply[8:], relayPort)
		conn.Write(reply)
		io.Copy(io.Discard, conn)
	}()
	return M.SocksaddrFromNet(listener.Addr())
}

func TestH_SOCKSUnspecifiedRelayAddress(t *testing.T) {
	server := hSOCKS5Server(t, 40000)
	recorder := &hRecordingDialer{}
	client := newClient(recorder, server, socks.Version5, "", "")
	conn, err := client.DialContext(context.Background(), N.NetworkUDP, M.ParseSocksaddr("1.1.1.1:53"))
	require.NoError(t, err)
	conn.Close()
	require.Equal(t, []M.Socksaddr{M.ParseSocksaddr("127.0.0.1:40000")}, recorder.udp,
		"an unspecified relay address means the server's own address")
}
