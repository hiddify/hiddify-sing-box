//go:build with_kcp

package v2raykcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type hEchoHandler struct{}

func (hEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	io.Copy(conn, conn)
}

func hStartServer(t *testing.T, options option.V2RayKCPOptions) M.Socksaddr {
	t.Helper()
	server, err := NewServer(context.Background(), log.NewNOPFactory().Logger(), options, nil, hEchoHandler{})
	require.NoError(t, err)
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, server.ServePacket(listener))
	t.Cleanup(func() { server.Close() })
	return M.SocksaddrFromNet(listener.LocalAddr())
}

// several sessions at once carry a megabyte each through the server and back
func TestH_KCPRoundTrip(t *testing.T) {
	serverAddr := hStartServer(t, option.V2RayKCPOptions{})
	client, err := NewClient(context.Background(), N.SystemDialer, serverAddr, option.V2RayKCPOptions{UplinkCapacity: 50, DownlinkCapacity: 50}, nil)
	require.NoError(t, err)
	errs := make(chan error, 3)
	for range 3 {
		go func() {
			errs <- hEcho(client, 1<<20)
		}()
	}
	for range 3 {
		require.NoError(t, <-errs)
	}
}

func hEcho(client interface {
	DialContext(context.Context) (net.Conn, error)
}, size int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	payload := make([]byte, size)
	rand.Read(payload)
	go conn.Write(payload)
	reply := make([]byte, size)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if !bytes.Equal(payload, reply) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestH_KCPOptions(t *testing.T) {
	_, err := newConfig(option.V2RayKCPOptions{MTU: 10})
	require.Error(t, err)
	_, err = newConfig(option.V2RayKCPOptions{TTI: 5})
	require.Error(t, err)
	config, err := newConfig(option.V2RayKCPOptions{})
	require.NoError(t, err)
	require.EqualValues(t, 1350, config.Mtu)
}
