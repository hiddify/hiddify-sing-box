package trojan

import (
	"context"
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

// A trojan outbound whose tls block is present but disabled dials in plain TCP,
// instead of handshaking with a nil TLS config.
func TestH_TrojanOutboundTLSDisabled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 56)
		_, err = io.ReadFull(conn, buffer)
		if err == nil {
			received <- buffer
		}
	}()
	for _, tlsOptions := range []*option.OutboundTLSOptions{{}, {Enabled: false}} {
		port := uint16(listener.Addr().(*net.TCPAddr).Port)
		outbound, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "trojan", option.TrojanOutboundOptions{
			ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
			Password:                    "password",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions},
		})
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
		cancel()
		require.NoError(t, err)
		_, err = conn.Write([]byte("x"))
		require.NoError(t, err)
		conn.Close()
		select {
		case header := <-received:
			// the trojan request starts with the hex SHA-224 of the password, sent in clear
			require.Len(t, header, 56)
		case <-time.After(5 * time.Second):
			t.Fatal("the server got no trojan request")
		}
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buffer := make([]byte, 56)
			if _, err = io.ReadFull(conn, buffer); err == nil {
				received <- buffer
			}
		}()
	}
}
