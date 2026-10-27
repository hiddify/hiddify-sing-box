package vless

import (
	"context"
	"errors"
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

// hBadServer accepts one connection, answers with garbage, and reports whether the client
// closed its side afterwards (a leaked client conn never does).
func hBadServer(t *testing.T) (uint16, <-chan bool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	closedByClient := make(chan bool, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n" + string(make([]byte, 2048))))
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err = io.Copy(io.Discard, conn)
		// EOF or a reset means the client closed its side; only the read deadline means it leaked
		var netErr net.Error
		closedByClient <- !(errors.As(err, &netErr) && netErr.Timeout())
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port), closedByClient
}

func hNewVLESSOutbound(t *testing.T, port uint16, encryption string, tlsOptions *option.OutboundTLSOptions) *Outbound {
	t.Helper()
	outbound, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "vless", option.VLESSOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		UUID:                        "b831381d-6324-4d53-ad4f-8cda48b30811",
		Encryption:                  encryption,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions},
	})
	require.NoError(t, err)
	return outbound.(*Outbound)
}

func TestH_VLESSEncryptionHandshakeFailure(t *testing.T) {
	_, clientX25519, _, _ := generateKeyStrings(t)
	encryption := "mlkem768x25519plus.native.1rtt." + clientX25519
	t.Run("dial", func(t *testing.T) {
		port, closedByClient := hBadServer(t)
		outbound := hNewVLESSOutbound(t, port, encryption, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
		require.Error(t, err)
		require.True(t, <-closedByClient, "the TCP connection leaked after a failed encryption handshake")
	})
	t.Run("listen packet", func(t *testing.T) {
		port, closedByClient := hBadServer(t)
		outbound := hNewVLESSOutbound(t, port, encryption, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := outbound.ListenPacket(ctx, M.ParseSocksaddr("example.com:443"))
		require.Error(t, err)
		require.True(t, <-closedByClient, "the TCP connection leaked after a failed encryption handshake")
	})
}

func TestH_VLESSTLSHandshakeFailureClosesConn(t *testing.T) {
	for _, network := range []string{"dial", "listen packet"} {
		t.Run(network, func(t *testing.T) {
			port, closedByClient := hBadServer(t)
			outbound := hNewVLESSOutbound(t, port, "", &option.OutboundTLSOptions{Enabled: true, ServerName: "example.com", Insecure: true})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var err error
			if network == "dial" {
				_, err = outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
			} else {
				_, err = outbound.ListenPacket(ctx, M.ParseSocksaddr("example.com:443"))
			}
			require.Error(t, err)
			require.True(t, <-closedByClient, "the TCP connection leaked after a failed TLS handshake")
		})
	}
}

// A server that accepts and never answers must not hold the encryption handshake past the
// caller's context; a URL test or dial would otherwise hang for good.
func TestH_VLESSEncryptionHandshakeHonoursContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	_, clientX25519, _, _ := generateKeyStrings(t)
	outbound := hNewVLESSOutbound(t, uint16(listener.Addr().(*net.TCPAddr).Port), "mlkem768x25519plus.native.1rtt."+clientX25519, nil)
	for _, network := range []string{"dial", "listen packet"} {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		start := time.Now()
		if network == "dial" {
			_, err = outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
		} else {
			_, err = outbound.ListenPacket(ctx, M.ParseSocksaddr("example.com:443"))
		}
		cancel()
		require.Error(t, err, network)
		require.Less(t, time.Since(start), 2*time.Second, network)
	}
}
