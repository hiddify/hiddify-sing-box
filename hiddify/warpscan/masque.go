package warpscan

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

// The ranges and port of Cloudflare's WARP MASQUE endpoints.
var (
	MASQUEPorts = []uint16{443}
	MASQUECIDRs = []netip.Prefix{
		netip.MustParsePrefix("162.159.198.0/24"),
		netip.MustParsePrefix("2606:4700:103::/64"),
	}
)

// MASQUEProbe probes with the handshake the MASQUE tunnel starts with: QUIC with its TLS
// configuration, or TLS over TCP when it uses HTTP/2.
func MASQUEProbe(dialer N.Dialer, tlsConfig aTLS.Config, useHTTP2 bool) Probe {
	if useHTTP2 {
		h2Config := tlsConfig.Clone()
		h2Config.SetNextProtos([]string{"h2"})
		return func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
			start := time.Now()
			conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.SocksaddrFromNetIP(addrPort))
			if err != nil {
				return 0, err
			}
			defer conn.Close()
			tlsConn, err := aTLS.ClientHandshake(ctx, conn, h2Config)
			if err != nil {
				return 0, err
			}
			tlsConn.Close()
			return time.Since(start), nil
		}
	}
	return func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
		start := time.Now()
		packetConn, err := dialer.ListenPacket(ctx, M.SocksaddrFromNetIP(addrPort))
		if err != nil {
			return 0, err
		}
		defer packetConn.Close()
		conn, err := qtls.Dial(ctx, bufio.NewBindPacketConn(packetConn, M.SocksaddrFromNetIP(addrPort).UDPAddr()), tlsConfig, &quic.Config{})
		if err != nil {
			return 0, err
		}
		conn.CloseWithError(0, "")
		return time.Since(start), nil
	}
}
