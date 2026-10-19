package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/yosida95/uritemplate/v3"
)

type (
	DialContext  func(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket func(network string, address string) (net.PacketConn, error)
)

type IpConn interface {
	ReadPacket() (b []byte, err error)
	WritePacket(b []byte) (icmp []byte, err error)
	Close() error
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

type quicIpConn struct {
	conn *connectip.Conn
	buf  []byte
}

func newQuicIpConn(conn *connectip.Conn) *quicIpConn {
	return &quicIpConn{
		conn: conn,
		buf:  make([]byte, 0xFFFF),
	}
}

func (c *quicIpConn) ReadPacket() ([]byte, error) {
	n, err := c.conn.ReadPacket(c.buf, true)
	if err != nil {
		return nil, err
	}
	return c.buf[:n], nil
}

func (c *quicIpConn) WritePacket(b []byte) (icmp []byte, err error) {
	return c.conn.WritePacket(b)
}

func (c *quicIpConn) Close() error {
	return c.conn.Close()
}

func ConnectTunnel(ctx context.Context, dialer N.Dialer, tlsConfig aTLS.Config, quicConfig *quic.Config, connectUri string, endpoint net.Addr, useHTTP2 bool, congestionControl func(conn *quic.Conn) congestion.CongestionControl) (io.Closer, IpConn, *http.Response, error) {
	if useHTTP2 {
		h2Endpoint, ok := endpoint.(*net.TCPAddr)
		if !ok || h2Endpoint == nil {
			return nil, nil, nil, errors.New("missing HTTP/2 TCP endpoint")
		}
		return ConnectTunnelH2(ctx, dialer, tlsConfig, h2Endpoint, connectUri)
	}

	udpConn, conn, err := dialQUIC(ctx, dialer, tlsConfig, quicConfig, endpoint, congestionControl)
	if err != nil {
		return nil, nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.CloseWithError(0, "handshake canceled")
	})
	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			0x276: 1,
		},
		DisableCompression: true,
	}
	hconn := tr.NewClientConn(conn)

	template := uritemplate.MustNew(connectUri)
	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}
	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		stop()
		_ = tr.Close()
		_ = conn.CloseWithError(0, "connect-ip dial failed")
		_ = udpConn.Close()
		if strings.Contains(err.Error(), "tls: access denied") {
			return nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return nil, nil, rsp, fmt.Errorf("failed to dial connect-ip: %w", err)
	}
	err = ipConn.AdvertiseRoute(ctx, []connectip.IPRoute{
		{
			IPProtocol: 0,
			StartIP:    netip.AddrFrom4([4]byte{}),
			EndIP:      netip.AddrFrom4([4]byte{255, 255, 255, 255}),
		},
		{
			IPProtocol: 0,
			StartIP:    netip.AddrFrom16([16]byte{}),
			EndIP: netip.AddrFrom16([16]byte{
				255, 255, 255, 255,
				255, 255, 255, 255,
				255, 255, 255, 255,
				255, 255, 255, 255,
			}),
		},
	})
	if err == nil && !stop() {
		err = ctx.Err()
	}
	if err != nil {
		stop()
		_ = ipConn.Close()
		_ = tr.Close()
		_ = udpConn.Close()
		return nil, nil, nil, err
	}

	closer := closerFunc(func() error {
		_ = tr.Close()
		_ = udpConn.Close()
		return nil
	})
	return closer, newQuicIpConn(ipConn), rsp, nil
}

func dialQUIC(ctx context.Context, dialer N.Dialer, tlsConfig aTLS.Config, quicConfig *quic.Config, endpoint net.Addr, congestionControl func(conn *quic.Conn) congestion.CongestionControl) (net.PacketConn, *quic.Conn, error) {
	quicEndpoint, ok := endpoint.(*net.UDPAddr)
	if !ok || quicEndpoint == nil {
		return nil, nil, errors.New("missing HTTP/3 UDP endpoint")
	}
	endpointAddrPort := quicEndpoint.AddrPort()
	udpConn, err := dialer.ListenPacket(
		ctx,
		M.SocksaddrFromNetIP(
			netip.AddrPortFrom(
				endpointAddrPort.Addr().Unmap(),
				endpointAddrPort.Port(),
			),
		),
	)
	if err != nil {
		return nil, nil, err
	}
	conn, err := qtls.Dial(
		ctx,
		bufio.NewBindPacketConn(udpConn, quicEndpoint),
		NewTLSConfig(tlsConfig, 20),
		quicConfig,
	)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, err
	}
	if congestionControl != nil {
		conn.SetCongestionControl(congestionControl(conn))
	}
	return udpConn, conn, nil
}
