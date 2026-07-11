package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

type (
	DialContext  func(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket func(network string, address string) (net.PacketConn, error)
)

func ConnectTunnel(ctx context.Context, dialer N.Dialer, tlsConfig aTLS.Config, quicConfig *quic.Config, connectUri string, endpoint net.Addr, useHTTP2 bool) (net.PacketConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
	template := uritemplate.MustNew(connectUri)
	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}
	if useHTTP2 {
		h2Endpoint, ok := endpoint.(*net.TCPAddr)
		if !ok || h2Endpoint == nil {
			return nil, nil, nil, nil, errors.New("missing HTTP/2 TCP endpoint")
		}
		h2Headers := additionalHeaders.Clone()
		h2Headers.Set("cf-connect-proto", "cf-connect-ip")
		h2Headers.Set("pq-enabled", "false")
		h2Client, err := newHTTP2Client(dialer, tlsConfig, h2Endpoint, connectUri)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to create HTTP/2 client: %w", err)
		}
		ipConn, rsp, err := connectip.DialH2(ctx, h2Client, template, h2Headers)
		if err != nil {
			if strings.Contains(err.Error(), "tls: access denied") {
				return nil, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
			}
			return nil, nil, nil, nil, fmt.Errorf("failed to dial connect-ip over HTTP/2: %w", err)
		}
		return nil, nil, ipConn, rsp, nil
	}
	quicEndpoint, ok := endpoint.(*net.UDPAddr)
	if !ok || quicEndpoint == nil {
		return nil, nil, nil, nil, errors.New("missing HTTP/3 UDP endpoint")
	}
	udpConn, err := dialer.ListenPacket(ctx, M.SocksaddrFromNetIP(quicEndpoint.AddrPort()))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	conn, err := qtls.Dial(
		ctx,
		udpConn,
		quicEndpoint,
		tlsConfig,
		quicConfig,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// official client still sends this out as well, even though
			// it's deprecated, see https://datatracker.ietf.org/doc/draft-ietf-masque-h3-datagram/00/
			// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
			// https://github.com/cloudflare/quiche/blob/7c66757dbc55b8d0c3653d4b345c6785a181f0b7/quiche/src/h3/frame.rs#L46
			0x276: 1,
		},
		DisableCompression: true,
	}
	hconn := tr.NewClientConn(conn)
	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		_ = tr.Close()
		_ = conn.CloseWithError(0, "connect-ip dial failed")
		if strings.Contains(err.Error(), "tls: access denied") {
			return udpConn, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return udpConn, nil, nil, nil, fmt.Errorf("failed to dial connect-ip: %w", err)
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
	if err != nil {
		return udpConn, nil, nil, nil, err
	}
	return udpConn, tr, ipConn, rsp, nil
}

func newHTTP2Client(dialer N.Dialer, baseTLSConfig aTLS.Config, endpoint *net.TCPAddr, connectURI string) (*http.Client, error) {
	if endpoint == nil {
		return nil, errors.New("missing HTTP/2 endpoint")
	}
	tlsConfig := baseTLSConfig.Clone()
	tlsConfig.SetNextProtos([]string{"h2"})
	return &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
				conn, err := dialer.DialContext(ctx, network, M.SocksaddrFromNetIP(endpoint.AddrPort()))
				if err != nil {
					return nil, err
				}
				tlsConn, err := tlsConfig.Client(conn)
				if err != nil {
					return nil, err
				}
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
	}, nil
}
