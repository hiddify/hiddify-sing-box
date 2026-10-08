package proxyproto

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/pires/go-proxyproto"
)

var _ N.Dialer = (*Dialer)(nil)

// Dialer sends a PROXY protocol header on every TCP connection it opens.
type Dialer struct {
	N.Dialer
	Version byte // 1 or 2; 0 means 1
}

func (d *Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil || N.NetworkName(network) != N.NetworkTCP {
		return conn, err
	}
	return WriteHeader(ctx, conn, d.Version, destination)
}

// WriteHeader sends the PROXY protocol header (version 1 or 2; 0 means 1) on a new outgoing TCP
// connection, closing it on failure. //H
func WriteHeader(ctx context.Context, conn net.Conn, version byte, destination M.Socksaddr) (net.Conn, error) {
	if version == 0 {
		version = 1
	}
	_, err := buildHeader(ctx, conn, version, destination).WriteTo(conn)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "write proxy protocol header")
	}
	return conn, nil
}

// buildHeader describes the connection: the source is the original client (from the inbound
// metadata), the destination the dialed address. Both must be of the same address family: when
// the client's is different, the connection's own local address is used instead, and when no
// pair matches, the header is "unknown" (LOCAL), so the receiver uses the connection's addresses.
func buildHeader(ctx context.Context, conn net.Conn, version byte, destination M.Socksaddr) *proxyproto.Header {
	target := destination.Unwrap()
	if !target.IsIP() {
		target = M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
	}
	var source M.Socksaddr
	if metadata := adapter.ContextFrom(ctx); metadata != nil {
		source = metadata.Source.Unwrap()
	}
	if target.IsIP() && (!source.IsIP() || source.Addr.Is4() != target.Addr.Is4()) {
		source = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	}
	if !target.IsIP() || !source.IsIP() || source.Addr.Is4() != target.Addr.Is4() {
		return &proxyproto.Header{Version: version, Command: proxyproto.LOCAL, TransportProtocol: proxyproto.UNSPEC}
	}
	return proxyproto.HeaderProxyFromAddrs(version, source.TCPAddr(), target.TCPAddr())
}
