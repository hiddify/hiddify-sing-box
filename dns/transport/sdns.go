package transport

import (
	"context"
	"github.com/ameshkov/dnsstamps"
	E "github.com/sagernet/sing/common/exceptions"
	"net"
	"sync"
	"time"

	"github.com/ameshkov/dnscrypt/v2"
	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.DNSTransport = (*SDNSTransport)(nil)

func RegisterSDNS(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.SDNSDNSServerOptions](registry, C.DNSTypeSDNS, NewSDNSTransport)
}

type SDNSTransport struct {
	dns.TransportAdapter
	client *dnscrypt.Client
	name   string
	stamp  string

	mtx  sync.Mutex
	info *dnscrypt.ResolverInfo // the cached resolver certificate
}

func NewSDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.SDNSDNSServerOptions) (adapter.DNSTransport, error) {
	stamp, err := dnsstamps.NewServerStampFromString(options.Stamp) // checked here, not at the first query
	if err != nil {
		return nil, E.Cause(err, "sdns: parse stamp")
	}
	if stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt {
		return nil, E.New("sdns: only DNSCrypt stamps are supported, this one is ", stamp.Proto.String(), "; use the https, tls or udp server type for it")
	}
	transportDialer, err := dns.NewRemoteDialer(ctx, options.RemoteDNSServerOptions)
	if err != nil {
		return nil, err
	}
	return &SDNSTransport{
		TransportAdapter: dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeSDNS, tag, options.RemoteDNSServerOptions), // tag, type and detour dependencies
		name:             tag,
		client: &dnscrypt.Client{
			Net:     "udp",
			Timeout: 10 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := transportDialer.DialContext(ctx, N.NetworkName(network), M.ParseSocksaddr(addr))
				if err != nil || N.NetworkName(network) != N.NetworkUDP {
					return conn, err
				}
				if _, isPacketConn := conn.(net.PacketConn); isPacketConn {
					return conn, nil
				}
				return &sdnsPacketConn{conn}, nil
			},
		},
		stamp: options.Stamp,
	}, err
}

func (t *SDNSTransport) Name() string {
	return t.name
}

func (t *SDNSTransport) Start(adapter.StartStage, *adapter.Scope) error {
	return nil
}

func (t *SDNSTransport) Close() error {
	return nil
}

func (t *SDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	callback(t.Exchange(ctx, message))
}

func (t *SDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	resolverInfo, err := t.resolverInfo()
	if err != nil {
		return nil, err
	}
	response, err := t.client.Exchange(message, resolverInfo)
	if err != nil {
		t.forget(resolverInfo) // the resolver may have rotated its certificate
	}
	return response, err
}

// resolverInfo returns the resolver certificate, fetching it only when there is none or it has
// expired: fetching costs a round trip before every query.
func (t *SDNSTransport) resolverInfo() (*dnscrypt.ResolverInfo, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if t.info != nil && time.Now().Unix() < int64(t.info.ResolverCert.NotAfter) {
		return t.info, nil
	}
	info, err := t.client.Dial(t.stamp)
	if err != nil {
		return nil, err
	}
	t.info = info
	return info, nil
}

func (t *SDNSTransport) forget(info *dnscrypt.ResolverInfo) {
	t.mtx.Lock()
	if t.info == info {
		t.info = nil
	}
	t.mtx.Unlock()
}

func (t *SDNSTransport) Reset() {
	t.mtx.Lock()
	t.info = nil // a new network may reach another instance of the resolver
	t.mtx.Unlock()
}

// sdnsPacketConn presents a connected UDP connection as a net.PacketConn. miekg/dns, which
// dnscrypt uses to fetch the resolver certificate, frames a connection as UDP only when it is
// one; sing-box's dialer wraps connected UDP sockets in a type that is not, and with TCP's
// length prefix the certificate request never gets an answer. //H
type sdnsPacketConn struct {
	net.Conn
}

func (c *sdnsPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(b)
	return n, c.Conn.RemoteAddr(), err
}

func (c *sdnsPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(b)
}
