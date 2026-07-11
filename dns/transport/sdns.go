package transport

import (
	"context"
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

	mtx sync.Mutex
}

func NewSDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.SDNSDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options.RemoteDNSServerOptions)
	if err != nil {
		return nil, err
	}
	return &SDNSTransport{
		client: &dnscrypt.Client{
			Net:     "udp",
			Timeout: 10 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return transportDialer.DialContext(ctx, N.NetworkName(network), M.ParseSocksaddr(addr))
			},
		},
		stamp: options.Stamp,
	}, err
}

func (t *SDNSTransport) Name() string {
	return t.name
}

func (t *SDNSTransport) Start(adapter.StartStage) error {
	return nil
}

func (t *SDNSTransport) Close() error {
	return nil
}

func (t *SDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	resolverInfo, err := t.client.Dial(t.stamp)
	if err != nil {
		return nil, err
	}
	return t.client.Exchange(message, resolverInfo)
}

func (t *SDNSTransport) Reset() {
}
