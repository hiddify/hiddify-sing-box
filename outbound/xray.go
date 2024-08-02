package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	dns "github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/xtls/xray-core/core"

	// Mandatory features. Can't remove unless there are replacements.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	// Fix dependency cycle caused by core import in internet package
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	// Inbound and outbound proxies.
	// _ "github.com/xtls/xray-core/proxy/blackhole"
	// _ "github.com/xtls/xray-core/proxy/dns"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"

	// _ "github.com/xtls/xray-core/proxy/http"
	// _ "github.com/xtls/xray-core/proxy/loopback"
	// _ "github.com/xtls/xray-core/proxy/shadowsocks"
	// _ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	// _ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	// _ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
	// _ "github.com/xtls/xray-core/proxy/wireguard"

	// Transports
	_ "github.com/xtls/xray-core/transport/internet/domainsocket"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/http"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
	_ "github.com/xtls/xray-core/transport/internet/quic"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"

	// Transport headers
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/headers/srtp"
	_ "github.com/xtls/xray-core/transport/internet/headers/tls"
	_ "github.com/xtls/xray-core/transport/internet/headers/utp"
	_ "github.com/xtls/xray-core/transport/internet/headers/wechat"

	// _ "github.com/xtls/xray-core/transport/internet/headers/wireguard"

	// JSON
	_ "github.com/xtls/xray-core/main/json"
)

var _ adapter.Outbound = (*Xray)(nil)

type Xray struct {
	myOutboundAdapter
	client       *socks.Client
	resolve      bool
	uotClient    *uot.Client
	xrayInstance *core.Instance
	proxyStr     string
}

func getRandomFreePort() uint16 {
	for {
		port := rand.Intn(25535) + 30000 // range 30000 to 65535
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			l.Close()
			l, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
			if err == nil {
				l.Close()
				return uint16(port)
			}
		}
	}
}
func NewXray(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.XrayOutboundOptions) (*Xray, error) {
	newuuid, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	userpass := newuuid.String()
	port := getRandomFreePort()
	outbounds := []map[string]any{}
	if options.XrayOutboundJson != nil {
		xrayconf := *options.XrayOutboundJson
		if options.Fragment == nil || options.Fragment.Packets == "" {
			xrayconf["sockopt"] = map[string]any{
				"mark": router.DefaultMark(),
			}
		} else {
			xrayconf["sockopt"] = map[string]any{
				"dialerProxy":      "fragment",
				"tcpKeepAliveIdle": 100,
				"tcpNoDelay":       true,
				"mark":             router.DefaultMark(),
			}
		}
		outbounds = append(outbounds, xrayconf)
	}

	if options.Fragment != nil && options.Fragment.Packets != "" {
		outbounds = append(outbounds, map[string]any{
			"tag":      "fragment",
			"protocol": "freedom",
			"settings": map[string]any{
				"domainStrategy": "AsIs",
				"fragment":       options.Fragment,
			},
			"streamSettings": map[string]any{
				"sockopt": map[string]any{
					"tcpKeepAliveIdle": 100,
					"tcpNoDelay":       true,
				},
			},
		})
	}

	xray := map[string]any{
		"log": map[string]any{
			"loglevel": options.LogLevel,
		},
		"inbounds": []any{
			map[string]any{
				"listen":   "127.0.0.1",
				"port":     port,
				"protocol": "socks",
				"settings": map[string]any{
					"udp":  true,
					"auth": "password",
					"accounts": []any{
						map[string]any{
							"user": userpass,
							"pass": userpass,
						},
					},
				},
			},
		},
		"outbounds": outbounds,
	}
	protocol, ok := outbounds[0]["protocol"].(string)
	if !ok {
		return nil, fmt.Errorf("incorrect protocol")
	}
	jsonData, err := json.MarshalIndent(xray, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling to JSON: %v", err)
	}
	fmt.Printf(string(jsonData))

	// options.XrayOutboundJson
	reader := bytes.NewReader(jsonData)

	xrayConfig, err := core.LoadConfig("json", reader)
	if err != nil {
		return nil, err
	}
	server, err := core.New(xrayConfig)
	if err != nil {
		return nil, err
	}
	socksNet := M.ParseSocksaddrHostPort("127.0.0.1", port)

	outboundDialer, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound := &Xray{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeSOCKS,
			network:      options.Network.Build(),
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		client: socks.NewClient(outboundDialer, socksNet, socks.Version5, userpass, userpass),
		// client:       socks.NewClient(outboundDialer, socksNet, socks.Version5, "", ""),
		resolve:      false,
		xrayInstance: server,
		proxyStr:     "X" + protocol,
	}
	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if uotOptions.Enabled {
		outbound.uotClient = &uot.Client{
			Dialer:  outbound.client,
			Version: uotOptions.Version,
		}
	}
	return outbound, nil
}

func (h *Xray) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		if h.uotClient != nil {
			h.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
			return h.uotClient.DialContext(ctx, network, destination)
		}
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if h.resolve && destination.IsFqdn() {
		destinationAddresses, err := h.router.LookupDefault(ctx, destination.Fqdn)
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, h.client, network, destination, destinationAddresses)
	}
	return h.client.DialContext(ctx, network, destination)
}

func (h *Xray) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	if h.uotClient != nil {
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.ListenPacket(ctx, destination)
	}
	if h.resolve && destination.IsFqdn() {
		destinationAddresses, err := h.router.LookupDefault(ctx, destination.Fqdn)
		if err != nil {
			return nil, err
		}
		packetConn, _, err := N.ListenSerial(ctx, h.client, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		return packetConn, nil
	}
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.client.ListenPacket(ctx, destination)
}

func (h *Xray) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	if h.resolve {
		return NewDirectConnection(ctx, h.router, h, conn, metadata, dns.DomainStrategyUseIPv4)
	} else {
		return NewConnection(ctx, h, conn, metadata)
	}
}

func (h *Xray) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	if h.resolve {
		return NewDirectPacketConnection(ctx, h.router, h, conn, metadata, dns.DomainStrategyUseIPv4)
	} else {
		return NewPacketConnection(ctx, h, conn, metadata)
	}
}
func (w *Xray) Start() error {
	return w.xrayInstance.Start()
}
func (w *Xray) Close() error {
	return w.xrayInstance.Close()
}

func (w *Xray) Type() string {
	return w.proxyStr
}
