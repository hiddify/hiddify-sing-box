package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	dns "github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	// Mandatory features. Can't remove unless there are replacements.

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/common/errors"

	// // Default commander and all its services. This is an optional feature.
	// _ "github.com/xtls/xray-core/app/commander"
	// _ "github.com/xtls/xray-core/app/log/command"
	// _ "github.com/xtls/xray-core/app/proxyman/command"
	// _ "github.com/xtls/xray-core/app/stats/command"

	// // Developer preview services
	_ "github.com/xtls/xray-core/app/observatory/command"

	// Other optional features.
	_ "github.com/xtls/xray-core/app/dns"
	// _ "github.com/xtls/xray-core/app/dns/fakedns"
	_ "github.com/xtls/xray-core/app/log"
	// _ "github.com/xtls/xray-core/app/metrics"
	// _ "github.com/xtls/xray-core/app/policy"
	// _ "github.com/xtls/xray-core/app/reverse"
	// _ "github.com/xtls/xray-core/app/router"
	// _ "github.com/xtls/xray-core/app/stats"

	// // Fix dependency cycle caused by core import in internet package
	// _ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"

	// // Developer preview features
	_ "github.com/xtls/xray-core/app/observatory"

	// Inbound and outbound proxies.
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/dns"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/http"
	_ "github.com/xtls/xray-core/proxy/loopback"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"

	// _ "github.com/xtls/xray-core/proxy/wireguard"

	// Transports
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
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

	// JSON & TOML & YAML
	_ "github.com/xtls/xray-core/main/json"
	// _ "github.com/xtls/xray-core/main/toml"
	// _ "github.com/xtls/xray-core/main/yaml"
	// // Load config from file or http(s)
	// _ "github.com/xtls/xray-core/main/confloader/external"
	// Commands
	// _ "github.com/xtls/xray-core/main/commands/all"

	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
)

var _ adapter.Outbound = (*Xray2)(nil)

type Xray2 struct {
	myOutboundAdapter
	resolve      bool
	xrayInstance *core.Instance
	proxyStr     string
	xlogger      *xlogInstance
	directDialer N.Dialer
}

const defaultXrayConfig = `{
  "log": {
	"loglevel": "info",
	"dnsLog": false
  },
  "inbounds": [],
  "outbounds": [],
  "routing": {
	"rules": []
  },
  "dns": {
	 "servers": [
      "8.8.8.8",
      "223.5.5.5",
	  "h2c://1.1.1.1/dns-query"
	  ],
	"tag": "hiddify-dns-out"
  }
}`

var mainProtocols = []string{"vmess", "vless", "trojan", "shadowsocks", "direct"}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func NewXray2(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.XrayOutboundOptions) (xray_ret *Xray2, err_ret error) {
	// var defConfig map[string]any
	// err := json.Unmarshal([]byte(defaultXrayConfig), &defConfig)
	// if err != nil {
	// 	return nil, err
	// }

	// xrayConfig, err := readXrayConfig(options.XConfig)
	// if err != nil {
	// 	return nil, err

	// }
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Xray2 outbound panic: ", r)
			xray_ret = nil
			err_ret = fmt.Errorf("invalid Xray Config: %v", r)
		}
	}()
	directDialer, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}

	if options.XConfig == nil {
		return nil, errors.New("xray config is nil")
	}
	xrayConfig := *options.XConfig
	if outbounds, exists := xrayConfig["outbounds"]; !exists || outbounds == nil {
		xrayConfig = map[string]any{"outbounds": []map[string]any{xrayConfig}}
	}
	// defConfig := xrayConfig
	selectedIff := router.DefaultInterface()
	for _, iff := range router.InterfaceFinder().Interfaces() {
		if !strings.Contains(iff.Name, "tun") {
			selectedIff = iff.Name
			break
		}
	}

	xrayConfig["inbounds"] = nil
	if options.XDebug {
		xrayConfig["log"] = &conf.LogConfig{
			LogLevel: "debug",
			DNSLog:   true,
		}
	} else {
		xrayConfig["log"] = &conf.LogConfig{
			LogLevel: "info",
			DNSLog:   false,
		}
	}

	if outbounds, ok := xrayConfig["outbounds"].([]interface{}); ok {
		for _, item := range outbounds {
			if out, ok := item.(map[string]any); ok {
				if out["streamSettings"] == nil {
					out["streamSettings"] = map[string]any{}
				}

				streamSettings, _ := out["streamSettings"].(map[string]any) // Ensure it's a map
				if streamSettings["sockopt"] == nil {
					streamSettings["sockopt"] = map[string]any{}
				}

				sockopt, _ := streamSettings["sockopt"].(map[string]any) // Ensure it's a map
				sockopt["interface"] = selectedIff

				// Update back
				streamSettings["sockopt"] = sockopt
				out["streamSettings"] = streamSettings
			}
		}
	}
	hasDnsHandler := false

	if dns, ok := xrayConfig["dns"].(map[string]interface{}); ok {
		if tag, exists := dns["tag"]; exists {
			if tagStr, ok := tag.(string); ok && len(tagStr) > 0 {
				hasDnsHandler = true
			}
		}
	}
	// {
	// 	xrayConfig["dns"] = defConfig["dns"]
	// }

	// dnsConfig, _ := xrayConfig["dns"].(map[string]any) // Safe type assertion

	// if dnsConfig["tag"] == nil || dnsConfig["tag"] == "" {
	// 	dnsConfig["tag"] = "hiddify-dns-out"
	// }

	// if servers, ok := dnsConfig["servers"].([]interface{}); !ok || len(servers) == 0 {
	// 	dnsConfig["servers"] = defConfig["dns"].(map[string]any)["servers"]
	// }

	protocol := "XRay"

	if outbounds, ok := xrayConfig["outbounds"].([]interface{}); ok {
		for _, item := range outbounds {
			if out, ok := item.(map[string]any); ok {
				if proto, exists := out["protocol"].(string); exists {
					protocol = proto
					if contains(mainProtocols, proto) { // Use proto, not out.Protocol
						break
					}
				}
			}
		}
	}
	jsonData, err := json.MarshalIndent(xrayConfig, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling to JSON: %v", err)
	}

	// fmt.Printf(string(jsonData))

	xlogger := xlogInstance{
		singlogger: logger,
		started:    false,
	}
	reader := bytes.NewReader(jsonData)
	xlog.RegisterHandler(&xlogger)
	xrayFinalConfig, err := core.LoadConfig("json", reader)
	if err != nil {
		return nil, err
	}
	server, err := core.NewWithContext(ctx, xrayFinalConfig)
	xlog.RegisterHandler(&xlogger)
	if err != nil {
		return nil, err
	}

	// socksNet := M.ParseSocksaddrHostPort("127.0.0.1", port)

	// outboundDialer, err := dialer.New(router, options.DialerOptions)
	// if err != nil {
	// 	return nil, err
	// }
	outbound := &Xray2{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeSOCKS,
			network:      options.Network.Build(),
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		// client: socks.NewClient(outboundDialer, socksNet, socks.Version5, userpass, userpass),
		// client:       socks.NewClient(outboundDialer, socksNet, socks.Version5, "", ""),
		resolve:      !hasDnsHandler,
		xrayInstance: server,
		xlogger:      &xlogger,
		proxyStr:     "X" + protocol,
		directDialer: directDialer,
	}
	// uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	// if uotOptions.Enabled {
	// 	outbound.uotClient = &uot.Client{
	// 		Dialer:  outbound.client,
	// 		Version: uotOptions.Version,
	// 	}
	// }
	return outbound, nil
}

func readXrayConfig(jsonData string) (*conf.Config, error) {
	xrayConfig := conf.Config{}
	err := json.Unmarshal([]byte(jsonData), &xrayConfig)
	if err != nil {
		return nil, err
	}
	return &xrayConfig, nil
}

func (h *Xray2) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	// h.logger.Info(ctx, "DialContext ", destination, fmt.Sprintf("%++v", metadata))
	if metadata.Protocol == "dns" && ((network == "tcp" && destination.Port == 443) || (network == "udp" && destination.Port == 853)) {
		// 	// TODO fix tls DNS
		return h.directDialer.DialContext(ctx, network, destination)
	}
	if h.resolve && destination.IsFqdn() {
		destinationAddresses, err := h.router.LookupDefault(ctx, destination.Fqdn)
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, h, network, destination, destinationAddresses)
	}
	var dest xnet.Destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		dest = xnet.TCPDestination(xnet.ParseAddress(destination.AddrString()), xnet.Port(destination.Port))
	case N.NetworkUDP:
		dest = xnet.UDPDestination(xnet.ParseAddress(destination.AddrString()), xnet.Port(destination.Port))
	}
	// h.logger.Info(ctx, "Dialing ", dest)
	return core.Dial(ctx, h.xrayInstance, dest)
}

func (h *Xray2) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	// h.logger.Info(ctx, "ListenPacket ", destination, fmt.Sprintf("%++v", metadata))
	if h.resolve && destination.IsFqdn() {
		destinationAddresses, err := h.router.LookupDefault(ctx, destination.Fqdn)
		if err != nil {
			return nil, err
		}
		packetConn, _, err := N.ListenSerial(ctx, h, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		return packetConn, nil
	}
	// h.logger.Info(ctx, "DialingUDP ", destination)
	if true {
		conn, err := h.DialContext(ctx, N.NetworkUDP, destination)
		// conn, err := core.DialUDP(ctx, h.xrayInstance)
		if err != nil {
			h.logger.InfoContext(ctx, "dial udp failed ", err)
			return nil, err
		}

		return bufio.NewUnbindPacketConnWithAddr(conn, destination), err
	} else {
		conn, err := core.DialUDP(ctx, h.xrayInstance)
		if err != nil {
			h.logger.InfoContext(ctx, "dial udp failed ", err)
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), err
	}
}

func (h *Xray2) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	if h.resolve {
		return NewDirectConnection(ctx, h.router, h, conn, metadata, dns.DomainStrategyUseIPv4)
	} else {
		return NewConnection(ctx, h, conn, metadata)
	}
}

func (h *Xray2) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	if h.resolve {
		return NewDirectPacketConnection(ctx, h.router, h, conn, metadata, dns.DomainStrategyUseIPv4)
	} else {
		return NewPacketConnection(ctx, h, conn, metadata)
	}
}

func (w *Xray2) Start() error {
	w.xlogger.started = true
	return w.xrayInstance.Start()
}

func (w *Xray2) Close() error {
	w.xlogger.started = false
	return w.xrayInstance.Close()
}

func (w *Xray2) Type() string {
	return w.proxyStr
}

// xlogInstance is a log.Handler that handles logs.
type xlogInstance struct {
	singlogger log.Logger
	started    bool
}

func (x *xlogInstance) Handle(msg xlog.Message) {
	if msg == nil {
		x.singlogger.Debug("no message")
		return
	}

	msgstr := fmt.Sprint("X:", msg)
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("connection tcp panic",
				"recover", r,
				"stack", string(debug.Stack()))
			x.singlogger.Error("connection tcp panic",
				"recover", r,
				"stack", string(debug.Stack()))
		}
	}()
	if !x.started {
		fmt.Println(msgstr)
		return
	}
	switch msg := msg.(type) {
	case *xlog.AccessMessage:
		x.singlogger.Trace(msgstr)
	case *xlog.DNSLog:
		x.singlogger.Trace(msgstr)
	case *xlog.GeneralMessage:
		switch msg.Severity {
		case xlog.Severity_Debug:
			x.singlogger.Debug(msgstr)
		case xlog.Severity_Info:
			x.singlogger.Info(msgstr)
		case xlog.Severity_Warning:
			x.singlogger.Warn(msgstr)
		case xlog.Severity_Error:
			x.singlogger.Error(msgstr)
		}
	default:
		x.singlogger.Debug(msgstr)
	}
}

var _ xlog.Handler = (*xlogInstance)(nil)
