package masterdns

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	mdconfig "github.com/hiddifydeveloper/MasterDnsVPN/pkg/config"
	mdclient "github.com/hiddifydeveloper/MasterDnsVPN/pkg/client"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MasterDnsOptions](registry, C.TypeMasterDNS, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	ctx    context.Context

	options option.MasterDnsOptions

	mu      sync.Mutex
	tunnel  *mdclient.Client
	client  *socks.Client
	started bool
	stopErr error
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MasterDnsOptions) (adapter.Outbound, error) {
	if len(options.Domains) == 0 {
		return nil, E.New("at least one domain is required")
	}
	if len(options.Resolvers) == 0 {
		return nil, E.New("at least one resolver is required")
	}
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeMasterDNS, tag, []string{N.NetworkTCP}, options.DialerOptions),
		ctx:     ctx,
		logger:  logger,
		options: options,
	}, nil
}

func (h *Outbound) PreStart() error {
	return nil
}

func (h *Outbound) PostStart() error {
	return h.startTunnel()
}

func (h *Outbound) startTunnel() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.started {
		return nil
	}

	stateDir, err := os.MkdirTemp("", "hiddify-masterdns-"+h.Tag())
	if err != nil {
		return E.Cause(err, "create masterdns state dir")
	}

	resolversPath := filepath.Join(stateDir, "resolvers.txt")
	if err := os.WriteFile(resolversPath, []byte(strings.Join(h.options.Resolvers, "\n")+"\n"), 0o600); err != nil {
		return E.Cause(err, "write masterdns resolvers file")
	}

	listenPort, err := freePort()
	if err != nil {
		return E.Cause(err, "allocate masterdns local port")
	}

	cfgJSON := h.buildConfigJSON(listenPort)
	encoded := base64.StdEncoding.EncodeToString(cfgJSON)
	resolversFilePath := resolversPath
	cfg, err := mdconfig.LoadClientConfigFromJSONBase64WithOverrides(encoded, mdconfig.ClientConfigOverrides{
		ResolversFilePath: &resolversFilePath,
	})
	if err != nil {
		return E.Cause(err, "build masterdns client config")
	}

	tunnel, err := mdclient.BootstrapLoadedConfig(cfg, "")
	if err != nil {
		return E.Cause(err, "bootstrap masterdns client")
	}

	runCtx, cancel := context.WithCancel(h.ctx)
	go func() {
		err := tunnel.Run(runCtx)
		h.mu.Lock()
		h.stopErr = err
		h.mu.Unlock()
	}()
	_ = cancel // cancellation happens via Outbound.Close -> h.ctx cancellation from the router

	dialOptions := h.options.DialerOptions
	dialOptions.Detour = ""
	outboundDialer, err := dialer.New(h.ctx, dialOptions, false)
	if err != nil {
		return E.Cause(err, "create masterdns local dialer")
	}

	socksAddr := option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(listenPort)}
	user, pass := h.options.SOCKS5User, h.options.SOCKS5Pass
	if !h.options.SOCKS5Auth {
		user, pass = "", ""
	}
	h.client = socks.NewClient(outboundDialer, socksAddr.Build(), socks.Version5, user, pass)
	h.tunnel = tunnel
	h.started = true
	return nil
}

// buildConfigJSON renders the subset of MasterDnsVPN's ClientConfig fields
// this outbound controls into the JSON shape LoadClientConfigFromJSONBase64
// expects (keys match the upstream TOML tags, see pkg/config/client.go).
func (h *Outbound) buildConfigJSON(listenPort int) []byte {
	doc := map[string]any{
		"DOMAINS":     h.options.Domains,
		"LISTEN_IP":   "127.0.0.1",
		"LISTEN_PORT": listenPort,
	}
	if h.options.ProtocolType != "" {
		doc["PROTOCOL_TYPE"] = h.options.ProtocolType
	}
	if h.options.SOCKS5Auth {
		doc["SOCKS5_AUTH"] = true
		doc["SOCKS5_USER"] = h.options.SOCKS5User
		doc["SOCKS5_PASS"] = h.options.SOCKS5Pass
	}
	if h.options.EncryptionKey != "" {
		doc["ENCRYPTION_KEY"] = h.options.EncryptionKey
	}
	if h.options.DataEncryptionMethod != nil {
		doc["DATA_ENCRYPTION_METHOD"] = *h.options.DataEncryptionMethod
	}
	if h.options.UploadCompressionType != nil {
		doc["UPLOAD_COMPRESSION_TYPE"] = *h.options.UploadCompressionType
	}
	if h.options.PacketDuplicationCount != nil {
		doc["PACKET_DUPLICATION_COUNT"] = *h.options.PacketDuplicationCount
	}
	if h.options.MinUploadMTU != nil {
		doc["MIN_UPLOAD_MTU"] = *h.options.MinUploadMTU
	}
	if h.options.MaxUploadMTU != nil {
		doc["MAX_UPLOAD_MTU"] = *h.options.MaxUploadMTU
	}
	raw, _ := json.Marshal(doc)
	return raw
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func (h *Outbound) IsReady() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.started
}

func (h *Outbound) DisplayType() string {
	str := C.ProxyDisplayName(h.Type())
	if !h.IsReady() {
		str += " ⚠️ Connecting..."
	} else {
		str += " ✔️"
	}
	return str
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !h.IsReady() {
		return nil, E.New("outbound is not started")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	return h.client.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !h.IsReady() {
		return nil, E.New("outbound is not started")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.client.ListenPacket(ctx, destination)
}

func (h *Outbound) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tunnel != nil {
		h.tunnel.StopAsyncRuntime()
	}
	return h.stopErr
}
