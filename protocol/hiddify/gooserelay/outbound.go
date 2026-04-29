// Package gooserelay wraps the GooseRelayVPN carrier as a sing-box outbound.
//
// Traffic is multiplexed over a domain-fronted HTTPS connection to a Google
// Apps Script endpoint, which forwards encrypted frames to the user's VPS.
// The carrier handles per-endpoint health and round-robin internally; this
// outbound only manages the lifecycle and wraps each session as a net.Conn.
package gooserelay

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	carrier "github.com/kianmhz/GooseRelayVPN/pkg/carrier"
	gsocks "github.com/kianmhz/GooseRelayVPN/pkg/socks"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

const (
	defaultGoogleHost      = "216.239.38.120:443"
	defaultDiagnoseTimeout = 10 * time.Second
)

var defaultSNIHosts = []string{"www.google.com"}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.GooseRelayOptions](registry, C.TypeGooseRelay, New)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx       context.Context
	logger    logger.ContextLogger
	options   option.GooseRelayOptions
	client    *carrier.Client
	uotClient *uot.Client

	mu        sync.Mutex
	runCancel context.CancelFunc
	started   int
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.GooseRelayOptions) (adapter.Outbound, error) {
	if len(options.ScriptKeys) == 0 {
		return nil, E.New("script_keys is required")
	}
	if options.TunnelKey == "" {
		return nil, E.New("tunnel_key is required")
	}
	if _, err := hex.DecodeString(options.TunnelKey); err != nil || len(options.TunnelKey) != 64 {
		return nil, E.New("tunnel_key must be 64 hex characters (AES-256)")
	}

	googleHost := options.GoogleHost
	if googleHost == "" {
		googleHost = defaultGoogleHost
	}
	sniHosts := options.SNI
	if len(sniHosts) == 0 {
		sniHosts = defaultSNIHosts
	}

	scriptURLs := make([]string, 0, len(options.ScriptKeys))
	for i, key := range options.ScriptKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, E.New("script_keys[", i, "] is empty")
		}
		scriptURLs = append(scriptURLs, fmt.Sprintf("https://script.google.com/macros/s/%s/exec", key))
	}

	client, err := carrier.New(carrier.Config{
		ScriptURLs:  scriptURLs,
		Fronting:    carrier.FrontingConfig{GoogleIP: googleHost, SNIHosts: sniHosts},
		AESKeyHex:   options.TunnelKey,
		DebugTiming: options.DebugTiming,
	})
	if err != nil {
		return nil, E.Cause(err, "construct carrier")
	}

	out := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeGooseRelay, tag, []string{N.NetworkTCP}, options.DialerOptions),
		ctx:     ctx,
		logger:  logger,
		options: options,
		client:  client,
	}
	if options.UDPOverTCP != nil && options.UDPOverTCP.Enabled {
		out.uotClient = &uot.Client{
			Dialer:  singDialerAdapter{out: out},
			Version: options.UDPOverTCP.Version,
		}
	}
	return out, nil
}

func (h *Outbound) PostStart() error {
	runCtx, cancel := context.WithCancel(h.ctx)
	h.mu.Lock()
	h.runCancel = cancel
	h.mu.Unlock()

	go func() {
		if err := h.client.Run(runCtx); err != nil && runCtx.Err() == nil {
			h.logger.Error("carrier run exited: ", err)
		}
	}()
	go h.diagnoseAndMarkReady()
	return nil
}

func (h *Outbound) diagnoseAndMarkReady() {
	budget := defaultDiagnoseTimeout
	if h.options.HandshakeTimeout != nil {
		if d := h.options.HandshakeTimeout.Build(); d > 0 {
			budget = d
		}
	}
	probeCtx, cancel := context.WithTimeout(h.ctx, budget)
	defer cancel()

	if err := h.client.Diagnose(probeCtx); err != nil {
		h.logger.Error("goose-relay diagnose failed: ", err)
		h.mu.Lock()
		h.started = -1
		h.mu.Unlock()
		return
	}
	h.mu.Lock()
	h.started = 1
	h.mu.Unlock()
	h.logger.Info("goose-relay ready (", len(h.options.ScriptKeys), " endpoints)")
}

func (h *Outbound) IsReady() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.started > 0
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !h.IsReady() {
		return nil, E.New("outbound is not started")
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
	default:
		return nil, E.New("network ", network, " not supported by goose-relay")
	}
	sess := h.client.NewSession(destination.String())
	return gsocks.NewVirtualConn(sess), nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.uotClient == nil {
		return nil, E.New("UDP over TCP is not enabled for this outbound")
	}
	if !h.IsReady() {
		return nil, E.New("outbound is not started")
	}
	return h.uotClient.ListenPacket(ctx, destination)
}

func (h *Outbound) DisplayType() string {
	str := C.ProxyDisplayName(h.Type())
	h.mu.Lock()
	state := h.started
	h.mu.Unlock()
	switch {
	case state == 0:
		return str + " ⚠️ Connecting..."
	case state < 0:
		return str + " ❌ Failed!"
	default:
		return fmt.Sprint(str, " ✔️ ", len(h.options.ScriptKeys), " endpoints")
	}
}

func (h *Outbound) Close() error {
	h.mu.Lock()
	cancel := h.runCancel
	h.runCancel = nil
	h.mu.Unlock()
	if cancel != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		h.client.Shutdown(shutdownCtx)
		shutdownCancel()
		cancel()
	}
	return nil
}

// singDialerAdapter bridges Outbound back to N.Dialer so uot.Client can dial
// its underlying TCP carrier session via DialContext.
type singDialerAdapter struct {
	out *Outbound
}

func (a singDialerAdapter) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return a.out.DialContext(ctx, network, destination)
}

func (a singDialerAdapter) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("not supported")
}
