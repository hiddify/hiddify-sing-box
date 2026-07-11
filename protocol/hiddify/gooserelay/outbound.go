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

	"github.com/kianmhz/GooseRelayVPN/goose"
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
	client    *goose.Client
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
	if len(options.TunnelKey) != 64 {
		return nil, E.New("tunnel_key must be 64 hex characters (AES-256)")
	}
	if _, err := hex.DecodeString(options.TunnelKey); err != nil {
		return nil, E.Cause(err, "tunnel_key not valid hex")
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
		if strings.ContainsAny(key, "/?#") {
			return nil, E.New("script_keys[", i, "] contains a URL separator (/?#); paste the deployment ID only")
		}
		scriptURLs = append(scriptURLs, fmt.Sprintf("https://script.google.com/macros/s/%s/exec", key))
	}

	client, err := goose.New(goose.Config{
		ScriptURLs:  scriptURLs,
		Fronting:    goose.FrontingConfig{GoogleIP: googleHost, SNIHosts: sniHosts},
		AESKeyHex:   options.TunnelKey,
		DebugTiming: options.DebugTiming,
	})
	if err != nil {
		return nil, E.Cause(err, "construct goose client")
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
			h.logger.ErrorContext(runCtx, "carrier run exited: ", err)
		}
	}()
	go h.diagnoseAndMarkReady(runCtx)
	return nil
}

// diagnoseAndMarkReady probes every configured script_key concurrently using a
// throwaway one-endpoint carrier per probe, and flips h.started:
//   - +1 (ready) as soon as ANY endpoint passes Diagnose,
//   - -1 (failed) only if ALL endpoints fail.
//
// Throwaway probes are cheap: carrier.New only allocates HTTP clients and
// returns; no goroutines are launched until Run is called, which we never do
// for probes. Cancelling probeCtx on first success aborts the remaining
// in-flight HTTP requests.
func (h *Outbound) diagnoseAndMarkReady(runCtx context.Context) {
	budget := defaultDiagnoseTimeout
	if h.options.HandshakeTimeout != nil {
		if d := h.options.HandshakeTimeout.Build(); d > 0 {
			budget = d
		}
	}
	probeCtx, cancel := context.WithTimeout(runCtx, budget)
	defer cancel()

	googleHost := h.options.GoogleHost
	if googleHost == "" {
		googleHost = defaultGoogleHost
	}
	sniHosts := h.options.SNI
	if len(sniHosts) == 0 {
		sniHosts = defaultSNIHosts
	}
	fronting := goose.FrontingConfig{GoogleIP: googleHost, SNIHosts: sniHosts}

	type probeResult struct {
		key string
		err error
	}
	keys := h.options.ScriptKeys
	results := make(chan probeResult, len(keys))
	for _, key := range keys {
		go func(k string) {
			trimmed := strings.TrimSpace(k)
			probe, err := goose.New(goose.Config{
				ScriptURLs: []string{fmt.Sprintf("https://script.google.com/macros/s/%s/exec", trimmed)},
				Fronting:   fronting,
				AESKeyHex:  h.options.TunnelKey,
			})
			if err != nil {
				results <- probeResult{trimmed, err}
				return
			}
			results <- probeResult{trimmed, probe.Diagnose(probeCtx)}
		}(key)
	}

	for i := 0; i < len(keys); i++ {
		select {
		case r := <-results:
			if r.err == nil {
				h.mu.Lock()
				h.started = 1
				h.mu.Unlock()
				h.logger.InfoContext(runCtx, "goose-relay ready (first healthy endpoint: ", r.key, ")")
				return
			}
			h.logger.WarnContext(probeCtx, "goose-relay endpoint ", r.key, " diagnose failed: ", r.err)
		case <-runCtx.Done():
			return
		}
	}

	h.mu.Lock()
	h.started = -1
	h.mu.Unlock()
	h.logger.ErrorContext(runCtx, "goose-relay: all ", len(keys), " endpoints failed diagnose")
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
	return h.client.Dial(destination.String()), nil
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
