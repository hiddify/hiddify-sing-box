// Package soar is the soar outbound: a Soar client (github.com/getlantern/soar) that carries TCP
// connections inside DNS queries, through recursive resolvers, to a Soar server that is the
// authority for the tunnel zone.
//
// The client keeps one session with the server and multiplexes the connections over it. The
// resolvers written in the config go through the outbound's smart pool (common/dnspool) by
// default, which the client sees as one resolver; with smart_pool off the client uses each as a
// path of its own. "auto", or no resolvers, turns on the client's own resolver discovery (its
// bundled per-country lists), whose resolvers are paths of their own either way.
package soar

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/soar"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/dnspool"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const (
	defaultConnectTimeout = 90 * time.Second

	// poolHistoryKey names the saved resolver scores of the smart pool in the cache file;
	// discoveryCacheKey the resolvers the client's own discovery found.
	poolHistoryKey    = "soar_resolvers"
	discoveryCacheKey = "soar_discovery"
	// poolMaxResolvers is how many working resolvers the smart pool keeps.
	poolMaxResolvers = 10
	// poolProbeConcurrency is how many resolvers are probed at once.
	poolProbeConcurrency = 100
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SoarOptions](registry, C.TypeSoar, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx            context.Context
	logger         logger.ContextLogger
	tag            string
	options        option.SoarOptions
	config         soar.Config
	connectTimeout time.Duration
	cache          adapter.CacheFile

	// smart pool: the client's one resolver is the pool, fed with the candidates that pass the probe
	pool       *dnspool.Pool
	candidates []dnspool.Candidate
	discover   bool          // the client's own discovery runs too
	poolReady  chan struct{} // closed when the first resolver joined the pool
	poolOnce   sync.Once

	mu        sync.Mutex
	client    *soar.Client
	ready     chan struct{} // closed when client is set
	runCancel context.CancelFunc
	runDone   chan struct{}
}

// ParsePublicKey reads the server's Ed25519 public key: base64 as soar-server prints it, with or
// without padding, base64url, or hex.
func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, E.New("public_key is required: the server's key, from soar-server pubkey")
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err := encoding.DecodeString(value); err == nil && len(key) == ed25519.PublicKeySize {
			return key, nil
		}
	}
	if key, err := hex.DecodeString(value); err == nil && len(key) == ed25519.PublicKeySize {
		return key, nil
	}
	return nil, E.New("public_key: not a ", ed25519.PublicKeySize, "-byte Ed25519 key in base64 or hex")
}

// validateZone checks the tunnel zone as far as a config can be checked: a DNS name.
func validateZone(zone string) error {
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if zone == "" {
		return E.New("domain is required: the tunnel zone of your Soar server")
	}
	if len(zone) > 200 {
		return E.New("domain ", strconv.Quote(zone), " is too long to carry data under it")
	}
	for _, label := range strings.Split(zone, ".") {
		if label == "" || len(label) > 63 {
			return E.New("domain ", strconv.Quote(zone), " is not a DNS name")
		}
	}
	return nil
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SoarOptions) (adapter.Outbound, error) {
	if err := validateZone(options.Domain); err != nil {
		return nil, err
	}
	serverKey, err := ParsePublicKey(options.PublicKey)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(options.TCP) {
	case "", "auto", "on", "only", "off":
	default:
		return nil, E.New("tcp must be auto, on, only or off, not ", strconv.Quote(options.TCP))
	}
	if options.PreTestDomain == "" {
		options.PreTestDomain = "www.google.com"
	}
	if options.PreTestRecordType == "" {
		options.PreTestRecordType = "a"
	}
	if options.Detour != "" {
		logger.Warn("soar: detour is not supported, the DNS queries go out directly")
	}
	explicit := make([]string, 0, len(options.Resolvers))
	for _, resolver := range options.Resolvers {
		if resolver = strings.TrimSpace(resolver); resolver != "" && !strings.EqualFold(resolver, dnspool.AutoResolver) {
			explicit = append(explicit, resolver)
		}
	}
	// "auto", or no resolvers at all: Soar's own discovery, from its bundled lists
	discover := len(explicit) == 0 || dnspool.HasAuto(options.Resolvers)
	// the smart pool (on unless turned off) carries the resolvers written in the config
	smartPool := options.SmartPool.IsEnabledOr(true) && len(explicit) > 0

	out := &Outbound{
		Adapter:        outbound.NewAdapterWithDialerOptions(C.TypeSoar, tag, []string{N.NetworkTCP}, options.DialerOptions),
		ctx:            ctx,
		logger:         logger,
		tag:            tag,
		options:        options,
		connectTimeout: durationOr(options.ConnectTimeout, defaultConnectTimeout),
		discover:       discover,
		poolReady:      make(chan struct{}),
		ready:          make(chan struct{}),
	}
	config := soar.Config{
		Zone:          strings.TrimSuffix(strings.TrimSpace(options.Domain), "."),
		ServerKey:     serverKey,
		SafeQName:     options.SafeQName,
		MaxQName:      options.MaxQName,
		Hold:          time.Duration(options.Hold),
		MaxInflight:   options.MaxInflight,
		MaxPathWindow: options.MaxPathWindow,
		MaxAnswer:     options.MaxAnswer,
		StreamWindow:  uint64(max(options.StreamWindow, 0)),
		SendBuffer:    options.SendBuffer,
		MaxStreams:    options.MaxStreams,
		SessionIdle:   time.Duration(options.SessionIdle),
		TCP:           strings.ToLower(options.TCP),
		Logger:        newSlogLogger(logger),
	}

	// smart_pool.discovery steers it, the same settings as the other DNS tunnels'
	config.Discovery = dnspool.SoarDiscovery(options.SmartPool.DiscoveryOptions())
	config.Discovery.Enabled = discover
	// the resolver sockets go out like any outbound's (bind_interface, routing_mark, the
	// platform's protect), or on a VPN their queries loop back into the tunnel
	dialerOptions := options.DialerOptions
	dialerOptions.Detour = ""
	defaultDialer, err := dialer.NewDefault(ctx, dialerOptions)
	if err != nil {
		return nil, err
	}
	listenOutside := func(ctx context.Context) (net.PacketConn, error) {
		return defaultDialer.ListenPacket(ctx, M.Socksaddr{})
	}
	config.ListenPacket = func(ctx context.Context, network, address string) (net.PacketConn, error) {
		return listenOutside(ctx)
	}
	config.DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
		return defaultDialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
	}

	if smartPool {
		candidates := dnspool.Expand(explicit)
		for _, candidate := range candidates {
			if err := dnspool.ValidateResolver(candidate.Address); err != nil {
				return nil, E.Cause(err, "resolver ", strconv.Quote(candidate.Address), ": with smart_pool write host:port, tcp://host:port, dot://host:port, https://host/path or auto")
			}
		}
		dial, err := dnspool.DialFunc(ctx, options.DialerOptions)
		if err != nil {
			return nil, err
		}
		pool, err := dnspool.StartPool(logger, tag, dnspool.PoolOptionsFrom(options.SmartPool), dial)
		if err != nil {
			return nil, err
		}
		poolAddr, err := net.ResolveUDPAddr("udp", pool.Addr())
		if err != nil {
			_ = pool.Close()
			return nil, err
		}
		out.pool = pool
		out.candidates = candidates
		// the client sees the pool as one resolver on the loopback, which reaches the resolvers
		// (over TCP too) itself; discovered resolvers, if any, are paths of their own. Datagrams
		// to the pool skip the protected socket, which may be bound to the outside interface.
		config.Resolvers = []string{pool.Addr()}
		config.ListenPacket = func(ctx context.Context, network, address string) (net.PacketConn, error) {
			return newSplitPacketConn(ctx, poolAddr, listenOutside)
		}
		if !discover {
			config.TCP = "off"
			if config.MaxPathWindow <= 0 {
				// the client's per-resolver window would cap the whole pool
				config.MaxPathWindow = max(config.MaxInflight, 128)
			}
		}
		logger.InfoContext(ctx, "soar smart_pool listening on ", pool.Addr())
	} else {
		for i, resolver := range explicit {
			if _, err := netip.ParseAddrPort(withPort(resolver)); err != nil {
				return nil, E.New("resolver ", strconv.Quote(resolver), ": without smart_pool Soar uses plain resolvers only, write an IP or IP:port")
			}
			explicit[i] = withPort(resolver)
		}
		config.Resolvers = explicit
	}
	out.config = config
	return out, nil
}

// orDefault is value, or fallback when value is not set.
func orDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

// withPort adds port 53 to a resolver written without one.
func withPort(resolver string) string {
	if _, _, err := net.SplitHostPort(resolver); err == nil {
		return resolver
	}
	return net.JoinHostPort(strings.Trim(resolver, "[]"), "53")
}

func durationOr(value interface{ Build() time.Duration }, fallback time.Duration) time.Duration {
	if d := value.Build(); d > 0 {
		return d
	}
	return fallback
}

func (h *Outbound) PreStart() error {
	h.cache = service.FromContext[adapter.CacheFile](h.ctx)
	return nil
}

func (h *Outbound) PostStart() error {
	config := h.config
	if config.Discovery.Enabled && h.cache != nil {
		config.Discovery.Cache = &discoveryCache{cache: h.cache, key: discoveryCacheKey + ":" + h.tag}
	}
	client, err := soar.NewClient(config)
	if err != nil {
		_ = h.pool.Close()
		return E.Cause(err, "soar")
	}
	runCtx, cancel := context.WithCancel(h.ctx)
	done := make(chan struct{})
	h.mu.Lock()
	h.client = client
	h.runCancel = cancel
	h.runDone = done
	h.mu.Unlock()
	close(h.ready)
	go func() {
		defer close(done)
		if h.pool != nil {
			h.fillPool(runCtx)
		}
	}()
	return nil
}

// fillPool puts the candidate resolvers that answer the probe into the pool, the ones that
// worked before first, up to poolMaxResolvers working ones, and probes more whenever fewer work.
func (h *Outbound) fillPool(ctx context.Context) {
	history := dnspool.LoadHistory(h.cache, poolHistoryKey)
	history.Sort(h.candidates)
	qtype := dnspool.QueryType(h.options.PreTestRecordType)
	discovery := h.options.SmartPool.DiscoveryOptions()
	added := h.pool.Fill(ctx, h.logger, dnspool.FillOptions{
		Candidates: h.candidates,
		Probe: func(ctx context.Context, address string) error {
			response, err := dnspool.Probe(ctx, h.logger, address, h.options.PreTestDomain, qtype, h.options.DialerOptions)
			return dnspool.CheckAnswer(address, response, err)
		},
		Want:        orDefault(discovery.Want, poolMaxResolvers),
		Concurrency: orDefault(discovery.Concurrency, poolProbeConcurrency),
		Pace:        discovery.Pace.Build(),
		History:     history,
		Cache:       h.cache,
		HistoryKey:  poolHistoryKey,
		OnFirst:     func() { h.poolOnce.Do(func() { close(h.poolReady) }) },
	})
	if ctx.Err() == nil && added == 0 {
		h.logger.ErrorContext(ctx, "soar: none of the ", len(h.candidates), " resolvers answered the probe")
	}
}

// PoolResolvers is the number of resolvers in the smart pool, 0 without one.
func (h *Outbound) PoolResolvers() int {
	if h.pool == nil {
		return 0
	}
	return len(h.pool.Manager().Resolvers())
}

// Config is the Soar client configuration in use.
func (h *Outbound) Config() soar.Config {
	return h.config
}

func (h *Outbound) currentClient() *soar.Client {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.client
}

// Status is ready once the session with the server is up; the client opens it at the first
// connection and again after it ends, so it never reports failed.
func (h *Outbound) Status() adapter.Status {
	if client := h.currentClient(); client != nil && client.Established() {
		return adapter.StatusReady
	}
	return adapter.StatusConnecting
}

// verifiedPaths is the number of resolvers that carried an authenticated answer.
func verifiedPaths(client *soar.Client) int {
	n := 0
	for _, stat := range client.PathStats() {
		if stat.Verified && !stat.Suspended {
			n++
		}
	}
	return n
}

// waitClient waits for the client (started in PostStart) and, when the pool is its only way
// out, for the pool's first resolver.
func (h *Outbound) waitClient(ctx context.Context) (*soar.Client, error) {
	select {
	case <-h.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if h.pool != nil && !h.discover {
		select {
		case <-h.poolReady:
		case <-ctx.Done():
			return nil, E.New("no resolver answered the probe yet: ", h.PoolResolvers(), " of ", len(h.candidates), " in the pool")
		}
	}
	return h.currentClient(), nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
	default:
		return nil, E.New("network ", network, " not supported by soar")
	}
	dialCtx, cancel := context.WithTimeout(ctx, h.connectTimeout)
	defer cancel()
	client, err := h.waitClient(dialCtx)
	if err != nil {
		return nil, E.Cause(err, "soar connect to ", destination)
	}
	if client == nil {
		return nil, E.New("outbound is closed")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	conn, err := client.DialContext(dialCtx, N.NetworkTCP, destination.String())
	if err != nil {
		return nil, E.Cause(err, "soar connect to ", destination)
	}
	return conn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("UDP is not supported by soar")
}

func (h *Outbound) DisplayType() string {
	// the status is shown on its own; the resolvers in use are not, also while connecting
	str := C.ProxyDisplayName(h.Type())
	active := h.PoolResolvers()
	if client := h.currentClient(); client != nil {
		active += verifiedPaths(client)
	}
	if active == 0 {
		return str
	}
	return fmt.Sprint(str, " · ", active, " resolvers")
}

func (h *Outbound) Close() error {
	h.mu.Lock()
	cancel := h.runCancel
	done := h.runDone
	client := h.client
	h.runCancel = nil
	h.client = nil
	h.mu.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			h.logger.Warn("soar resolver pool did not stop in time")
		}
	}
	if client != nil {
		_ = client.Close()
	}
	return h.pool.Close()
}

// discoveryCache keeps the resolvers the client's discovery verified in the cache file, so the
// next start tries them first.
type discoveryCache struct {
	cache adapter.CacheFile
	key   string
}

func (c *discoveryCache) Load() []string {
	saved := c.cache.LoadBinary(c.key)
	if saved == nil || len(saved.Content) == 0 {
		return nil
	}
	return strings.Split(string(saved.Content), "\n")
}

func (c *discoveryCache) Store(resolvers []string) {
	_ = c.cache.SaveBinary(c.key, &adapter.SavedBinary{LastUpdated: time.Now(), Content: []byte(strings.Join(resolvers, "\n"))})
}
