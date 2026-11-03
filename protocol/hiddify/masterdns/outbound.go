// Package masterdns is the masterdns outbound: a MasterDnsVPN client that carries TCP connections
// inside DNS queries to a MasterDnsVPN server, through public DNS resolvers.
//
// The client (masterdnsvpn-go/lib, the Hiddify fork of MasterDnsVPN) tests the resolvers, agrees
// on an MTU with the server, opens one session and multiplexes the connections over it with its
// own reliable delivery (ARQ). This outbound only maps the options, runs the client and turns each
// connection into a stream.
package masterdns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	mdns "masterdnsvpn-go/lib"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/dnspool"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/batch"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/service"
)

const (
	defaultReadyTimeout   = 30 * time.Second
	defaultConnectTimeout = 30 * time.Second

	// poolHistoryKey names the saved resolver scores in the cache file.
	poolHistoryKey = "masterdns_resolvers"
	// poolMaxResolvers is how many resolvers the smart pool takes; checking stops once it has them.
	poolMaxResolvers = 10
	// defaultPoolDuplicate is the pool's duplicate count without packet_duplication. The pool
	// sends only the copies that carry data, so more is safe; measured (test/dnstunnel-bench),
	// three copies gave 30 Mbit/s on one resolver 10 ms away against 21 with two, and the same on
	// the loopback. MasterDnsVPN's own sample config duplicates three times as well.
	defaultPoolDuplicate = 3
	// poolProbeConcurrency is how many resolvers are probed at once.
	poolProbeConcurrency = 100
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MasterDNSOptions](registry, C.TypeMasterDNS, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx       context.Context
	logger    logger.ContextLogger
	options   option.MasterDNSOptions
	client    *mdns.Client
	uotClient *uot.Client

	readyTimeout   time.Duration
	connectTimeout time.Duration

	// smart pool: the client's one resolver is the pool, fed with the candidates that pass the probe
	pool       *dnspool.Pool
	candidates []dnspool.Candidate
	cache      adapter.CacheFile
	poolReady  chan struct{} // closed when the first resolver joined the pool
	poolOnce   sync.Once

	mu        sync.Mutex
	runCancel context.CancelFunc
	runDone   chan struct{}
}

// balancingStrategies are the names of RESOLVER_BALANCING_STRATEGY 1 to 8.
var balancingStrategies = []string{
	"random", "round-robin", "least-loss", "lowest-latency", "hybrid",
	"loss-then-latency", "least-loss-top-random", "least-loss-top-round-robin",
}

func parseBalancing(value string) (int, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 1 || n > len(balancingStrategies) {
			return 0, E.New("balancing must be 1 to ", len(balancingStrategies))
		}
		return n, nil
	}
	v = strings.NewReplacer("_", "-", " ", "-").Replace(v)
	for i, name := range balancingStrategies {
		if v == name {
			return i + 1, nil
		}
	}
	return 0, E.New("unknown balancing ", strconv.Quote(value), ": use ", strings.Join(balancingStrategies, ", "))
}

func parseCompression(value string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "off", "none", "0":
		return 0, nil
	case "zstd", "1":
		return 1, nil
	case "lz4", "2":
		return 2, nil
	case "zlib", "3":
		return 3, nil
	}
	return 0, E.New("unknown compression ", strconv.Quote(value), ": use off, zstd, lz4 or zlib")
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MasterDNSOptions) (adapter.Outbound, error) {
	if len(options.Domains) == 0 {
		return nil, E.New("domains is required: the tunnel domain of your MasterDnsVPN server")
	}
	if len(options.Resolvers) == 0 {
		return nil, E.New("resolvers is required: at least one DNS resolver, such as 8.8.8.8")
	}
	if !options.SmartPool.IsEnabled() {
		if dnspool.HasAuto(options.Resolvers) {
			return nil, E.New("resolvers \"auto\" (the built-in list) needs smart_pool: true, the MasterDnsVPN client cannot test thousands of resolvers itself")
		}
		for _, resolver := range options.Resolvers {
			if strings.Contains(resolver, "://") {
				return nil, E.New("resolver ", strconv.Quote(resolver), ": without smart_pool MasterDnsVPN uses plain UDP resolvers only, write an IP, IP:port or a range")
			}
		}
	}
	var candidates []dnspool.Candidate
	if options.SmartPool.IsEnabled() {
		candidates = dnspool.Expand(options.Resolvers)
		for _, candidate := range candidates {
			if candidate.Auto {
				continue
			}
			if err := dnspool.ValidateResolver(candidate.Address); err != nil {
				return nil, E.Cause(err, "resolver ", strconv.Quote(candidate.Address), ": with smart_pool write host:port, dot://host:port, https://host/path or auto")
			}
		}
	}
	if options.PreTestDomain == "" {
		options.PreTestDomain = "www.google.com"
	}
	if options.PreTestRecordType == "" {
		options.PreTestRecordType = "a"
	}
	encryption, err := mdns.ParseEncryptionMethod(options.Encryption)
	if err != nil {
		return nil, E.Cause(err, "encryption")
	}
	if encryption != mdns.EncryptionNone && options.Key == "" {
		return nil, E.New("key is required: the server's encryption key (encrypt_key.txt)")
	}
	balancing, err := parseBalancing(options.Balancing)
	if err != nil {
		return nil, err
	}
	uploadCompression, err := parseCompression(options.UploadCompression)
	if err != nil {
		return nil, E.Cause(err, "upload_compression")
	}
	downloadCompression, err := parseCompression(options.DownloadCompression)
	if err != nil {
		return nil, E.Cause(err, "download_compression")
	}

	// the resolver sockets are opened by the MasterDnsVPN client, not through a sing-box dialer:
	// give them the socket control of one (bind_interface, routing_mark, the platform's protect),
	// or on a VPN their queries loop back into the tunnel
	defaultDialer, err := dialer.NewDefault(ctx, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	socketControl, _ := defaultDialer.UDPListenerControl()
	if options.Detour != "" {
		logger.Warn("masterdns: detour is not supported, the DNS queries go out directly")
	}

	out := &Outbound{
		Adapter:        outbound.NewAdapterWithDialerOptions(C.TypeMasterDNS, tag, []string{N.NetworkTCP}, options.DialerOptions),
		ctx:            ctx,
		logger:         logger,
		options:        options,
		readyTimeout:   durationOr(options.ReadyTimeout, defaultReadyTimeout),
		connectTimeout: durationOr(options.ConnectTimeout, defaultConnectTimeout),
		candidates:     candidates,
		poolReady:      make(chan struct{}),
	}

	resolvers := []string(options.Resolvers)
	if options.SmartPool.IsEnabled() {
		dial, err := dnspool.DialFunc(ctx, options.DialerOptions)
		if err != nil {
			return nil, err
		}
		poolOptions := dnspool.PoolOptionsFrom(options.SmartPool)
		if poolOptions.Duplicate == 0 {
			// behind the pool the client sees one resolver and cannot send a packet over
			// several: the pool does it, over resolvers without a rate limit
			poolOptions.Duplicate = options.PacketDuplication
			if poolOptions.Duplicate <= 0 {
				poolOptions.Duplicate = defaultPoolDuplicate
			}
		}
		pool, err := dnspool.StartPool(logger, tag, poolOptions, dial)
		if err != nil {
			return nil, err
		}
		out.pool = pool
		resolvers = []string{pool.Addr()}
		logger.InfoContext(ctx, "masterdns smart_pool listening on ", pool.Addr())
	}

	client, err := mdns.New(mdns.Options{
		Domains:          options.Domains,
		Resolvers:        resolvers,
		EncryptionMethod: encryption,
		EncryptionKey:    options.Key,
		Mode:             options.Mode,
		LogLevel:         options.LogLevel,
		Log:              out.logLine,
		SocketControl:    controlFunc(socketControl),
		Tune: func(cfg *mdns.ClientConfig) {
			applyTuning(cfg, options, balancing, uploadCompression, downloadCompression)
		},
	})
	if err != nil {
		_ = out.pool.Close()
		return nil, E.Cause(err, "masterdns")
	}
	out.client = client

	if options.UDPOverTCP != nil && options.UDPOverTCP.Enabled {
		out.uotClient = &uot.Client{
			Dialer:  singDialerAdapter{out: out},
			Version: options.UDPOverTCP.Version,
		}
	}
	return out, nil
}

func durationOr(value badoptionDuration, fallback time.Duration) time.Duration {
	if d := value.Build(); d > 0 {
		return d
	}
	return fallback
}

type badoptionDuration interface {
	Build() time.Duration
}

func controlFunc(fn control.Func) func(network, address string, rc syscall.RawConn) error {
	if fn == nil {
		return nil
	}
	return func(network, address string, rc syscall.RawConn) error {
		return fn(network, address, rc)
	}
}

// applyTuning copies the set options onto the MasterDnsVPN client configuration. An unset option
// keeps the client's default.
func applyTuning(cfg *mdns.ClientConfig, options option.MasterDNSOptions, balancing, uploadCompression, downloadCompression int) {
	if balancing > 0 {
		cfg.ResolverBalancingStrategy = balancing
	}
	if options.PacketDuplication > 0 {
		cfg.PacketDuplicationCount = options.PacketDuplication
	}
	if options.SetupPacketDuplication > 0 {
		cfg.SetupPacketDuplicationCount = options.SetupPacketDuplication
	}
	cfg.UploadCompressionType = uploadCompression
	cfg.DownloadCompressionType = downloadCompression
	cfg.BaseEncodeData = options.BaseEncode
	if options.MinUploadMTU > 0 {
		cfg.MinUploadMTU = options.MinUploadMTU
	}
	if options.MaxUploadMTU > 0 {
		cfg.MaxUploadMTU = options.MaxUploadMTU
	}
	if options.MinDownloadMTU > 0 {
		cfg.MinDownloadMTU = options.MinDownloadMTU
	}
	if options.MaxDownloadMTU > 0 {
		cfg.MaxDownloadMTU = options.MaxDownloadMTU
	}
	if d := options.MTUTestTimeout.Build(); d > 0 {
		cfg.MTUTestTimeout = d.Seconds()
	}
	if options.MTUTestRetries > 0 {
		cfg.MTUTestRetries = options.MTUTestRetries
	}
	if options.MTUTestParallelism > 0 {
		cfg.MTUTestParallelism = options.MTUTestParallelism
	}
	if options.AutoRemoveLowMTUResolvers != nil {
		cfg.AutoRemoveLowMTUServers = *options.AutoRemoveLowMTUResolvers
	}
	if options.RecheckInactiveResolvers != nil {
		cfg.RecheckInactiveServersEnabled = *options.RecheckInactiveResolvers
	}
	if options.AutoDisableTimeoutResolvers != nil {
		cfg.AutoDisableTimeoutServers = *options.AutoDisableTimeoutResolvers
	}
	if options.Workers > 0 {
		cfg.RX_TX_Workers = options.Workers
	}
	if options.ProcessWorkers > 0 {
		cfg.TunnelProcessWorkers = options.ProcessWorkers
	}
	if options.ARQWindow > 0 {
		cfg.ARQWindowSize = options.ARQWindow
	}
}

// logLine writes a MasterDnsVPN client message to the outbound's logger at the same level.
func (h *Outbound) logLine(level int, message string) {
	switch level {
	case mdns.LevelDebug:
		h.logger.Debug(message)
	case mdns.LevelWarn:
		h.logger.Warn(message)
	case mdns.LevelError:
		h.logger.Error(message)
	default:
		h.logger.Info(message)
	}
}

// Config is the MasterDnsVPN client configuration in use.
func (h *Outbound) Config() mdns.ClientConfig {
	return h.client.Config()
}

func (h *Outbound) PreStart() error {
	h.cache = service.FromContext[adapter.CacheFile](h.ctx)
	return nil
}

func (h *Outbound) PostStart() error {
	runCtx, cancel := context.WithCancel(h.ctx)
	done := make(chan struct{})
	h.mu.Lock()
	h.runCancel = cancel
	h.runDone = done
	h.mu.Unlock()
	go func() {
		defer close(done)
		if h.pool != nil {
			// the client's first MTU test needs a resolver in the pool
			go h.fillPool(runCtx)
			select {
			case <-h.poolReady:
			case <-runCtx.Done():
				return
			}
		}
		if err := h.client.Run(runCtx); err != nil && runCtx.Err() == nil {
			h.logger.ErrorContext(runCtx, "masterdns client stopped: ", err)
		}
	}()
	return nil
}

// fillPool probes the candidate resolvers, the ones that worked before first, and puts those
// that answer into the pool, up to poolMaxResolvers. Scores are kept in the cache file, like
// the dnstt outbound's.
func (h *Outbound) fillPool(ctx context.Context) {
	history := dnspool.LoadHistory(h.cache, poolHistoryKey)
	defer history.Save(h.cache, poolHistoryKey, h.logger)
	history.Sort(h.candidates)

	var added int32
	var addedMu sync.Mutex
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](poolProbeConcurrency))
	for _, candidate := range h.candidates {
		if ctx.Err() != nil {
			break
		}
		b.Go(candidate.Address, func() (any, error) {
			addedMu.Lock()
			full := added >= poolMaxResolvers
			addedMu.Unlock()
			if full || ctx.Err() != nil {
				return nil, nil
			}
			qtype := dnspool.QueryType(h.options.PreTestRecordType)
			response, err := dnspool.Probe(ctx, h.logger, candidate.Address, h.options.PreTestDomain, qtype, h.options.DialerOptions)
			if err := dnspool.CheckAnswer(candidate.Address, response, err); err != nil {
				history.Record(candidate.Address, -3)
				h.logger.DebugContext(ctx, "resolver ", candidate.Address, " failed: ", err)
				return nil, nil
			}
			if err := h.pool.Add(candidate.Address); err != nil {
				h.logger.WarnContext(ctx, "resolver ", candidate.Address, " not added: ", err)
				return nil, nil
			}
			history.Record(candidate.Address, 1)
			addedMu.Lock()
			added++
			addedMu.Unlock()
			h.logger.InfoContext(ctx, "resolver ", candidate.Address, " is working and added to the pool")
			h.poolOnce.Do(func() {
				close(h.poolReady)
				history.Save(h.cache, poolHistoryKey, h.logger)
			})
			return nil, nil
		})
	}
	_ = b.Wait()
	if ctx.Err() == nil && added == 0 {
		h.logger.ErrorContext(ctx, "masterdns: none of the ", len(h.candidates), " resolvers answered the probe")
	}
}

// PoolResolvers is the number of resolvers in the smart pool, 0 without one.
func (h *Outbound) PoolResolvers() int {
	if h.pool == nil {
		return 0
	}
	return len(h.pool.Manager().Resolvers())
}

func (h *Outbound) isStarted() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.runCancel != nil
}

// Status is ready once the session with the server is open. The client keeps testing resolvers
// and retrying the session, so it never reports failed. //H
func (h *Outbound) Status() adapter.Status {
	if h.client.Ready() {
		return adapter.StatusReady
	}
	return adapter.StatusConnecting
}

// waitReady waits for the session, up to ready_timeout, so a connection made right after start
// does not fail while the resolvers are still being tested.
func (h *Outbound) waitReady(ctx context.Context) error {
	if h.client.Ready() {
		return nil
	}
	if !h.isStarted() {
		return E.New("outbound is not started")
	}
	waitCtx, cancel := context.WithTimeout(ctx, h.readyTimeout)
	defer cancel()
	if err := h.client.WaitReady(waitCtx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		active, total := h.client.Resolvers()
		if h.pool != nil {
			return E.New("tunnel not ready after ", h.readyTimeout, ": ", h.PoolResolvers(), " of ", len(h.candidates), " resolvers answered the probe, no session with the server yet")
		}
		return E.New("tunnel not ready after ", h.readyTimeout, ": ", active, " of ", total, " resolvers passed the test, no session with the server yet")
	}
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
	default:
		return nil, E.New("network ", network, " not supported by masterdns")
	}
	if err := h.waitReady(ctx); err != nil {
		return nil, err
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	conn, err := h.client.Dial(ctx, destination.AddrString(), destination.Port, h.connectTimeout)
	if err != nil {
		return nil, E.Cause(err, "masterdns connect to ", destination)
	}
	return conn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.uotClient == nil {
		return nil, E.New("UDP over TCP is not enabled for this outbound")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	return h.uotClient.ListenPacket(ctx, destination)
}

func (h *Outbound) DisplayType() string {
	str := C.ProxyDisplayName(h.Type()) // adapter.DisplayType adds the status mark
	if !h.client.Ready() {
		return str
	}
	active, _ := h.client.Resolvers()
	if h.pool != nil {
		active = h.PoolResolvers()
	}
	return fmt.Sprint(str, " ✔️ ", active, " resolvers")
}

func (h *Outbound) Close() error {
	h.mu.Lock()
	cancel := h.runCancel
	done := h.runDone
	h.runCancel = nil
	h.mu.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			h.logger.Warn("masterdns client did not stop in time")
		}
	}
	return h.pool.Close()
}

// singDialerAdapter lets uot.Client dial its TCP carrier through the outbound.
type singDialerAdapter struct {
	out *Outbound
}

func (a singDialerAdapter) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return a.out.DialContext(ctx, network, destination)
}

func (a singDialerAdapter) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("not supported")
}
