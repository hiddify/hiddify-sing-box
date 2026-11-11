package outbound

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// A lazy outbound ("lazy": true) is in the box under its tag from the start, in the groups and
// in the monitoring like any other, but it is only its options: the real outbound is created
// when a connection or a test first goes through it, and closed again when nothing has used it
// for lazyLinger. Nothing in the config changes for that, so there is no reload: a profile of
// hundreds of proxies runs the few in use.
//
// What uses it is counted: every connection it dialed until that connection closes, and every
// Acquire until its release. The real outbound is never closed under a connection.

// lazyLinger is how long the real outbound stays after its last connection closed: the next
// connection of the same browsing finds it, with whatever session it keeps (QUIC, a multiplex).
// A connection that closes while something else still holds the outbound leaves no such wait, so
// a URL test, which holds it over its connections (Acquire), frees it when it ends: testing a
// whole profile keeps as many loaded as are tested at once.
var lazyLinger = 30 * time.Second

// lazyRetry is how long a real outbound that could not be created is not tried again: its options
// are the same, and so is the error, at every connection in between.
var lazyRetry = 30 * time.Second

func RegisterLazy(registry *Registry) {
	Register[option.HLazyOptions](registry, C.TypeHLazy, NewLazy)
}

var (
	_ adapter.LazyOutbound            = (*Lazy)(nil)
	_ adapter.Lifecycle               = (*Lazy)(nil)
	_ adapter.InterfaceUpdateListener = (*Lazy)(nil)
	_ adapter.StatusErrorer           = (*Lazy)(nil)
	_ adapter.OutboundWithMultiplex   = (*Lazy)(nil)
)

type Lazy struct {
	ctx          context.Context
	router       adapter.Router
	logger       log.ContextLogger
	registry     adapter.OutboundRegistry
	tag          string
	typ          string
	options      any
	dependencies []string

	loadAccess sync.Mutex // one load or unload at a time
	access     sync.Mutex
	parent     context.Context // of the scope the lazy outbound was started in; nil before
	inner      adapter.Outbound
	scope      *adapter.Scope // inner's
	network    []string       // inner's, once it was created
	users      int            // everything that holds it: connections, dials under way, tests
	conns      int            // of users, the connections that are open
	idleAt     time.Time      // inner stays until then
	timer      *time.Timer
	failure    error // why inner could not be created the last time
	failedAt   time.Time
	closed     bool
	loads      int
}

func NewLazy(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HLazyOptions) (adapter.Outbound, error) {
	registry := service.FromContext[adapter.OutboundRegistry](ctx)
	if registry == nil {
		return nil, E.New("missing outbound registry in context")
	}
	if options.Type == "" || options.Type == C.TypeHLazy {
		return nil, E.New("lazy outbound: missing type")
	}
	option.MigrateTLSFragment(options.Options) // as the manager does for an outbound it creates
	return &Lazy{
		ctx:          ctx,
		router:       router,
		logger:       logger,
		registry:     registry,
		tag:          tag,
		typ:          options.Type,
		options:      options.Options,
		dependencies: options.Dependencies,
	}, nil
}

// Type is the type of the real outbound: what the lazy one stands for.
func (l *Lazy) Type() string {
	return l.typ
}

func (l *Lazy) Tag() string {
	return l.tag
}

// Network is what the real outbound carries, once it was created; TCP and UDP until then.
func (l *Lazy) Network() []string {
	l.access.Lock()
	defer l.access.Unlock()
	if l.network != nil {
		return l.network
	}
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (l *Lazy) Dependencies() []string {
	return l.dependencies
}

func (l *Lazy) DisplayType() string {
	if inner, release := l.use(); inner != nil {
		defer release()
		if displayer, ok := inner.(interface{ DisplayType() string }); ok {
			return displayer.DisplayType()
		}
	}
	return C.ProxyDisplayName(l.typ)
}

// Status is the real outbound's; without one, ready, as a connection creates it, or failed when
// it could not be created the last time.
func (l *Lazy) Status() adapter.Status {
	l.access.Lock()
	inner, failure := l.inner, l.failure
	l.access.Unlock()
	switch {
	case inner != nil:
		return inner.Status()
	case failure != nil:
		return adapter.StatusFailed
	}
	return adapter.StatusReady
}

func (l *Lazy) StatusError() error {
	l.access.Lock()
	inner, failure := l.inner, l.failure
	l.access.Unlock()
	if inner != nil {
		return adapter.StatusError(inner)
	}
	return failure
}

func (l *Lazy) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	l.access.Lock()
	l.parent = scope.Context()
	l.access.Unlock()
	scope.Add(l.Close)
	return nil
}

// Close closes the real outbound, whatever uses it, for good.
func (l *Lazy) Close() error {
	l.access.Lock()
	l.closed = true
	if l.timer != nil {
		l.timer.Stop()
	}
	l.access.Unlock()
	l.loadAccess.Lock()
	defer l.loadAccess.Unlock()
	l.access.Lock()
	inner, scope := l.inner, l.scope
	l.inner, l.scope = nil, nil
	l.access.Unlock()
	if inner == nil {
		return nil
	}
	return scope.Close()
}

func (l *Lazy) Loaded() bool {
	l.access.Lock()
	defer l.access.Unlock()
	return l.inner != nil
}

func (l *Lazy) Acquire() func() {
	l.access.Lock()
	l.users++
	l.access.Unlock()
	var once sync.Once
	return func() { once.Do(func() { l.release(false) }) }
}

// Unload closes the real outbound unless a connection is open through it. A dial or a test
// still under way does not hold it: one that hangs on a dead server would keep the outbound for
// good, and closing the outbound is what ends it.
func (l *Lazy) Unload() {
	l.access.Lock()
	l.idleAt = time.Time{}
	l.access.Unlock()
	l.unload(true)
}

// MultiplexEnabled is the real outbound's, which it creates for that: the URL test asks it right
// before it dials, to open the shared session first and time a request on it.
func (l *Lazy) MultiplexEnabled() bool {
	inner, err := l.acquire()
	if err != nil {
		return false
	}
	defer l.release(false)
	multiplex, isMultiplex := inner.(adapter.OutboundWithMultiplex)
	return isMultiplex && multiplex.MultiplexEnabled()
}

func (l *Lazy) InterfaceUpdated(ctx context.Context) {
	inner, release := l.use()
	if inner == nil {
		return
	}
	defer release()
	if listener, isListener := inner.(adapter.InterfaceUpdateListener); isListener {
		listener.InterfaceUpdated(ctx)
	}
}

func (l *Lazy) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	inner, err := l.acquire()
	if err != nil {
		return nil, err
	}
	conn, err := inner.DialContext(ctx, network, destination)
	if err != nil {
		l.release(true)
		return nil, err
	}
	l.opened()
	return &lazyConn{Conn: conn, lazy: l}, nil
}

func (l *Lazy) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	inner, err := l.acquire()
	if err != nil {
		return nil, err
	}
	conn, err := inner.ListenPacket(ctx, destination)
	if err != nil {
		l.release(true)
		return nil, err
	}
	l.opened()
	return &lazyPacketConn{NetPacketConn: bufio.NewPacketConn(conn), lazy: l}, nil
}

// opened counts a connection that a dial, already counted as a user, opened.
func (l *Lazy) opened() {
	l.access.Lock()
	l.conns++
	l.access.Unlock()
}

// connClosed gives back a connection: its count and its use.
func (l *Lazy) connClosed() {
	l.access.Lock()
	l.conns--
	l.access.Unlock()
	l.release(true)
}

// use is the real outbound when there is one, held until release is called; nil otherwise.
func (l *Lazy) use() (adapter.Outbound, func()) {
	l.access.Lock()
	defer l.access.Unlock()
	if l.inner == nil {
		return nil, nil
	}
	l.users++
	return l.inner, func() { l.release(false) }
}

// acquire is the real outbound, created when there is none, held until release is called.
func (l *Lazy) acquire() (adapter.Outbound, error) {
	l.access.Lock()
	if l.closed {
		l.access.Unlock()
		return nil, E.New("outbound closed")
	}
	l.users++ // first, so that it is not unloaded from here on
	inner := l.inner
	l.access.Unlock()
	if inner != nil {
		return inner, nil
	}
	inner, err := l.load()
	if err != nil {
		l.release(false)
		return nil, err
	}
	return inner, nil
}

// load creates and starts the real outbound, unless another caller just did.
func (l *Lazy) load() (adapter.Outbound, error) {
	l.loadAccess.Lock()
	defer l.loadAccess.Unlock()
	l.access.Lock()
	inner, parent, closed := l.inner, l.parent, l.closed
	failure := l.failure
	if failure != nil && time.Since(l.failedAt) >= lazyRetry {
		failure = nil
	}
	l.access.Unlock()
	switch {
	case inner != nil:
		return inner, nil
	case closed:
		return nil, E.New("outbound closed")
	case parent == nil:
		return nil, E.New("outbound not started")
	case failure != nil:
		return nil, failure
	}
	name := "outbound/" + l.typ + "[" + l.tag + "]"
	scope := adapter.NewScope(parent, l.logger)
	created, err := l.registry.CreateOutbound(l.ctx, l.router, l.logger, l.tag, l.typ, l.options)
	if err == nil {
		if lifecycle, isLifecycle := adapter.AsLifecycle(created); isLifecycle {
			for _, stage := range adapter.ListStartStages {
				if err = scope.Start(name, lifecycle, stage); err != nil {
					break
				}
			}
		}
	}
	l.access.Lock()
	if err == nil && l.closed {
		err = E.New("outbound closed")
	}
	if err != nil {
		if !l.closed {
			l.failure, l.failedAt = E.Cause(err, "load ", name), time.Now()
			err = l.failure
		}
		l.access.Unlock()
		_ = scope.Close()
		l.logger.Error(err)
		return nil, err
	}
	l.inner, l.scope, l.network, l.failure = created, scope, created.Network(), nil
	l.loads++
	l.access.Unlock()
	l.logger.Debug("lazy outbound loaded")
	return created, nil
}

// release gives back what acquire, use or Acquire held. linger: it was a connection, so the real
// outbound stays for the next one, when this was the last use of it.
func (l *Lazy) release(linger bool) {
	l.access.Lock()
	l.users--
	if l.users > 0 || l.inner == nil || l.closed {
		l.access.Unlock()
		return
	}
	if linger {
		l.idleAt = time.Now().Add(lazyLinger)
	}
	wait := time.Until(l.idleAt)
	if wait > 0 {
		l.armLocked(wait)
	}
	l.access.Unlock()
	if wait <= 0 {
		go l.unloadIdle()
	}
}

func (l *Lazy) unloadIdle() {
	l.unload(false)
}

// armLocked has unloadIdle run after wait; access must be held.
func (l *Lazy) armLocked(wait time.Duration) {
	if l.timer == nil {
		l.timer = time.AfterFunc(wait, l.unloadIdle)
	} else {
		l.timer.Reset(wait)
	}
}

// unload closes the real outbound when nothing uses it and its time is over; otherwise it does
// nothing, or waits for that time. now: also under a dial or a test, and whatever the time; never
// under an open connection.
func (l *Lazy) unload(now bool) {
	l.loadAccess.Lock()
	defer l.loadAccess.Unlock()
	l.access.Lock()
	if l.inner == nil || l.closed || l.conns > 0 || (l.users > 0 && !now) {
		l.access.Unlock()
		return
	}
	if wait := time.Until(l.idleAt); wait > 0 {
		l.armLocked(wait)
		l.access.Unlock()
		return
	}
	scope := l.scope
	l.inner, l.scope = nil, nil
	l.access.Unlock()
	if err := scope.Close(); err != nil {
		l.logger.Debug("lazy outbound unloaded: ", err)
		return
	}
	l.logger.Debug("lazy outbound unloaded")
}

type lazyConn struct {
	net.Conn
	lazy *Lazy
	once sync.Once
}

func (c *lazyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.lazy.connClosed)
	return err
}

func (c *lazyConn) ReaderReplaceable() bool {
	return true
}

func (c *lazyConn) WriterReplaceable() bool {
	return true
}

func (c *lazyConn) Upstream() any {
	return c.Conn
}

type lazyPacketConn struct {
	N.NetPacketConn
	lazy *Lazy
	once sync.Once
}

func (c *lazyPacketConn) Close() error {
	err := c.NetPacketConn.Close()
	c.once.Do(c.lazy.connClosed)
	return err
}

func (c *lazyPacketConn) ReaderReplaceable() bool {
	return true
}

func (c *lazyPacketConn) WriterReplaceable() bool {
	return true
}

func (c *lazyPacketConn) Upstream() any {
	return c.NetPacketConn
}
