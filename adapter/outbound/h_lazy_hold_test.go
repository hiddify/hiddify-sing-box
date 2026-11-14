package outbound

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// lazyStagedWorld counts what the real outbounds of a lazy one go through, and sets their status.
type lazyStagedWorld struct {
	lazyTestWorld
	stages atomic.Int32 // start stages run
	status atomic.Uint32
	held   atomic.Bool // the last one was created from the held options
}

type lazyStagedOptions struct {
	world *lazyStagedWorld
	held  bool
}

type lazyStagedOutbound struct {
	lazyTestOutbound
	world *lazyStagedWorld
}

func (o *lazyStagedOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	o.world.stages.Add(1)
	return nil
}

func (o *lazyStagedOutbound) Status() adapter.Status {
	return adapter.Status(o.world.status.Load())
}

// newStagedLazy is a lazy outbound over a staged real one, not started.
func newStagedLazy(t *testing.T) (*Lazy, *lazyStagedWorld, context.Context) {
	t.Helper()
	world := &lazyStagedWorld{}
	registry := NewRegistry()
	Register[lazyStagedOptions](registry, "staged", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options lazyStagedOptions) (adapter.Outbound, error) {
		world.created.Add(1)
		world.held.Store(options.held)
		return &lazyStagedOutbound{lazyTestOutbound: lazyTestOutbound{Adapter: NewAdapter("staged", tag, []string{N.NetworkTCP}, nil), world: &world.lazyTestWorld}, world: world}, nil
	})
	RegisterLazy(registry)
	ctx := service.ContextWith[adapter.OutboundRegistry](service.ContextWithDefaultRegistry(context.Background()), registry)
	created, err := registry.CreateOutbound(ctx, nil, log.NewNOPFactory().NewLogger("lazy"), "proxy", C.TypeHLazy,
		&option.HLazyOptions{Type: "staged", Options: &lazyStagedOptions{world: world}, HeldOptions: &lazyStagedOptions{world: world, held: true}})
	require.NoError(t, err)
	return created.(*Lazy), world, ctx
}

func startLazy(t *testing.T, ctx context.Context, lazy *Lazy) {
	t.Helper()
	scope := adapter.NewScope(ctx, log.NewNOPFactory().NewLogger("lazy"))
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, scope.Start("lazy", lazy, stage))
	}
	t.Cleanup(func() { _ = scope.Close() })
}

// Held before the box starts (a DNS server needs its endpoint): the real one is created then,
// from the config's own options, starts with the stand-in, and is never unloaded while held.
func TestH_LazyHeldBeforeStart(t *testing.T) {
	setLazyTimes(t, 50*time.Millisecond, time.Minute)
	lazy, world, ctx := newStagedLazy(t)
	inner, release, err := lazy.Hold()
	require.NoError(t, err)
	require.True(t, lazy.Held())
	require.True(t, lazy.Loaded())
	require.True(t, world.held.Load(), "from the held options")
	require.EqualValues(t, 0, world.stages.Load(), "not started before the box")
	startLazy(t, ctx, lazy)
	require.EqualValues(t, len(adapter.ListStartStages), world.stages.Load(), "started with the stand-in, every stage")

	conn, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	lazy.Unload()
	time.Sleep(120 * time.Millisecond)
	require.True(t, lazy.Loaded(), "never unloaded while held")
	require.EqualValues(t, 1, world.created.Load())
	same, releaseSame, err := lazy.Hold()
	require.NoError(t, err)
	require.Same(t, inner, same, "one real one for every hold")
	releaseSame()
	release()
	release()
	require.False(t, lazy.Held())
	require.Eventually(t, func() bool { return !lazy.Loaded() }, 2*time.Second, 5*time.Millisecond, "released: the usual rules")
}

// Held once started: created and started now, from the lazy options.
func TestH_LazyHeldAfterStart(t *testing.T) {
	lazy, world, ctx := newStagedLazy(t)
	startLazy(t, ctx, lazy)
	_, release, err := lazy.Hold()
	require.NoError(t, err)
	defer release()
	require.False(t, world.held.Load(), "the box runs: as a connection creates it")
	require.EqualValues(t, len(adapter.ListStartStages), world.stages.Load())
}

// One that still registers or searches (WARP) is not closed for being idle: that would start its
// search over. Unloaded on purpose it goes; once through, the usual rules.
func TestH_LazyWarmingStaysWhenIdle(t *testing.T) {
	setLazyTimes(t, 40*time.Millisecond, time.Minute)
	lazy, world, ctx := newStagedLazy(t)
	startLazy(t, ctx, lazy)
	world.status.Store(uint32(adapter.StatusSearching))
	release := lazy.Acquire()
	_, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.NoError(t, err) // the test's connection
	release()
	time.Sleep(150 * time.Millisecond)
	require.True(t, lazy.Loaded(), "kept while it searches")
	world.status.Store(uint32(adapter.StatusReady))
	lazy.Unload()
	require.True(t, lazy.Loaded(), "not under its open connection")
}

func TestH_LazyWarmingGoesWhenThroughOrUnloaded(t *testing.T) {
	setLazyTimes(t, 40*time.Millisecond, time.Minute)
	lazy, world, ctx := newStagedLazy(t)
	startLazy(t, ctx, lazy)
	world.status.Store(uint32(adapter.StatusRegistering))
	release := lazy.Acquire()
	conn, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	release()
	time.Sleep(150 * time.Millisecond)
	require.True(t, lazy.Loaded(), "kept while it registers")
	world.status.Store(uint32(adapter.StatusReady))
	require.Eventually(t, func() bool { return !lazy.Loaded() }, 2*time.Second, 5*time.Millisecond, "through: closed when idle")

	world.status.Store(uint32(adapter.StatusSearching))
	conn, err = lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	lazy.Unload()
	require.False(t, lazy.Loaded(), "unloaded on purpose (keep top rests it): its search stops")
}
