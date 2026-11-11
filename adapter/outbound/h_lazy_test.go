package outbound

import (
	"context"
	"errors"
	"net"
	"sync"
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

type lazyTestOptions struct {
	Fail *atomic.Bool
}

// lazyTestWorld counts the real outbounds a lazy one creates and closes.
type lazyTestWorld struct {
	created, closed atomic.Int32
	dialErr         atomic.Bool
}

type lazyTestOutbound struct {
	Adapter
	world *lazyTestWorld
}

func (o *lazyTestOutbound) Close() error {
	o.world.closed.Add(1)
	return nil
}

func (o *lazyTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if o.world.dialErr.Load() {
		return nil, errors.New("unreachable")
	}
	near, far := net.Pipe()
	go func() { _, _ = far.Read(make([]byte, 1)); far.Close() }()
	return near, nil
}

func (o *lazyTestOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

// newTestLazy is a started lazy outbound over a counted real one, closed with the test.
func newTestLazy(t *testing.T) (*Lazy, *lazyTestWorld, *atomic.Bool) {
	t.Helper()
	world := &lazyTestWorld{}
	fail := &atomic.Bool{}
	registry := NewRegistry()
	Register[lazyTestOptions](registry, "lazytest", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options lazyTestOptions) (adapter.Outbound, error) {
		if options.Fail.Load() {
			return nil, errors.New("bad options")
		}
		world.created.Add(1)
		return &lazyTestOutbound{Adapter: NewAdapter("lazytest", tag, []string{N.NetworkTCP}, nil), world: world}, nil
	})
	RegisterLazy(registry)
	ctx := service.ContextWith[adapter.OutboundRegistry](service.ContextWithDefaultRegistry(context.Background()), registry)
	logger := log.NewNOPFactory().NewLogger("lazy")
	created, err := registry.CreateOutbound(ctx, nil, logger, "proxy", C.TypeHLazy,
		&option.HLazyOptions{Type: "lazytest", Options: &lazyTestOptions{Fail: fail}, Dependencies: []string{"hop"}})
	require.NoError(t, err)
	lazy := created.(*Lazy)
	scope := adapter.NewScope(ctx, logger)
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, scope.Start("lazy", lazy, stage))
	}
	t.Cleanup(func() { _ = scope.Close() })
	return lazy, world, fail
}

func setLazyTimes(t *testing.T, linger, retry time.Duration) {
	t.Helper()
	oldLinger, oldRetry := lazyLinger, lazyRetry
	lazyLinger, lazyRetry = linger, retry
	t.Cleanup(func() { lazyLinger, lazyRetry = oldLinger, oldRetry })
}

func TestH_LazyLoadsOnUseAndUnloadsWhenIdle(t *testing.T) {
	setLazyTimes(t, 80*time.Millisecond, time.Minute)
	lazy, world, _ := newTestLazy(t)
	require.Equal(t, "lazytest", lazy.Type(), "the type of what it stands for")
	require.Equal(t, []string{"hop"}, lazy.Dependencies())
	require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP}, lazy.Network(), "not known before the first load")
	require.Equal(t, adapter.StatusReady, lazy.Status())
	require.False(t, lazy.Loaded())
	require.EqualValues(t, 0, world.created.Load(), "nothing is created until it is used")

	first, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.NoError(t, err)
	second, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.NoError(t, err)
	require.True(t, lazy.Loaded())
	require.EqualValues(t, 1, world.created.Load(), "one real outbound for both connections")
	require.Equal(t, []string{N.NetworkTCP}, lazy.Network(), "the real outbound's, once known")

	require.NoError(t, first.Close())
	lazy.Unload()
	time.Sleep(150 * time.Millisecond)
	require.True(t, lazy.Loaded(), "never closed under a connection")
	require.EqualValues(t, 0, world.closed.Load())

	require.NoError(t, second.Close())
	require.NoError(t, second.Close(), "a second close releases nothing more")
	require.True(t, lazy.Loaded(), "it stays a while for the next connection")
	require.Eventually(t, func() bool { return world.closed.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	require.False(t, lazy.Loaded())
	require.Equal(t, []string{N.NetworkTCP}, lazy.Network(), "kept after the unload")

	third, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.NoError(t, err)
	require.EqualValues(t, 2, world.created.Load(), "created again when needed again")
	require.NoError(t, third.Close())
}

// A URL test holds the outbound over its connections and frees it at once: testing a whole
// profile must not leave every proxy loaded for the linger time.
func TestH_LazyAcquireHoldsAndFreesAtOnce(t *testing.T) {
	setLazyTimes(t, time.Hour, time.Minute)
	lazy, world, _ := newTestLazy(t)
	release := lazy.Acquire()
	require.False(t, lazy.Loaded(), "holding creates nothing")
	for range 2 {
		conn, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	}
	require.True(t, lazy.Loaded())
	require.EqualValues(t, 1, world.created.Load(), "held between the two connections")
	release()
	release()
	require.Eventually(t, func() bool { return world.closed.Load() == 1 }, 2*time.Second, 5*time.Millisecond, "no linger after a test")
	require.False(t, lazy.Loaded())

	// Unload does not wait for a test or a dial that hangs
	hung := lazy.Acquire()
	held, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.NoError(t, err)
	lazy.Unload()
	require.True(t, lazy.Loaded(), "a connection is open")
	require.NoError(t, held.Close())
	lazy.Unload()
	require.False(t, lazy.Loaded(), "only a test holds it")
	hung()
	require.False(t, lazy.Loaded())

	// a connection of its own lingers; Unload ends that
	conn, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	time.Sleep(50 * time.Millisecond)
	require.True(t, lazy.Loaded())
	lazy.Unload()
	require.False(t, lazy.Loaded())
}

func TestH_LazyFailedDialStillReleases(t *testing.T) {
	setLazyTimes(t, 20*time.Millisecond, time.Minute)
	lazy, world, _ := newTestLazy(t)
	world.dialErr.Store(true)
	_, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.Error(t, err)
	require.Eventually(t, func() bool { return !lazy.Loaded() }, 2*time.Second, 5*time.Millisecond)
	packet, err := lazy.ListenPacket(context.Background(), M.Socksaddr{})
	require.NoError(t, err)
	require.True(t, lazy.Loaded())
	require.NoError(t, packet.Close())
	require.Eventually(t, func() bool { return !lazy.Loaded() }, 2*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return world.created.Load() == world.closed.Load() }, 2*time.Second, 5*time.Millisecond)
}

func TestH_LazyThatCannotBeCreated(t *testing.T) {
	setLazyTimes(t, time.Hour, 100*time.Millisecond)
	lazy, world, fail := newTestLazy(t)
	fail.Store(true)
	_, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.ErrorContains(t, err, "bad options")
	require.Equal(t, adapter.StatusFailed, lazy.Status())
	require.ErrorContains(t, lazy.StatusError(), "bad options")

	fail.Store(false)
	_, err = lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.ErrorContains(t, err, "bad options", "not created again at every connection")
	require.EqualValues(t, 0, world.created.Load())

	time.Sleep(150 * time.Millisecond)
	conn, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.NoError(t, err, "tried again after a while")
	require.Equal(t, adapter.StatusReady, lazy.Status())
	require.NoError(t, conn.Close())
}

func TestH_LazyConcurrentUse(t *testing.T) {
	setLazyTimes(t, 0, time.Minute)
	lazy, world, _ := newTestLazy(t)
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 20 {
				conn, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
				if err != nil {
					t.Error(err)
					return
				}
				_ = lazy.Status()
				_ = conn.Close()
			}
		}()
	}
	group.Wait()
	require.Eventually(t, func() bool { return !lazy.Loaded() }, 2*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return world.created.Load() == world.closed.Load() }, 2*time.Second, 5*time.Millisecond, "every real outbound created was closed")
}

func TestH_LazyClose(t *testing.T) {
	setLazyTimes(t, time.Hour, time.Minute)
	lazy, world, _ := newTestLazy(t)
	conn, err := lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.NoError(t, err)
	require.NoError(t, lazy.Close())
	require.EqualValues(t, 1, world.closed.Load(), "closing the box closes it, used or not")
	require.NoError(t, conn.Close())
	_, err = lazy.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	require.Error(t, err)
	require.EqualValues(t, 1, world.created.Load())
}
