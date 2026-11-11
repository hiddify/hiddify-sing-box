package box_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// hEchoServer answers every connection with what it reads.
func hEchoServer(t *testing.T) M.Socksaddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return M.ParseSocksaddr(listener.Addr().String())
}

func hLazyConfig(mixedPort int, lazyDirect bool) string {
	return `{
	"log": {"disabled": true},
	"inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": ` + strconv.Itoa(mixedPort) + `}],
	"outbounds": [
		{"type": "selector", "tag": "select", "lazy": true, "outbounds": ["p1", "p2"], "default": "p1"},
		{"type": "socks", "tag": "p1", "lazy": true, "server": "127.0.0.1", "server_port": ` + strconv.Itoa(mixedPort) + `},
		{"type": "socks", "tag": "p2", "lazy": true, "server": "127.0.0.1", "server_port": 1, "detour": "direct"},
		{"type": "direct", "tag": "direct", "lazy": ` + strconv.FormatBool(lazyDirect) + `}
	],
	"route": {"rules": [{"inbound": "in", "outbound": "direct"}], "final": "select"},
	"experimental": {"monitoring": {"urls": ["http://127.0.0.1:1/none"], "keep_top": {"count": 1}}}
}`
}

// A lazy outbound is in the box from the start, in its group, with nothing behind it; the first
// connection creates the real outbound, and it goes when nothing uses it. Hot reload leaves an
// unchanged one alone and replaces a changed one, with the group that holds it.
func TestH_LazyOutboundInBox(t *testing.T) {
	echo := hEchoServer(t)
	mixedPort := hFreeTCPPort(t)
	ctx := include.Context(context.Background())
	options := hParseOptions(t, ctx, hLazyConfig(mixedPort, true))
	content, err := json.MarshalContext(ctx, options.Outbounds[1])
	require.NoError(t, err)
	require.Contains(t, string(content), `"lazy":true`, "the option is written back")

	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())

	p1, isLazy := hOutbound(t, instance, "p1").(adapter.LazyOutbound)
	require.True(t, isLazy)
	require.Equal(t, "socks", p1.Type(), "the type of what it stands for")
	// the monitoring tests them at start, and frees each when its test is over
	require.Eventually(t, func() bool {
		return !p1.Loaded() && !hOutbound(t, instance, "p2").(adapter.LazyOutbound).Loaded()
	}, 20*time.Second, 10*time.Millisecond, "nothing stays created for one that is not used")
	require.Equal(t, []string{"direct"}, hOutbound(t, instance, "p2").Dependencies(), "its detour is known without creating it")
	_, isLazy = hOutbound(t, instance, "direct").(adapter.LazyOutbound)
	require.False(t, isLazy, "direct is not worth it")
	selector, isGroup := hOutbound(t, instance, "select").(adapter.OutboundGroup)
	require.True(t, isGroup, "a group is never lazy")
	require.Equal(t, "p1", selector.Selected(N.NetworkTCP).Tag())

	// through the selector and the lazy socks outbound, to the mixed inbound, to the echo server
	conn, err := selector.(N.Dialer).DialContext(context.Background(), N.NetworkTCP, echo)
	require.NoError(t, err)
	require.True(t, p1.Loaded(), "created by the first connection")
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	answer := make([]byte, 4)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = io.ReadFull(conn, answer)
	require.NoError(t, err)
	require.Equal(t, "ping", string(answer))
	p1.Unload()
	require.True(t, p1.Loaded(), "not under a connection")
	require.NoError(t, conn.Close()) // the selector closes what is under it in the background
	require.Eventually(t, func() bool {
		p1.Unload()
		return !p1.Loaded()
	}, 5*time.Second, 10*time.Millisecond)

	// the same options again: nothing is touched
	same := hParseOptions(t, ctx, hLazyConfig(mixedPort, true))
	result, err := instance.HotReloadWithResult(context.Background(), &same)
	require.NoError(t, err)
	require.True(t, result.IsEmpty())
	require.Same(t, p1, hOutbound(t, instance, "p1"))

	// direct stops being marked lazy (it never was): it is the same outbound, so p2, which dials
	// through it, and the selector are replaced; p1 is not
	changed := hParseOptions(t, ctx, hLazyConfig(mixedPort, false))
	result, err = instance.HotReloadWithResult(context.Background(), &changed)
	require.NoError(t, err)
	require.Equal(t, []string{"direct", "p2", "select"}, result.Outbounds.Replaced)
	require.Same(t, p1, hOutbound(t, instance, "p1"))
	p2, isLazy := hOutbound(t, instance, "p2").(adapter.LazyOutbound)
	require.True(t, isLazy, "a replaced lazy outbound is lazy")
	require.False(t, p2.Loaded())

	// the keep top options change without a restart, and nothing else of experimental does
	moreKept := hParseOptions(t, ctx, strings.Replace(hLazyConfig(mixedPort, false), `"count": 1`, `"count": 1, "quick": true`, 1))
	result, err = instance.HotReloadWithResult(context.Background(), &moreKept)
	require.NoError(t, err)
	require.True(t, result.KeepTop)
	require.True(t, result.Outbounds.IsEmpty())
	otherURL := hParseOptions(t, ctx, strings.Replace(hLazyConfig(mixedPort, false), "/none", "/other", 1))
	_, err = instance.HotReloadWithResult(context.Background(), &otherURL)
	require.ErrorContains(t, err, "experimental")

	_, err = p2.DialContext(context.Background(), N.NetworkTCP, echo)
	require.Error(t, err, "nothing listens on its server")
	require.True(t, p2.Loaded(), "kept a while after a connection, failed or not")
	require.NoError(t, instance.Close())
	require.False(t, p2.Loaded(), "closed with the box")
}
