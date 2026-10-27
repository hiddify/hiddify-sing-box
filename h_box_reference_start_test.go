package box_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Start must not wait for a multiplexed dial in progress: the reference manager's first update
// closes idle mux sessions of unreferenced outbounds, and sing-mux holds that lock for the whole
// dial of a new session.
func TestH_StartDoesNotWaitForMuxDial(t *testing.T) {
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer blackhole.Close()
	go func() {
		for {
			conn, err := blackhole.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"disabled": true},
		"outbounds": [
			{"type": "direct", "tag": "direct"},
			{"type": "socks", "tag": "dead", "server": "127.0.0.1", "server_port": `+strconv.Itoa(blackhole.Addr().(*net.TCPAddr).Port)+`},
			{"type": "vless", "tag": "mux-out", "server": "127.0.0.1", "server_port": 1, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
				"detour": "dead", "multiplex": {"enabled": true}}
		],
		"route": {"final": "direct"}
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	muxOut, loaded := instance.Outbound().Outbound("mux-out")
	require.True(t, loaded)
	go func() {
		dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := muxOut.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
		if err == nil {
			conn.Close()
		}
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	require.NoError(t, instance.Start())
	require.Less(t, time.Since(start), 2*time.Second, "Start waited for the mux dial")
}
