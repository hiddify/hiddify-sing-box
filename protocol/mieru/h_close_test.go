package mieru

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// muxRoutines counts the maintenance goroutines of mieru multiplexers (protocol.NewMux), one for
// each client that was started and not stopped.
func muxRoutines() int {
	buf := make([]byte, 1<<20)
	return strings.Count(string(buf[:runtime.Stack(buf, true)]), "mieru/v3/pkg/protocol.NewMux.func1(")
}

// Closing the outbound stops its mieru client. The client has Stop, not Close, so common.Close
// did nothing with it: every outbound closed, as keep top closes each lazy one after its test,
// left its multiplexer behind, with a goroutine a ticker wakes every 5 s.
func TestH_MieruOutboundCloseStopsClient(t *testing.T) {
	ctx := context.Background()
	before := muxRoutines()
	var outbounds []*Outbound
	for range 5 {
		out, err := NewOutbound(ctx, &echoRouter{}, log.NewNOPFactory().Logger(), "mieru-out", option.MieruOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1"},
			PortBindings:  []option.MieruPortBinding{{Protocol: "TCP", Port: freeTCPPort(t)}},
			UserName:      "alice",
			Password:      "secret",
		})
		require.NoError(t, err)
		outbounds = append(outbounds, out.(*Outbound))
	}
	require.Equal(t, before+len(outbounds), muxRoutines(), "a multiplexer for each client that runs")
	for _, out := range outbounds {
		require.True(t, out.client.IsRunning())
		require.NoError(t, out.Close())
		require.False(t, out.client.IsRunning(), "Close must stop the mieru client")
		_, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("10.0.0.1:80"))
		require.Error(t, err, "a closed outbound dials nothing")
	}
	require.Eventually(t, func() bool { return muxRoutines() == before }, 5*time.Second, 20*time.Millisecond,
		"the multiplexers of the closed outbounds are gone")
}
