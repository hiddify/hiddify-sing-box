package call

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/call"

	"github.com/stretchr/testify/require"
)

// a failed connect is retried until it works; dials are released after the first try
func TestH_ConnectWithRetry(t *testing.T) {
	saved := connectRetryDelays
	connectRetryDelays = []time.Duration{time.Millisecond}
	defer func() { connectRetryDelays = saved }()

	var attempts, firsts int
	var stored *call.Bridge
	want := &call.Bridge{}
	connectWithRetry(context.Background(), log.NewNOPFactory().Logger(), func() (*call.Bridge, error) {
		attempts++
		if attempts < 3 {
			return nil, errors.New("not yet")
		}
		return want, nil
	}, func(bridge *call.Bridge) { stored = bridge }, func() { firsts++ })
	require.Equal(t, 3, attempts)
	require.Equal(t, 1, firsts)
	require.Same(t, want, stored)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempts = 0
	connectWithRetry(ctx, log.NewNOPFactory().Logger(), func() (*call.Bridge, error) {
		attempts++
		return nil, errors.New("down")
	}, func(*call.Bridge) {}, nil)
	require.Equal(t, 1, attempts, "a closed box stops retrying")
}

// A bridge that connects after the box closed is closed: the closer had found none to close, and
// the bridge's call session ran on.
func TestH_ConnectWithRetryClosesALateBridge(t *testing.T) {
	for _, late := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		var left int
		connectWithRetry(ctx, log.NewNOPFactory().Logger(), func() (*call.Bridge, error) {
			if late {
				cancel() // the box closes while the connect is on its way
			}
			return call.NewBridge(nil, func() { left++ }), nil
		}, func(*call.Bridge) {}, nil)
		cancel()
		if late {
			require.Equal(t, 1, left, "the late bridge was left open")
		} else {
			require.Zero(t, left, "a bridge in time is the closer's to close")
		}
	}
}

// The inbound's side of the call names its handlers, so every bridge has them from the start.
func TestH_InboundCallConfigHasTheHandlers(t *testing.T) {
	inbound := &Inbound{options: option.CallInboundOptions{CallCommonOptions: option.CallCommonOptions{Platform: "vk"}}}
	config := inbound.callConfig(nil)
	require.Equal(t, call.RoleCreator, config.Role)
	require.NotNil(t, config.Accept.TCP)
	require.NotNil(t, config.Accept.UDP)
}

// a wbstream mode that does not exist fails at load, not on every retry
func TestH_CallModeCheckedAtLoad(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "call", option.CallOutboundOptions{
		JoinLink: "x", CallCommonOptions: option.CallCommonOptions{Platform: "wbstream", Mode: "audio"},
	})
	require.ErrorContains(t, err, "unknown wbstream mode")
}
