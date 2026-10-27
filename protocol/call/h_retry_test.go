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

// a wbstream mode that does not exist fails at load, not on every retry
func TestH_CallModeCheckedAtLoad(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "call", option.CallOutboundOptions{
		JoinLink: "x", CallCommonOptions: option.CallCommonOptions{Platform: "wbstream", Mode: "audio"},
	})
	require.ErrorContains(t, err, "unknown wbstream mode")
}
