package telemost

import (
	"context"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// ConnectCreator joins the conference (or makes one) and returns once the session runs: the
// function that ends it, and the link the other side joins with. Connections of the peers that
// join, now or after a reconnect, go to accept.
//
// Hiddify: it waited 60 s for a first peer and failed without one, and the inbound tried again:
// a server nobody had joined yet made a new conference every two minutes.
func ConnectCreator(ctx context.Context, cookieStr, joinLink string, readBuf int, dialer N.Dialer, accept tunnel.AcceptHandlers, logger logger.ContextLogger) (func(), string, error) {
	cfg, err := FetchConfig(dialer, logger)
	if err != nil {
		return nil, "", err
	}
	var connInfo *ConnInfo
	if joinLink != "" {
		connInfo, err = joinExistingConference(dialer, cookieStr, joinLink, cfg, logger)
	} else {
		connInfo, err = CreateAndJoinCall(dialer, cookieStr, cfg, logger)
	}
	if err != nil {
		return nil, "", err
	}
	if readBuf <= 0 {
		readBuf = 32768
	}
	bridgeCtx, cancel := context.WithCancel(context.Background()) // the session outlives the dial
	bridge := &Bridge{
		ctx:       bridgeCtx,
		cancel:    cancel,
		connInfo:  connInfo,
		config:    cfg,
		cookieStr: cookieStr,
		peers:     make(map[string]string),
		seenPids:  make(map[string]bool),
		readBuf:   readBuf,
		dialer:    dialer,
		accept:    accept,
		logger:    logger,
	}
	go bridge.Run()
	return bridge.Close, connInfo.ConferenceURI, nil
}

// ConnectJoiner joins the conference and returns the bridge to dial through, and the function
// that leaves the conference.
func ConnectJoiner(ctx context.Context, joinLink, displayName string, readBuf int, dialer N.Dialer, dnsRouter adapter.DNSRouter, logger logger.ContextLogger) (*tunnel.RelayBridge, func(), error) {
	if displayName == "" {
		displayName = "Joiner"
	}
	if readBuf <= 0 {
		readBuf = 32768
	}
	joiner := NewTelemostJoiner(
		logger,
		dialer,
		dnsRouter,
		nil,
		common.AddTunnelTracks,
		common.ReadTrack,
	)
	tunCh := make(chan tunnel.DataTunnel, 1)
	// TODO(hiddify): only the first tunnel is taken. The one the joiner makes when it joins again
	// is dropped below and the bridge keeps the dead one: give it to the bridge (SwapTunnel).
	joiner.OnConnected = func(tun tunnel.DataTunnel) {
		select {
		case tunCh <- tun:
		default:
		}
	}
	params := fmt.Sprintf(`{"joinLink":%q,"displayName":%q}`, joinLink, displayName)
	// TODO(hiddify): RunWithParams returns when its first join fails and tells nobody: the select
	// below waits until ctx ends and the caller never retries. Have it report its end and error.
	go joiner.RunWithParams(params)
	select {
	case tun := <-tunCh:
		rb := tunnel.NewJoinerBridge(tun, logger)
		rb.SetOnConfigAck(joiner.MarkConfigAcked)
		rb.MarkReady()
		return rb, joiner.Close, nil
	case <-ctx.Done():
		joiner.Close()
		return nil, nil, ctx.Err()
	}
}

func CreateConferenceForTest(dialer N.Dialer, cookieStr string) (string, error) {
	nop := logger.NOP()
	cfg, err := FetchConfig(dialer, nop)
	if err != nil {
		return "", err
	}
	connInfo, err := CreateAndJoinCall(dialer, cookieStr, cfg, nop)
	if err != nil {
		return "", err
	}
	return connInfo.ConferenceURI, nil
}
