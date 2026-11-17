package telemost

import (
	"context"
	"fmt"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func ConnectCreator(ctx context.Context, cookieStr, joinLink string, readBuf int, dialer N.Dialer, logger logger.ContextLogger) (*tunnel.RelayBridge, string, error) {
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
		logger:    logger,
	}
	go bridge.Run()
	deadline := time.Now().Add(60 * time.Second)
	for bridge.getActiveBridge() == nil {
		// a connect that gives up ends the session it started: left running, it kept the call
		// and joined it again for the rest of the process
		if time.Now().After(deadline) {
			bridge.Close()
			return nil, "", fmt.Errorf("telemost: creator tunnel timed out")
		}
		select {
		case <-ctx.Done():
			bridge.Close()
			return nil, "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return bridge.getActiveBridge(), connInfo.ConferenceURI, nil
}

func ConnectJoiner(ctx context.Context, joinLink, displayName string, readBuf int, dialer N.Dialer, dnsRouter adapter.DNSRouter, logger logger.ContextLogger) (*tunnel.RelayBridge, error) {
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
	joiner.OnConnected = func(tun tunnel.DataTunnel) {
		select {
		case tunCh <- tun:
		default:
		}
	}
	params := fmt.Sprintf(`{"joinLink":%q,"displayName":%q}`, joinLink, displayName)
	go joiner.RunWithParams(params)
	select {
	case tun := <-tunCh:
		rb := tunnel.NewRelayBridge(tun, "joiner", readBuf, dialer, logger)
		rb.SetOnConfigAck(joiner.MarkConfigAcked)
		rb.MarkReady()
		return rb, nil
	case <-ctx.Done():
		joiner.Close()
		return nil, ctx.Err()
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
