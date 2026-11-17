package vk

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing-box/transport/call/tunnel/rtc"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// ConnectCreator joins the call (or makes one) and returns once the session runs: the function
// that ends it, and the link the other side joins with. Connections of the peers that join, now
// or after a reconnect, go to accept.
//
// Hiddify: it waited 60 s for a first peer, failed without one and left the session running,
// and the inbound tried again: a server nobody had joined yet started one more call session
// every two minutes, none of which could be stopped, and a peer that joined one of them later
// was served by a bridge without the inbound's handlers.
func ConnectCreator(ctx context.Context, cookieStr, joinLink string, readBuf int, dialer N.Dialer, dnsRouter adapter.DNSRouter, accept tunnel.AcceptHandlers, logger logger.ContextLogger) (func(), string, error) {
	cfg, err := FetchConfig(logger)
	if err != nil {
		return nil, "", err
	}
	var callInfo *CallInfo
	if joinLink != "" {
		callInfo, err = JoinExistingCall(dialer, cookieStr, joinLink, cfg, logger)
	} else {
		callInfo, err = CreateAndJoinCall(dialer, cookieStr, "", cfg, logger)
	}
	if err != nil {
		return nil, "", err
	}
	if readBuf <= 0 {
		readBuf = 32768
	}
	obf, err := tunnel.NewTunnelObfuscator(tunnel.DeriveSecretFromJoinLink(callInfo.JoinLink))
	if err != nil {
		return nil, "", fmt.Errorf("vk: obfuscator init: %w", err)
	}
	bridge := newBridge(dialer, dnsRouter, readBuf, obf, accept, logger)
	go bridge.Run(callInfo, cookieStr, cfg)
	return bridge.Close, callInfo.JoinLink, nil
}

// newBridge is a creator's bridge, not yet running.
func newBridge(dialer N.Dialer, dnsRouter adapter.DNSRouter, readBuf int, obf *tunnel.TunnelObfuscator, accept tunnel.AcceptHandlers, logger logger.ContextLogger) *Bridge {
	ctx, cancel := context.WithCancel(context.Background()) // the session outlives the dial
	bridge := &Bridge{
		dialer:    dialer,
		dnsRouter: dnsRouter,
		readBuf:   readBuf,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
		accept:    accept,
	}
	bridge.newRelay = func() Relay {
		ur := NewTunnelRelay(dialer, logger)
		ur.readBufSize = readBuf
		ur.SetObfuscator(obf)
		ur.OnConnected = bridge.tunnelConnected
		return ur
	}
	return bridge
}

// tunnelConnected makes the bridge of a peer that connected: its connections go to the handlers
// the session was given.
func (b *Bridge) tunnelConnected(tun tunnel.DataTunnel) {
	rb := tunnel.NewCreatorBridge(tun, b.accept, b.logger)
	rb.MarkReady()
	if st, ok := tun.(*rtc.SymmetricScreenTunnel); ok {
		rb.SetOnPeerConfig(func(fps, batch, trackCount int) {
			st.SetTrackCount(trackCount)
			b.setScreenSharing(trackCount > 1)
		})
	}
	b.mu.Lock()
	if b.ctx.Err() != nil { // closed while the peer connected
		b.mu.Unlock()
		rb.Close()
		return
	}
	b.activeBridge = rb
	b.mu.Unlock()
}

// ConnectJoiner joins the call and returns the bridge to dial through, and the function that
// leaves the call.
func ConnectJoiner(ctx context.Context, joinLink, displayName string, readBuf int, dialer N.Dialer, dnsRouter adapter.DNSRouter, logger logger.ContextLogger) (*tunnel.RelayBridge, func(), error) {
	if displayName == "" {
		displayName = "Joiner"
	}
	if readBuf <= 0 {
		readBuf = 32768
	}
	authJSON, err := RunVKAuth(dialer, joinLink, displayName, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("vk: auth: %w", err)
	}
	var params VKAuthParams
	if err := json.Unmarshal([]byte(authJSON), &params); err != nil {
		return nil, nil, fmt.Errorf("vk: decode auth params: %w", err)
	}
	params.TunnelMode = "video"
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, nil, fmt.Errorf("vk: encode auth params: %w", err)
	}
	joiner := NewVKJoiner(
		logger,
		nil,
		common.AddTunnelTracks,
		common.ReadTrack,
		dialer,
		dnsRouter,
	)
	tunCh := make(chan tunnel.DataTunnel, 1)
	joiner.OnConnected = func(tun tunnel.DataTunnel) {
		select {
		case tunCh <- tun:
		default:
		}
	}
	go joiner.RunWithParams(string(paramsJSON))
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
