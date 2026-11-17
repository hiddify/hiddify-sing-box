package dion

import (
	"context"
	"fmt"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// ConnectCreator joins the room (or makes one) and returns once the session runs: the function
// that ends it, and the link the other side joins with. Connections of the peers that join go to
// accept.
//
// Hiddify: it waited 60 s for a first peer and failed without one, and the inbound tried again:
// a server nobody had joined yet made a new room every two minutes.
func ConnectCreator(ctx context.Context, cookieStr, roomID, email, password string, readBuf int, dialer N.Dialer, dnsRouter adapter.DNSRouter, accept tunnel.AcceptHandlers, logger logger.ContextLogger) (func(), string, error) {
	auth, err := NewSession(dialer)
	if err != nil {
		return nil, "", fmt.Errorf("dion: new session: %w", err)
	}
	if cookieStr != "" || email == "" || password == "" { // Hiddify: email and password alone log in
		if err := auth.LoadCookieString(cookieStr); err != nil {
			return nil, "", fmt.Errorf("dion: load cookies: %w", err)
		}
	}
	auth.SetCredentials(email, password)
	if err := auth.EnsureValidToken(); err != nil {
		return nil, "", fmt.Errorf("dion: ensure valid token: %w", err)
	}
	requestedRoom := ParseRoom(roomID)
	var event *EventInfo
	if requestedRoom != "" {
		event, err = auth.GetEventBySlug(requestedRoom)
		if err != nil {
			return nil, "", fmt.Errorf("dion: get event by slug: %w", err)
		}
	} else {
		event, err = auth.CreateRoom()
		if err != nil {
			return nil, "", fmt.Errorf("dion: create room: %w", err)
		}
	}
	joinLink := WebBase + "/event/" + event.Slug
	if readBuf <= 0 {
		readBuf = 32768
	}
	obf, err := tunnel.NewTunnelObfuscator(tunnel.DeriveSecretFromJoinLink(event.Slug))
	if err != nil {
		return nil, "", fmt.Errorf("dion: obfuscator init: %w", err)
	}
	var (
		access      sync.Mutex
		activeRelay *tunnel.RelayBridge
		closed      bool
	)
	call := NewCall(CallConfig{
		Auth:        auth,
		Event:       event,
		Obfuscator:  obf,
		DisplayName: "Creator",
		Logger:      logger,
		Dialer:      dialer,
		DNSRouter:   dnsRouter,
		Role:        RoleCreator,
	})
	call.OnConnected = func(tun tunnel.DataTunnel) {
		next := tunnel.NewCreatorBridge(tun, accept, logger)
		next.MarkReady()
		access.Lock()
		if closed { // closed while the peer connected
			access.Unlock()
			next.Close()
			return
		}
		previous := activeRelay
		activeRelay = next
		access.Unlock()
		if previous != nil {
			previous.Reset()
		}
	}
	call.OnPeerRestart = func() {
		access.Lock()
		active := activeRelay
		access.Unlock()
		if active != nil {
			active.Reset()
		}
	}
	if err := call.Start(); err != nil {
		call.Close()
		return nil, "", fmt.Errorf("dion: call start: %w", err)
	}
	// TODO(hiddify): nobody waits for call.Done(): when ICE or the signaling dies, the session is
	// over and is not joined again. Return Done, so protocol/call connects again with its backoff.
	return func() {
		call.Close()
		access.Lock()
		closed = true
		active := activeRelay
		access.Unlock()
		if active != nil {
			active.Close()
		}
	}, joinLink, nil
}

// ConnectJoiner joins the room and returns the bridge to dial through, and the function that
// leaves the room.
func ConnectJoiner(ctx context.Context, roomID, displayName string, readBuf int, dialer N.Dialer, dnsRouter adapter.DNSRouter, logger logger.ContextLogger) (*tunnel.RelayBridge, func(), error) {
	if displayName == "" {
		displayName = "Joiner"
	}
	if readBuf <= 0 {
		readBuf = 32768
	}
	joiner := NewDionJoiner(logger, dialer, dnsRouter)
	tunCh := make(chan tunnel.DataTunnel, 1)
	// TODO(hiddify): only the first tunnel is taken. The one the joiner makes when it joins again
	// is dropped below and the bridge keeps the dead one: give it to the bridge (SwapTunnel).
	joiner.OnConnected = func(tun tunnel.DataTunnel) {
		select {
		case tunCh <- tun:
		default:
		}
	}
	params := fmt.Sprintf(`{"roomId":%q,"displayName":%q}`, roomID, displayName)
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
