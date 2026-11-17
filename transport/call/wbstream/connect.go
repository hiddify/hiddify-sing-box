package wbstream

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// ConnectCreator joins the room (or makes one) and returns once the session runs: the function
// that ends it, and the link the other side joins with. Connections of the peers that join, now
// or after a reconnect, go to accept.
//
// Hiddify: it waited 60 s for a first peer and failed without one, and the inbound tried again:
// a server nobody had joined yet joined its room anew every two minutes. Its rejoining loop
// ended only with the context of the connect, and closing the bridge left the session up.
func ConnectCreator(ctx context.Context, cookieStr, roomID, mode string, readBuf int, dialer N.Dialer, accept tunnel.AcceptHandlers, logger logger.ContextLogger) (func(), string, error) {
	deviceID := common.CookieValue(cookieStr, "__wb_device_id")
	if deviceID == "" {
		return nil, "", fmt.Errorf("wbstream: cookies missing __wb_device_id")
	}
	cookieHeader := common.FilterCookies(cookieStr, WBStreamCookieAllowlist)
	httpClient := common.HttpClient(dialer)
	bearer, rotated, err := RefreshAccessToken(httpClient, cookieHeader, deviceID)
	if err != nil {
		return nil, "", fmt.Errorf("wbstream: slide-v3 refresh: %w", err)
	}
	cookieHeader = mergeCookies(cookieHeader, rotated)
	requestedRoom := ParseRoomID(roomID)
	resolvedRoomID, roomToken, accessToken, serverURL, err := AuthAsLoggedIn(httpClient, cookieHeader, bearer, requestedRoom, "Creator")
	if err != nil {
		return nil, "", fmt.Errorf("wbstream: auth: %w", err)
	}
	if readBuf <= 0 {
		readBuf = 32768
	}
	if mode == "" {
		mode = TunnelModeDC
	}
	obf, err := tunnel.NewTunnelObfuscator(tunnel.DeriveSecretFromJoinLink(resolvedRoomID))
	if err != nil {
		return nil, "", fmt.Errorf("wbstream: obfuscator init: %w", err)
	}

	var relay atomic.Pointer[tunnel.RelayBridge] // made when the first peer connects
	joinSession := func(token, access, server string) (*Session, <-chan tunnel.DataTunnel) {
		tunCh := make(chan tunnel.DataTunnel, 1)
		sess := NewSession(SessionConfig{
			RoomToken:   token,
			ServerURL:   server,
			DisplayName: "Creator",
			TunnelMode:  mode,
			Obfuscator:  obf,
			Logger:      logger,
			Dialer:      dialer,
			RoomID:      resolvedRoomID,
			AccessToken: access,
			ReadBuf:     readBuf,
		})
		sess.OnConnected = func(tun tunnel.DataTunnel) {
			select {
			case tunCh <- tun:
			default:
			}
		}
		sess.OnPeerRestart = func() {
			if active := relay.Load(); active != nil {
				active.Reset()
			}
		}
		return sess, tunCh
	}

	sess, tunCh := joinSession(roomToken, accessToken, serverURL)
	if err := sess.Start(); err != nil {
		return nil, "", fmt.Errorf("wbstream: session start: %w", err)
	}
	// the session outlives the dial; cancelled, the loop closes the session and the bridge
	sessionCtx, cancel := context.WithCancel(context.Background())
	go creatorLoop(sessionCtx, &relay, accept, sess, tunCh, joinSession, httpClient, cookieHeader, bearer, deviceID, resolvedRoomID, logger)
	return cancel, APIBase + "/room/" + resolvedRoomID, nil
}

// ConnectJoiner joins the room and returns the bridge to dial through, and the function that
// leaves the room.
func ConnectJoiner(ctx context.Context, roomID, displayName, mode string, readBuf int, dialer N.Dialer, dnsRouter adapter.DNSRouter, logger logger.ContextLogger) (*tunnel.RelayBridge, func(), error) {
	roomID = ParseRoomID(roomID)
	if displayName == "" {
		displayName = "Joiner"
	}
	if mode == "" {
		mode = TunnelModeDC
	}
	if readBuf <= 0 {
		readBuf = 32768
	}
	joiner := NewWBStreamJoiner(logger, dialer, dnsRouter, nil)
	tunCh := make(chan tunnel.DataTunnel, 1)
	joiner.OnConnected = func(tun tunnel.DataTunnel) {
		select {
		case tunCh <- tun:
		default:
		}
	}
	params := fmt.Sprintf(`{"roomId":%q,"displayName":%q,"tunnelMode":%q}`, roomID, displayName, mode)
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

// creatorLoop is a creator's session from the moment it is up until ctx ends: it gives each
// peer's tunnel to the bridge, and joins the room again when the session ends.
func creatorLoop(
	ctx context.Context,
	relay *atomic.Pointer[tunnel.RelayBridge],
	accept tunnel.AcceptHandlers,
	current *Session,
	tunCh <-chan tunnel.DataTunnel,
	joinSession func(token, access, server string) (*Session, <-chan tunnel.DataTunnel),
	httpClient *http.Client,
	cookieHeader, bearer, deviceID, roomID string,
	logger logger.ContextLogger,
) {
	defer func() {
		current.Close()
		if active := relay.Load(); active != nil {
			active.Close()
		}
	}()
	for {
		// the session is up: a peer's tunnel comes, or the session ends
		select {
		case tun := <-tunCh:
			if active := relay.Load(); active != nil {
				active.SwapTunnel(tun)
				logger.Info("wbstream: creator tunnel reconnected")
			} else {
				relay.Store(tunnel.NewCreatorBridge(tun, accept, logger))
			}
			select {
			case <-current.Done():
			case <-ctx.Done():
				return
			}
		case <-current.Done():
		case <-ctx.Done():
			return
		}
		current.Close()
		logger.Debug("wbstream: creator session ended, rejoining")
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			_, roomToken, accessToken, serverURL, err := AuthAsLoggedIn(httpClient, cookieHeader, bearer, roomID, "Creator")
			if err != nil {
				logger.Warn(fmt.Sprintf("wbstream: rejoin auth failed: %v, refreshing bearer", err))
				var rotated map[string]string
				bearer, rotated, err = RefreshAccessToken(httpClient, cookieHeader, deviceID)
				if err != nil {
					logger.Warn(fmt.Sprintf("wbstream: rejoin token refresh failed: %v, retrying", err))
					continue
				}
				cookieHeader = mergeCookies(cookieHeader, rotated)
				_, roomToken, accessToken, serverURL, err = AuthAsLoggedIn(httpClient, cookieHeader, bearer, roomID, "Creator")
				if err != nil {
					logger.Warn(fmt.Sprintf("wbstream: rejoin auth failed: %v, retrying", err))
					continue
				}
			}
			newSess, newTunCh := joinSession(roomToken, accessToken, serverURL)
			if err := newSess.Start(); err != nil {
				logger.Warn(fmt.Sprintf("wbstream: rejoin session start failed: %v, retrying", err))
				continue
			}
			current, tunCh = newSess, newTunCh
			break
		}
	}
}
