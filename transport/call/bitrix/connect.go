package bitrix

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// ConnectJoiner joins the call and returns the bridge to dial through, and the function that
// leaves the call.
func ConnectJoiner(ctx context.Context, joinLink, displayName, mode string, readBuf int, dialer N.Dialer, logger logger.ContextLogger) (*tunnel.RelayBridge, func(), error) {
	if displayName == "" {
		displayName = "Joiner"
	}
	if mode == "" {
		mode = TunnelModeVideo
	}
	if readBuf <= 0 {
		readBuf = 32768
	}
	params := struct {
		JoinLink    string `json:"joinLink"`
		DisplayName string `json:"displayName"`
		TunnelMode  string `json:"tunnelMode"`
	}{
		JoinLink:    joinLink,
		DisplayName: displayName,
		TunnelMode:  mode,
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, nil, fmt.Errorf("bitrix: encode params: %w", err)
	}
	joiner := NewBitrixJoiner(logger, nil, dialer)
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
