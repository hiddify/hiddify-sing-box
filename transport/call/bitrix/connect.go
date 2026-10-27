package bitrix

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing-box/transport/call/tunnel/rtc"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func ConnectJoiner(ctx context.Context, joinLink, displayName, mode string, readBuf int, dialer N.Dialer, logger logger.ContextLogger) (*tunnel.RelayBridge, error) {
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
		return nil, fmt.Errorf("bitrix: encode params: %w", err)
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
		rb := tunnel.NewRelayBridge(tun, "joiner", bridgeReadBufFor(tun, readBuf), dialer, logger)
		rb.SetOnConfigAck(joiner.MarkConfigAcked)
		rb.MarkReady()
		return rb, nil
	case <-ctx.Done():
		joiner.Close()
		return nil, ctx.Err()
	}
}

func bridgeReadBufFor(tun tunnel.DataTunnel, readBuf int) int {
	switch tun.(type) {
	case *rtc.DCTunnel, *rtc.MultiTrackKCPTunnel:
		return readBuf
	}
	return common.VP8BufSize
}
