package bitrix

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	headless "github.com/kulikov0/headless-client"
	"github.com/kulikov0/headless-client/webrtc"
)

const (
	bitrixReconnectInitialDelay = time.Second
	bitrixReconnectMaxDelay     = 16 * time.Second
)

type BitrixJoiner struct {
	logger            logger.ContextLogger
	OnConnected       func(tunnel.DataTunnel)
	OnRemoteCandidate func(target int, candidateOrSDP string)
	PCConfig          common.PeerConnectionConfigurer
	Dialer            N.Dialer

	joinLink    string
	displayName string
	portal      string
	alias       string
	tunnelMode  string
	vp8FPS      int
	vp8Batch    int
	reliable    bool
	dualTrack   bool

	sessMu sync.Mutex
	sig    *Signal
	ms     *MediaSession
	pull   *PullClient

	closeMu sync.Mutex
	closed  bool

	stopCh           chan struct{}
	stopOnce         sync.Once
	reconnectAttempt atomic.Int32
}

func NewBitrixJoiner(logger logger.ContextLogger, pcConfig common.PeerConnectionConfigurer, dialer N.Dialer) *BitrixJoiner {
	return &BitrixJoiner{
		logger:   logger,
		PCConfig: pcConfig,
		Dialer:   dialer,
		stopCh:   make(chan struct{}),
	}
}

func (j *BitrixJoiner) MarkConfigAcked() {
	j.sessMu.Lock()
	ms := j.ms
	j.sessMu.Unlock()
	if ms != nil {
		ms.MarkConfigAcked()
	}
}

func (j *BitrixJoiner) RunWithParams(jsonParams string) {
	var params struct {
		JoinLink    string `json:"joinLink"`
		DisplayName string `json:"displayName"`
		TunnelMode  string `json:"tunnelMode"`
		VP8FPS      int    `json:"vp8Fps"`
		VP8Batch    int    `json:"vp8Batch"`
		Reliable    bool   `json:"reliable"`
		DualTrack   bool   `json:"dualTrack"`
	}
	if err := json.Unmarshal([]byte(jsonParams), &params); err != nil {
		j.logger.Error(fmt.Sprintf("bitrix-joiner: failed to parse params: %v", err))
		return
	}
	j.joinLink = params.JoinLink
	j.displayName = params.DisplayName
	if j.displayName == "" {
		j.displayName = "Joiner"
	}
	if strings.EqualFold(params.TunnelMode, "dc") {
		j.tunnelMode = TunnelModeDC
	} else {
		j.tunnelMode = TunnelModeVideo
	}
	j.vp8FPS = params.VP8FPS
	if j.vp8FPS <= 0 {
		j.vp8FPS = 24
	}
	j.vp8Batch = params.VP8Batch
	if j.vp8Batch <= 0 {
		j.vp8Batch = 30
	}
	j.reliable = params.Reliable
	j.dualTrack = params.DualTrack

	portal, alias, err := parseBitrixJoinLink(j.joinLink)
	if err != nil {
		j.logger.Error(fmt.Sprintf("bitrix-joiner: %v", err))
		return
	}
	j.portal = portal
	j.alias = alias
	j.logger.Debug(fmt.Sprintf("bitrix-joiner: portal=%s alias=%s mode=%s vp8Fps=%d vp8Batch=%d reliable=%v dualTrack=%v",
		j.portal, j.alias, j.tunnelMode, j.vp8FPS, j.vp8Batch, j.reliable, j.dualTrack))

	if err := j.runOnce(); err != nil {
		j.logger.Error(fmt.Sprintf("bitrix-joiner: %v", err))
		return
	}
	for {
		if j.isClosed() {
			return
		}
		j.logger.Info("bitrix-joiner: tunnel lost")
		j.resetSessionState()
		if !j.waitBeforeRetry(int(j.reconnectAttempt.Load())) {
			return
		}
		j.reconnectAttempt.Add(1)
		if j.isClosed() {
			return
		}
		j.logger.Info(fmt.Sprintf("bitrix-joiner: reconnect attempt #%d", j.reconnectAttempt.Load()))
		if err := j.runOnce(); err != nil {
			j.logger.Warn(fmt.Sprintf("bitrix-joiner: %v, will retry", err))
		}
	}
}

func (j *BitrixJoiner) Close() {
	j.closeMu.Lock()
	j.closed = true
	j.closeMu.Unlock()
	j.stopOnce.Do(func() { close(j.stopCh) })
	j.resetSessionState()
}

func (j *BitrixJoiner) runOnce() error {
	userAgent := headless.ChromeWindows.UserAgent()
	c, err := NewClient(j.portal, userAgent, j.Dialer, j.logger)
	if err != nil {
		return fmt.Errorf("new client: %w", err)
	}
	c.HTTP.Transport = j.makeTransport()

	res, err := c.JoinAsGuest(j.alias, j.displayName)
	if err != nil {
		return fmt.Errorf("join as guest: %w", err)
	}
	j.logger.Debug(fmt.Sprintf("bitrix-joiner: roomId=%s mediaServer=%s", res.RoomID, res.MediaServerURL))

	var configureSettingEngine func(*webrtc.SettingEngine)
	if j.PCConfig != nil {
		configureSettingEngine = j.PCConfig.ConfigureSettingEngine
	}

	var once sync.Once
	connected := make(chan struct{})
	sig, err := ConnectSignal(SignalConfig{
		SignalURL:              SignalURL(res),
		Origin:                 j.portal,
		UserAgent:              userAgent,
		Logger:                 j.logger,
		ConfigureSettingEngine: configureSettingEngine,
		NetDialContext:         j.makeDialContext(),
		OnConnected: func() {
			once.Do(func() { close(connected) })
		},
		OnRemoteCandidate: j.OnRemoteCandidate,
	})
	if err != nil {
		return fmt.Errorf("signal connect: %w", err)
	}

	ms, err := NewMediaSession(MediaParams{
		Signal:    sig,
		Alias:     j.alias,
		Mode:      j.tunnelMode,
		FPS:       j.vp8FPS,
		Batch:     j.vp8Batch,
		Reliable:  j.reliable,
		DualTrack: j.dualTrack,
		Logger:    j.logger,
	})
	if err != nil {
		sig.Close()
		return fmt.Errorf("media session: %w", err)
	}
	ms.OnConnected = func(tun tunnel.DataTunnel) {
		j.reconnectAttempt.Store(0)
		j.logger.Info(fmt.Sprintf("bitrix-joiner: === TUNNEL CONNECTED === %T", tun))
		if j.OnConnected != nil {
			j.OnConnected(tun)
		}
	}
	j.setSession(sig, ms)

	done := make(chan struct{})
	go func() {
		if err := sig.Run(); err != nil {
			j.logger.Debug(fmt.Sprintf("bitrix-joiner: signal run ended: %s", common.MaskError(err)))
		}
		close(done)
	}()

	select {
	case <-connected:
	case <-done:
		return fmt.Errorf("signal closed before media connect")
	case <-j.stopCh:
		sig.Close()
		return nil
	}

	j.startKickWatch(c, sig, userAgent)

	if err := ms.Start(); err != nil {
		sig.Close()
		return fmt.Errorf("media start: %w", err)
	}

	select {
	case <-done:
	case <-j.stopCh:
		sig.Close()
	}
	return nil
}

func (j *BitrixJoiner) makeDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if j.Dialer == nil {
		return nil
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return j.Dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
	}
}

func (j *BitrixJoiner) makeTransport() http.RoundTripper {
	return headless.ChromeWindows.Transport(headless.TLSOptions{
		DialContext: j.makeDialContext(),
	})
}

func (j *BitrixJoiner) setSession(sig *Signal, ms *MediaSession) {
	j.sessMu.Lock()
	j.sig = sig
	j.ms = ms
	j.sessMu.Unlock()
}

func (j *BitrixJoiner) startKickWatch(c *Client, sig *Signal, userAgent string) {
	selfID := sig.LocalUserID()
	if selfID == "" {
		j.logger.Debug("bitrix-joiner: self userId unknown, kick-detect disabled")
		return
	}
	pc, err := c.PullConfig()
	if err != nil {
		j.logger.Debug(fmt.Sprintf("bitrix-joiner: pull config failed, kick-detect disabled: %s", common.MaskError(err)))
		return
	}
	pull := NewPullClient(pc, userAgent, j.portal, j.logger)
	pull.SetOnUserLeave(func(uid string) {
		if uid != selfID {
			return
		}
		j.logger.Info(fmt.Sprintf("bitrix-joiner: kicked from conference (userId=%s), shutting down", uid))
		go j.Close()
	})
	j.sessMu.Lock()
	j.pull = pull
	j.sessMu.Unlock()
	go func() {
		if err := pull.Run(); err != nil {
			j.logger.Debug(fmt.Sprintf("bitrix-joiner: subws2 pull ended: %s", common.MaskError(err)))
		}
	}()
}

func (j *BitrixJoiner) resetSessionState() {
	j.sessMu.Lock()
	sig := j.sig
	ms := j.ms
	pull := j.pull
	j.sig = nil
	j.ms = nil
	j.pull = nil
	j.sessMu.Unlock()
	if pull != nil {
		pull.Close()
	}
	if ms != nil {
		ms.Stop()
	}
	if sig != nil {
		sig.Close()
	}
}

func (j *BitrixJoiner) waitBeforeRetry(attempt int) bool {
	delay := common.BackoffWithJitter(attempt, bitrixReconnectInitialDelay, bitrixReconnectMaxDelay)
	j.logger.Debug(fmt.Sprintf("bitrix-joiner: waiting %s before reconnect", delay))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return !j.isClosed()
	case <-j.stopCh:
		return false
	}
}

func (j *BitrixJoiner) isClosed() bool {
	j.closeMu.Lock()
	defer j.closeMu.Unlock()
	return j.closed
}

func parseBitrixJoinLink(joinLink string) (portal, alias string, err error) {
	u, err := url.Parse(joinLink)
	if err != nil {
		return "", "", fmt.Errorf("bad join link: %w", err)
	}
	portal = u.Scheme + "://" + u.Host
	alias = strings.TrimPrefix(u.Path, "/video/")
	if alias == "" || portal == "://" {
		return "", "", fmt.Errorf("link missing portal or /video/CODE: %s", joinLink)
	}
	return portal, alias, nil
}
