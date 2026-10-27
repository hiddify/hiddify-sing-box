package vk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/headlessapi"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing-box/transport/call/tunnel/rtc"
	"github.com/sagernet/sing-box/transport/call/wtsignal"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	headless "github.com/kulikov0/headless-client"
	"github.com/kulikov0/headless-client/webrtc"
)

const (
	vkReconnectInitialDelay = time.Second
	vkReconnectMaxDelay     = 16 * time.Second
	vkMaxReconnectAttempts  = 10
)

const vkOrigin = "https://vk.ru"

const vkTopologyDirect = "DIRECT"

type vkAuthRottenError struct {
	Code string
	Msg  string
}

func (e *vkAuthRottenError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("auth rotten: %s %s", e.Code, e.Msg)
	}
	return fmt.Sprintf("auth rotten: %s", e.Code)
}

type VKAuthParams struct {
	SessionKey      string `json:"sessionKey"`
	ApplicationKey  string `json:"applicationKey"`
	APIBaseURL      string `json:"apiBaseURL"`
	JoinLink        string `json:"joinLink"`
	AnonymToken     string `json:"anonymToken"`
	AppVersion      string `json:"appVersion"`
	ProtocolVersion string `json:"protocolVersion"`
	TunnelMode      string `json:"tunnelMode"`
	VP8FPS          int    `json:"vp8Fps"`
	VP8Batch        int    `json:"vp8Batch"`
	DualTrack       bool   `json:"dualTrack"`
}

type VKJoinResponse struct {
	Endpoint   string `json:"endpoint"`
	WtEndpoint string `json:"wt_endpoint"`
	Token      string `json:"token"`
	TurnServer struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	} `json:"turn_server"`
	StunServer struct {
		URLs []string `json:"urls"`
	} `json:"stun_server"`
}

type VKJoiner struct {
	logger            logger.ContextLogger
	OnConnected       func(tunnel.DataTunnel)
	OnRemoteCandidate func(target int, candidateOrSDP string)
	PCConfig          common.PeerConnectionConfigurer
	AddTracks         common.AddTunnelTracksFunc
	ReadTrackFn       common.ReadTrackFunc
	Dialer            N.Dialer
	DNSRouter         adapter.DNSRouter

	authParams   *VKAuthParams
	joinResp     *VKJoinResponse
	sfu          *wtsignal.Conn
	vkMu         sync.Mutex
	vkSeq        int
	remotePeerID *int64

	pc             *webrtc.PeerConnection
	sampleTrack    *webrtc.TrackLocalStaticSample
	dc             *webrtc.DataChannel
	vp8tunnel      *rtc.VP8DataTunnel
	sym            *rtc.SymmetricScreenTunnel
	producerScreen screenUplink
	obf            *tunnel.TunnelObfuscator
	vp8FPS         int
	vp8Batch       int
	dualTrack      bool
	remoteSet      bool
	pendingICE     []webrtc.ICECandidateInit

	configAck        tunnel.ConfigAckTracker
	reconnectAttempt atomic.Int32
	stopCh           chan struct{}
	stopOnce         sync.Once
}

func NewVKJoiner(logger logger.ContextLogger, pcConfig common.PeerConnectionConfigurer, addTracks common.AddTunnelTracksFunc, readTrackFn common.ReadTrackFunc, dialer N.Dialer, dnsRouter adapter.DNSRouter) *VKJoiner {
	return &VKJoiner{
		logger:      logger,
		PCConfig:    pcConfig,
		AddTracks:   addTracks,
		ReadTrackFn: readTrackFn,
		Dialer:      dialer,
		DNSRouter:   dnsRouter,
		stopCh:      make(chan struct{}),
	}
}

func (h *VKJoiner) RunWithParams(jsonParams string) {
	var params VKAuthParams
	if err := json.Unmarshal([]byte(jsonParams), &params); err != nil {
		h.logger.Error(fmt.Sprintf("vk-joiner: failed to parse auth params: %v", err))
		return
	}
	h.authParams = &params
	obf, err := tunnel.NewTunnelObfuscator(tunnel.DeriveSecretFromJoinLink(params.JoinLink))
	if err != nil {
		h.logger.Error(fmt.Sprintf("vk-joiner: obfuscator init failed: %v", err))
		return
	}
	h.obf = obf
	h.vp8FPS = params.VP8FPS
	h.vp8Batch = params.VP8Batch
	// h.dualTrack = params.DualTrack // temporarily disabled for VK joiners
	h.logger.Debug("vk-joiner: auth params received")
	h.logger.Debug(fmt.Sprintf("vk-joiner: obf key-source=%q localEpoch=0x%08x", params.JoinLink, obf.LocalEpoch()))
	h.logger.Debug(fmt.Sprintf("vk-joiner:   appVersion=%s protocolVersion=%s vp8Fps=%d vp8Batch=%d",
		params.AppVersion, params.ProtocolVersion, params.VP8FPS, params.VP8Batch))
	h.logger.Info("vk-joiner: connecting")
	if err := h.runOnce(); err != nil {
		h.logger.Error(fmt.Sprintf("vk-joiner: %v", err))
		return
	}
	for {
		if h.isClosed() {
			return
		}
		h.logger.Info("vk-joiner: tunnel lost")
		if !h.waitBeforeRetry(int(h.reconnectAttempt.Load())) {
			return
		}
		attempt := h.reconnectAttempt.Add(1)
		if h.isClosed() {
			return
		}
		if int(attempt) > vkMaxReconnectAttempts {
			h.logger.Warn(fmt.Sprintf("vk-joiner: gave up after %d consecutive reconnect attempts", vkMaxReconnectAttempts))
			return
		}
		h.logger.Info(fmt.Sprintf("vk-joiner: reconnect attempt #%d", attempt))
		if err := h.runOnce(); err != nil {
			if _, ok := errors.AsType[*vkAuthRottenError](err); ok {
				h.logger.Error(fmt.Sprintf("vk-joiner: %v, surrendering", err))
				return
			}
			h.logger.Warn(fmt.Sprintf("vk-joiner: %v, will retry", err))
		}
	}
}

func (h *VKJoiner) Close() {
	h.stopOnce.Do(func() { close(h.stopCh) })
	StopCaptchaProxy()
	h.vkMu.Lock()
	sfu := h.sfu
	h.sfu = nil
	h.vkMu.Unlock()
	if sfu != nil {
		sfu.Close()
	}
	if h.vp8tunnel != nil {
		h.vp8tunnel.Stop()
	}
	if h.pc != nil {
		h.pc.Close()
	}
}

func (h *VKJoiner) closeTransport() {
	h.vkMu.Lock()
	sfu := h.sfu
	h.vkMu.Unlock()
	if sfu != nil {
		sfu.Close()
	}
}

func (h *VKJoiner) runOnce() error {
	h.resetSessionState()
	if err := h.joinCall(); err != nil {
		return err
	}
	h.connectSFU()
	return nil
}

func (h *VKJoiner) MarkConfigAcked() { h.configAck.Mark() }

func (h *VKJoiner) waitBeforeRetry(attempt int) bool {
	delay := common.BackoffWithJitter(attempt, vkReconnectInitialDelay, vkReconnectMaxDelay)
	h.logger.Debug(fmt.Sprintf("vk-joiner: waiting %s before reconnect", delay))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return !h.isClosed()
	case <-h.stopCh:
		return false
	}
}

func (h *VKJoiner) isClosed() bool {
	select {
	case <-h.stopCh:
		return true
	default:
		return false
	}
}

func (h *VKJoiner) resetSessionState() {
	h.vkMu.Lock()
	sfu := h.sfu
	h.sfu = nil
	h.vkSeq = 0
	h.vkMu.Unlock()
	if sfu != nil {
		sfu.Close()
	}
	if h.sym != nil {
		h.sym.Stop()
		h.sym = nil
	}
	if h.vp8tunnel != nil {
		h.vp8tunnel.Stop()
		h.vp8tunnel = nil
	}
	h.producerScreen.reset()
	if h.dc != nil {
		h.dc.Close()
		h.dc = nil
	}
	if h.pc != nil {
		h.pc.Close()
		h.pc = nil
	}
	h.sampleTrack = nil
	h.remoteSet = false
	h.pendingICE = nil
	h.remotePeerID = nil
	h.joinResp = nil
}

func (h *VKJoiner) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return h.Dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
}

func (h *VKJoiner) resolveHost(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	rd, hasRD := h.Dialer.(dialer.ResolveDialer)
	if h.DNSRouter == nil || !hasRD {
		return "", fmt.Errorf("no DNS router available to resolve %s", host)
	}
	addrs, err := h.DNSRouter.Lookup(context.Background(), host, rd.QueryOptions())
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses for %s", host)
	}
	return addrs[0].String(), nil
}

func (h *VKJoiner) joinCall() error {
	apiURL := h.authParams.APIBaseURL
	parsed, err := url.Parse(apiURL)
	if err != nil {
		return fmt.Errorf("bad apiBaseURL: %w", err)
	}
	screenFlag := "false"
	if h.dualTrack {
		screenFlag = "true"
	}
	body := url.Values{
		"method":          {"vchat.joinConversationByLink"},
		"session_key":     {h.authParams.SessionKey},
		"application_key": {h.authParams.ApplicationKey},
		"joinLink":        {h.authParams.JoinLink},
		"anonymToken":     {h.authParams.AnonymToken},
		"isVideo":         {"true"},
		"isAudio":         {"false"},
		"mediaSettings":   {`{"isAudioEnabled":false,"isVideoEnabled":true,"isScreenSharingEnabled":` + screenFlag + `}`},
		"format":          {"json"},
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: headless.ChromeWindows.Transport(headless.TLSOptions{
			ServerName:  parsed.Hostname(),
			DialContext: h.dialContext,
		}),
	}
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", headless.ChromeWindows.UserAgent())
	h.logger.Debug("vk-joiner: calling joinConversationByLink...")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("joinConversationByLink: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read join response: %w", err)
	}
	var joinResp VKJoinResponse
	if jsonErr := json.Unmarshal(raw, &joinResp); jsonErr != nil {
		return fmt.Errorf("decode join response: %w (body: %s)", jsonErr, common.BodySnippet(raw))
	}
	if joinResp.Endpoint == "" {
		if rotten := detectVKAuthRotten(raw); rotten != nil {
			return rotten
		}
		return fmt.Errorf("empty endpoint in join response: %s", common.BodySnippet(raw))
	}
	h.joinResp = &joinResp
	h.logger.Debug(fmt.Sprintf("vk-joiner: joined, turn=%v", joinResp.TurnServer.URLs))
	return nil
}

func (h *VKJoiner) connectSFU() {
	endpoint := h.joinResp.WtEndpoint
	if endpoint == "" {
		h.logger.Error("vk-joiner: no wt_endpoint in join response, cannot connect")
		return
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		h.logger.Error(fmt.Sprintf("vk-joiner: bad endpoint URL: %s", common.MaskError(err)))
		return
	}
	hostname := parsed.Hostname()
	resolvedIP, err := h.resolveHost(hostname)
	if err != nil {
		h.logger.Error(fmt.Sprintf("vk-joiner: DNS resolve failed: %s", common.MaskError(err)))
		return
	}
	h.logger.Debug(fmt.Sprintf("vk-joiner: resolved %s -> %s", common.MaskAddr(hostname), common.MaskAddr(resolvedIP)))
	capabilities := "2F7F"
	wtURL := endpoint +
		"&platform=WEB" +
		"&appVersion=" + h.authParams.AppVersion +
		"&version=" + h.authParams.ProtocolVersion +
		"&device=browser&capabilities=" + capabilities + "&clientType=VK&tgt=join&compression=deflate-raw"
	sfu, err := wtsignal.Dial(wtURL, hostname, resolvedIP, vkOrigin)
	if err != nil {
		h.logger.Error(fmt.Sprintf("vk-joiner: WebTransport connect failed: %s", common.MaskError(err)))
		return
	}
	h.vkMu.Lock()
	h.sfu = sfu
	h.vkSeq = 0
	h.vkMu.Unlock()
	h.logger.Debug("vk-joiner: WebTransport connected")
	h.vkSend("update-media-modifiers", map[string]any{
		"mediaModifiers": map[string]any{"denoise": true, "denoiseAnn": true},
	})
	h.vkSend("change-media-settings", map[string]any{
		"mediaSettings": map[string]any{
			"isAudioEnabled": false, "isVideoEnabled": true,
			"isScreenSharingEnabled": h.dualTrack, "isFastScreenSharingEnabled": false,
			"isAudioSharingEnabled": false, "isAnimojiEnabled": false,
		},
	})
	h.readLoop()
}

func (h *VKJoiner) vkSend(command string, extra map[string]any) {
	h.vkMu.Lock()
	defer h.vkMu.Unlock()
	if h.sfu == nil {
		return
	}
	h.vkSeq++
	extra["command"] = command
	extra["sequence"] = h.vkSeq
	out, _ := json.Marshal(extra)
	h.sfu.Send(out)
	h.logger.Debug(fmt.Sprintf("vk-joiner: -> %s", command))
}

func (h *VKJoiner) vkSendTransmitData(participantId int64, payload map[string]any) {
	h.vkMu.Lock()
	defer h.vkMu.Unlock()
	if h.sfu == nil {
		return
	}
	h.vkSeq++
	payloadJSON, _ := json.Marshal(payload)
	out := fmt.Sprintf(`{"command":"transmit-data","sequence":%d,"participantId":%d,"data":%s}`,
		h.vkSeq, participantId, payloadJSON)
	h.sfu.Send([]byte(out))
}

func (h *VKJoiner) readLoop() {
	h.vkMu.Lock()
	sfu := h.sfu
	h.vkMu.Unlock()
	if sfu == nil {
		return
	}
	for {
		msg, err := sfu.Recv()
		if err != nil {
			h.logger.Debug(fmt.Sprintf("vk-joiner: WebTransport closed: %s", common.MaskError(err)))
			return
		}
		if string(msg) == "ping" {
			sfu.Send([]byte("pong"))
			continue
		}
		h.handleVKMessage(msg)
	}
}

func (h *VKJoiner) handleVKMessage(raw []byte) {
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}
	msgType, _ := msg["type"].(string)
	switch msgType {
	case "notification":
		notif, _ := msg["notification"].(string)
		switch notif {
		case "connection":
			h.handleConnection(msg)
		case "transmitted-data":
			data, _ := msg["data"].(map[string]any)
			if data != nil {
				if pid, ok := msg["participantId"].(float64); ok && h.remotePeerID == nil {
					h.onRegisteredPeer(int64(pid))
				}
				h.onTransmittedData(data)
			}
		case "registered-peer":
			if pid, ok := msg["participantId"].(float64); ok {
				h.onRegisteredPeer(int64(pid))
			}
		case "topology-changed":
			topo, _ := msg["topology"].(string)
			h.logger.Debug(fmt.Sprintf("vk-joiner: topology: %s", topo))
			if topo != "" && topo != vkTopologyDirect {
				h.logger.Debug(fmt.Sprintf("vk-joiner: %s topology -> closing transport to reconnect and recover DIRECT", topo))
				h.closeTransport()
			}
		case "participant-joined", "participant-added":
			h.logger.Debug(fmt.Sprintf("vk-joiner: <- %s", notif))
		case "participant-left":
			h.logger.Debug(fmt.Sprintf("vk-joiner: <- %s", notif))
		case "hungup":
			h.logger.Debug("vk-joiner: peer hungup -> closing transport to reconnect")
			h.closeTransport()
		}
	case "response":
		seq, _ := msg["sequence"].(float64)
		h.logger.Debug(fmt.Sprintf("vk-joiner: <- response seq=%d", int(seq)))
	case "error":
		errMsg, _ := msg["message"].(string)
		errCode, _ := msg["error"].(string)
		h.logger.Warn(fmt.Sprintf("vk-joiner: ERROR: %s %s", errCode, errMsg))
	}
}

func (h *VKJoiner) handleConnection(msg map[string]any) {
	if conv, ok := msg["conversation"].(map[string]any); ok {
		topo, _ := conv["topology"].(string)
		h.logger.Debug(fmt.Sprintf("vk-joiner: connection topology=%q", topo))
	}
	convParams, ok := msg["conversationParams"].(map[string]any)
	if !ok {
		return
	}
	turn, ok := convParams["turn"].(map[string]any)
	if !ok {
		return
	}
	urlsRaw, _ := turn["urls"].([]any)
	var urls []string
	for _, u := range urlsRaw {
		if s, ok := u.(string); ok {
			urls = append(urls, s)
		}
	}
	username, _ := turn["username"].(string)
	credential, _ := turn["credential"].(string)
	h.joinResp.TurnServer.URLs = urls
	h.joinResp.TurnServer.Username = username
	h.joinResp.TurnServer.Credential = credential
	h.logger.Debug(fmt.Sprintf("vk-joiner: TURN from connection: %v", urls))
	if h.pc == nil {
		h.initPC()
	}
}

func (h *VKJoiner) initPC() {
	var iceServers []webrtc.ICEServer
	if len(h.joinResp.StunServer.URLs) > 0 {
		iceServers = append(iceServers, webrtc.ICEServer{
			URLs: common.ResolveICEHosts(h.joinResp.StunServer.URLs, h.DNSRouter, h.Dialer, h.logger, "vk-joiner"),
		})
	}
	if len(h.joinResp.TurnServer.URLs) > 0 {
		iceServers = append(iceServers, webrtc.ICEServer{
			URLs:       common.ResolveICEHosts(h.joinResp.TurnServer.URLs, h.DNSRouter, h.Dialer, h.logger, "vk-joiner"),
			Username:   h.joinResp.TurnServer.Username,
			Credential: h.joinResp.TurnServer.Credential,
		})
	}
	mode := h.authParams.TunnelMode
	api, err := headlessapi.WebRTCAPI(headlessapi.Options{
		Profile: headless.ChromeWindows.WithDTLS13Mimicry(),
		Configure: func(settingEngine *webrtc.SettingEngine) {
			settingEngine.DisableCloseByDTLS(true)
			settingEngine.DetachDataChannels()
			if h.PCConfig != nil {
				h.PCConfig.ConfigureSettingEngine(settingEngine)
			}
		},
	})
	if err != nil {
		h.logger.Error(fmt.Sprintf("vk-joiner: failed to build webrtc api: %v", err))
		return
	}

	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: iceServers,
	})
	if err != nil {
		h.logger.Error(fmt.Sprintf("vk-joiner: failed to create PC: %v", err))
		return
	}
	h.pc = pc
	h.logger.Debug(fmt.Sprintf("vk-joiner: tunnel mode: %s", mode))
	if mode == "video" {
		h.sampleTrack = h.AddTracks(pc, h.logger, "vk-joiner")
	}
	negotiated := true
	dcID := uint16(2)
	dc, err := pc.CreateDataChannel("tunnel", &webrtc.DataChannelInit{
		Negotiated: &negotiated,
		ID:         &dcID,
	})
	if err != nil {
		h.logger.Warn(fmt.Sprintf("vk-joiner: could not create tunnel DC: %v", err))
	} else {
		h.dc = dc
		dc.OnOpen(func() {
			h.logger.Debug("vk-joiner: tunnel DC open")
			if mode == "dc" {
				h.reconnectAttempt.Store(0)
				h.logger.Info("vk-joiner: === DC TUNNEL CONNECTED ===")
				if h.OnConnected != nil {
					h.OnConnected(rtc.NewDCTunnel(dc, h.obf, common.RTPBufSize, h.logger))
				}
			}
		})
		dc.OnClose(func() {
			h.logger.Debug("vk-joiner: tunnel DC closed")
		})
	}
	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		h.onLocalICECandidate(candidate)
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		h.logger.Debug(fmt.Sprintf("vk-joiner: PC state: %s", state.String()))
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateDisconnected {
			h.logger.Debug(fmt.Sprintf("vk-joiner: PC %s, closing transport to trigger reconnect", state.String()))
			h.closeTransport()
		}
		if mode == "video" && state == webrtc.PeerConnectionStateConnected && h.vp8tunnel == nil {
			h.reconnectAttempt.Store(0)
			h.logger.Info("vk-joiner: === TUNNEL CONNECTED ===")
			h.vp8tunnel = rtc.NewVP8DataTunnel(h.sampleTrack, h.obf, h.logger)
			h.vp8tunnel.Start(h.vp8FPS, h.vp8Batch)
			var downlink tunnel.DataTunnel = h.vp8tunnel
			trackCount := 1
			if h.dualTrack {
				writer := rtc.NewScreenWriter(h.obf, "screen-up", h.logger)
				writer.Reconfigure(h.vp8tunnel.FPS(), h.vp8tunnel.Batch())
				writer.SetSend(h.producerScreen.send)
				h.sym = rtc.NewSymmetricScreenTunnel(h.vp8tunnel, writer, h.obf, h.producerScreen.ready, h.logger)
				h.sym.SetTrackCount(2)
				downlink = h.sym
				trackCount = 2
				h.logger.Info("vk-joiner: === SYMMETRIC DUAL-TRACK: camera VP8 + screen DCs ===")
			}
			vp8tun := h.vp8tunnel
			if !h.configAck.Acknowledged() {
				acked, cancel := h.configAck.Arm()
				go tunnel.SendVP8ConfigUntilAcked(acked, cancel, h.stopCh, vp8tun,
					vp8tun.FPS(), vp8tun.Batch(), trackCount, h.logger, "vk-joiner")
				h.logger.Debug(fmt.Sprintf("vk-joiner: pushed vp8 config to creator fps=%d batch=%d trackCount=%d", vp8tun.FPS(), vp8tun.Batch(), trackCount))
			}
			if h.OnConnected != nil {
				h.OnConnected(downlink)
			}
		}
	})
	if mode == "video" {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			h.logger.Debug(fmt.Sprintf("vk-joiner: remote DataChannel: label=%q id=%v", dc.Label(), dc.ID()))
			if !h.dualTrack {
				return
			}
			switch dc.Label() {
			case "consumerScreenShare":
				readScreenDataChannel(dc, func(frame []byte) {
					if h.sym != nil {
						h.sym.HandleScreenFrame(frame)
					}
				}, h.logger)
			case "producerScreenShare":
				attachScreenWriterDC(dc, h.producerScreen.attach, h.logger)
			}
		})
		pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
			h.logger.Debug(fmt.Sprintf("vk-joiner: remote track: codec=%s ssrc=%d", track.Codec().MimeType, track.SSRC()))
			go h.ReadTrackFn(track, func(frame []byte) {
				if h.vp8tunnel != nil {
					h.vp8tunnel.HandleFrame(frame)
				}
			}, h.logger, "vk-joiner")
		})
	}
	h.logger.Debug("vk-joiner: PC ready, waiting for remote offer")
}

func (h *VKJoiner) onRegisteredPeer(pid int64) {
	h.remotePeerID = &pid
	h.logger.Debug(fmt.Sprintf("vk-joiner: peer registered: %d", pid))
}

func (h *VKJoiner) onLocalICECandidate(candidate *webrtc.ICECandidate) {
	if h.remotePeerID == nil {
		return
	}
	candidateJSON := candidate.ToJSON()
	raw, _ := json.Marshal(candidateJSON)
	var parsed any
	json.Unmarshal(raw, &parsed)
	h.vkSendTransmitData(*h.remotePeerID, map[string]any{"candidate": parsed})
}

func (h *VKJoiner) onTransmittedData(data map[string]any) {
	if h.pc == nil {
		return
	}
	if candidate, ok := data["candidate"]; ok {
		candidateJSON, _ := json.Marshal(candidate)
		var candidateInit webrtc.ICECandidateInit
		json.Unmarshal(candidateJSON, &candidateInit)
		if h.OnRemoteCandidate != nil {
			h.OnRemoteCandidate(0, candidateInit.Candidate)
		}
		if h.remoteSet {
			h.pc.AddICECandidate(candidateInit)
		} else {
			h.pendingICE = append(h.pendingICE, candidateInit)
		}
	}
	if sdp, ok := data["sdp"].(map[string]any); ok {
		sdpType, _ := sdp["type"].(string)
		sdpStr, _ := sdp["sdp"].(string)
		if h.OnRemoteCandidate != nil {
			h.OnRemoteCandidate(-1, sdpStr)
		}
		h.logger.Debug(fmt.Sprintf("vk-joiner: remote SDP: %s", sdpType))
		switch sdpType {
		case "answer":
			h.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdpStr})
			h.remoteSet = true
			for _, candidate := range h.pendingICE {
				h.pc.AddICECandidate(candidate)
			}
			h.pendingICE = nil
		case "offer":
			h.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdpStr})
			h.remoteSet = true
			for _, candidate := range h.pendingICE {
				h.pc.AddICECandidate(candidate)
			}
			h.pendingICE = nil
			answer, err := h.pc.CreateAnswer(nil)
			if err != nil || h.remotePeerID == nil {
				h.logger.Warn(fmt.Sprintf("vk-joiner: create answer failed: %v", err))
				return
			}
			h.pc.SetLocalDescription(answer)
			sdpJSON, _ := json.Marshal(answer.SDP)
			h.vkMu.Lock()
			if h.sfu != nil {
				h.vkSeq++
				raw := fmt.Sprintf(`{"command":"transmit-data","sequence":%d,"participantId":%d,"data":{"sdp":{"sdp":%s,"type":%q},"animojiVersion":2},"participantType":"USER"}`,
					h.vkSeq, *h.remotePeerID, sdpJSON, answer.Type.String())
				h.sfu.Send([]byte(raw))
				h.logger.Debug(fmt.Sprintf("vk-joiner: -> answer (seq=%d)", h.vkSeq))
			}
			h.vkMu.Unlock()
		}
	}
}

func detectVKAuthRotten(raw []byte) *vkAuthRottenError {
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil
	}
	errCode, _ := generic["error_code"].(string)
	if errCode == "" {
		if codeNum, ok := generic["error_code"].(float64); ok {
			errCode = fmt.Sprintf("%.0f", codeNum)
		}
	}
	if errCode == "" {
		errCode, _ = generic["errorCode"].(string)
	}
	if errCode == "" {
		return nil
	}
	switch errCode {
	case "SESSION_EXPIRED", "AUTH_LOGIN", "SESSION_NOT_FOUND", "INVALID_SESSION_KEY":
		errMsg, _ := generic["error_msg"].(string)
		return &vkAuthRottenError{Code: errCode, Msg: errMsg}
	}
	return nil
}
