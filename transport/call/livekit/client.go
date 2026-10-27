package livekit

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/headlessapi"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	headless "github.com/kulikov0/headless-client"
	"github.com/kulikov0/headless-client/webrtc"
	"github.com/kulikov0/headless-client/websocket"
)

const (
	ProtocolVersion = "15"
	SDKName         = "js"
	SDKVersion      = "2.7.0"
	PingPeriod      = 5 * time.Second

	TargetPublisher  = signalTargetPublisher
	TargetSubscriber = signalTargetSubscriber

	TrackTypeAudio         = trackTypeAudio
	TrackTypeVideo         = trackTypeVideo
	TrackTypeData          = trackTypeData
	TrackSourceCamera      = trackSourceCamera
	TrackSourceScreenShare = trackSourceScreenShare
)

type (
	ICEServer    = iceServer
	JoinResponse = joinResponse
)

type Config struct {
	ServerURL              string
	Token                  string
	Origin                 string
	UserAgent              string
	Codec                  Codec
	Logger                 logger.ContextLogger
	ConfigureSettingEngine func(*webrtc.SettingEngine)
	NetDialContext         func(ctx context.Context, network, addr string) (net.Conn, error)
	DNSRouter              adapter.DNSRouter
	Dialer                 N.Dialer
}

type Client struct {
	logger logger.ContextLogger

	wsURL  string
	token  string
	origin string
	ua     string
	codec  Codec

	configureSettingEngine func(*webrtc.SettingEngine)
	netDialContext         func(ctx context.Context, network, addr string) (net.Conn, error)
	dnsRouter              adapter.DNSRouter
	dialer                 N.Dialer

	ws   *websocket.Conn
	wsMu sync.Mutex

	join JoinResponse

	pubPC        *webrtc.PeerConnection
	subPC        *webrtc.PeerConnection
	pubMu        sync.Mutex
	subMu        sync.Mutex
	pubRemoteSet bool
	subRemoteSet bool
	pubPending   []webrtc.ICECandidateInit
	subPending   []webrtc.ICECandidateInit

	joined     chan struct{}
	joinedOnce sync.Once
	closed     atomic.Bool

	OnReady             func()
	OnTrack             func(*webrtc.TrackRemote, *webrtc.RTPReceiver)
	OnDataChannel       func(*webrtc.DataChannel)
	OnPubConnected      func()
	OnSubConnected      func()
	OnParticipantUpdate func([]ParticipantInfo)
	OnRemoteCandidate   func(target int, candidate webrtc.ICECandidateInit)
	OnRemoteSDP         func(target int, sdpType, sdp string)
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.Codec == nil {
		return nil, fmt.Errorf("livekit: no codec")
	}
	return &Client{
		logger:                 cfg.Logger,
		wsURL:                  cfg.ServerURL,
		token:                  cfg.Token,
		origin:                 cfg.Origin,
		ua:                     cfg.UserAgent,
		codec:                  cfg.Codec,
		configureSettingEngine: cfg.ConfigureSettingEngine,
		netDialContext:         cfg.NetDialContext,
		dnsRouter:              cfg.DNSRouter,
		dialer:                 cfg.Dialer,
		joined:                 make(chan struct{}),
	}, nil
}

func (c *Client) Join() JoinResponse            { return c.join }
func (c *Client) PubPC() *webrtc.PeerConnection { return c.pubPC }
func (c *Client) SubPC() *webrtc.PeerConnection { return c.subPC }
func (c *Client) Joined() <-chan struct{}       { return c.joined }

func (c *Client) Connect() error {
	target, err := c.codec.DialURL(c.wsURL, c.token)
	if err != nil {
		return err
	}

	headers := headless.ChromeWindows.Headers(headless.DestWebSocket)
	if c.ua != "" {
		headers.Set("User-Agent", c.ua)
	}
	if c.origin != "" {
		headers.Set("Origin", c.origin)
	}

	dialer := headless.ChromeWindows.WebSocketDialer(headless.TLSOptions{DialContext: c.netDialContext})
	if c.netDialContext != nil {
		dialer.NetDialContext = c.netDialContext
	}
	conn, resp, err := dialer.Dial(target, headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("ws dial: %w, status %d", err, resp.StatusCode)
		}
		return fmt.Errorf("ws dial: %w", err)
	}
	c.wsMu.Lock()
	c.ws = conn
	c.wsMu.Unlock()
	c.logger.Info("[lk] signaling connected")
	return nil
}

func (c *Client) SendOffer(sdp string) error {
	return c.sendSignal(c.codec.EncodeOffer(sdp))
}

func (c *Client) SendAnswer(sdp string) error {
	return c.sendSignal(c.codec.EncodeAnswer(sdp))
}

func (c *Client) SendTrickle(candidate webrtc.ICECandidateInit, target int) error {
	return c.sendSignal(c.codec.EncodeTrickle(candidate, target))
}

func (c *Client) SendAddTrack(cid, name string, trackType, source int, width, height uint32) error {
	return c.sendSignal(c.codec.EncodeAddTrack(AddTrackParams{
		CID:    cid,
		Name:   name,
		Type:   trackType,
		Source: source,
		Width:  width,
		Height: height,
	}))
}

func (c *Client) SendLeave() error { return c.sendSignal(c.codec.EncodeLeave()) }

func (c *Client) SendPing() error {
	return c.sendSignal(c.codec.EncodePing(time.Now().UnixMilli()))
}

func (c *Client) Close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	c.wsMu.Lock()
	ws := c.ws
	c.ws = nil
	c.wsMu.Unlock()
	common.CloseWS(ws)
	c.pubMu.Lock()
	pubPC := c.pubPC
	c.pubMu.Unlock()
	c.subMu.Lock()
	subPC := c.subPC
	c.subMu.Unlock()
	if pubPC != nil {
		_ = pubPC.Close()
	}
	if subPC != nil {
		_ = subPC.Close()
	}
}

func (c *Client) ReadLoop() error {
	defer c.Close()
	c.wsMu.Lock()
	ws := c.ws
	c.wsMu.Unlock()
	if ws == nil {
		return fmt.Errorf("ws not connected")
	}
	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			if c.closed.Load() {
				return nil
			}
			return err
		}
		if !c.codec.Accepts(mt) {
			continue
		}
		c.handleSignal(data)
	}
}

func (c *Client) PingLoop() {
	select {
	case <-c.joined:
	case <-time.After(30 * time.Second):
		return
	}
	period := PingPeriod
	if c.join.PingIntervalSec > 0 {
		period = time.Duration(c.join.PingIntervalSec) * time.Second
	}
	t := time.NewTicker(period)
	defer t.Stop()
	var sentN int
	for range t.C {
		if c.closed.Load() {
			return
		}
		if err := c.SendPing(); err != nil {
			c.logger.Warn(fmt.Sprintf("[lk] ping send failed: %v", err))
			return
		}
		sentN++
		if sentN <= 3 || sentN%12 == 0 {
			c.logger.Debug(fmt.Sprintf("[lk] ping #%d sent", sentN))
		}
	}
}

func (c *Client) sendSignal(payload []byte) error {
	if payload == nil {
		return nil
	}
	c.wsMu.Lock()
	defer c.wsMu.Unlock()
	if c.ws == nil {
		return fmt.Errorf("ws not connected")
	}
	return c.ws.WriteMessage(c.codec.MessageType(), payload)
}

func (c *Client) iceServersAsWebRTC() []webrtc.ICEServer {
	out := make([]webrtc.ICEServer, 0, len(c.join.ICEServers))
	for _, s := range c.join.ICEServers {
		urls := common.ResolveICEHosts(s.URLs, c.dnsRouter, c.dialer, c.logger, "[lk]")
		ice := webrtc.ICEServer{URLs: urls}
		if s.Username != "" {
			ice.Username = s.Username
			ice.Credential = s.Credential
		}
		out = append(out, ice)
	}
	return out
}

func (c *Client) buildPeerConnections() error {
	cfg := webrtc.Configuration{ICEServers: c.iceServersAsWebRTC()}

	api, err := headlessapi.WebRTCAPI(headlessapi.Options{
		Profile: headless.ChromeWindows,
		Configure: func(settingEngine *webrtc.SettingEngine) {
			if c.configureSettingEngine != nil {
				c.configureSettingEngine(settingEngine)
			}
			settingEngine.DetachDataChannels()
		},
	})
	if err != nil {
		return fmt.Errorf("build webrtc api: %w", err)
	}

	pubPC, err := api.NewPeerConnection(cfg)
	if err != nil {
		return fmt.Errorf("create pub pc: %w", err)
	}
	subPC, err := api.NewPeerConnection(cfg)
	if err != nil {
		_ = pubPC.Close()
		return fmt.Errorf("create sub pc: %w", err)
	}
	c.pubMu.Lock()
	c.pubPC = pubPC
	c.pubMu.Unlock()
	c.subMu.Lock()
	c.subPC = subPC
	c.subMu.Unlock()
	pubPC.OnICECandidate(func(cand *webrtc.ICECandidate) {
		if cand == nil {
			c.logger.Debug("[lk] pub ICE gathering complete")
			return
		}
		c.logger.Debug(fmt.Sprintf("[lk] pub local cand: %s", cand.String()))
		_ = c.SendTrickle(cand.ToJSON(), TargetPublisher)
	})
	subPC.OnICECandidate(func(cand *webrtc.ICECandidate) {
		if cand == nil {
			c.logger.Debug("[lk] sub ICE gathering complete")
			return
		}
		c.logger.Debug(fmt.Sprintf("[lk] sub local cand: %s", cand.String()))
		_ = c.SendTrickle(cand.ToJSON(), TargetSubscriber)
	})
	pubPC.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		c.logger.Debug(fmt.Sprintf("[lk] pub PC state: %s", state.String()))
		if state == webrtc.PeerConnectionStateConnected && c.OnPubConnected != nil {
			c.OnPubConnected()
		}
	})
	subPC.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		c.logger.Debug(fmt.Sprintf("[lk] sub PC state: %s", state.String()))
		if state == webrtc.PeerConnectionStateConnected && c.OnSubConnected != nil {
			c.OnSubConnected()
		}
	})
	pubPC.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		c.logger.Debug(fmt.Sprintf("[lk] pub ICE state: %s", state.String()))
	})
	subPC.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		c.logger.Debug(fmt.Sprintf("[lk] sub ICE state: %s", state.String()))
	})
	subPC.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		c.logger.Debug(fmt.Sprintf("[lk] sub remote track: %s", track.Codec().MimeType))
		if c.OnTrack != nil {
			c.OnTrack(track, receiver)
		}
	})
	subPC.OnDataChannel(func(dc *webrtc.DataChannel) {
		c.logger.Debug(fmt.Sprintf("[lk] sub data channel: %s", dc.Label()))
		if c.OnDataChannel != nil {
			c.OnDataChannel(dc)
		}
	})
	c.logger.Debug(fmt.Sprintf("[lk] PCs created, %d ICE servers", len(c.join.ICEServers)))
	for i, s := range c.join.ICEServers {
		c.logger.Debug(fmt.Sprintf("[lk] iceServer[%d]: urls=%v hasCred=%v", i, s.URLs, s.Username != ""))
	}
	return nil
}

func (c *Client) handleSignal(data []byte) {
	ev, err := c.codec.Decode(data)
	if err != nil {
		c.logger.Warn(fmt.Sprintf("[lk] decode signal: %v", err))
		return
	}
	switch ev.Kind {
	case EventJoin:
		c.join = *ev.Join
		c.logger.Info(fmt.Sprintf("[lk] join: room=%s participant=%s subscriberPrimary=%v iceServers=%d pingTimeout=%ds pingInterval=%ds",
			c.join.RoomName, c.join.ParticipantID, c.join.SubscriberPrimary, len(c.join.ICEServers),
			c.join.PingTimeoutSec, c.join.PingIntervalSec))
		if err := c.buildPeerConnections(); err != nil {
			c.logger.Error(fmt.Sprintf("[lk] %v", err))
			return
		}
		c.joinedOnce.Do(func() { close(c.joined) })
		if c.OnReady != nil {
			c.OnReady()
		}
	case EventAnswer:
		c.logger.Debug(fmt.Sprintf("[lk] pub answer received, %d bytes", len(ev.SDP)))
		c.applyPubAnswer(ev.SDP)
	case EventOffer:
		c.logger.Debug(fmt.Sprintf("[lk] sub offer received, %d bytes", len(ev.SDP)))
		c.applySubOfferAndAnswer(ev.SDP)
	case EventTrickle:
		c.logger.Debug(fmt.Sprintf("[lk] trickle target=%d", ev.Trickle.Target))
		c.applyRemoteTrickle(*ev.Trickle)
	case EventToken:
		c.token = ev.Token
		c.logger.Debug("[lk] token refreshed")
	case EventLeave:
		if ev.Leave != nil {
			c.logger.Debug(fmt.Sprintf("[lk] ignored leave reason=%s action=%s",
				DisconnectReasonName(ev.Leave.Reason), LeaveActionName(ev.Leave.Action)))
		} else {
			c.logger.Debug("[lk] ignored leave")
		}
	case EventUpdate:
		if c.OnParticipantUpdate != nil {
			c.OnParticipantUpdate(ev.Participants)
		}
	default:
		c.logger.Debug(fmt.Sprintf("[lk] unhandled signal, %d bytes", len(data)))
	}
}

func (c *Client) applyPubAnswer(sdp string) {
	if c.OnRemoteSDP != nil {
		c.OnRemoteSDP(TargetPublisher, "answer", sdp)
	}
	c.pubMu.Lock()
	defer c.pubMu.Unlock()
	if c.pubPC == nil {
		return
	}
	if err := c.pubPC.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdp}); err != nil {
		c.logger.Warn(fmt.Sprintf("[lk] set pub remote answer: %v", err))
		return
	}
	c.pubRemoteSet = true
	c.drainPendingLocked(c.pubPC, &c.pubPending)
}

func (c *Client) applySubOfferAndAnswer(sdp string) {
	if c.OnRemoteSDP != nil {
		c.OnRemoteSDP(TargetSubscriber, "offer", sdp)
	}
	c.subMu.Lock()
	if c.subPC == nil {
		c.subMu.Unlock()
		return
	}
	subPC := c.subPC
	if err := subPC.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdp}); err != nil {
		c.subMu.Unlock()
		c.logger.Warn(fmt.Sprintf("[lk] set sub remote offer: %v", err))
		return
	}
	c.subRemoteSet = true
	c.drainPendingLocked(subPC, &c.subPending)
	c.subMu.Unlock()

	answer, err := subPC.CreateAnswer(nil)
	if err != nil {
		c.logger.Warn(fmt.Sprintf("[lk] create sub answer: %v", err))
		return
	}
	if err := subPC.SetLocalDescription(answer); err != nil {
		c.logger.Warn(fmt.Sprintf("[lk] set sub local answer: %v", err))
		return
	}
	if err := c.SendAnswer(answer.SDP); err != nil {
		c.logger.Warn(fmt.Sprintf("[lk] send answer: %v", err))
	}
}

func (c *Client) drainPendingLocked(pc *webrtc.PeerConnection, pending *[]webrtc.ICECandidateInit) {
	for _, ic := range *pending {
		if err := pc.AddICECandidate(ic); err != nil {
			c.logger.Warn(fmt.Sprintf("[lk] add pending candidate: %v", err))
		}
	}
	*pending = nil
}

func (c *Client) applyRemoteTrickle(m TrickleEvent) {
	if c.OnRemoteCandidate != nil {
		c.OnRemoteCandidate(m.Target, m.Candidate)
	}
	mu := &c.subMu
	pc := &c.subPC
	ready := &c.subRemoteSet
	pending := &c.subPending
	if m.Target == TargetPublisher {
		mu = &c.pubMu
		pc = &c.pubPC
		ready = &c.pubRemoteSet
		pending = &c.pubPending
	}
	mu.Lock()
	defer mu.Unlock()
	if *pc == nil || !*ready {
		*pending = append(*pending, m.Candidate)
		return
	}
	if err := (*pc).AddICECandidate(m.Candidate); err != nil {
		c.logger.Warn(fmt.Sprintf("[lk] add candidate: %v", err))
	}
}
