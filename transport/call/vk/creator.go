package vk

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing-box/transport/call/wtsignal"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/kulikov0/headless-client/webrtc"
)

const topologyDirect = "DIRECT"

type Bridge struct {
	mu            sync.Mutex
	sfu           *wtsignal.Conn
	vkSeq         int
	iceServers    []webrtc.ICEServer
	topology      string
	peers         map[int64]struct{}
	relay         Relay
	newRelay      func() Relay
	p2p           *P2PHandler
	screenSharing bool

	dialer       N.Dialer
	dnsRouter    adapter.DNSRouter
	activeBridge *tunnel.RelayBridge
	readBuf      int
	logger       logger.ContextLogger
}

func (b *Bridge) setScreenSharing(enabled bool) {
	b.mu.Lock()
	if b.sfu == nil || b.screenSharing == enabled {
		b.mu.Unlock()
		return
	}
	b.screenSharing = enabled
	b.mu.Unlock()
	b.logger.Debug(fmt.Sprintf("[vk-ws] peer track count change, screenshare=%v", enabled))
	b.sendMediaSettings(enabled)
}

func (b *Bridge) vkSend(command string, extra map[string]any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sfu == nil {
		return
	}
	b.vkSeq++
	seq := b.vkSeq
	var out []byte
	if pid, ok := extra["participantId"]; ok {
		dataJSON, _ := json.Marshal(extra["data"])
		out = []byte(fmt.Sprintf(`{"command":%q,"sequence":%d,"participantId":%v,"data":%s}`,
			command, seq, pid, dataJSON))
	} else {
		extra["command"] = command
		extra["sequence"] = seq
		out, _ = json.Marshal(extra)
	}
	b.sfu.Send(out)
	b.logger.Debug(fmt.Sprintf("[vk-ws] -> %s", command))
}

func (b *Bridge) sendMediaSettings(screenSharing bool) {
	b.vkSend("change-media-settings", map[string]any{
		"mediaSettings": map[string]any{
			"isAudioEnabled": false, "isVideoEnabled": true,
			"isScreenSharingEnabled": screenSharing, "isFastScreenSharingEnabled": false,
			"isAudioSharingEnabled": false, "isAnimojiEnabled": false,
		},
	})
}

func (b *Bridge) handleVKMessage(raw []byte) {
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}
	msgType, _ := msg["type"].(string)
	switch msgType {
	case "notification":
		notif, _ := msg["notification"].(string)
		b.logger.Debug(fmt.Sprintf("[vk-ws] <- notification: %s", notif))
		switch notif {
		case "connection":
			if conv, ok := msg["conversation"].(map[string]any); ok {
				topo, _ := conv["topology"].(string)
				b.logger.Debug(fmt.Sprintf("[vk-ws]    connection topology=%q", topo))
			}
			b.logger.Debug("[vk-ws]    TURN creds received")
		case "transmitted-data":
			data, _ := msg["data"].(map[string]any)
			if data != nil && b.topology == topologyDirect && b.p2p != nil {
				b.p2p.OnTransmittedData(data)
			}
		case "registered-peer":
			pid, _ := msg["participantId"].(float64)
			if b.topology == topologyDirect && b.p2p != nil {
				b.p2p.OnRegisteredPeer(int64(pid))
			}
		case "topology-changed":
			topo, _ := msg["topology"].(string)
			b.logger.Debug(fmt.Sprintf("[vk-ws]    Topology changed to %s", topo))
			b.topology = topo
			if topo != topologyDirect {
				b.failForServerTopology("SERVER topology")
				return
			}
		case "participant-joined", "participant-added":
			if pid, ok := msg["participantId"].(float64); ok {
				b.peers[int64(pid)] = struct{}{}
				b.logger.Debug(fmt.Sprintf("[vk-ws]    Participant %d joined (total: %d)", int64(pid), len(b.peers)))
				if b.topology != topologyDirect {
					b.failForServerTopology("participant joined under SERVER")
					return
				}
			}
		case "participant-left":
			if pid, ok := msg["participantId"].(float64); ok {
				delete(b.peers, int64(pid))
				b.logger.Debug(fmt.Sprintf("[vk-ws]    Participant %d left (total: %d)", int64(pid), len(b.peers)))
			}
		case "hungup":
			if pid, ok := msg["participantId"].(float64); ok {
				delete(b.peers, int64(pid))
				b.logger.Debug(fmt.Sprintf("[vk-ws]    Participant %d hung up (total: %d)", int64(pid), len(b.peers)))
			} else {
				b.logger.Debug("[vk-ws]    Participant hung up")
			}
		case "closed-conversation":
			reason, _ := msg["reason"].(string)
			b.logger.Debug(fmt.Sprintf("[vk-ws]    Conversation closed: %s", reason))
			b.mu.Lock()
			if b.sfu != nil {
				b.sfu.Close()
			}
			b.mu.Unlock()
		default:
			snippet, _ := json.Marshal(msg)
			if len(snippet) > 1000 {
				snippet = append(snippet[:1000], '.', '.', '.')
			}
			b.logger.Debug(fmt.Sprintf("[vk-ws]    unhandled: %s", string(snippet)))
		}
	case "response":
		seq, _ := msg["sequence"].(float64)
		snippet, _ := json.Marshal(msg)
		if len(snippet) > 1000 {
			snippet = append(snippet[:1000], '.', '.', '.')
		}
		b.logger.Debug(fmt.Sprintf("[vk-ws] <- response seq=%d: %s", int(seq), string(snippet)))
	case "error":
		errMsg, _ := msg["message"].(string)
		errCode, _ := msg["error"].(string)
		b.logger.Warn(fmt.Sprintf("[vk-ws] <- error: %s %s", errCode, errMsg))
	}
}

func (b *Bridge) connectVKWs(wtURL string) error {
	parsed, err := url.Parse(wtURL)
	if err != nil {
		return err
	}
	host := parsed.Hostname()
	resolvedIP, err := b.resolveHost(host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	sfu, err := wtsignal.Dial(wtURL, host, resolvedIP, vkOrigin)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.sfu = sfu
	b.vkSeq = 0
	b.mu.Unlock()
	return nil
}

func (b *Bridge) resolveHost(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	rd, hasRD := b.dialer.(dialer.ResolveDialer)
	if b.dnsRouter == nil || !hasRD {
		return "", fmt.Errorf("no DNS router available to resolve %s", host)
	}
	addrs, err := b.dnsRouter.Lookup(context.Background(), host, rd.QueryOptions())
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses for %s", host)
	}
	return addrs[0].String(), nil
}

func (b *Bridge) initRelay() {
	if b.relay != nil {
		b.relay.Close()
	}
	b.topology = topologyDirect
	b.peers = make(map[int64]struct{})
	b.relay = b.newRelay()
	b.p2p = NewP2PHandler(b)
	b.p2p.Init()
}

func (b *Bridge) failForServerTopology(reason string) {
	b.logger.Error(fmt.Sprintf("[vk-ws]    %s -> VK moved this call to server topology, it cannot be tunneled, create a new call and connect again", reason))
}

func (b *Bridge) readLoop() error {
	b.mu.Lock()
	sfu := b.sfu
	b.mu.Unlock()
	if sfu == nil {
		return fmt.Errorf("no transport")
	}
	for {
		msg, err := sfu.Recv()
		if err != nil {
			return err
		}
		if string(msg) == "ping" {
			sfu.Send([]byte("pong"))
			continue
		}
		b.handleVKMessage(msg)
	}
}

func (b *Bridge) Run(callInfo *CallInfo, cookieStr string, cfg VKConfig) {
	b.logger.Info(fmt.Sprintf("CALL CREATED join_link=%s turn=%s protocol=v%s sdk=%s",
		callInfo.JoinLink, strings.Join(callInfo.TurnServer.URLs, ", "), cfg.ProtocolVersion, cfg.SDKVersion))
	b.iceServers = buildWebRTCICEServers(BuildICEServers(callInfo))
	wtEndpoint := callInfo.WtEndpoint
	capabilities := "2F7F"
	makeWtURL := func(ep string) string {
		return ep +
			"&platform=WEB" +
			"&appVersion=" + cfg.AppVersion +
			"&version=" + cfg.ProtocolVersion +
			"&device=browser&capabilities=" + capabilities + "&clientType=VK&tgt=join&compression=deflate-raw"
	}
	for {
		b.initRelay()
		if wtEndpoint == "" {
			b.logger.Error("[vk-ws] no wt_endpoint in join response")
			return
		}
		b.logger.Debug("[vk-ws] Connecting...")
		if err := b.connectVKWs(makeWtURL(wtEndpoint)); err != nil {
			b.logger.Warn(fmt.Sprintf("[vk-ws] Connect failed: %s, retrying in 5s...", common.MaskError(err)))
			time.Sleep(5 * time.Second)
			continue
		}
		b.logger.Debug("[vk-ws] Connected")
		b.mu.Lock()
		b.screenSharing = false
		b.mu.Unlock()
		b.sendMediaSettings(false)
		err := b.readLoop()
		b.logger.Debug(fmt.Sprintf("[vk-ws] Closed: %s", common.MaskError(err)))
		b.mu.Lock()
		b.sfu = nil
		b.mu.Unlock()
		b.logger.Debug("[vk-ws] Rejoining in 3s...")
		time.Sleep(3 * time.Second)
		joinResp, rerr := authAndJoin(b.dialer, cookieStr, callInfo.OKJoinLink, cfg)
		if rerr != nil {
			b.logger.Warn(fmt.Sprintf("[rejoin] Failed: %v, retrying in 5s...", rerr))
			time.Sleep(5 * time.Second)
			continue
		}
		wtEndpoint = joinResp.WtEndpoint
		callInfo.TurnServer = joinResp.TurnServer
		callInfo.StunServer = joinResp.StunServer
		b.iceServers = buildWebRTCICEServers(BuildICEServers(callInfo))
	}
}

func buildWebRTCICEServers(specs []ICEServerSpec) []webrtc.ICEServer {
	out := make([]webrtc.ICEServer, len(specs))
	for i, s := range specs {
		out[i] = webrtc.ICEServer{URLs: s.URLs, Username: s.Username, Credential: s.Credential}
	}
	return out
}
