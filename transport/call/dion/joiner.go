package dion

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

const (
	dionReconnectInitialDelay = time.Second
	dionReconnectMaxDelay     = 16 * time.Second
)

type DionJoiner struct {
	logger      logger.ContextLogger
	dialer      N.Dialer
	dnsRouter   adapter.DNSRouter
	OnConnected func(tunnel.DataTunnel)

	roomID      string
	displayName string

	mu       sync.Mutex
	call     *Call
	closed   bool
	stopCh   chan struct{}
	stopOnce sync.Once

	configAck        tunnel.ConfigAckTracker
	reconnectAttempt atomic.Int32
}

func NewDionJoiner(logger logger.ContextLogger, dialer N.Dialer, dnsRouter adapter.DNSRouter) *DionJoiner {
	return &DionJoiner{
		logger:    logger,
		dialer:    dialer,
		dnsRouter: dnsRouter,
		stopCh:    make(chan struct{}),
	}
}

func (j *DionJoiner) RunWithParams(jsonParams string) {
	var params struct {
		RoomID      string `json:"roomId"`
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal([]byte(jsonParams), &params); err != nil {
		j.logger.Error(fmt.Sprintf("dion-joiner: failed to parse params: %v", err))
		return
	}
	slug := ParseRoom(params.RoomID)
	if slug == "" {
		j.logger.Error("dion-joiner: missing roomId")
		return
	}
	j.roomID = slug
	j.displayName = params.DisplayName
	if j.displayName == "" {
		j.displayName = "Joiner"
	}
	j.logger.Debug(fmt.Sprintf("dion-joiner: room=%s name=%s", j.roomID, j.displayName))
	j.logger.Info("dion-joiner: connecting")
	if err := j.runOnce(); err != nil {
		j.logger.Error(fmt.Sprintf("dion-joiner: %v", err))
		return
	}
	for {
		if j.isClosed() {
			j.logger.Debug("dion-joiner: stopped")
			return
		}
		j.logger.Info("dion-joiner: tunnel lost")
		if !j.waitBeforeRetry(int(j.reconnectAttempt.Load())) {
			return
		}
		j.reconnectAttempt.Add(1)
		if j.isClosed() {
			return
		}
		j.logger.Info(fmt.Sprintf("dion-joiner: reconnect attempt #%d", j.reconnectAttempt.Load()))
		if err := j.runOnce(); err != nil {
			j.logger.Warn(fmt.Sprintf("dion-joiner: %v, will retry", err))
		}
	}
}

func (j *DionJoiner) MarkConfigAcked() { j.configAck.Mark() }

func (j *DionJoiner) Close() {
	j.mu.Lock()
	j.closed = true
	call := j.call
	j.call = nil
	j.mu.Unlock()
	j.stopOnce.Do(func() { close(j.stopCh) })
	if call != nil {
		call.Close()
	}
}

func (j *DionJoiner) runOnce() error {
	auth, event, err := JoinAsGuest(j.dialer, j.roomID, j.displayName)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	obf, err := tunnel.NewTunnelObfuscator(tunnel.DeriveSecretFromJoinLink(event.Slug))
	if err != nil {
		return fmt.Errorf("obfuscator init: %w", err)
	}
	j.logger.Debug(fmt.Sprintf("dion-joiner: obf key-source=%q localEpoch=0x%08x", event.Slug, obf.LocalEpoch()))
	call := NewCall(CallConfig{
		Auth:        auth,
		Event:       event,
		Obfuscator:  obf,
		DisplayName: j.displayName,
		Logger:      j.logger,
		Dialer:      j.dialer,
		DNSRouter:   j.dnsRouter,
		Role:        RoleJoiner,
	})
	call.OnConnected = func(tun tunnel.DataTunnel) {
		j.reconnectAttempt.Store(0)
		j.logger.Info("dion-joiner: === TUNNEL CONNECTED ===")
		if j.OnConnected != nil {
			j.OnConnected(tun)
		}
	}
	call.OnKicked = func() {
		j.logger.Debug("dion-joiner: kicked from conference, shutting down")
		go j.Close()
	}
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		call.Close()
		return nil
	}
	j.call = call
	j.mu.Unlock()
	if err := call.Start(); err != nil {
		j.mu.Lock()
		if j.call == call {
			j.call = nil
		}
		j.mu.Unlock()
		return fmt.Errorf("call: %w", err)
	}
	<-call.Done()
	call.Close()
	j.mu.Lock()
	if j.call == call {
		j.call = nil
	}
	j.mu.Unlock()
	j.logger.Debug("dion-joiner: call ended")
	return nil
}

func (j *DionJoiner) waitBeforeRetry(attempt int) bool {
	delay := common.BackoffWithJitter(attempt, dionReconnectInitialDelay, dionReconnectMaxDelay)
	j.logger.Debug(fmt.Sprintf("dion-joiner: waiting %s before reconnect", delay))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return !j.isClosed()
	case <-j.stopCh:
		return false
	}
}

func (j *DionJoiner) isClosed() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.closed
}
