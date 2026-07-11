package firebasetunnel

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.FirebaseTunnelInboundOptions](registry, C.TypeFirebaseTunnelInbound, NewInbound)
}

// Inbound discovers pending Firebase Tunnel sessions and routes each one
// through the sing-box router. Traffic accounting is handled automatically
// by the router once metadata.User is set.
type Inbound struct {
	inbound.Adapter
	ctx     context.Context
	logger  logger.ContextLogger
	router  adapter.ConnectionRouterEx
	fb      *firebaseClient
	hmacKey []byte // integrity key when no per-user PSK; nil otherwise

	users          map[string]userConfig
	pollInterval   time.Duration
	sessionTimeout time.Duration

	maxSessions        int
	maxSessionsPerUser int
	sessionRate        int

	mu            sync.Mutex
	activeSessions int
	perUserActive  map[string]int
	perUserBucket  map[string]*tokenBucket

	closing atomic.Bool
	cancel  context.CancelFunc
}

func NewInbound(ctx context.Context, router adapter.Router, lg log.ContextLogger, tag string, options option.FirebaseTunnelInboundOptions) (adapter.Inbound, error) {
	if len(options.FirebaseURLs) == 0 {
		return nil, E.New("firebase_urls is required")
	}
	if options.FirebaseSecret == "" && options.FirebaseAuthToken == "" {
		return nil, E.New("one of firebase_secret or firebase_auth_token is required")
	}
	if len(options.Users) == 0 {
		return nil, E.New("users must have at least one entry")
	}

	retryLimit := options.RetryLimit
	if retryLimit == 0 {
		retryLimit = defaultRetryLimit
	}

	users := make(map[string]userConfig, len(options.Users))
	for _, u := range options.Users {
		if u.Name == "" {
			return nil, E.New("user name must not be empty")
		}
		uc := userConfig{name: u.Name}
		if u.PSK != "" {
			k := deriveKey(u.PSK)
			uc.key = &k
		}
		users[u.Name] = uc
	}

	h := &Inbound{
		Adapter:            inbound.NewAdapter(C.TypeFirebaseTunnelInbound, tag),
		ctx:                ctx,
		logger:             lg,
		router:             router,
		fb:                 newFirebaseClient(options.FirebaseURLs[0], options.FirebaseSecret, options.FirebaseAuthToken, retryLimit, lg),
		users:              users,
		pollInterval:       durationOr(time.Duration(options.PollInterval), defaultPollInterval),
		sessionTimeout:     durationOr(time.Duration(options.SessionTimeout), defaultSessionTimeout),
		maxSessions:        intOr(options.MaxSessions, defaultMaxSessions),
		maxSessionsPerUser: intOr(options.MaxSessionsPerUser, defaultMaxSessionsPerUser),
		sessionRate:        intOr(options.MaxSessionsPerSecondPerUser, defaultMaxSessionsPerSecondPerUser),
		perUserActive:      make(map[string]int),
		perUserBucket:      make(map[string]*tokenBucket),
	}

	if options.FirebaseSecret != "" {
		h.hmacKey = deriveHMACKey(options.FirebaseSecret)
	}

	return h, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	ctx, cancel := context.WithCancel(h.ctx)
	h.cancel = cancel
	go h.loopWithRestart(ctx, h.pollLoop)
	go h.loopWithRestart(ctx, h.gcLoop)
	return nil
}

func (h *Inbound) Close() error {
	h.closing.Store(true)
	deadline := time.Now().Add(drainTimeout)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		active := h.activeSessions
		h.mu.Unlock()
		if active == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if h.cancel != nil {
		h.cancel()
	}
	return nil
}

// loopWithRestart runs fn(ctx) and restarts it on error after a 5-second
// backoff. Stops when ctx is cancelled.
func (h *Inbound) loopWithRestart(ctx context.Context, fn func(context.Context) error) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := fn(ctx); err != nil {
			h.logger.ErrorContext(ctx, "firebasetunnel: loop exited with error, restarting: ", err)
		}
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (h *Inbound) pollLoop(ctx context.Context) error {
	seen := make(map[string]struct{})
	events := h.fb.listen(ctx, pathSessionsRoot())
	ticker := time.NewTicker(h.pollInterval)
	defer ticker.Stop()

	dispatch := func() {
		var raw map[string]sessionMetadata
		if found, err := h.fb.Get(ctx, pathSessionsRoot(), &raw); err != nil || !found {
			return
		}
		for id, meta := range raw {
			if meta.State != sessionStatePending {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			meta.SessionID = id
			go h.handleSession(ctx, meta)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-events:
			if !ok {
				events = h.fb.listen(ctx, pathSessionsRoot())
				continue
			}
			dispatch()
		case <-ticker.C:
			dispatch()
		}
	}
}

func (h *Inbound) handleSession(ctx context.Context, meta sessionMetadata) {
	sessionID := meta.SessionID

	userCfg, ok := h.users[meta.User]
	if !ok {
		h.logger.WarnContext(ctx, "firebasetunnel: rejecting session ", sessionID, ": unknown user")
		h.closeSession(ctx, sessionID)
		return
	}
	if !h.acquireSessionSlot(meta.User) {
		h.logger.WarnContext(ctx, "firebasetunnel: rejecting session ", sessionID, ": limit/rate exceeded for user ", meta.User)
		h.closeSession(ctx, sessionID)
		return
	}
	defer h.releaseSessionSlot(meta.User)

	// Collision defense: re-read to verify CreatedAt hasn't changed.
	var current sessionMetadata
	if found, _ := h.fb.Get(ctx, pathMetadata(sessionID), &current); !found || current.CreatedAt != meta.CreatedAt {
		h.logger.WarnContext(ctx, "firebasetunnel: session collision for ", sessionID, ", rejecting")
		h.closeSession(ctx, sessionID)
		return
	}

	destination := M.ParseSocksaddrHostPort(meta.TargetHost, meta.TargetPort)
	inboundMeta := adapter.InboundContext{
		Inbound:     h.Tag(),
		InboundType: C.TypeFirebaseTunnelInbound,
		Destination: destination,
		User:        meta.User,
	}

	updated := meta
	updated.State = sessionStateActive
	if err := h.fb.Put(ctx, pathMetadata(sessionID), &updated); err != nil {
		h.logger.WarnContext(ctx, "firebasetunnel: marking session active failed: ", err)
		return
	}

	sessionKey := userCfg.key
	sessionHMACKey := h.hmacKey
	if sessionKey != nil {
		sessionHMACKey = nil // AEAD covers integrity; HMAC not needed
	}

	local, remote := net.Pipe()

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		h.runRelay(ctx, sessionID, remote, sessionKey, sessionHMACKey)
	}()

	// sing-box router handles routing, outbound selection, and traffic
	// accounting automatically because metadata.User is already set.
	h.router.RouteConnectionEx(ctx, local, inboundMeta, func(error) {})
	<-relayDone

	updated.State = sessionStateClosed
	_ = h.fb.Put(context.Background(), pathMetadata(sessionID), &updated)
	if err := h.fb.Delete(context.Background(), "sessions/"+sessionID); err != nil {
		h.logger.WarnContext(ctx, "firebasetunnel: session cleanup failed: ", err)
	}
}

func (h *Inbound) closeSession(ctx context.Context, sessionID string) {
	_ = h.fb.Put(ctx, pathMetadata(sessionID), &sessionMetadata{SessionID: sessionID, State: sessionStateClosed})
}

func (h *Inbound) runRelay(ctx context.Context, sessionID string, conn net.Conn, key *[32]byte, hmacKey []byte) {
	defer conn.Close()

	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	c2sDone := make(chan struct{})
	go func() {
		defer close(c2sDone)
		h.runC2S(relayCtx, sessionID, conn, key, hmacKey)
	}()

	s2cDone := make(chan struct{})
	go func() {
		defer close(s2cDone)
		sender := newChunkSender(relayCtx, pathS2C(sessionID), sessionID, "s2c",
			h.fb, h.pollInterval, defaultReadBufSize, key, hmacKey, h.logger)
		copyToSender(relayCtx, conn, sender, h.logger)
	}()

	select {
	case <-c2sDone:
	case <-s2cDone:
	}
	cancel()
}

func (h *Inbound) runC2S(ctx context.Context, sessionID string, conn net.Conn, key *[32]byte, hmacKey []byte) {
	receiver, byteRx := newChunkReceiver(key, hmacKey, sessionID, "c2s")
	var deliveredUpTo *uint64
	c2sPath := pathC2S(sessionID)
	ackPath := pathAcks(sessionID) + "/c2s_ack"
	lastActivity := time.Now()

	for {
		if time.Since(lastActivity) > h.sessionTimeout {
			h.logger.WarnContext(ctx, "firebasetunnel: session ", sessionID, " timed out")
			return
		}

		var meta sessionMetadata
		if found, err := h.fb.Get(ctx, pathMetadata(sessionID), &meta); err == nil && found && isTerminal(meta.State) {
			return
		}

		chunks, err := fetchNewChunks(ctx, h.fb, c2sPath, deliveredUpTo)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(h.pollInterval):
				continue
			}
		}
		if len(chunks) > 0 {
			lastActivity = time.Now()
		}

		for _, ck := range chunks {
			newAck, err := receiver.ingest(ctx, ck)
			if err != nil {
				h.logger.WarnContext(ctx, "firebasetunnel: c2s ingest error (session ", sessionID, "): ", err)
				return
			}
			if newAck == nil {
				continue
			}
			deliveredUpTo = newAck
			if err := drainInto(byteRx, conn); err != nil {
				return
			}
			if err := updateAckAndCleanup(ctx, h.fb, ackPath, c2sPath, *newAck, h.logger); err != nil {
				h.logger.WarnContext(ctx, "firebasetunnel: ack update failed: ", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(h.pollInterval):
		}
	}
}

func (h *Inbound) gcLoop(ctx context.Context) error {
	ticker := time.NewTicker(h.sessionTimeout / 2)
	defer ticker.Stop()
	const closedGrace = 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			var raw map[string]sessionMetadata
			if found, err := h.fb.Get(ctx, pathSessionsRoot(), &raw); err != nil || !found {
				continue
			}
			now := nowMillis()
			for id, meta := range raw {
				age := time.Duration(now-meta.CreatedAt) * time.Millisecond
				stale := (meta.State == sessionStatePending && age > h.sessionTimeout) ||
					(isTerminal(meta.State) && age > h.sessionTimeout+closedGrace)
				if stale {
					if err := h.fb.Delete(ctx, "sessions/"+id); err != nil {
						h.logger.WarnContext(ctx, "firebasetunnel: gc delete failed for ", id, ": ", err)
					}
				}
			}
		}
	}
}

func (h *Inbound) acquireSessionSlot(user string) bool {
	if h.closing.Load() {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	bucket, ok := h.perUserBucket[user]
	if !ok {
		bucket = newTokenBucket(h.sessionRate, h.sessionRate)
		h.perUserBucket[user] = bucket
	}
	if !bucket.take() || h.activeSessions >= h.maxSessions || h.perUserActive[user] >= h.maxSessionsPerUser {
		return false
	}
	h.activeSessions++
	h.perUserActive[user]++
	return true
}

func (h *Inbound) releaseSessionSlot(user string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.activeSessions--
	if h.perUserActive[user]--; h.perUserActive[user] == 0 {
		delete(h.perUserActive, user)
	}
}
