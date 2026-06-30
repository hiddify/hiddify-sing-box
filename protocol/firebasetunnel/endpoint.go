package firebasetunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Timing / capacity defaults. Callers may override via options.
const (
	defaultBatchInterval     = 50 * time.Millisecond
	defaultBatchMaxBytes     = 32 * 1024
	defaultRetryLimit        = 5
	defaultActivationTimeout = 30 * time.Second
	defaultS2CPollInterval   = 150 * time.Millisecond
	defaultReadBufSize       = 32 * 1024
	warnActivationAfter      = 3 * time.Second

	defaultPollInterval                = 200 * time.Millisecond
	defaultSessionTimeout              = 300 * time.Second
	defaultMaxSessions                 = 1000
	defaultMaxSessionsPerUser          = 50
	defaultMaxSessionsPerSecondPerUser = 5
	drainTimeout                       = 5 * time.Second
)

// userConfig holds per-user server-side settings derived from options at
// construction time.
type userConfig struct {
	name string
	key  *[32]byte // nil → no PSK, HMAC-only integrity
}

// serverState holds all fields that are only needed in server (inbound) mode.
// When Endpoint.srv is nil the endpoint is in client (outbound) mode.
type serverState struct {
	router         adapter.Router
	users          map[string]userConfig
	pollInterval   time.Duration
	sessionTimeout time.Duration
	tracker        adapter.SSMTracker

	maxSessions        int
	maxSessionsPerUser int
	sessionRate        int

	mu             sync.Mutex
	activeSessions int
	perUserActive  map[string]int
	perUserBucket  map[string]*tokenBucket

	closing atomic.Bool
	stop    context.CancelFunc
}

// Endpoint implements adapter.Endpoint for the Firebase Tunnel protocol in
// either client (outbound) or server (inbound) mode.
//
// Role is fixed at construction time:
//   - options.Client != nil → client mode: dials via DialContext
//   - options.Server != nil → server mode: discovers sessions in pollLoop
//
// Exactly one must be set; NewEndpoint validates this.
type Endpoint struct {
	outbound.Adapter
	ctx     context.Context
	logger  logger.ContextLogger
	fb      *firebaseClient
	key     *[32]byte // encryption key (PSK-derived); nil → HMAC-only
	hmacKey []byte    // integrity key; nil when key != nil or no secret

	// client-mode only
	user              string
	batchInterval     time.Duration
	batchMaxBytes     int
	activationTimeout time.Duration

	// non-nil only in server mode
	srv *serverState
}

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.FirebaseTunnelOptions](registry, C.TypeFirebaseTunnel, NewEndpoint)
}

func NewEndpoint(ctx context.Context, router adapter.Router, lg log.ContextLogger, tag string, options option.FirebaseTunnelOptions) (adapter.Endpoint, error) {
	switch {
	case options.Server != nil && options.Client != nil:
		return nil, E.New("firebasetunnel: set exactly one of server or client, not both")
	case options.Server == nil && options.Client == nil:
		return nil, E.New("firebasetunnel: one of server or client must be set")
	case len(options.FirebaseURLs) == 0:
		return nil, E.New("firebase_urls is required")
	case options.FirebaseSecret == "" && options.FirebaseAuthToken == "":
		return nil, E.New("one of firebase_secret or firebase_auth_token is required")
	}

	retryLimit := options.RetryLimit
	if retryLimit == 0 {
		retryLimit = defaultRetryLimit
	}

	ep := &Endpoint{
		Adapter: outbound.NewAdapter(C.TypeFirebaseTunnel, tag, []string{N.NetworkTCP}, nil),
		ctx:     ctx,
		logger:  lg,
		fb:      newFirebaseClient(options.FirebaseURLs[0], options.FirebaseSecret, options.FirebaseAuthToken, retryLimit, lg),
	}

	if options.Client != nil {
		return ep, ep.applyClientOptions(options)
	}
	return ep, ep.applyServerOptions(ctx, router, options)
}

func (e *Endpoint) applyClientOptions(options option.FirebaseTunnelOptions) error {
	c := options.Client
	if c.User == "" {
		return E.New("client.user is required")
	}

	if c.PSK != "" {
		k := deriveKey(c.PSK)
		e.key = &k
	} else if options.FirebaseSecret != "" {
		e.hmacKey = deriveHMACKey(options.FirebaseSecret)
	}

	e.user = c.User
	e.batchInterval = durationOr(time.Duration(c.BatchInterval), defaultBatchInterval)
	e.batchMaxBytes = intOr(c.BatchMaxBytes, defaultBatchMaxBytes)
	e.activationTimeout = durationOr(time.Duration(c.ActivationTimeout), defaultActivationTimeout)
	return nil
}

func (e *Endpoint) applyServerOptions(ctx context.Context, router adapter.Router, options option.FirebaseTunnelOptions) error {
	s := options.Server
	if len(s.Users) == 0 {
		return E.New("server.users must have at least one entry")
	}

	users := make(map[string]userConfig, len(s.Users))
	for _, u := range s.Users {
		if u.Name == "" {
			return E.New("user name must not be empty")
		}
		uc := userConfig{name: u.Name}
		if u.PSK != "" {
			k := deriveKey(u.PSK)
			uc.key = &k
		}
		users[u.Name] = uc
	}

	if options.FirebaseSecret != "" {
		e.hmacKey = deriveHMACKey(options.FirebaseSecret)
	}

	e.srv = &serverState{
		router:             router,
		users:              users,
		pollInterval:       durationOr(time.Duration(s.PollInterval), defaultPollInterval),
		sessionTimeout:     durationOr(time.Duration(s.SessionTimeout), defaultSessionTimeout),
		maxSessions:        intOr(s.MaxSessions, defaultMaxSessions),
		maxSessionsPerUser: intOr(s.MaxSessionsPerUser, defaultMaxSessionsPerUser),
		sessionRate:        intOr(s.MaxSessionsPerSecondPerUser, defaultMaxSessionsPerSecondPerUser),
		perUserActive:      make(map[string]int),
		perUserBucket:      make(map[string]*tokenBucket),
	}
	return nil
}

// SetTracker wires per-user traffic accounting into the SSM stats subsystem.
// No-op in client mode.
func (e *Endpoint) SetTracker(tracker adapter.SSMTracker) {
	if e.srv == nil {
		return
	}
	e.srv.mu.Lock()
	e.srv.tracker = tracker
	e.srv.mu.Unlock()
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	if e.srv == nil || stage != adapter.StartStatePostStart {
		return nil
	}
	ctx, cancel := context.WithCancel(e.ctx)
	e.srv.stop = cancel
	go e.runWithRecovery(ctx, e.pollLoop)
	go e.runWithRecovery(ctx, e.gcLoop)
	return nil
}

func (e *Endpoint) Close() error {
	if e.srv == nil {
		return nil
	}
	srv := e.srv
	srv.closing.Store(true)
	deadline := time.Now().Add(drainTimeout)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		active := srv.activeSessions
		srv.mu.Unlock()
		if active == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if srv.stop != nil {
		srv.stop()
	}
	return nil
}

// DialContext is only valid in client mode; returns os.ErrInvalid in server mode.
func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if e.srv != nil || network != N.NetworkTCP {
		return nil, os.ErrInvalid
	}

	sessionID := uuid.New().String()
	meta := sessionMetadata{
		SessionID:  sessionID,
		Version:    protocolVersion,
		TargetHost: destination.AddrString(),
		TargetPort: destination.Port,
		CreatedAt:  nowMillis(),
		State:      sessionStatePending,
		User:       e.user,
	}
	if err := e.fb.Put(ctx, pathMetadata(sessionID), &meta); err != nil {
		return nil, fmt.Errorf("firebasetunnel: creating session: %w", err)
	}

	activateCtx, cancel := context.WithTimeout(ctx, e.activationTimeout)
	defer cancel()
	if err := e.waitForActive(activateCtx, sessionID); err != nil {
		return nil, fmt.Errorf("firebasetunnel: session activation: %w", err)
	}

	local, remote := net.Pipe()
	go e.runSession(ctx, sessionID, remote)
	return local, nil
}

func (e *Endpoint) ListenPacket(_ context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// ── client internals ──────────────────────────────────────────────────────────

func (e *Endpoint) waitForActive(ctx context.Context, sessionID string) error {
	path := pathMetadata(sessionID)
	start := time.Now()
	warned := false
	consecutiveErrors := 0

	for {
		var meta sessionMetadata
		found, err := e.fb.Get(ctx, path, &meta)
		if err != nil {
			consecutiveErrors++
			e.logger.WarnContext(ctx, "firebasetunnel: poll error waiting for session ", sessionID, " to activate: ", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(jitteredBackoff(consecutiveErrors)):
				continue
			}
		}
		consecutiveErrors = 0

		if found {
			switch meta.State {
			case sessionStateActive:
				return nil
			case sessionStateClosed:
				return E.New("server rejected session")
			}
		}

		if !warned && time.Since(start) > warnActivationAfter {
			warned = true
			e.logger.WarnContext(ctx, "firebasetunnel: session ", sessionID, " still pending after ",
				time.Since(start).Round(time.Second), " — server may be absent or overloaded")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (e *Endpoint) runSession(ctx context.Context, sessionID string, conn net.Conn) {
	defer conn.Close()

	sender := newChunkSender(ctx, pathC2S(sessionID), sessionID, "c2s",
		e.fb, e.batchInterval, e.batchMaxBytes, e.key, e.hmacKey, e.logger)

	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	c2sDone := make(chan struct{})
	go func() {
		defer close(c2sDone)
		copyToSender(relayCtx, conn, sender, e.logger)
		_ = e.setSessionState(context.Background(), sessionID, sessionStateClosing)
	}()

	s2cDone := make(chan struct{})
	go func() {
		defer close(s2cDone)
		e.runS2C(relayCtx, sessionID, conn)
	}()

	select {
	case <-c2sDone:
	case <-s2cDone:
	}
	cancel()

	_ = e.setSessionState(context.Background(), sessionID, sessionStateClosed)
	if err := e.fb.Delete(context.Background(), "sessions/"+sessionID); err != nil {
		e.logger.WarnContext(ctx, "firebasetunnel: session cleanup failed: ", err)
	}
}

func (e *Endpoint) runS2C(ctx context.Context, sessionID string, conn net.Conn) {
	receiver, byteRx := newChunkReceiver(e.key, e.hmacKey, sessionID, "s2c")
	var deliveredUpTo *uint64
	s2cPath := pathS2C(sessionID)
	ackPath := pathAcks(sessionID) + "/s2c_ack"

	for {
		var meta sessionMetadata
		if found, err := e.fb.Get(ctx, pathMetadata(sessionID), &meta); err == nil && found && isTerminal(meta.State) {
			return
		}

		chunks, err := fetchNewChunks(ctx, e.fb, s2cPath, deliveredUpTo)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(defaultS2CPollInterval):
				continue
			}
		}

		for _, ck := range chunks {
			newAck, err := receiver.ingest(ctx, ck)
			if err != nil {
				e.logger.WarnContext(ctx, "firebasetunnel: s2c ingest error: ", err)
				return
			}
			if newAck == nil {
				continue
			}
			deliveredUpTo = newAck
			if err := drainInto(byteRx, conn); err != nil {
				return
			}
			if err := updateAckAndCleanup(ctx, e.fb, ackPath, s2cPath, *newAck, e.logger); err != nil {
				e.logger.WarnContext(ctx, "firebasetunnel: ack update failed: ", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(defaultS2CPollInterval):
		}
	}
}

func (e *Endpoint) setSessionState(ctx context.Context, sessionID string, state sessionState) error {
	path := pathMetadata(sessionID)
	var meta sessionMetadata
	found, err := e.fb.Get(ctx, path, &meta)
	if err != nil || !found {
		return err
	}
	meta.State = state
	return e.fb.Put(ctx, path, &meta)
}

// ── server internals ──────────────────────────────────────────────────────────

func (e *Endpoint) runWithRecovery(ctx context.Context, fn func(context.Context)) {
	for {
		if ctx.Err() != nil {
			return
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					e.logger.ErrorContext(ctx, "firebasetunnel: server loop panic, restarting: ", r)
				}
			}()
			fn(ctx)
		}()
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

func (e *Endpoint) pollLoop(ctx context.Context) {
	srv := e.srv
	seen := make(map[string]struct{})
	events := e.fb.listen(ctx, pathSessionsRoot())
	ticker := time.NewTicker(srv.pollInterval)
	defer ticker.Stop()

	dispatch := func() {
		var raw map[string]sessionMetadata
		if found, err := e.fb.Get(ctx, pathSessionsRoot(), &raw); err != nil || !found {
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
			go e.handleSession(ctx, meta)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				events = e.fb.listen(ctx, pathSessionsRoot())
				continue
			}
			dispatch()
		case <-ticker.C:
			dispatch()
		}
	}
}

func (e *Endpoint) handleSession(ctx context.Context, meta sessionMetadata) {
	sessionID := meta.SessionID
	srv := e.srv

	userCfg, ok := srv.users[meta.User]
	if !ok {
		e.logger.WarnContext(ctx, "firebasetunnel: rejecting session ", sessionID, ": unknown user")
		e.closeSession(ctx, sessionID)
		return
	}
	if !e.acquireSessionSlot(meta.User) {
		e.logger.WarnContext(ctx, "firebasetunnel: rejecting session ", sessionID, ": limit/rate exceeded for user ", meta.User)
		e.closeSession(ctx, sessionID)
		return
	}
	defer e.releaseSessionSlot(meta.User)

	// Collision defense: re-read to verify CreatedAt hasn't changed under us.
	var current sessionMetadata
	if found, _ := e.fb.Get(ctx, pathMetadata(sessionID), &current); !found || current.CreatedAt != meta.CreatedAt {
		e.logger.WarnContext(ctx, "firebasetunnel: session collision for ", sessionID, ", rejecting")
		e.closeSession(ctx, sessionID)
		return
	}

	destination := M.ParseSocksaddrHostPort(meta.TargetHost, meta.TargetPort)
	inboundMeta := adapter.InboundContext{
		Inbound:     e.Tag(),
		InboundType: C.TypeFirebaseTunnel,
		Destination: destination,
		User:        meta.User,
	}

	local, remote := net.Pipe()
	var conn net.Conn = local
	srv.mu.Lock()
	tracker := srv.tracker
	srv.mu.Unlock()
	if tracker != nil {
		conn = tracker.TrackConnection(conn, inboundMeta)
	}

	updated := meta
	updated.State = sessionStateActive
	if err := e.fb.Put(ctx, pathMetadata(sessionID), &updated); err != nil {
		remote.Close()
		local.Close()
		e.logger.WarnContext(ctx, "firebasetunnel: marking session active failed: ", err)
		return
	}

	sessionKey := userCfg.key
	sessionHMACKey := e.hmacKey
	if sessionKey != nil {
		sessionHMACKey = nil // AEAD handles integrity; HMAC not needed
	}

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		e.runRelay(ctx, sessionID, remote, sessionKey, sessionHMACKey)
	}()

	srv.router.RouteConnectionEx(ctx, conn, inboundMeta, func(error) {})
	<-relayDone

	updated.State = sessionStateClosed
	_ = e.fb.Put(context.Background(), pathMetadata(sessionID), &updated)
	if err := e.fb.Delete(context.Background(), "sessions/"+sessionID); err != nil {
		e.logger.WarnContext(ctx, "firebasetunnel: session cleanup failed: ", err)
	}
}

func (e *Endpoint) closeSession(ctx context.Context, sessionID string) {
	_ = e.fb.Put(ctx, pathMetadata(sessionID), &sessionMetadata{SessionID: sessionID, State: sessionStateClosed})
}

func (e *Endpoint) runRelay(ctx context.Context, sessionID string, conn net.Conn, key *[32]byte, hmacKey []byte) {
	defer conn.Close()
	srv := e.srv

	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	c2sDone := make(chan struct{})
	go func() {
		defer close(c2sDone)
		e.runC2S(relayCtx, sessionID, conn, key, hmacKey)
	}()

	s2cDone := make(chan struct{})
	go func() {
		defer close(s2cDone)
		sender := newChunkSender(relayCtx, pathS2C(sessionID), sessionID, "s2c",
			e.fb, srv.pollInterval, defaultReadBufSize, key, hmacKey, e.logger)
		copyToSender(relayCtx, conn, sender, e.logger)
	}()

	select {
	case <-c2sDone:
	case <-s2cDone:
	}
	cancel()
}

func (e *Endpoint) runC2S(ctx context.Context, sessionID string, conn net.Conn, key *[32]byte, hmacKey []byte) {
	srv := e.srv
	receiver, byteRx := newChunkReceiver(key, hmacKey, sessionID, "c2s")
	var deliveredUpTo *uint64
	c2sPath := pathC2S(sessionID)
	ackPath := pathAcks(sessionID) + "/c2s_ack"
	lastActivity := time.Now()

	for {
		if time.Since(lastActivity) > srv.sessionTimeout {
			e.logger.WarnContext(ctx, "firebasetunnel: session ", sessionID, " timed out")
			return
		}

		var meta sessionMetadata
		if found, err := e.fb.Get(ctx, pathMetadata(sessionID), &meta); err == nil && found && isTerminal(meta.State) {
			return
		}

		chunks, err := fetchNewChunks(ctx, e.fb, c2sPath, deliveredUpTo)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(srv.pollInterval):
				continue
			}
		}
		if len(chunks) > 0 {
			lastActivity = time.Now()
		}

		for _, ck := range chunks {
			newAck, err := receiver.ingest(ctx, ck)
			if err != nil {
				e.logger.WarnContext(ctx, "firebasetunnel: c2s ingest error (session ", sessionID, "): ", err)
				return
			}
			if newAck == nil {
				continue
			}
			deliveredUpTo = newAck
			if err := drainInto(byteRx, conn); err != nil {
				return
			}
			if err := updateAckAndCleanup(ctx, e.fb, ackPath, c2sPath, *newAck, e.logger); err != nil {
				e.logger.WarnContext(ctx, "firebasetunnel: ack update failed: ", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(srv.pollInterval):
		}
	}
}

func (e *Endpoint) gcLoop(ctx context.Context) {
	srv := e.srv
	ticker := time.NewTicker(srv.sessionTimeout / 2)
	defer ticker.Stop()
	const closedGrace = 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var raw map[string]sessionMetadata
			if found, err := e.fb.Get(ctx, pathSessionsRoot(), &raw); err != nil || !found {
				continue
			}
			now := nowMillis()
			for id, meta := range raw {
				age := time.Duration(now-meta.CreatedAt) * time.Millisecond
				stale := (meta.State == sessionStatePending && age > srv.sessionTimeout) ||
					(isTerminal(meta.State) && age > srv.sessionTimeout+closedGrace)
				if stale {
					if err := e.fb.Delete(ctx, "sessions/"+id); err != nil {
						e.logger.WarnContext(ctx, "firebasetunnel: gc delete failed for ", id, ": ", err)
					}
				}
			}
		}
	}
}

func (e *Endpoint) acquireSessionSlot(user string) bool {
	srv := e.srv
	if srv.closing.Load() {
		return false
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()

	bucket, ok := srv.perUserBucket[user]
	if !ok {
		bucket = newTokenBucket(srv.sessionRate, srv.sessionRate)
		srv.perUserBucket[user] = bucket
	}
	if !bucket.take() || srv.activeSessions >= srv.maxSessions || srv.perUserActive[user] >= srv.maxSessionsPerUser {
		return false
	}
	srv.activeSessions++
	srv.perUserActive[user]++
	return true
}

func (e *Endpoint) releaseSessionSlot(user string) {
	srv := e.srv
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.activeSessions--
	if srv.perUserActive[user]--; srv.perUserActive[user] == 0 {
		delete(srv.perUserActive, user)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// isTerminal reports whether s is a state that signals the session is ending.
func isTerminal(s sessionState) bool {
	return s == sessionStateClosing || s == sessionStateClosed
}

// drainInto reads all buffered data from ch and writes it to conn.
// Returns the first write error encountered, or nil.
func drainInto(ch <-chan []byte, conn net.Conn) error {
	for {
		select {
		case data := <-ch:
			if _, err := conn.Write(data); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

// copyToSender reads from conn in a loop and feeds each chunk to sender.
// Stops (without error) when conn returns an error or ctx is cancelled.
func copyToSender(ctx context.Context, conn net.Conn, sender *chunkSender, lg logger.ContextLogger) {
	buf := make([]byte, defaultReadBufSize)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if feedErr := sender.feed(ctx, buf[:n]); feedErr != nil {
				if lg != nil {
					lg.WarnContext(ctx, "firebasetunnel: sender feed error: ", feedErr)
				}
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// durationOr returns d if d > 0, otherwise fallback.
func durationOr(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

// intOr returns v if v > 0, otherwise fallback.
func intOr(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}
