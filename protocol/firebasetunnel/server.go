package firebasetunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

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

const (
	defaultPollInterval               = 200 * time.Millisecond
	defaultSessionTimeout             = 300 * time.Second
	defaultMaxSessions                = 1000
	defaultMaxSessionsPerUser         = 50
	defaultMaxSessionsPerSecondPerUser = 5
)

func RegisterServerEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.FirebaseTunnelServerOptions](registry, C.TypeFirebaseTunnelServer, NewServerEndpoint)
}

type firebaseTunnelUserConfig struct {
	name string
	key  *[32]byte
}

type ServerEndpoint struct {
	outbound.Adapter
	ctx            context.Context
	logger         logger.ContextLogger
	router         adapter.Router
	fb             *firebaseClient
	users          map[string]firebaseTunnelUserConfig
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

	stop context.CancelFunc
}

func NewServerEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FirebaseTunnelServerOptions) (adapter.Endpoint, error) {
	urls := options.FirebaseURLs
	if len(urls) == 0 {
		return nil, E.New("firebase_urls is required")
	}
	if options.FirebaseSecret == "" && options.FirebaseAuthToken == "" {
		return nil, E.New("one of firebase_secret or firebase_auth_token is required")
	}
	if len(options.Users) == 0 {
		return nil, E.New("at least one user is required")
	}

	retryLimit := options.RetryLimit
	if retryLimit == 0 {
		retryLimit = defaultRetryLimit
	}
	fb := newFirebaseClient(urls[0], options.FirebaseSecret, options.FirebaseAuthToken, retryLimit, logger)

	users := make(map[string]firebaseTunnelUserConfig, len(options.Users))
	for _, u := range options.Users {
		if u.Name == "" {
			return nil, E.New("user name must not be empty")
		}
		cfg := firebaseTunnelUserConfig{name: u.Name}
		if u.PSK != "" {
			k := deriveKey(u.PSK)
			cfg.key = &k
		}
		users[u.Name] = cfg
	}

	pollInterval := time.Duration(options.PollInterval)
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	sessionTimeout := time.Duration(options.SessionTimeout)
	if sessionTimeout <= 0 {
		sessionTimeout = defaultSessionTimeout
	}
	maxSessions := options.MaxSessions
	if maxSessions <= 0 {
		maxSessions = defaultMaxSessions
	}
	maxSessionsPerUser := options.MaxSessionsPerUser
	if maxSessionsPerUser <= 0 {
		maxSessionsPerUser = defaultMaxSessionsPerUser
	}
	sessionRate := options.MaxSessionsPerSecondPerUser
	if sessionRate <= 0 {
		sessionRate = defaultMaxSessionsPerSecondPerUser
	}

	return &ServerEndpoint{
		Adapter:            outbound.NewAdapter(C.TypeFirebaseTunnelServer, tag, []string{N.NetworkTCP}, nil),
		ctx:                ctx,
		logger:             logger,
		router:             router,
		fb:                 fb,
		users:              users,
		pollInterval:       pollInterval,
		sessionTimeout:     sessionTimeout,
		maxSessions:        maxSessions,
		maxSessionsPerUser: maxSessionsPerUser,
		sessionRate:        sessionRate,
		perUserActive:      make(map[string]int),
		perUserBucket:      make(map[string]*tokenBucket),
	}, nil
}

// SetTracker wires per-user traffic accounting into the existing SSM stats
// subsystem (the same one Hiddify Manager already polls for shadowsocks
// usage). Not part of adapter.ManagedSSMServer (that interface requires
// adapter.Inbound, which this Endpoint is not) — call directly if your box
// construction code has a tracker to attach.
func (s *ServerEndpoint) SetTracker(tracker adapter.SSMTracker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tracker = tracker
}

func (s *ServerEndpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	ctx, cancel := context.WithCancel(s.ctx)
	s.stop = cancel
	go s.runWithRecovery(ctx, s.pollLoop)
	go s.runWithRecovery(ctx, s.gcLoop)
	return nil
}

func (s *ServerEndpoint) Close() error {
	if s.stop != nil {
		s.stop()
	}
	return nil
}

// runWithRecovery restarts fn with backoff if it panics, so a bug in the
// poll/GC loop can't crash the rest of the sing-box process.
func (s *ServerEndpoint) runWithRecovery(ctx context.Context, fn func(context.Context)) {
	for {
		if ctx.Err() != nil {
			return
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.logger.ErrorContext(ctx, "firebasetunnel: server loop panic, restarting: ", r)
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

func (s *ServerEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (s *ServerEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// pollLoop watches sessions/ for new Pending sessions and dispatches each
// to handleSession. Uses Firebase's SSE listen stream rather than tight
// polling; falls back to a coarse poll if the stream is unavailable.
func (s *ServerEndpoint) pollLoop(ctx context.Context) {
	seen := make(map[string]struct{})
	events := s.fb.listen(ctx, pathSessionsRoot())
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	checkNow := func() {
		var raw map[string]sessionMetadata
		found, err := s.fb.Get(ctx, pathSessionsRoot(), &raw)
		if err != nil || !found {
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
			go s.handleSession(ctx, meta)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				events = s.fb.listen(ctx, pathSessionsRoot())
				continue
			}
			checkNow()
		case <-ticker.C:
			checkNow()
		}
	}
}

func (s *ServerEndpoint) handleSession(ctx context.Context, meta sessionMetadata) {
	sessionID := meta.SessionID

	userCfg, ok := s.users[meta.User]
	if !ok {
		s.logger.WarnContext(ctx, "firebasetunnel: rejecting session ", sessionID, ": unknown user")
		_ = s.fb.Put(ctx, pathMetadata(sessionID), &sessionMetadata{SessionID: sessionID, State: sessionStateClosed})
		return
	}

	if !s.acquireSessionSlot(meta.User) {
		s.logger.WarnContext(ctx, "firebasetunnel: rejecting session ", sessionID, ": session limit or rate limit exceeded for user ", meta.User)
		_ = s.fb.Put(ctx, pathMetadata(sessionID), &sessionMetadata{SessionID: sessionID, State: sessionStateClosed})
		return
	}
	defer s.releaseSessionSlot(meta.User)

	destination := M.ParseSocksaddrHostPort(meta.TargetHost, meta.TargetPort)

	metadata := adapter.InboundContext{
		Inbound:     s.Tag(),
		InboundType: C.TypeFirebaseTunnelServer,
		Destination: destination,
		User:        meta.User,
	}

	local, remote := net.Pipe()
	var conn net.Conn = local
	s.mu.Lock()
	tracker := s.tracker
	s.mu.Unlock()
	if tracker != nil {
		conn = tracker.TrackConnection(conn, metadata)
	}

	updated := meta
	updated.State = sessionStateActive
	if err := s.fb.Put(ctx, pathMetadata(sessionID), &updated); err != nil {
		remote.Close()
		local.Close()
		s.logger.WarnContext(ctx, "firebasetunnel: marking session active failed: ", err)
		return
	}

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		s.runRelay(ctx, sessionID, remote, userCfg.key)
	}()

	onClose := func(error) {}
	s.router.RouteConnectionEx(ctx, conn, metadata, onClose)

	<-relayDone

	finalMeta := updated
	finalMeta.State = sessionStateClosed
	_ = s.fb.Put(context.Background(), pathMetadata(sessionID), &finalMeta)
	if err := s.fb.Delete(context.Background(), "sessions/"+sessionID); err != nil {
		s.logger.WarnContext(ctx, "firebasetunnel: session cleanup failed: ", err)
	}
}

// runRelay pumps bytes between conn (the local-process side of the
// net.Pipe routed through sing-box) and the Firebase c2s/s2c queues.
func (s *ServerEndpoint) runRelay(ctx context.Context, sessionID string, conn net.Conn, key *[32]byte) {
	defer conn.Close()
	c2sPath := pathC2S(sessionID)
	s2cPath := pathS2C(sessionID)
	ackC2SPath := pathAcks(sessionID) + "/c2s_ack"

	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	c2sDone := make(chan struct{})
	go func() {
		defer close(c2sDone)
		s.runC2S(relayCtx, sessionID, conn, c2sPath, ackC2SPath, key)
	}()

	s2cDone := make(chan struct{})
	go func() {
		defer close(s2cDone)
		sender := newChunkSender(relayCtx, s2cPath, s.fb, 50*time.Millisecond, defaultReadBufSize, key, s.logger)
		buf := make([]byte, defaultReadBufSize)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if feedErr := sender.feed(relayCtx, buf[:n]); feedErr != nil {
					s.logger.WarnContext(ctx, "firebasetunnel: s2c feed error: ", feedErr)
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-c2sDone:
	case <-s2cDone:
	}
	cancel()
}

func (s *ServerEndpoint) runC2S(ctx context.Context, sessionID string, conn net.Conn, c2sPath, ackC2SPath string, key *[32]byte) {
	receiver, byteRx := newChunkReceiver(key)
	var deliveredUpTo *uint64
	lastActivity := time.Now()

	for {
		if time.Since(lastActivity) > s.sessionTimeout {
			s.logger.WarnContext(ctx, "firebasetunnel: session ", sessionID, " timed out")
			return
		}

		var meta sessionMetadata
		found, err := s.fb.Get(ctx, pathMetadata(sessionID), &meta)
		if err == nil && found && (meta.State == sessionStateClosing || meta.State == sessionStateClosed) {
			return
		}

		chunks, err := fetchNewChunks(ctx, s.fb, c2sPath, deliveredUpTo)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.pollInterval):
				continue
			}
		}
		if len(chunks) > 0 {
			lastActivity = time.Now()
		}

		for _, ck := range chunks {
			newAck, err := receiver.ingest(ctx, ck)
			if err != nil {
				s.logger.WarnContext(ctx, "firebasetunnel: c2s ingest error (session ", sessionID, "): ", err)
				return
			}
			if newAck == nil {
				continue
			}
			deliveredUpTo = newAck
		drainLoop:
			for {
				select {
				case data := <-byteRx:
					if _, err := conn.Write(data); err != nil {
						return
					}
				default:
					break drainLoop
				}
			}
			if err := updateAckAndCleanup(ctx, s.fb, ackC2SPath, c2sPath, *newAck, s.logger); err != nil {
				s.logger.WarnContext(ctx, "firebasetunnel: ack update failed: ", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(s.pollInterval):
		}
	}
}

// gcLoop periodically sweeps sessions/ for abandoned sessions: ones that
// never reached Active before SessionTimeout, or that have lingered in
// Closing/Closed past a short grace period.
func (s *ServerEndpoint) gcLoop(ctx context.Context) {
	ticker := time.NewTicker(s.sessionTimeout / 2)
	defer ticker.Stop()
	const closedGrace = 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var raw map[string]sessionMetadata
			found, err := s.fb.Get(ctx, pathSessionsRoot(), &raw)
			if err != nil || !found {
				continue
			}
			now := nowMillis()
			for id, meta := range raw {
				age := time.Duration(now-meta.CreatedAt) * time.Millisecond
				stale := (meta.State == sessionStatePending && age > s.sessionTimeout) ||
					((meta.State == sessionStateClosing || meta.State == sessionStateClosed) && age > s.sessionTimeout+closedGrace)
				if stale {
					if err := s.fb.Delete(ctx, "sessions/"+id); err != nil {
						s.logger.WarnContext(ctx, "firebasetunnel: gc delete failed for ", id, ": ", err)
					}
				}
			}
		}
	}
}

// acquireSessionSlot enforces global/per-user session caps and per-user
// session-creation rate limiting. Returns false if the session should be
// rejected.
func (s *ServerEndpoint) acquireSessionSlot(user string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.perUserBucket[user]
	if !ok {
		bucket = newTokenBucket(s.sessionRate, s.sessionRate)
		s.perUserBucket[user] = bucket
	}
	if !bucket.take() {
		return false
	}
	if s.activeSessions >= s.maxSessions {
		return false
	}
	if s.perUserActive[user] >= s.maxSessionsPerUser {
		return false
	}
	s.activeSessions++
	s.perUserActive[user]++
	return true
}

func (s *ServerEndpoint) releaseSessionSlot(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeSessions--
	s.perUserActive[user]--
}

var _ = fmt.Sprintf
