package firebasetunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
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

const (
	defaultBatchInterval     = 50 * time.Millisecond
	defaultBatchMaxBytes     = 32 * 1024
	defaultRetryLimit        = 5
	defaultActivationTimeout = 30 * time.Second
	defaultS2CPollInterval   = 150 * time.Millisecond
	defaultReadBufSize       = 32 * 1024

	// warnActivationAfter is how long waitForActive waits before emitting a
	// Warn log so operators know the server may be absent.
	warnActivationAfter = 3 * time.Second
)

func RegisterClientEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.FirebaseTunnelClientOptions](registry, C.TypeFirebaseTunnelClient, NewClientEndpoint)
}

type ClientEndpoint struct {
	outbound.Adapter
	logger            logger.ContextLogger
	fb                *firebaseClient
	user              string
	key               *[32]byte
	hmacKey           []byte
	batchInterval     time.Duration
	batchMaxBytes     int
	activationTimeout time.Duration
}

func NewClientEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FirebaseTunnelClientOptions) (adapter.Endpoint, error) {
	urls := options.FirebaseURLs
	if len(urls) == 0 {
		return nil, E.New("firebase_urls is required")
	}
	if options.FirebaseSecret == "" && options.FirebaseAuthToken == "" {
		return nil, E.New("one of firebase_secret or firebase_auth_token is required")
	}
	if options.User == "" {
		return nil, E.New("user is required")
	}

	retryLimit := options.RetryLimit
	if retryLimit == 0 {
		retryLimit = defaultRetryLimit
	}
	fb := newFirebaseClient(urls[0], options.FirebaseSecret, options.FirebaseAuthToken, retryLimit, logger)

	var key *[32]byte
	if options.PSK != "" {
		k := deriveKey(options.PSK)
		key = &k
	}

	// Derive HMAC key from firebase_secret for integrity on unencrypted path.
	var hmacKey []byte
	if options.FirebaseSecret != "" && key == nil {
		hmacKey = deriveHMACKey(options.FirebaseSecret)
	}

	batchInterval := time.Duration(options.BatchInterval)
	if batchInterval <= 0 {
		batchInterval = defaultBatchInterval
	}
	batchMaxBytes := options.BatchMaxBytes
	if batchMaxBytes <= 0 {
		batchMaxBytes = defaultBatchMaxBytes
	}
	activationTimeout := time.Duration(options.ActivationTimeout)
	if activationTimeout <= 0 {
		activationTimeout = defaultActivationTimeout
	}

	return &ClientEndpoint{
		Adapter:           outbound.NewAdapter(C.TypeFirebaseTunnelClient, tag, []string{N.NetworkTCP}, nil),
		logger:            logger,
		fb:                fb,
		user:              options.User,
		key:               key,
		hmacKey:           hmacKey,
		batchInterval:     batchInterval,
		batchMaxBytes:     batchMaxBytes,
		activationTimeout: activationTimeout,
	}, nil
}

func (c *ClientEndpoint) Start(stage adapter.StartStage) error {
	return nil
}

func (c *ClientEndpoint) Close() error {
	return nil
}

func (c *ClientEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
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
		User:       c.user,
	}
	if err := c.fb.Put(ctx, pathMetadata(sessionID), &meta); err != nil {
		return nil, fmt.Errorf("firebasetunnel: creating session: %w", err)
	}

	activateCtx, cancel := context.WithTimeout(ctx, c.activationTimeout)
	defer cancel()
	if err := c.waitForActive(activateCtx, sessionID); err != nil {
		return nil, fmt.Errorf("firebasetunnel: session activation: %w", err)
	}

	local, remote := net.Pipe()
	go c.runSession(ctx, sessionID, remote)
	return local, nil
}

func (c *ClientEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (c *ClientEndpoint) waitForActive(ctx context.Context, sessionID string) error {
	path := pathMetadata(sessionID)
	start := time.Now()
	warned := false
	consecutiveErrors := 0

	for {
		var meta sessionMetadata
		found, err := c.fb.Get(ctx, path, &meta)
		if err != nil {
			consecutiveErrors++
			backoff := jitteredBackoff(consecutiveErrors)
			c.logger.WarnContext(ctx, "firebasetunnel: poll error waiting for session ", sessionID, " to activate: ", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
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
			c.logger.WarnContext(ctx, "firebasetunnel: session ", sessionID, " still pending after ", time.Since(start).Round(time.Second), " — server may be absent or overloaded")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// runSession relays bytes between conn (the server-side end of the
// net.Pipe handed to the caller of DialContext) and Firebase, until conn
// closes or the server marks the session Closed.
func (c *ClientEndpoint) runSession(ctx context.Context, sessionID string, conn net.Conn) {
	defer conn.Close()
	sender := newChunkSender(ctx, pathC2S(sessionID), sessionID, "c2s", c.fb, c.batchInterval, c.batchMaxBytes, c.key, c.hmacKey, c.logger)

	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	c2sDone := make(chan struct{})
	go func() {
		defer close(c2sDone)
		buf := make([]byte, defaultReadBufSize)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if feedErr := sender.feed(relayCtx, buf[:n]); feedErr != nil {
					c.logger.WarnContext(ctx, "firebasetunnel: c2s feed error: ", feedErr)
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = c.setSessionState(context.Background(), sessionID, sessionStateClosing)
	}()

	s2cDone := make(chan struct{})
	go func() {
		defer close(s2cDone)
		c.runS2C(relayCtx, sessionID, conn)
	}()

	select {
	case <-c2sDone:
	case <-s2cDone:
	}
	cancel()

	_ = c.setSessionState(context.Background(), sessionID, sessionStateClosed)
	if err := c.fb.Delete(context.Background(), "sessions/"+sessionID); err != nil {
		c.logger.WarnContext(ctx, "firebasetunnel: session cleanup failed: ", err)
	}
}

func (c *ClientEndpoint) runS2C(ctx context.Context, sessionID string, conn net.Conn) {
	receiver, byteRx := newChunkReceiver(c.key, c.hmacKey, sessionID, "s2c")
	var deliveredUpTo *uint64
	s2cPath := pathS2C(sessionID)
	ackPath := pathAcks(sessionID) + "/s2c_ack"

	for {
		var meta sessionMetadata
		found, err := c.fb.Get(ctx, pathMetadata(sessionID), &meta)
		if err == nil && found && (meta.State == sessionStateClosing || meta.State == sessionStateClosed) {
			return
		}

		chunks, err := fetchNewChunks(ctx, c.fb, s2cPath, deliveredUpTo)
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
				c.logger.WarnContext(ctx, "firebasetunnel: s2c ingest error: ", err)
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
			if err := updateAckAndCleanup(ctx, c.fb, ackPath, s2cPath, *newAck, c.logger); err != nil {
				c.logger.WarnContext(ctx, "firebasetunnel: ack update failed: ", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(defaultS2CPollInterval):
		}
	}
}

func (c *ClientEndpoint) setSessionState(ctx context.Context, sessionID string, state sessionState) error {
	path := pathMetadata(sessionID)
	var meta sessionMetadata
	found, err := c.fb.Get(ctx, path, &meta)
	if err != nil || !found {
		return err
	}
	meta.State = state
	return c.fb.Put(ctx, path, &meta)
}

var _ = io.EOF
