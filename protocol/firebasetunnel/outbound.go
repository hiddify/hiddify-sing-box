package firebasetunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.FirebaseTunnelOutboundOptions](registry, C.TypeFirebaseTunnelOutbound, NewOutbound)
}

// Outbound dials through Firebase Realtime Database as a transport. It writes a
// session request to Firebase and waits for the server to activate it, then
// relays data through the session's chunk queues.
type Outbound struct {
	outbound.Adapter
	ctx               context.Context
	logger            logger.ContextLogger
	fb                *firebaseClient
	key               *[32]byte // nil → HMAC-only
	hmacKey           []byte
	user              string
	batchInterval     time.Duration
	batchMaxBytes     int
	activationTimeout time.Duration
}

func NewOutbound(ctx context.Context, _ adapter.Router, lg log.ContextLogger, tag string, options option.FirebaseTunnelOutboundOptions) (adapter.Outbound, error) {
	if len(options.FirebaseURLs) == 0 {
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

	o := &Outbound{
		Adapter:           outbound.NewAdapter(C.TypeFirebaseTunnelOutbound, tag, []string{N.NetworkTCP}, nil),
		ctx:               ctx,
		logger:            lg,
		fb:                newFirebaseClient(options.FirebaseURLs[0], options.FirebaseSecret, options.FirebaseAuthToken, retryLimit, lg),
		user:              options.User,
		batchInterval:     durationOr(time.Duration(options.BatchInterval), defaultBatchInterval),
		batchMaxBytes:     intOr(options.BatchMaxBytes, defaultBatchMaxBytes),
		activationTimeout: durationOr(time.Duration(options.ActivationTimeout), defaultActivationTimeout),
	}

	if options.PSK != "" {
		k := deriveKey(options.PSK)
		o.key = &k
	} else if options.FirebaseSecret != "" {
		o.hmacKey = deriveHMACKey(options.FirebaseSecret)
	}

	return o, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
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
		User:       o.user,
	}
	if err := o.fb.Put(ctx, pathMetadata(sessionID), &meta); err != nil {
		return nil, fmt.Errorf("firebasetunnel: creating session: %w", err)
	}

	activateCtx, cancel := context.WithTimeout(ctx, o.activationTimeout)
	defer cancel()
	if err := o.waitForActive(activateCtx, sessionID); err != nil {
		return nil, fmt.Errorf("firebasetunnel: session activation: %w", err)
	}

	local, remote := net.Pipe()
	go o.runSession(ctx, sessionID, remote)
	return local, nil
}

func (o *Outbound) ListenPacket(_ context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (o *Outbound) waitForActive(ctx context.Context, sessionID string) error {
	path := pathMetadata(sessionID)
	start := time.Now()
	warned := false
	consecutiveErrors := 0

	for {
		var meta sessionMetadata
		found, err := o.fb.Get(ctx, path, &meta)
		if err != nil {
			consecutiveErrors++
			o.logger.WarnContext(ctx, "firebasetunnel: poll error waiting for session ", sessionID, " to activate: ", err)
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
			o.logger.WarnContext(ctx, "firebasetunnel: session ", sessionID, " still pending after ",
				time.Since(start).Round(time.Second), " — server may be absent or overloaded")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (o *Outbound) runSession(ctx context.Context, sessionID string, conn net.Conn) {
	defer conn.Close()

	sender := newChunkSender(ctx, pathC2S(sessionID), sessionID, "c2s",
		o.fb, o.batchInterval, o.batchMaxBytes, o.key, o.hmacKey, o.logger)

	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	c2sDone := make(chan struct{})
	go func() {
		defer close(c2sDone)
		copyToSender(relayCtx, conn, sender, o.logger)
		_ = o.setSessionState(context.Background(), sessionID, sessionStateClosing)
	}()

	s2cDone := make(chan struct{})
	go func() {
		defer close(s2cDone)
		o.runS2C(relayCtx, sessionID, conn)
	}()

	select {
	case <-c2sDone:
	case <-s2cDone:
	}
	cancel()

	_ = o.setSessionState(context.Background(), sessionID, sessionStateClosed)
	if err := o.fb.Delete(context.Background(), "sessions/"+sessionID); err != nil {
		o.logger.WarnContext(ctx, "firebasetunnel: session cleanup failed: ", err)
	}
}

func (o *Outbound) runS2C(ctx context.Context, sessionID string, conn net.Conn) {
	receiver, byteRx := newChunkReceiver(o.key, o.hmacKey, sessionID, "s2c")
	var deliveredUpTo *uint64
	s2cPath := pathS2C(sessionID)
	ackPath := pathAcks(sessionID) + "/s2c_ack"

	for {
		var meta sessionMetadata
		if found, err := o.fb.Get(ctx, pathMetadata(sessionID), &meta); err == nil && found && isTerminal(meta.State) {
			return
		}

		chunks, err := fetchNewChunks(ctx, o.fb, s2cPath, deliveredUpTo)
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
				o.logger.WarnContext(ctx, "firebasetunnel: s2c ingest error: ", err)
				return
			}
			if newAck == nil {
				continue
			}
			deliveredUpTo = newAck
			if err := drainInto(byteRx, conn); err != nil {
				return
			}
			if err := updateAckAndCleanup(ctx, o.fb, ackPath, s2cPath, *newAck, o.logger); err != nil {
				o.logger.WarnContext(ctx, "firebasetunnel: ack update failed: ", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(defaultS2CPollInterval):
		}
	}
}

func (o *Outbound) setSessionState(ctx context.Context, sessionID string, state sessionState) error {
	path := pathMetadata(sessionID)
	var meta sessionMetadata
	found, err := o.fb.Get(ctx, path, &meta)
	if err != nil || !found {
		return err
	}
	meta.State = state
	return o.fb.Put(ctx, path, &meta)
}
