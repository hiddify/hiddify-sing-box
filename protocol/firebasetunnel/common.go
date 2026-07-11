package firebasetunnel

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// Timing / capacity defaults.
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

// isTerminal reports whether s is a state that signals the session is ending.
func isTerminal(s sessionState) bool {
	return s == sessionStateClosing || s == sessionStateClosed
}

// drainInto reads all buffered data from ch and writes it to conn.
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
