//go:build with_utls

package tls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

// realityKeyShareFailures is the number of failed REALITY handshakes in a row after which a client
// with key_share "auto" changes its key share.
const realityKeyShareFailures = 2

// realityKeyShareCacheTTL is how long a tested key share is kept; after that the server is
// untested again.
const realityKeyShareCacheTTL = 30 * 24 * time.Hour

const realityKeyShareCachePrefix = "reality-key-share:"

// errRealityVerificationFailed is returned when the server answered with a certificate that is not
// REALITY's: a server that refused the ClientHello and forwarded it to the target, a wrong key, or
// a man in the middle.
var errRealityVerificationFailed = E.New("reality verification failed")

// realityKeyShareAuto picks the key share of a REALITY client with key_share "auto".
//
// Real Chrome never retries without its post-quantum key share, so a client that does stands out
// to an observer. The test is therefore made once per server, and its result kept:
//
//  1. Untested: hybrid (X25519MLKEM768 and X25519), which every Xray version accepts.
//  2. After realityKeyShareFailures hybrid handshakes in a row that get no answer (a timeout, a
//     reset, a closed connection), it tries classical (X25519 only, the ClientHello of an older
//     browser, one TCP segment). A failed REALITY verification does not count: the ClientHello got
//     through, so classical would not help, and a man in the middle that answers with its own
//     certificate cannot start the test.
//  3. A classical handshake that works settles it on classical. realityKeyShareFailures failed
//     classical handshakes (Xray v26.9.8+ servers refuse classical with a failed verification)
//     settle it on hybrid, which is never tested again.
//
// The state belongs to the server (address, server name, public key), not to the outbound, so it
// outlives a config reload or subscription update; the settled key share is saved in the cache
// file, so a restarted core does not test again.
type realityKeyShareAuto struct {
	cacheTag  string
	access    sync.Mutex
	loaded    bool // the cache file was read
	tested    bool // the test was made: classical is not tried again after hybrid
	classical bool
	settled   bool // the current key share is final and saved
	failures  int
}

var realityKeyShareAutos sync.Map // server key → *realityKeyShareAuto

func realityKeyShareAutoFor(serverAddress string, serverName string, publicKey []byte) *realityKeyShareAuto {
	hash := sha256.New()
	for _, part := range [][]byte{[]byte(serverAddress), []byte(serverName), publicKey} {
		hash.Write(part)
		hash.Write([]byte{0})
	}
	cacheTag := realityKeyShareCachePrefix + hex.EncodeToString(hash.Sum(nil)[:16])
	auto, _ := realityKeyShareAutos.LoadOrStore(cacheTag, &realityKeyShareAuto{cacheTag: cacheTag})
	return auto.(*realityKeyShareAuto)
}

// useClassical returns the key share for the next handshake. cacheCtx is that of the current
// config, for its cache file.
func (a *realityKeyShareAuto) useClassical(cacheCtx context.Context) bool {
	a.access.Lock()
	defer a.access.Unlock()
	if !a.loaded {
		a.loaded = true
		if cacheFile := service.FromContext[adapter.CacheFile](cacheCtx); cacheFile != nil {
			if saved := cacheFile.LoadBinary(a.cacheTag); saved != nil && time.Since(saved.LastUpdated) < realityKeyShareCacheTTL {
				switch string(saved.Content) {
				case "classical":
					a.tested, a.classical, a.settled = true, true, true
				case "hybrid":
					a.tested, a.settled = true, true
				}
			}
		}
	}
	return a.classical
}

// report records the result of a handshake made with the key share classical. ctx is the
// handshake's: errors that do not come from the server or the network (the caller cancelled) are
// not counted. cacheCtx is that of the current config, for its cache file.
func (a *realityKeyShareAuto) report(ctx context.Context, cacheCtx context.Context, logger logger.ContextLogger, classical bool, err error) {
	if err != nil && (errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled)) {
		return
	}
	a.access.Lock()
	defer a.access.Unlock()
	if classical != a.classical {
		return // a handshake started before the last change
	}
	if err == nil || (!classical && errors.Is(err, errRealityVerificationFailed)) {
		a.failures = 0
		if err == nil && classical && !a.settled {
			a.settle(cacheCtx, logger, ctx, "reality: the classical key share works, kept for this server")
		}
		return
	}
	a.failures++
	if a.failures < realityKeyShareFailures {
		return
	}
	a.failures = 0
	if classical {
		a.classical = false
		a.settle(cacheCtx, logger, ctx, "reality: classical key share handshakes fail, back to the hybrid one for this server: ", err)
		return
	}
	if a.tested {
		return // hybrid was settled: no second test
	}
	a.tested = true
	a.classical = true
	if logger != nil {
		logger.WarnContext(ctx, "reality: hybrid key share handshakes get no answer, testing the classical one (a smaller ClientHello) once: ", err)
	}
}

// settle makes the current key share final and saves it in the cache file.
func (a *realityKeyShareAuto) settle(cacheCtx context.Context, logger logger.ContextLogger, ctx context.Context, message ...any) {
	a.tested = true
	a.settled = true
	if logger != nil {
		logger.WarnContext(ctx, message...)
	}
	cacheFile := service.FromContext[adapter.CacheFile](cacheCtx)
	if cacheFile == nil {
		return
	}
	content := "hybrid"
	if a.classical {
		content = "classical"
	}
	_ = cacheFile.SaveBinary(a.cacheTag, &adapter.SavedBinary{Content: []byte(content), LastUpdated: time.Now()})
}
