package warpscan

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing/common/logger"
)

// The scanning engine is edgescan, shared with the Psiphon outbound; this package keeps what is
// WARP's own (its ranges, ports, probes and noises) and the names the WARP code uses.
type (
	Book        = edgescan.Book
	Result      = edgescan.Result
	Probe       = edgescan.Probe
	Defaults    = edgescan.Defaults
	Request     = edgescan.Request
	NetworkInfo = edgescan.NetworkInfo
	Status      = edgescan.Status
	Record      = edgescan.Record
)

const (
	MaxScore         = edgescan.MaxScore
	MinScore         = edgescan.MinScore
	RecentScoreFloor = edgescan.RecentScoreFloor
	RecentWindow     = edgescan.RecentWindow
	FailurePeriod    = edgescan.FailurePeriod
)

var (
	NewBook       = edgescan.NewBook
	NoiseMethod   = edgescan.NoiseMethod
	DetectNetwork = edgescan.DetectNetwork
)

// storeSuffix follows the client's key in the cache file.
const storeSuffix = "/warp-scanner"

// scannerName prefixes the log lines of the WARP scans.
const scannerName = "WARP scanner"

// Scan is edgescan.Scan, logged as the WARP scanner.
func Scan(ctx context.Context, logger logger.ContextLogger, request Request) ([]Result, error) {
	if request.Name == "" {
		request.Name = scannerName
	}
	return edgescan.Scan(ctx, logger, request)
}

// Load returns the client's score book, or an empty one.
func Load(cacheFile adapter.CacheFile, key string) *Book {
	return edgescan.Load(cacheFile, key+storeSuffix)
}

// Save keeps the client's score book.
func Save(cacheFile adapter.CacheFile, key string, book *Book) error {
	return edgescan.Save(cacheFile, key+storeSuffix, book)
}
