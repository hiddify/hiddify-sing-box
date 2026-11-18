package masque

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.DeepSearcher = (*Outbound)(nil)

// DeepSearchAvailable reports whether the scanner's last search found no endpoint and no deep
// search runs.
func (w *Outbound) DeepSearchAvailable() bool {
	return w.currentScanner() != nil && w.scanStatus.DeepSearchAvailable()
}

// StartDeepSearch starts a deep search in the background, for each HTTP version the tunnel uses:
// no time limit and more workers. The tunnel takes the endpoint it finds the next time the one in
// use does not connect.
func (w *Outbound) StartDeepSearch() error {
	scanner := w.currentScanner()
	if scanner == nil {
		return E.New("WARP over MASQUE: the scanner is off")
	}
	if !w.scanStatus.DeepSearchAvailable() || !w.scanStatus.TryStartDeep() {
		return nil // nothing gave up, or a deep search runs
	}
	w.logger.Info("WARP scanner: deep search")
	mode, _ := tunnelMode(scanner.options)
	for _, http2 := range []bool{false, true} {
		if mode == masque.ModeAuto || (mode == masque.ModeHTTP2) == http2 {
			scanner.searchInBackground(http2, nil, true)
		}
	}
	return nil
}

// searchOptions are the search options of the scanner, nil without one.
func searchOptions(scanner *option.WARPScannerOptions) *option.EdgeSearchOptions {
	if scanner == nil {
		return nil
	}
	return &scanner.EdgeSearchOptions
}

// currentScanner is the scanner of the started tunnel, nil before or without one.
func (w *Outbound) currentScanner() *masqueScanner {
	w.tunnelAccess.Lock()
	defer w.tunnelAccess.Unlock()
	return w.scanner
}
