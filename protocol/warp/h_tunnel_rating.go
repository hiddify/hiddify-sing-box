package warp

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/hiddify/rating"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

// Auto mode rates its tunnels per network, as the scanner rates noises (a rating.Score per
// network, kept in the cache file): a tunnel that connected gains a point, one that answered the
// race but did not connect loses one, and so does one that stayed silent in a race another tunnel
// answered. Among the tunnels that answer a race, the one used is drawn by weight: the tunnel that
// works on the network is taken most of the time, and the others still get their turn, so auto
// mode moves when the network starts letting another one through, or stops letting this one.

// tunnelBookSuffix names the tunnel ratings in the cache file, apart from the endpoint scores.
const tunnelBookSuffix = "/tunnels"

func tunnelMethod(mode string) string {
	return "tunnel/" + mode
}

// tunnelNetwork is the network the tunnels are rated on, empty while it is not known (a network
// change until it is named again).
func (w *WARPEndpoint) tunnelNetwork() string {
	if network := w.ratedNetwork.Load(); network != nil {
		return network.Name
	}
	return ""
}

// detectNetwork names the network the box is on (see warpscan.DetectNetwork), through the
// endpoint's dialer, in the background: auto mode does it while it gets its devices and races
// the tunnels, and the scanner of the start takes it over (see newFailover).
func (w *WARPEndpoint) detectNetwork(ctx context.Context) <-chan warpscan.NetworkInfo {
	result := make(chan warpscan.NetworkInfo, 1)
	traceDialer, err := dialer.NewWithOptions(dialer.Options{ // the trace URLs are named by domain
		Context:          w.ctx,
		Options:          w.options.DialerOptions,
		RemoteIsDomain:   true,
		ResolverOnDetour: true,
	})
	if err != nil {
		w.logger.WarnContext(w.ctx, "WARP: ", err)
		close(result)
		return result
	}
	go func() {
		network := w.scanStore().Network(ctx, w.logger, traceDialer)
		w.ratedNetwork.Store(&network)
		result <- network
	}()
	return result
}

// tunnelBook is the tunnel ratings of the scan store: shared by the WARP endpoints on the network.
func (w *WARPEndpoint) tunnelBook() *warpscan.Book {
	return w.scanStore().Book(edgescan.KindWARPTunnels)
}

// rateTunnels records an outcome on the current network and saves it.
func (w *WARPEndpoint) rateTunnels(record func(book *warpscan.Book, network string, now time.Time)) {
	network := w.tunnelNetwork()
	if network == "" {
		return
	}
	store := w.scanStore()
	record(store.Book(edgescan.KindWARPTunnels), network, time.Now())
	if err := store.Save(); err != nil {
		w.logger.WarnContext(w.ctx, "WARP auto mode: save tunnel ratings: ", err)
	}
}

// tunnelConnected counts a connect of mode.
func (w *WARPEndpoint) tunnelConnected(mode string) {
	w.rateTunnels(func(book *warpscan.Book, network string, now time.Time) {
		book.SettleMethods(network, tunnelMethod(mode), nil, now)
	})
}

// tunnelsFailed counts modes that did not get through.
func (w *WARPEndpoint) tunnelsFailed(modes ...string) {
	if len(modes) == 0 {
		return
	}
	w.rateTunnels(func(book *warpscan.Book, network string, now time.Time) {
		for _, mode := range modes {
			book.MethodFailure(network, tunnelMethod(mode), now)
		}
	})
}

// orderTunnels returns modes in a weighted random order by their rating on the current network.
func (w *WARPEndpoint) orderTunnels(modes []string) []string {
	methods := make([]string, len(modes))
	byMethod := make(map[string]string, len(modes))
	for i, mode := range modes {
		methods[i] = tunnelMethod(mode)
		byMethod[methods[i]] = mode
	}
	ordered := w.tunnelBook().OrderMethods(w.tunnelNetwork(), methods, nil)
	result := make([]string, len(ordered))
	for i, method := range ordered {
		result[i] = byMethod[method]
	}
	return result
}

// tunnelScore is the rating of mode on the current network, for the log.
func (w *WARPEndpoint) tunnelScore(mode string) rating.Score {
	score, _ := w.tunnelBook().MethodScore(w.tunnelNetwork(), tunnelMethod(mode))
	return score
}

func (w *WARPEndpoint) paused() bool {
	pauseManager := service.FromContext[pause.Manager](w.ctx)
	return pauseManager != nil && (pauseManager.IsDevicePaused() || pauseManager.IsNetworkPaused())
}
