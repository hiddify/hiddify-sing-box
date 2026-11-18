package warp

import (
	"github.com/sagernet/sing-box/hiddify/edgescan"
)

// scanStore is where the endpoint keeps its scores and its tunnel ratings: the store shared by
// every scanner that reaches the network directly (no detour, or a direct one), so several WARP
// endpoints, and Psiphon, learn from each other and share their searches; or one of its own
// behind another detour, which sees another network. The scores it kept under its own keys before
// join the store once.
func (w *WARPEndpoint) scanStore() *edgescan.Store {
	store := edgescan.OpenScannerStore(w.ctx, w.options.Detour, w.uniqueID+"/edge-scanner")
	store.Adopt(edgescan.KindWARP, w.uniqueID+"/warp-scanner")
	// the tunnel ratings were saved through warpscan.Save, which adds its suffix
	store.Adopt(edgescan.KindWARPTunnels, w.uniqueID+tunnelBookSuffix+"/warp-scanner")
	return store
}
