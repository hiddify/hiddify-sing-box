package awg

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.InterfaceUpdateListener = (*Endpoint)(nil)

// InterfaceUpdated connects the bind again after a network change: the network manager has
// closed its connection to the peer (see transport/awg/h_bind_update.go).
func (w *Endpoint) InterfaceUpdated(ctx context.Context) {
	if !w.deviceStarted.Load() {
		return
	}
	go w.updateBind(ctx)
}

// Close stops the updates before the device closes. It does not wait for one under way: a
// send stalled on the detour may hold it, and the device's Close aborts that send.
func (w *Endpoint) Close() error {
	w.deviceStarted.Store(false)
	return w.Device.Close()
}

func (w *Endpoint) updateBind(ctx context.Context) {
	w.bindAccess.Lock()
	defer w.bindAccess.Unlock()
	if ctx.Err() != nil || w.ctx.Err() != nil || !w.deviceStarted.Load() {
		return
	}
	// the peer's domain may have another address on this network; a move connects the bind again
	if _, rebound := w.resolvePeersLocked(); rebound {
		return
	}
	if err := w.Device.BindUpdate(); err != nil {
		w.logger.Error(E.Cause(err, "update AmneziaWG bind after network change"))
	}
}
