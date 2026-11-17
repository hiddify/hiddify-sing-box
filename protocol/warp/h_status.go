package warp

import (
	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// StatusError says why the endpoint is not ready, for the app: the error that failed it, or what
// the tunnel inside it says (over MASQUE, why its last connect failed).
func (w *WARPEndpoint) StatusError() error {
	if err := w.failError.Get(); err != nil {
		return err
	}
	if inner, ok := w.currentEndpoint().(adapter.StatusErrorer); ok {
		return inner.StatusError()
	}
	return nil
}

// notReady is the error of a dial while there is no inner endpoint: what the endpoint is doing
// instead, and why its last attempt failed. It said "endpoint not initialized" alone, thousands
// of times, while the reason (a device that could not register) was logged once in between.
func (w *WARPEndpoint) notReady() error {
	select {
	case <-w.done:
		return E.New("WARP is closed")
	default:
	}
	if err := w.failError.Get(); err != nil {
		return E.Cause(err, "WARP failed")
	}
	var doing string
	switch {
	case w.registering.Load():
		doing = "registering a device"
	case w.selecting.Load():
		doing = "auto mode is choosing a tunnel"
	case w.scanStatus.IsScanning():
		doing = "searching for an endpoint that answers"
	default:
		doing = "connecting"
	}
	if err := w.attemptError.Get(); err != nil {
		return E.Cause(err, "WARP is not connected yet, ", doing, "; last attempt")
	}
	return E.New("WARP is not connected yet, ", doing)
}
