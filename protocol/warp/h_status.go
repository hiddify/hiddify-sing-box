package warp

import "github.com/sagernet/sing-box/adapter"

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
