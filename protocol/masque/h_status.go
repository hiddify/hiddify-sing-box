package masque

import E "github.com/sagernet/sing/common/exceptions"

// StatusError says why the outbound is not ready, for the app: the device could not be
// registered or the tunnel set up, or else why the tunnel's last connect failed.
func (w *Outbound) StatusError() error {
	if err := w.setupError.Get(); err != nil {
		return err
	}
	if tunnel := w.currentTunnel(); tunnel != nil {
		return tunnel.LastError()
	}
	return nil
}

// errNoDevice is the error of a masque outbound without a device: it does not register WARP
// devices.
var errNoDevice = E.New("masque outbound needs a device (an enrolled MASQUE key); to register a WARP device, use the warp endpoint with mode masque")

// SetOnRejected sets what is told when Cloudflare refuses the device (its key was never enrolled,
// or the device was deleted), for the warp endpoint to take another device. Set it before the
// outbound starts.
func (w *Outbound) SetOnRejected(onRejected func(err error)) {
	w.onRejected = onRejected
}
