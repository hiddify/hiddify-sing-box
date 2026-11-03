package masque

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
