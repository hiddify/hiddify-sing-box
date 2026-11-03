package masque

// LastError is why the tunnel's last connect failed; nil once one worked, and before the first.
func (e *Tunnel) LastError() error {
	if err := e.lastError.Load(); err != nil {
		return *err
	}
	return nil
}
