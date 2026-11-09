package awg

import (
	"errors"
	"net"
)

// When the network changes, the network manager closes every connection its dialers made
// (ConnectionManager.CloseAll), the bind's connection to the peer among them. The device then
// sent into a closed socket for good: the endpoint reconnects the bind with BindUpdate, as the
// WireGuard endpoint does.

// BindUpdate closes the bind's connections and opens them again; nothing before the device starts.
func (d *Device) BindUpdate() error {
	if d.awgDevice == nil {
		return nil
	}
	return d.awgDevice.BindUpdate()
}

// closeConn closes c; one the network manager closed already is not an error, or BindUpdate
// would stop there and never open the bind again.
func closeConn(c net.PacketConn) error {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}
