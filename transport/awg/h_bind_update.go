package awg

import (
	"errors"
	"net"
	"net/netip"
	"os"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
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

// SetPeerEndpoint sets the address of the peer with the public key (hex), resolved from its
// domain once the box started. The only peer's address is also where the bind connects: it
// connects again at once. A handshake then starts, from the bind that gets the answer.
func (d *Device) SetPeerEndpoint(publicKey string, address netip.AddrPort, only bool) error {
	if d.awgDevice == nil {
		return os.ErrInvalid
	}
	if err := d.awgDevice.IpcSet("public_key=" + publicKey + "\nupdate_only=true\nendpoint=" + address.String()); err != nil {
		return err
	}
	if bind, isBind := d.bind.(*bind_adapter); isBind && only {
		bind.setPeer(address)
		if err := d.awgDevice.BindUpdate(); err != nil {
			return err
		}
	}
	// the handshakes sent before had no address: start one now, not at the next retry in 5 seconds
	var key device.NoisePublicKey
	if err := key.FromHex(publicKey); err == nil {
		if peer := d.awgDevice.LookupPeer(key); peer != nil {
			peer.ExpireCurrentKeypairs() // lets the handshake go at once; the keys were of the old address
			peer.SendHandshakeInitiation(false)
		}
	}
	return nil
}

// closeConn closes c; one the network manager closed already is not an error, or BindUpdate
// would stop there and never open the bind again.
func closeConn(c net.PacketConn) error {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}
