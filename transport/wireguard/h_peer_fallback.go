package wireguard

import (
	"encoding/hex"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/hiddify/peerfallback"
	"github.com/sagernet/wireguard-go/conn"
)

// The fallback addresses of an endpoint with a single peer given by an IP address (see package
// peerfallback). A move sets the peer's endpoint in the device and starts a handshake there at
// once; a bind connected to the peer's address dials the new one.

type peerFallback = peerfallback.Fallback

func newPeerFallback(e *Endpoint, bind conn.Bind) *peerFallback {
	if len(e.options.PeerFallback) == 0 || len(e.peers) != 1 || !e.peers[0].endpoint.IsValid() {
		return nil
	}
	clientBind, isClient := bind.(*ClientBind)
	if isClient && !clientBind.isConnect {
		clientBind = nil
	}
	publicKey := hex.EncodeToString(e.peers[0].publicKey[:])
	return peerfallback.New(peerfallback.Options{
		Logger:    e.options.Logger,
		Addresses: append([]netip.AddrPort{e.peers[0].endpoint}, e.options.PeerFallback...),
		Status:    e.peerStatus,
		Move: func(address netip.AddrPort) bool {
			if clientBind != nil {
				clientBind.moveTo(address)
			}
			if wgDevice := e.device.Load(); wgDevice != nil {
				if err := wgDevice.IpcSet("public_key=" + publicKey + "\nupdate_only=true\nendpoint=" + address.String()); err != nil {
					e.options.Logger.Error("set the peer's address: ", err)
				}
				if peer, loaded := wgDevice.LookupActivePeer(e.peers[0].publicKey); loaded {
					peer.ExpireCurrentKeypairs() // a handshake at once, not at the next retry in 5 seconds
					peer.SendHandshakeInitiation(false)
				}
			}
			return clientBind != nil
		},
	})
}

// pathChanged is called when the path to the peer may have changed: the fallback starts again
// from the peer's own address, and MTU discovery runs again.
func (e *Endpoint) pathChanged() {
	if e.fallback.PathChanged() {
		return // the bind dials the first address, which calls pathChanged again
	}
	e.mtuProbe.pathChanged()
}

// moveTo makes the bind send to address: the connection through the dialer is made again.
func (c *ClientBind) moveTo(address netip.AddrPort) {
	c.connAccess.Lock()
	c.connectAddr = address
	current := c.conn.Load()
	c.connAccess.Unlock()
	if current != nil {
		current.Close()
	}
}

func (e *Endpoint) peerStatus() (time.Time, uint64) {
	state, err := e.IpcGet()
	if err != nil {
		return time.Time{}, 0
	}
	return peerfallback.ParseStatus(state)
}
