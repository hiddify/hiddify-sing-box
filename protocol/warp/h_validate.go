package warp

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// A WireGuard or AmneziaWG device is checked where it comes in, not where it is used.
//
// A device config that cannot run a tunnel (no peer, no address for the tunnel, no key) was only
// found by the code that built the inner endpoint, on every try: an incomplete answer of the
// WARP API was saved to the pool and handed out again at each start, and the start retried
// "start WARP endpoint" for good, shown as searching. Now:
//   - the profile written in the config is checked when the config loads;
//   - a device the API returned is checked before it is saved: an incomplete one ends the start
//     as failed, with the reason, and is not kept;
//   - a saved device that is incomplete is retired when the pool hands out devices.

// invalidDeviceError says a device cannot run a tunnel as it is: trying again does not help.
type invalidDeviceError struct{ error }

func (e invalidDeviceError) Unwrap() error { return e.error }

// validateWARPDevice reports why config cannot run a tunnel on any endpoint: nil when it can.
func validateWARPDevice(config *C.WARPConfig) error {
	switch {
	case config == nil:
		return invalidDeviceError{E.New("WARP config is missing")}
	case config.PrivateKey == "":
		return invalidDeviceError{E.New("WARP config has no private key")}
	case len(config.Peers) == 0:
		return invalidDeviceError{E.New("WARP config has no peers")}
	case config.Peers[0].PublicKey == "":
		return invalidDeviceError{E.New("WARP config has no peer public key")}
	}
	if _, err := warpInterfaceAddresses(config); err != nil {
		return invalidDeviceError{err}
	}
	return nil
}

// validateWARPConfig reports why config cannot run a tunnel on an endpoint with server: the
// device itself, and a peer address and port, from the device or from server and server_port.
func validateWARPConfig(config *C.WARPConfig, server option.ServerOptions) error {
	if err := validateWARPDevice(config); err != nil {
		return err
	}
	if _, _, err := warpPeerEndpoint(config, server); err != nil {
		return invalidDeviceError{err}
	}
	return nil
}
