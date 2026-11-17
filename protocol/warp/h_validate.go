package warp

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// A WireGuard or AmneziaWG device is checked where it comes in, not where it is used.
//
// A device config that cannot run a tunnel (no peer, no address for the tunnel, no key) was only
// found by the code that built the inner endpoint, on every try: an incomplete answer of the
// WARP API was saved to the pool and handed out again at each start, and the start retried
// "start WARP endpoint" for good, shown as searching. Now:
//   - the profile written in the config is checked when the endpoint is made: an incomplete one
//     is not used, see inlineWARPProfile;
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

// inlineWARPProfile is the profile written in the config (private_key, interface, peers) when
// it can run a tunnel. It is nil when the config has none, and when the one it has is
// incomplete: the endpoint then says what is missing and goes on as an endpoint without a
// profile does, with a saved device of the pool or a new registration.
//
// An incomplete profile is not an error of the config. It was one for a while, and stopped the
// whole config for one WARP entry: hiddify-core makes this profile from a WireGuard config to
// WARP, with what that config has.
func inlineWARPProfile(ctx context.Context, logger log.ContextLogger, mode string, options *option.WARPEndpointOptions) *C.WARPConfig {
	config := options.WARPConfig
	if mode == modeMASQUE || !writtenWARPProfile(config) { // MASQUE runs on masque.device, not on this profile
		return config
	}
	if err := validateWARPConfig(config, options.ServerOptions); err != nil {
		logger.WarnContext(ctx, "WARP: the profile in the config is incomplete and is not used (", err, "): a saved device is taken, or a new one is registered")
		return nil
	}
	return config
}

// writtenWARPProfile reports whether the config carries any part of a profile.
func writtenWARPProfile(config *C.WARPConfig) bool {
	return config != nil && (config.PrivateKey != "" || len(config.Peers) > 0 ||
		config.Interface.Addresses.V4 != "" || config.Interface.Addresses.V6 != "")
}
