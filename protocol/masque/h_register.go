package masque

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

// A device from a masque:// link is used as it is, with no call to Cloudflare's API. When
// Cloudflare refuses it (its key was never enrolled, or the device was deleted), a link to
// WARP is still a WARP config: the outbound then registers a device the way the profile does,
// saves it in the cache file as the link device's replacement, and runs the tunnel with it. A
// later start takes the replacement first, as long as the link still carries the device it
// replaced; a link with another device is tried again. A replacement Cloudflare refuses in its
// turn is replaced after rejectRegisterMin, doubling each time up to rejectRegisterMax, so a
// refusal that is not the device's fault does not register devices without end.

const (
	rejectRegisterMin = time.Minute
	rejectRegisterMax = 30 * time.Minute
)

// warpPrefixes are the address ranges of Cloudflare's WARP endpoints: WireGuard, and MASQUE for
// WARP, WARP+ and Zero Trust accounts.
var warpPrefixes = []netip.Prefix{
	netip.MustParsePrefix("162.159.192.0/24"),
	netip.MustParsePrefix("162.159.193.0/24"),
	netip.MustParsePrefix("162.159.195.0/24"),
	netip.MustParsePrefix("162.159.197.0/24"),
	netip.MustParsePrefix("162.159.198.0/24"),
	netip.MustParsePrefix("162.159.199.0/24"),
	netip.MustParsePrefix("188.114.96.0/22"),
	netip.MustParsePrefix("2606:4700:102::/48"),
	netip.MustParsePrefix("2606:4700:103::/48"),
	netip.MustParsePrefix("2606:4700:104::/48"),
}

// isWARPDevice reports a device config that points at Cloudflare's WARP: an endpoint in WARP's
// ranges, or the tunnel's server name being Cloudflare's (the default when empty). Only such a
// device can be replaced by registering one.
func isWARPDevice(config *Config, serverName string) bool {
	if serverName == "" || strings.HasSuffix(strings.ToLower(serverName), ".cloudflareclient.com") {
		return true
	}
	for _, endpoint := range []string{config.EndpointV4, config.EndpointV6, config.EndpointH2V4, config.EndpointH2V6} {
		if endpoint == "" {
			continue
		}
		addr, err := netip.ParseAddr(endpoint)
		if err != nil {
			continue
		}
		for _, prefix := range warpPrefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// registersOnRejection reports an outbound whose device, from a link, is replaced by a
// registered one when Cloudflare refuses it.
func (w *Outbound) registersOnRejection() bool {
	return w.options.Device != nil && w.warpConfig != nil && isWARPDevice(w.warpConfig, w.options.ServerName)
}

// replacementFor is the registered device saved in the cache file as the replacement of the
// link's device, or nil when there is none or it replaced another device.
func (w *Outbound) replacementFor(device *Config) *Config {
	cacheFile := service.FromContext[adapter.CacheFile](w.ctx)
	if w.options.Profile.Recreate || cacheFile == nil || !cacheFile.StoreMASQUEConfig() {
		return nil
	}
	saved := cacheFile.LoadBinary(w.profileKey)
	if saved == nil {
		return nil
	}
	var replacement *Config
	if err := json.Unmarshal(saved.Content, &replacement); err != nil || replacement == nil {
		return nil
	}
	if replacement.ReplacedDevice != device.PrivateKey {
		return nil
	}
	return replacement
}

// deviceRejected is the tunnel's answer to a device Cloudflare refused: register another one, in
// its own goroutine, and run the tunnel with it. One registration at a time, and after the
// first one not more often than the backoff allows.
func (w *Outbound) deviceRejected(err error) {
	if !w.rejected.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer w.rejected.Store(false)
		w.registerAccess.Lock()
		wait := w.registerWait
		tooSoon := !w.lastRegistered.IsZero() && time.Since(w.lastRegistered) < wait
		w.registerAccess.Unlock()
		if tooSoon || w.isClosed() {
			return
		}
		w.logger.WarnContext(w.ctx, "WARP refused the device: ", err, "; registering a new one")
		w.recreate.Store(true) // not the saved replacement: that is the one refused, or none
		replacement, ok := w.register()
		if !ok {
			return
		}
		w.registerAccess.Lock()
		w.lastRegistered = time.Now()
		if wait == 0 {
			w.registerWait = rejectRegisterMin
		} else {
			w.registerWait = min(2*wait, rejectRegisterMax)
		}
		w.registerAccess.Unlock()
		w.restart(replacement)
	}()
}

// replaceTunnel closes the tunnel and starts one with config.
func (w *Outbound) replaceTunnel(config *Config) {
	w.closeTunnel()
	if w.isClosed() {
		return
	}
	if err := w.startTunnel(config); err != nil {
		w.logger.ErrorContext(w.ctx, err)
	}
	if w.isClosed() { // closed while the tunnel was set up
		w.closeTunnel()
	}
}
