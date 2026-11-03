//go:build with_masque

package warp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

// A masque:// link to WARP carries a device enrolled elsewhere: masque.device. The endpoint uses
// it before its saved devices and before registering one. When Cloudflare refuses it (its key was
// never enrolled, or the device was deleted), the endpoint remembers that in the cache file,
// takes a saved device or registers one as for any WARP config, and does not try the link's
// device again while the config carries it.

// refusedLinkDeviceSuffix is the cache key, after the unique_identifier, of the link device
// Cloudflare refused: the SHA-256 of its key.
const refusedLinkDeviceSuffix = "/refused-masque-device"

// validateMASQUEDevice fails a config whose link device cannot work: a key that does not parse,
// no address, no endpoint.
func validateMASQUEDevice(options *option.WARPEndpointOptions) error {
	if options.MASQUE == nil || options.MASQUE.Device == nil {
		return nil
	}
	if _, err := masque.DeviceConfig(options.MASQUE.Device); err != nil {
		return E.Cause(err, "warp masque.device")
	}
	return nil
}

// linkMASQUEProfile is the link's device as a profile, or nil when there is none or Cloudflare
// refused it. Like a WireGuard config written inline, it is never pooled nor retired.
func (w *WARPEndpoint) linkMASQUEProfile() *warpProfile {
	if w.options.MASQUE == nil || w.options.MASQUE.Device == nil || w.linkDeviceWasRefused() {
		return nil
	}
	device := w.options.MASQUE.Device
	config, err := masque.DeviceConfig(device)
	if err != nil { // checked when the config loaded
		return nil
	}
	content, err := json.Marshal(config)
	if err != nil {
		return nil
	}
	return &warpProfile{Kind: kindMASQUE, ID: device.ID, MASQUE: content, inline: true}
}

func (w *WARPEndpoint) linkDeviceKey() string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(w.options.MASQUE.Device.PrivateKey)))
	return hex.EncodeToString(sum[:])
}

func (w *WARPEndpoint) linkDeviceWasRefused() bool {
	if w.linkRefused.Load() {
		return true
	}
	cacheFile := service.FromContext[adapter.CacheFile](w.ctx)
	if cacheFile == nil || !cacheFile.StoreWARPConfig() {
		return false
	}
	saved := cacheFile.LoadBinary(w.uniqueID + refusedLinkDeviceSuffix)
	refused := saved != nil && string(saved.Content) == w.linkDeviceKey()
	w.linkRefused.Store(refused)
	return refused
}

// linkDeviceRefused is the tunnel's answer to Cloudflare refusing the link's device: remember it,
// and start again with a saved or a registered device. Once. The tunnel calls it from its connect,
// which closing the tunnel waits for, so the restart runs on its own.
func (w *WARPEndpoint) linkDeviceRefused(err error) {
	if w.rememberLinkDeviceRefused() {
		go w.restart("Cloudflare refused the link's MASQUE device (" + err.Error() + "), taking another device")
	}
}

// rememberLinkDeviceRefused marks the link's device refused, in the cache file too; false when it
// was already.
func (w *WARPEndpoint) rememberLinkDeviceRefused() bool {
	if !w.linkRefused.CompareAndSwap(false, true) {
		return false
	}
	if cacheFile := service.FromContext[adapter.CacheFile](w.ctx); cacheFile != nil && cacheFile.StoreWARPConfig() {
		if err := cacheFile.SaveBinary(w.uniqueID+refusedLinkDeviceSuffix, &adapter.SavedBinary{LastUpdated: time.Now(), Content: []byte(w.linkDeviceKey())}); err != nil {
			w.logger.WarnContext(w.ctx, "WARP: remember the refused link device: ", err)
		}
	}
	return true
}
