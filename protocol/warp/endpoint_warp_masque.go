//go:build with_masque

package warp

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// masqueKeySuffix keeps the MASQUE device and its scanner scores apart from the WireGuard ones
// of the same endpoint: enrolling a MASQUE key takes the device off WireGuard.
const masqueKeySuffix = "/masque"

// connectMASQUE registers the device, or loads the saved one, and runs a MASQUE tunnel to WARP
// as the inner endpoint. The tunnel looks up endpoints with the scanner and reconnects by itself.
func (w *WARPEndpoint) connectMASQUE() {
	key := w.uniqueID + masqueKeySuffix
	cacheFile := service.FromContext[adapter.CacheFile](w.ctx)
	store := cacheFile != nil && cacheFile.StoreWARPConfig()
	var config *masque.Config
	if !w.options.Profile.Recreate && store {
		if saved := cacheFile.LoadBinary(key); saved != nil {
			if err := json.Unmarshal(saved.Content, &config); err != nil {
				w.logger.ErrorContext(w.ctx, E.Cause(err, "load WARP MASQUE device"))
				config = nil
			}
		}
	}
	if config == nil {
		if !w.retry("register WARP MASQUE device", func() error {
			var err error
			config, err = registerMASQUE(w.ctx, &w.options.Profile)
			return err
		}) {
			return
		}
		if store {
			if content, err := json.Marshal(config); err != nil {
				w.logger.ErrorContext(w.ctx, err)
			} else {
				cacheFile.SaveBinary(key, &adapter.SavedBinary{LastUpdated: time.Now(), Content: content})
			}
		}
	}
	var peer M.Socksaddr
	if w.options.Server != "" || w.options.ServerPort != 0 {
		peer = M.ParseSocksaddrHostPort(w.options.Server, w.options.ServerPort)
	}
	inner, err := masque.NewWARPOutbound(w.ctx, w.logger, w.tag, masqueOptions(w.options), config, peer, key)
	if err != nil {
		w.logger.ErrorContext(w.ctx, err)
		return
	}
	if err = adapter.StartLate(w.scope, "outbound/masque["+w.tag+"]", inner); err != nil {
		w.logger.ErrorContext(w.ctx, E.Cause(err, "start WARP MASQUE tunnel"))
		return
	}
	select {
	case <-w.done:
		adapter.CloseLate(w.scope, inner)
		return
	default:
	}
	w.mtx.Lock()
	w.endpoint = inner
	w.scanStatusOf = func() *warpscan.Status { return inner.ScanStatus() }
	w.mtx.Unlock()
}

// registerMASQUE gives the device of profile, or a new one, a MASQUE key, reaching the API as
// the WireGuard registration does.
func registerMASQUE(ctx context.Context, profile *option.WARPProfile) (*masque.Config, error) {
	var config *masque.Config
	err := withWARPAPI(ctx, profile, func(dialer N.Dialer) error {
		api := cloudflare.NewCloudflareApiDetour(dialer)
		id, token := profile.ID, profile.AuthToken
		if id == "" || token == "" {
			device, err := api.CreateProfileLicense(ctx, profile.PrivateKey, profile.License)
			if err != nil {
				return err
			}
			id, token = device.ID, device.Token
		}
		var err error
		config, err = masque.EnrollWARP(ctx, api, token, id)
		return err
	})
	return config, err
}

// masqueOptions are the settings of the MASQUE tunnel, from the warp endpoint's.
func masqueOptions(options option.WARPEndpointOptions) option.MASQUEOutboundOptions {
	return option.MASQUEOutboundOptions{
		DialerOptions:            options.DialerOptions,
		MASQUEOutboundTLSOptions: options.MASQUE.TLS,
		UseIPv6:                  options.MASQUE.UseIPv6,
		UDPTimeout:               options.UDPTimeout,
		UDPKeepalivePeriod:       options.MASQUE.UDPKeepalivePeriod,
		UDPInitialPacketSize:     options.MASQUE.UDPInitialPacketSize,
		MTU:                      options.MTU,
		ReconnectDelay:           options.MASQUE.ReconnectDelay,
		Scanner:                  options.Scanner,
		VHTTP:                    options.MASQUE.VHTTP,
		ServerName:               options.MASQUE.ServerName,
	}
}
