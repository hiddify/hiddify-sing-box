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
)

// masqueIncluded tells auto mode that MASQUE is in the build.
const masqueIncluded = true

// connectMASQUE runs a MASQUE tunnel to WARP with the device of profile as the inner endpoint.
// The tunnel looks up endpoints with the scanner and reconnects by itself.
func (w *WARPEndpoint) connectMASQUE(done <-chan struct{}, profile *warpProfile) {
	key := w.uniqueID + legacyMASQUESuffix // the scanner scores, apart from the WireGuard ones
	var config *masque.Config
	if err := json.Unmarshal(profile.MASQUE, &config); err != nil || config == nil {
		w.profiles.retire(profile, "unreadable MASQUE device")
		w.restart("the saved MASQUE device is unreadable")
		return
	}
	var peer M.Socksaddr
	if w.mode == modeMASQUE && (w.options.Server != "" || w.options.ServerPort != 0) { // in auto mode, server is the WireGuard peer
		peer = M.ParseSocksaddrHostPort(w.options.Server, w.options.ServerPort)
	}
	inner, err := masque.NewWARPOutbound(w.ctx, w.logger, w.tag, masqueOptions(w.options), config, peer, key)
	if err != nil {
		w.fail(err)
		return
	}
	if err = adapter.StartLate(w.scope, "outbound/masque["+w.tag+"]", inner); err != nil {
		w.fail(E.Cause(err, "start WARP MASQUE tunnel"))
		return
	}
	select {
	case <-done:
		adapter.CloseLate(w.scope, inner)
		return
	default:
	}
	w.mtx.Lock()
	w.endpoint = inner
	w.scanStatusOf = func() *warpscan.Status { return inner.ScanStatus() }
	w.mtx.Unlock()
}

// registerMASQUEProfile registers a WARP device with a MASQUE key.
func registerMASQUEProfile(ctx context.Context, profile *option.WARPProfile) (*warpProfile, error) {
	config, err := registerMASQUE(ctx, profile)
	if err != nil {
		return nil, err
	}
	content, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return &warpProfile{Kind: kindMASQUE, ID: config.ID, Token: config.AccessToken, MASQUE: content, Created: time.Now()}, nil
}

// probeMASQUE times a TLS handshake with the MASQUE endpoint of profile, for auto mode.
func (w *WARPEndpoint) probeMASQUE(ctx context.Context, profile *warpProfile) (time.Duration, error) {
	var config *masque.Config
	if err := json.Unmarshal(profile.MASQUE, &config); err != nil || config == nil {
		return 0, E.New("unreadable MASQUE device")
	}
	return masque.ProbeWARP(ctx, w.logger, masqueOptions(w.options), config, M.Socksaddr{})
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
	if options.MASQUE == nil { // auto mode without a masque block
		options.MASQUE = &option.WARPMASQUEOptions{}
	}
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
