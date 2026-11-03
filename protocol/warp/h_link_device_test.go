//go:build with_masque

package warp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func hLinkDevice(t *testing.T) *option.MASQUEDeviceOptions {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return &option.MASQUEDeviceOptions{PrivateKey: base64.StdEncoding.EncodeToString(der), IPv4: "172.16.0.2", EndpointV6: "[2606:4700:103::2]:443", ID: "link-device"}
}

func hLinkOptions(device *option.MASQUEDeviceOptions) option.WARPEndpointOptions {
	return option.WARPEndpointOptions{UniqueIdentifier: "link", Mode: "masque", MASQUE: &option.WARPMASQUEOptions{Device: device}}
}

// A link device that cannot work fails the config, as a masque outbound's does.
func TestH_WARPLinkDeviceIsChecked(t *testing.T) {
	_, err := NewWARPEndpoint(hTestContext(t), nil, hLogger(), "warp-tag", hLinkOptions(&option.MASQUEDeviceOptions{PrivateKey: "junk", IPv4: "172.16.0.2"}))
	require.ErrorContains(t, err, "warp masque.device")
}

// A masque:// link's device is used first, before the saved devices and registering; once
// Cloudflare refuses it, a saved device is taken, and the link's is not tried again while the
// config carries it, also after a restart of the app.
func TestH_WARPLinkDeviceThenPool(t *testing.T) {
	cache := &hFakeCacheFile{store: map[string]*adapter.SavedBinary{}}
	ctx := service.ContextWith[adapter.CacheFile](hShortContext(t), cache)
	device := hLinkDevice(t)
	ep := hNewWARP(t, ctx, hLinkOptions(device))
	done := make(chan struct{})
	defer close(done)

	profile := ep.obtainProfile(done, kindMASQUE)
	require.NotNil(t, profile)
	require.True(t, profile.inline, "the link's device, never pooled")
	require.Equal(t, "link-device", profile.ID)
	var config struct {
		PrivateKey string `json:"private_key"`
	}
	require.NoError(t, json.Unmarshal(profile.MASQUE, &config))
	require.NotEmpty(t, config.PrivateKey)

	pooled, err := json.Marshal(map[string]string{"private_key": config.PrivateKey, "ipv4": "172.16.0.3"})
	require.NoError(t, err)
	ep.profiles.add(&warpProfile{Kind: kindMASQUE, ID: "pooled", Token: "token", MASQUE: pooled})

	require.True(t, ep.rememberLinkDeviceRefused())
	require.False(t, ep.rememberLinkDeviceRefused(), "once")
	profile = ep.obtainProfile(done, kindMASQUE)
	require.NotNil(t, profile)
	require.Equal(t, "pooled", profile.ID, "a saved device after the refusal")

	again := hNewWARP(t, ctx, hLinkOptions(device))
	require.Nil(t, again.linkMASQUEProfile(), "remembered in the cache file")
	other := hNewWARP(t, ctx, hLinkOptions(hLinkDevice(t)))
	require.NotNil(t, other.linkMASQUEProfile(), "a link with another device is tried")
}
