//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

func hHybridGroups(spec *utls.ClientHelloSpec) (curves bool, keyShares bool, x25519 bool) {
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedCurvesExtension:
			for _, curve := range extension.Curves {
				curves = curves || curve == utls.X25519MLKEM768
			}
		case *utls.KeyShareExtension:
			for _, share := range extension.KeyShares {
				keyShares = keyShares || share.Group == utls.X25519MLKEM768
				x25519 = x25519 || share.Group == utls.X25519
			}
		}
	}
	return
}

func TestH_RealityKeyShare(t *testing.T) {
	for _, id := range []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto, utls.HelloSafari_Auto, utls.HelloEdge_Auto} {
		spec, err := realityClientHelloSpec(id, &utls.Config{ServerName: "example.com"}, false)
		require.NoError(t, err)
		curves, keyShares, x25519 := hHybridGroups(spec)
		require.True(t, curves && keyShares && x25519, id.Str())

		spec, err = realityClientHelloSpec(id, &utls.Config{ServerName: "example.com"}, true)
		require.NoError(t, err)
		curves, keyShares, x25519 = hHybridGroups(spec)
		require.False(t, curves || keyShares, "classical keeps no X25519MLKEM768: %s", id.Str())
		require.True(t, x25519, "the REALITY auth share stays: %s", id.Str())
	}
}

func TestH_RealityKeyShareOption(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	options := func(keyShare string) option.OutboundTLSOptions {
		return option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.com",
			UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
			Reality:    &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), KeyShare: keyShare},
		}
	}
	for _, keyShare := range []string{"", "hybrid", "classical"} {
		config, err := NewRealityClient(context.Background(), log.NewNOPFactory().Logger(), "example.com", options(keyShare))
		require.NoError(t, err, keyShare)
		require.Equal(t, keyShare == "classical", config.(*RealityClientConfig).Clone().(*RealityClientConfig).classical)
	}
	_, err = NewRealityClient(context.Background(), log.NewNOPFactory().Logger(), "example.com", options("classic"))
	require.ErrorContains(t, err, "unknown reality key_share")
}

// The classical ClientHello is that of an older version of the same browser, from before it sent a
// post-quantum key share, and fits in one TCP segment.
func TestH_RealityClassicalHelloIsOlderBrowser(t *testing.T) {
	require.Equal(t, utls.HelloChrome_120, realityClassicalHelloID(utls.HelloChrome_Auto))
	require.Equal(t, utls.HelloChrome_120, realityClassicalHelloID(utls.HelloEdge_Auto))
	require.Equal(t, utls.HelloFirefox_120, realityClassicalHelloID(utls.HelloFirefox_Auto))
	require.Equal(t, utls.HelloSafari_16_0, realityClassicalHelloID(utls.HelloSafari_Auto))
	require.Equal(t, utls.HelloSafari_16_0, realityClassicalHelloID(utls.HelloIOS_Auto))
	require.Equal(t, utls.HelloAndroid_11_OkHttp, realityClassicalHelloID(utls.HelloAndroid_11_OkHttp))
	for _, id := range []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto, utls.HelloSafari_Auto, utls.HelloIOS_Auto,
		utls.HelloEdge_Auto, utls.HelloAndroid_11_OkHttp, utls.Hello360_Auto, utls.HelloQQ_Auto, utls.HelloRandomized} {
		config := &utls.Config{ServerName: "www.example.com"}
		spec, err := realityClientHelloSpec(id, config, true)
		require.NoError(t, err, id.Str())
		uConn := utls.UClient(nil, config, utls.HelloCustom)
		require.NoError(t, uConn.ApplyPreset(spec), id.Str())
		require.NoError(t, uConn.BuildHandshakeState(), id.Str())
		require.Less(t, len(uConn.HandshakeState.Hello.Raw), 1200, "classical ClientHello of %s fits one segment", id.Str())
	}
}
