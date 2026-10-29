package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

// masque:// links carry an enrolled device with its key in PKCS #8 and the endpoint's key as
// bare DER, both in URL base64; the outbound only registered a new device through the API.
func TestH_MASQUEDeviceWithoutAPI(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerDER, err := x509.MarshalPKIXPublicKey(&peer.PublicKey)
	require.NoError(t, err)

	options := option.MASQUEOutboundOptions{Device: &option.MASQUEDeviceOptions{
		PrivateKey:        base64.RawURLEncoding.EncodeToString(keyDER),
		EndpointPublicKey: base64.RawURLEncoding.EncodeToString(peerDER),
		IPv4:              "172.16.0.2",
		EndpointV4:        "162.159.198.60:443",
		EndpointV6:        "[2606:4700:103::2]:443",
	}}
	outbound, err := newWARPOutbound(context.Background(), log.NewNOPFactory().Logger(), "masque", options, nil, M.Socksaddr{}, "")
	require.NoError(t, err)
	config := outbound.warpConfig
	require.NotNil(t, config, "the device is used, not registered")

	privateKey, err := config.GetEcPrivateKey()
	require.NoError(t, err)
	require.True(t, privateKey.Equal(key))
	publicKey, err := config.GetEcEndpointPublicKey()
	require.NoError(t, err)
	require.True(t, publicKey.Equal(&peer.PublicKey))
	require.Equal(t, "162.159.198.60", config.EndpointV4)
	require.Equal(t, "2606:4700:103::2", config.EndpointV6)
	require.NotEmpty(t, config.EndpointH2V4, "Cloudflare's HTTP/2 endpoint by default")

	options.Device.PrivateKey = "bm90IGEga2V5"
	_, err = newWARPOutbound(context.Background(), log.NewNOPFactory().Logger(), "masque", options, nil, M.Socksaddr{}, "")
	require.Error(t, err, "a bad device fails the config")
}
