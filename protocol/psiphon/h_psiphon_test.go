package psiphon

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/secret"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestH_PsiphonBuildConfigDefaults(t *testing.T) {
	t.Parallel()
	config, err := buildConfig(option.PsiphonOutboundOptions{}, defaultEstablishTunnelTimeout)
	require.NoError(t, err)
	require.Equal(t, defaultDataDirectory, config.DataRootDirectory)
	require.Equal(t, defaultPropagationChannelID, config.PropagationChannelId)
	require.Equal(t, defaultSponsorID, config.SponsorId)
	require.Equal(t, defaultNetworkID, config.NetworkID)
	require.Equal(t, defaultClientPlatform, config.ClientPlatform)
	require.Equal(t, defaultRemoteServerListURL, config.RemoteServerListUrl)
	require.Equal(t, defaultRemoteServerListFilename, config.RemoteServerListDownloadFilename)
	require.Equal(t, defaultSignaturePublicKey, config.RemoteServerListSignaturePublicKey)
	require.True(t, config.AllowDefaultDNSResolverWithBindToDevice)
	require.True(t, config.DisableLocalHTTPProxy)
	require.True(t, config.DisableLocalSocksProxy)
	require.Empty(t, config.UpstreamProxyURL)
	require.Empty(t, config.EgressRegion)
	require.NotNil(t, config.EstablishTunnelTimeoutSeconds)
	require.Equal(t, 60, *config.EstablishTunnelTimeoutSeconds)
	require.Equal(t, defaultDataDirectory, config.MigrateDataStoreDirectory)
	require.Equal(t, defaultDataDirectory, config.MigrateObfuscatedServerListDownloadDirectory)
	require.Equal(t, filepath.Join(defaultDataDirectory, "server_list_compressed"), config.MigrateRemoteServerListDownloadFilename)
}

func TestH_PsiphonBuildConfigOverrides(t *testing.T) {
	t.Parallel()
	allow := false
	options := option.PsiphonOutboundOptions{
		DataDirectory:                           "/tmp/psi",
		EgressRegion:                            "DE",
		PropagationChannelID:                    "PC",
		SponsorID:                               "SP",
		NetworkID:                               "NET",
		ClientPlatform:                          "iOS",
		ClientVersion:                           "42",
		RemoteServerListURL:                     "https://example.invalid/list",
		RemoteServerListDownloadFilename:        "rsl",
		RemoteServerListSignaturePublicKey:      "KEY",
		UpstreamProxyURL:                        "socks5://127.0.0.1:1080",
		AllowDefaultDNSResolverWithBindToDevice: &allow,
	}
	config, err := buildConfig(options, 90*time.Second)
	require.NoError(t, err)
	require.Equal(t, "/tmp/psi", config.DataRootDirectory)
	require.Equal(t, "DE", config.EgressRegion)
	require.Equal(t, "PC", config.PropagationChannelId)
	require.Equal(t, "SP", config.SponsorId)
	require.Equal(t, "NET", config.NetworkID)
	require.Equal(t, "iOS", config.ClientPlatform)
	require.Equal(t, "42", config.ClientVersion)
	require.Equal(t, "https://example.invalid/list", config.RemoteServerListUrl)
	require.Equal(t, "rsl", config.RemoteServerListDownloadFilename)
	require.Equal(t, "KEY", config.RemoteServerListSignaturePublicKey)
	require.Equal(t, "socks5://127.0.0.1:1080", config.UpstreamProxyURL)
	require.False(t, config.AllowDefaultDNSResolverWithBindToDevice)
	require.Equal(t, 90, *config.EstablishTunnelTimeoutSeconds)
	require.Equal(t, "/tmp/psi", config.MigrateDataStoreDirectory)
	require.Equal(t, filepath.Join("/tmp/psi", "server_list_compressed"), config.MigrateRemoteServerListDownloadFilename)
}

func TestH_PsiphonDurationToSeconds(t *testing.T) {
	t.Parallel()
	require.Equal(t, 1, *durationToSecondsPtr(0))
	require.Equal(t, 1, *durationToSecondsPtr(-time.Second))
	require.Equal(t, 1, *durationToSecondsPtr(500 * time.Millisecond))
	require.Equal(t, 2, *durationToSecondsPtr(2900 * time.Millisecond))
	require.Equal(t, 300, *durationToSecondsPtr(5 * time.Minute))
}

func newTestOutbound(t *testing.T, options option.PsiphonOutboundOptions) *Outbound {
	out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "psiphon-out", options)
	require.NoError(t, err)
	return out.(*Outbound)
}

func TestH_PsiphonOutboundBeforeStart(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, option.PsiphonOutboundOptions{EstablishTunnelTimeout: badoption.Duration(10 * time.Second)})
	require.Equal(t, C.TypePsiphon, out.Type())
	require.Equal(t, []string{N.NetworkTCP}, out.Network())
	require.Equal(t, 10, *out.psiphon.config.EstablishTunnelTimeoutSeconds)
	require.False(t, out.IsReady())
	require.Equal(t, "connecting...", out.psiphon.State())
	require.Contains(t, out.DisplayType(), "Connecting")

	_, err := out.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:443"))
	require.ErrorContains(t, err, "controller not initialized")
	_, err = out.DialContext(context.Background(), N.NetworkUDP, M.ParseSocksaddr("1.1.1.1:53"))
	require.ErrorContains(t, err, "UDP is not supported")
	_, err = out.DialContext(context.Background(), "icmp", M.ParseSocksaddr("1.1.1.1:0"))
	require.ErrorIs(t, err, N.ErrUnknownNetwork)
	_, err = out.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	require.ErrorContains(t, err, "UDP is not supported")

	out.requestReconnect()
	out.requestReconnect()
	require.Len(t, out.reconnectCh, 1)
}

func TestH_PsiphonDefaultTimeout(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, option.PsiphonOutboundOptions{})
	require.Equal(t, int(defaultEstablishTunnelTimeout/time.Second), *out.psiphon.config.EstablishTunnelTimeoutSeconds)
}

func TestH_PsiphonCloseBeforeStart(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, option.PsiphonOutboundOptions{})
	require.NotPanics(t, func() { _ = out.Close() })
}

func TestH_PsiphonInterfaceUpdatedBeforeStart(t *testing.T) {
	t.Parallel()
	out := newTestOutbound(t, option.PsiphonOutboundOptions{})
	require.NotPanics(t, func() { out.InterfaceUpdated(context.Background()) })
}

// an example config
const hTestPartnerConfig = `{
	"PropagationChannelId": "AAAAAAAAAAAAAAAA",
	"SponsorId": "BBBBBBBBBBBBBBBB",
	"TargetApiProtocol": "ssh",
	"EstablishTunnelTimeoutSeconds": 0,
	"ServerEntrySignaturePublicKey": "server-entry-key",
	"RemoteServerListSignaturePublicKey": "remote-list-key",
	"AdditionalParameters": "encrypted-parameters"
}`

func TestH_PsiphonBuildConfigFromPartnerConfig(t *testing.T) {
	t.Parallel()
	config, err := buildConfig(option.PsiphonOutboundOptions{Config: base64.StdEncoding.EncodeToString([]byte(hTestPartnerConfig))}, 90*time.Second)
	require.NoError(t, err)
	require.Equal(t, "AAAAAAAAAAAAAAAA", config.PropagationChannelId)
	require.Equal(t, "BBBBBBBBBBBBBBBB", config.SponsorId)
	require.Equal(t, "ssh", config.TargetAPIProtocol)
	require.Equal(t, "server-entry-key", config.ServerEntrySignaturePublicKey)
	require.Equal(t, "remote-list-key", config.RemoteServerListSignaturePublicKey)
	require.Equal(t, "encrypted-parameters", config.AdditionalParameters)
	// unset values still get the defaults; managed values are not taken from the config
	require.Equal(t, defaultRemoteServerListURL, config.RemoteServerListUrl)
	require.Equal(t, defaultDataDirectory, config.DataRootDirectory)
	require.Equal(t, 90, *config.EstablishTunnelTimeoutSeconds, "a 0 (forever) timeout must not hang the outbound")
	require.True(t, config.DisableLocalHTTPProxy)
	require.True(t, config.DisableLocalSocksProxy)
}

func TestH_PsiphonExplicitOptionsOverridePartnerConfig(t *testing.T) {
	t.Parallel()
	config, err := buildConfig(option.PsiphonOutboundOptions{
		Config:       base64.StdEncoding.EncodeToString([]byte(hTestPartnerConfig)),
		SponsorID:    "CCCCCCCCCCCCCCCC",
		EgressRegion: "DE",
	}, defaultEstablishTunnelTimeout)
	require.NoError(t, err)
	require.Equal(t, "CCCCCCCCCCCCCCCC", config.SponsorId)
	require.Equal(t, "AAAAAAAAAAAAAAAA", config.PropagationChannelId)
	require.Equal(t, "DE", config.EgressRegion)
}

func TestH_PsiphonBuildConfigBase64Variants(t *testing.T) {
	t.Parallel()
	// URL-safe without padding, surrounded by whitespace
	encoded := "  " + base64.RawURLEncoding.EncodeToString([]byte(hTestPartnerConfig)) + "\n"
	config, err := buildConfig(option.PsiphonOutboundOptions{Config: encoded}, defaultEstablishTunnelTimeout)
	require.NoError(t, err)
	require.Equal(t, "BBBBBBBBBBBBBBBB", config.SponsorId)

	_, err = buildConfig(option.PsiphonOutboundOptions{Config: "not base64!"}, defaultEstablishTunnelTimeout)
	require.ErrorContains(t, err, "decode psiphon config")
	_, err = buildConfig(option.PsiphonOutboundOptions{Config: base64.StdEncoding.EncodeToString([]byte("{not json"))}, defaultEstablishTunnelTimeout)
	require.ErrorContains(t, err, "parse psiphon config")
}

// embedded config and key are package-level build-time values: these tests must not run in parallel
func hWithEmbedded(t *testing.T, key, config string) {
	oldKey, oldConfig := secret.Key, embeddedHiddifyConfig
	secret.Key, embeddedHiddifyConfig = key, config
	t.Cleanup(func() { secret.Key, embeddedHiddifyConfig = oldKey, oldConfig })
}

func hTestKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestH_PsiphonEncryptedConfig(t *testing.T) {
	key := hTestKey(t)
	hWithEmbedded(t, key, "")
	encrypted, err := secret.Encrypt(key, []byte(hTestPartnerConfig))
	require.NoError(t, err)

	config, err := buildConfig(option.PsiphonOutboundOptions{Config: encrypted}, defaultEstablishTunnelTimeout)
	require.NoError(t, err)
	require.Equal(t, "BBBBBBBBBBBBBBBB", config.SponsorId)
	require.Equal(t, "encrypted-parameters", config.AdditionalParameters)
}

func TestH_PsiphonHiddifyConfig(t *testing.T) {
	key := hTestKey(t)
	encrypted, err := secret.Encrypt(key, []byte(hTestPartnerConfig))
	require.NoError(t, err)
	hWithEmbedded(t, key, encrypted)

	config, err := buildConfig(option.PsiphonOutboundOptions{Config: "hiddify", EgressRegion: "DE"}, defaultEstablishTunnelTimeout)
	require.NoError(t, err)
	require.Equal(t, "BBBBBBBBBBBBBBBB", config.SponsorId, "config hiddify uses the embedded config")
	require.Equal(t, "DE", config.EgressRegion)
}

func TestH_PsiphonHiddifyConfigNotEmbedded(t *testing.T) {
	hWithEmbedded(t, "", "")
	config, err := buildConfig(option.PsiphonOutboundOptions{Config: "hiddify"}, defaultEstablishTunnelTimeout)
	require.NoError(t, err, "builds without the secret fall back to the defaults")
	require.Equal(t, defaultSponsorID, config.SponsorId)
}

func TestH_PsiphonEncryptedConfigWrongKey(t *testing.T) {
	encrypted, err := secret.Encrypt(hTestKey(t), []byte(hTestPartnerConfig))
	require.NoError(t, err)
	other := make([]byte, 32)
	hWithEmbedded(t, base64.StdEncoding.EncodeToString(other), "")
	// not decryptable with this build's key: treated as plain base64, which is not a JSON config
	_, err = buildConfig(option.PsiphonOutboundOptions{Config: encrypted}, defaultEstablishTunnelTimeout)
	require.ErrorContains(t, err, "parse psiphon config")
}
