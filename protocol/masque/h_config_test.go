package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/sagernet/sing-box/adapter/htest"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func hECKeys(t *testing.T) (*ecdsa.PrivateKey, string, string) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return privateKey, base64.StdEncoding.EncodeToString(privateDER), string(publicPEM)
}

func TestH_ConfigKeys(t *testing.T) {
	privateKey, privateB64, publicPEM := hECKeys(t)
	config := &Config{PrivateKey: privateB64, EndpointPubKey: publicPEM}
	parsedPrivate, err := config.GetEcPrivateKey()
	require.NoError(t, err)
	require.True(t, privateKey.Equal(parsedPrivate))
	parsedPublic, err := config.GetEcEndpointPublicKey()
	require.NoError(t, err)
	require.True(t, privateKey.PublicKey.Equal(parsedPublic))

	_, err = (&Config{PrivateKey: "!!"}).GetEcPrivateKey()
	require.ErrorContains(t, err, "failed to decode private key")
	_, err = (&Config{PrivateKey: base64.StdEncoding.EncodeToString([]byte("junk"))}).GetEcPrivateKey()
	require.ErrorContains(t, err, "failed to parse private key")

	_, err = (&Config{EndpointPubKey: "not pem"}).GetEcEndpointPublicKey()
	require.ErrorContains(t, err, "failed to decode endpoint public key")
	_, err = (&Config{EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")}))}).GetEcEndpointPublicKey()
	require.ErrorContains(t, err, "failed to parse public key")
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKIXPublicKey(edPublic)
	require.NoError(t, err)
	_, err = (&Config{EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDER}))}).GetEcEndpointPublicKey()
	require.ErrorContains(t, err, "failed to assert public key as ECDSA")
}

func TestH_ConfigSelectEndpoint(t *testing.T) {
	config := &Config{
		EndpointV4:   "162.159.198.1",
		EndpointV6:   "2606:4700:103::1",
		EndpointH2V4: "162.159.198.2",
		EndpointH2V6: "2606:4700:103::2",
	}
	for _, testCase := range []struct {
		http2, ipv6 bool
		expected    string
	}{
		{false, false, "udp 162.159.198.1:443"},
		{false, true, "udp [2606:4700:103::1]:443"},
		{true, false, "tcp 162.159.198.2:443"},
		{true, true, "tcp [2606:4700:103::2]:443"},
	} {
		addr, err := config.SelectEndpointFromConfig(testCase.http2, testCase.ipv6, 443)
		require.NoError(t, err)
		require.Equal(t, testCase.expected, addr.Network()+" "+addr.String())
	}

	_, err := (&Config{}).SelectEndpointFromConfig(true, true, 443)
	require.ErrorContains(t, err, "requires config endpoint_h2_v6")
	_, err = (&Config{EndpointH2V6: "bad"}).SelectEndpointFromConfig(true, true, 443)
	require.ErrorContains(t, err, "invalid endpoint_h2_v6")
	_, err = (&Config{EndpointH2V4: "bad"}).SelectEndpointFromConfig(true, false, 443)
	require.ErrorContains(t, err, "invalid endpoint_h2_v4")
	_, err = (&Config{}).SelectEndpointFromConfig(false, true, 443)
	require.ErrorContains(t, err, "invalid endpoint_v6")
	_, err = (&Config{EndpointV4: "1.2.3"}).SelectEndpointFromConfig(false, false, 443)
	require.ErrorContains(t, err, "invalid endpoint_v4")
}

func TestH_ConfigJSONRoundTrip(t *testing.T) {
	config := Config{PrivateKey: "pk", EndpointV4: "1.1.1.1", EndpointV6: "::1", EndpointH2V4: "2.2.2.2", EndpointPubKey: "pem", License: "lic", ID: "id", AccessToken: "tok", IPv4: "172.16.0.2", IPv6: "fd00::2"}
	content, err := json.Marshal(config)
	require.NoError(t, err)
	var fields map[string]string
	require.NoError(t, json.Unmarshal(content, &fields))
	require.Equal(t, "2.2.2.2", fields["endpoint_h2_v4"])
	require.Equal(t, "tok", fields["access_token"])
	var decoded Config
	require.NoError(t, json.Unmarshal(content, &decoded))
	require.Equal(t, config, decoded)
}

type hErrorLogger struct {
	log.ContextLogger
	access sync.Mutex
	errors []string
}

func (l *hErrorLogger) ErrorContext(ctx context.Context, args ...any) {
	l.access.Lock()
	l.errors = append(l.errors, fmt.Sprint(args...))
	l.access.Unlock()
}

func (l *hErrorLogger) logged() []string {
	l.access.Lock()
	defer l.access.Unlock()
	return append([]string(nil), l.errors...)
}

func hNewOutbound(t *testing.T, ctx context.Context, logger log.ContextLogger, options option.MASQUEOutboundOptions) *Outbound {
	created, err := NewOutbound(ctx, nil, logger, "masque-out", options)
	require.NoError(t, err)
	return created.(*Outbound)
}

// hConfigOutbound is an outbound with the device config, as the warp endpoint creates it.
func hConfigOutbound(t *testing.T, ctx context.Context, logger log.ContextLogger, options option.MASQUEOutboundOptions, config Config) *Outbound {
	out, err := newWARPOutbound(ctx, logger, "masque-out", options, &config, M.Socksaddr{}, "")
	require.NoError(t, err)
	return out
}

// hDevice is a device of a masque:// link, with a new key.
func hDevice(t *testing.T) *option.MASQUEDeviceOptions {
	_, privateB64, _ := hECKeys(t)
	return &option.MASQUEDeviceOptions{PrivateKey: privateB64, IPv4: "172.16.0.2", EndpointV4: "127.0.0.1"}
}

func TestH_OutboundStartHandlerFailureModes(t *testing.T) {
	_, privateB64, publicPEM := hECKeys(t)
	valid := Config{PrivateKey: privateB64, EndpointPubKey: publicPEM, EndpointV4: "127.0.0.1", EndpointV6: "::1", IPv4: "172.16.0.2", IPv6: "fd00::2"}
	for _, testCase := range []struct {
		name     string
		mutate   func(config *Config, options *option.MASQUEOutboundOptions)
		expected string
	}{
		{"private key", func(c *Config, o *option.MASQUEOutboundOptions) { c.PrivateKey = "!!" }, "failed to get private key"},
		{"public key", func(c *Config, o *option.MASQUEOutboundOptions) { c.EndpointPubKey = "" }, "failed to get public key"},
		{"endpoint", func(c *Config, o *option.MASQUEOutboundOptions) { c.EndpointV4 = "" }, "failed to select endpoint"},
		{"h2 v6 endpoint", func(c *Config, o *option.MASQUEOutboundOptions) { o.UseHTTP2, o.UseIPv6 = true, true }, "requires config endpoint_h2_v6"},
		{"dialer", func(c *Config, o *option.MASQUEOutboundOptions) { o.Detour = "missing" }, "missing outbound manager"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := valid
			var options option.MASQUEOutboundOptions
			testCase.mutate(&config, &options)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			logger := &hErrorLogger{ContextLogger: log.NewNOPFactory().NewLogger("masque")}
			out := hConfigOutbound(t, ctx, logger, options, config)
			require.NoError(t, htest.Start(out, adapter.StartStatePostStart))
			_, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:80"))
			require.ErrorContains(t, err, "tunnel not initialized")
			logged := logger.logged()
			require.Len(t, logged, 1)
			require.Contains(t, logged[0], testCase.expected)
		})
	}
}

// A masque outbound does not register WARP devices: without a device it fails the config, and
// says to use the warp endpoint.
func TestH_OutboundNeedsADevice(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().NewLogger("masque"), "masque-out", option.MASQUEOutboundOptions{
		Profile: option.CloudflareProfile{Detour: "direct"},
	})
	require.ErrorIs(t, err, errNoDevice)
	require.ErrorContains(t, err, "warp endpoint with mode masque")
}

func TestH_OutboundWaitsForStartup(t *testing.T) {
	out := hNewOutbound(t, context.Background(), log.NewNOPFactory().NewLogger("masque"), option.MASQUEOutboundOptions{Device: hDevice(t)})
	require.Equal(t, C.TypeMASQUE, out.Type())
	require.Equal(t, "masque-out", out.Tag())
	require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, out.Network())
	require.NoError(t, htest.Start(out, adapter.StartStateStart), "only post-start triggers the handler")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:80"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	_, _, err = out.ListenPacketWithDestination(ctx, M.ParseSocksaddr("1.1.1.1:53"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestH_RegisterOutbound(t *testing.T) {
	registry := outbound.NewRegistry()
	RegisterOutbound(registry)
	options, loaded := registry.CreateOptions(C.TypeMASQUE)
	require.True(t, loaded)
	require.IsType(t, &option.MASQUEOutboundOptions{}, options)
}

// unique_identifier names the scanner scores, so renaming the outbound keeps them
func TestH_OutboundUniqueIdentifier(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("masque")
	out := hNewOutbound(t, context.Background(), logger, option.MASQUEOutboundOptions{UniqueIdentifier: "device-1", Device: hDevice(t)})
	require.Equal(t, "device-1", out.profileKey)
	out = hNewOutbound(t, context.Background(), logger, option.MASQUEOutboundOptions{Device: hDevice(t)})
	require.Equal(t, "masque-out", out.profileKey, "the tag without one")
}

// The warp endpoint is told when Cloudflare refuses the device, to take another one; the outbound
// itself registers none.
func TestH_OutboundPassesRejectionOn(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("masque")
	out := hNewOutbound(t, context.Background(), logger, option.MASQUEOutboundOptions{Device: hDevice(t)})
	var refused error
	out.SetOnRejected(func(err error) { refused = err })
	out.onRejected(E.New("403"))
	require.EqualError(t, refused, "403")
}
