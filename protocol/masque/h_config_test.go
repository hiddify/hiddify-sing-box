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
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
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

type hMASQUECache struct {
	adapter.CacheFile
	store map[string]*adapter.SavedBinary
	loads []string
}

func (c *hMASQUECache) StoreMASQUEConfig() bool { return true }

func (c *hMASQUECache) LoadBinary(tag string) *adapter.SavedBinary {
	c.loads = append(c.loads, tag)
	return c.store[tag]
}

func hNewOutbound(t *testing.T, ctx context.Context, logger log.ContextLogger, options option.MASQUEOutboundOptions) *Outbound {
	created, err := NewOutbound(ctx, nil, logger, "masque-out", options)
	require.NoError(t, err)
	return created.(*Outbound)
}

func hCachedContext(t *testing.T, config Config) (context.Context, *hMASQUECache) {
	content, err := json.Marshal(config)
	require.NoError(t, err)
	cache := &hMASQUECache{store: map[string]*adapter.SavedBinary{"masque-out": {Content: content}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return service.ContextWith[adapter.CacheFile](ctx, cache), cache
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
			ctx, cache := hCachedContext(t, config)
			logger := &hErrorLogger{ContextLogger: log.NewNOPFactory().NewLogger("masque")}
			out := hNewOutbound(t, ctx, logger, options)
			require.NoError(t, out.Start(adapter.StartStatePostStart))
			_, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:80"))
			require.ErrorContains(t, err, "tunnel not initialized")
			require.Equal(t, []string{"masque-out"}, cache.loads)
			logged := logger.logged()
			require.Len(t, logged, 1)
			require.Contains(t, logged[0], testCase.expected)
		})
	}
}

func TestH_OutboundMalformedCache(t *testing.T) {
	cache := &hMASQUECache{store: map[string]*adapter.SavedBinary{"masque-out": {Content: []byte("{")}}}
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cache)
	logger := &hErrorLogger{ContextLogger: log.NewNOPFactory().NewLogger("masque")}
	out := hNewOutbound(t, ctx, logger, option.MASQUEOutboundOptions{})
	out.startHandler()
	require.Len(t, logger.logged(), 1)
	_, err := out.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	require.ErrorContains(t, err, "tunnel not initialized")
	require.ErrorContains(t, out.Close(), "tunnel not initialized")
}

func TestH_OutboundWaitsForStartup(t *testing.T) {
	out := hNewOutbound(t, context.Background(), log.NewNOPFactory().NewLogger("masque"), option.MASQUEOutboundOptions{})
	require.Equal(t, C.TypeMASQUE, out.Type())
	require.Equal(t, "masque-out", out.Tag())
	require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, out.Network())
	require.NoError(t, out.Start(adapter.StartStateStart), "only post-start triggers the handler")
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
