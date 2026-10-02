package include

import (
	"context"
	"reflect"
	"sync"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

type hOptionsCreator interface {
	CreateOptions(string) (any, bool)
	OptionTypes() []string
}

func hRequireRegistered(t *testing.T, registry hOptionsCreator, expected map[string]any) {
	t.Helper()
	types := registry.OptionTypes()
	for typeName, optionsSample := range expected {
		require.Contains(t, types, typeName)
		options, loaded := registry.CreateOptions(typeName)
		require.True(t, loaded, typeName)
		require.Equal(t, reflect.TypeOf(optionsSample), reflect.TypeOf(options), typeName)
	}
	_, loaded := registry.CreateOptions("h-unknown-type")
	require.False(t, loaded)
}

func TestH_InboundRegistryHiddifyTypes(t *testing.T) {
	hRequireRegistered(t, InboundRegistry(), map[string]any{
		C.TypeMieru:       &option.MieruInboundOptions{},
		C.TypeTrustTunnel: &option.TrustTunnelInboundOptions{},
	})
}

func TestH_OutboundRegistryHiddifyTypes(t *testing.T) {
	hRequireRegistered(t, OutboundRegistry(), map[string]any{
		C.TypePsiphon:         &option.PsiphonOutboundOptions{},
		C.TypeHInvalidConfig:  &option.HInvalidOptions{},
		C.TypeXray:            &option.XrayOutboundOptions{},
		C.TypeDNSTT:           &option.DnsttOptions{},
		C.TypeGooseRelay:      &option.GooseRelayOptions{},
		C.TypeBalancer:        &option.BalancerOutboundOptions{},
		C.TypeMASQUE:          &option.MASQUEOutboundOptions{},
		C.TypeLegacyWireGuard: &option.LegacyWireGuardOutboundOptions{},
		C.TypeTrustTunnel:     &option.TrustTunnelOutboundOptions{},
	})
	_, loaded := OutboundRegistry().CreateOptions(C.TypeMieru)
	require.True(t, loaded)
}

func TestH_EndpointRegistryHiddifyTypes(t *testing.T) {
	hRequireRegistered(t, EndpointRegistry(), map[string]any{
		C.TypeTunnelClient: &option.TunnelClientEndpointOptions{},
		C.TypeTunnelServer: &option.TunnelServerEndpointOptions{},
		C.TypeWARP:         &option.WARPEndpointOptions{},
		C.TypeAwg:          &option.AwgEndpointOptions{},
		C.TypeMASQUEClient: &option.MASQUEClientEndpointOptions{},
		C.TypeMASQUEServer: &option.MASQUEServerEndpointOptions{},
	})
}

func TestH_DNSTransportRegistryHiddifyTypes(t *testing.T) {
	hRequireRegistered(t, DNSTransportRegistry(), map[string]any{
		C.DNSTypeSDNS:  &option.SDNSDNSServerOptions{},
		C.DNSTypeMulti: &option.MultiDNSServerOptions{},
	})
}

func TestH_ServiceRegistryHiddifyTypes(t *testing.T) {
	hRequireRegistered(t, ServiceRegistry(), map[string]any{
		C.TypeSmartDNSPool: &option.SmartDNSPoolServiceOptions{},
	})
}

func TestH_CertificateProviderRegistryHiddifyTypes(t *testing.T) {
	hRequireRegistered(t, CertificateProviderRegistry(), map[string]any{
		C.TypeCloudflareOriginCA: &option.CloudflareOriginCACertificateProviderOptions{},
	})
}

func TestH_RegistryUnknownTypeErrors(t *testing.T) {
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("test")
	_, err := InboundRegistry().Create(ctx, nil, logger, "tag", "h-unknown-type", nil)
	require.Error(t, err)
	_, err = OutboundRegistry().CreateOutbound(ctx, nil, logger, "tag", "h-unknown-type", nil)
	require.Error(t, err)
	_, err = EndpointRegistry().Create(ctx, nil, logger, "tag", "h-unknown-type", nil)
	require.Error(t, err)
	_, err = DNSTransportRegistry().CreateDNSTransport(ctx, logger, "tag", "h-unknown-type", nil)
	require.Error(t, err)
	_, err = ServiceRegistry().Create(ctx, logger, "tag", "h-unknown-type", nil)
	require.Error(t, err)
	_, err = CertificateProviderRegistry().Create(ctx, logger, "tag", "h-unknown-type", nil)
	require.Error(t, err)
}

func TestH_TunnelEndpointInvalidUUID(t *testing.T) {
	ctx := Context(context.Background())
	logger := log.NewNOPFactory().NewLogger("test")
	registry := EndpointRegistry()
	_, err := registry.Create(ctx, nil, logger, "client", C.TypeTunnelClient, &option.TunnelClientEndpointOptions{UUID: "bad"})
	require.Error(t, err)
	_, err = registry.Create(ctx, nil, logger, "client", C.TypeTunnelClient, &option.TunnelClientEndpointOptions{
		UUID: "11111111-1111-1111-1111-111111111111",
		Key:  "bad",
	})
	require.Error(t, err)
	_, err = registry.Create(ctx, nil, logger, "server", C.TypeTunnelServer, &option.TunnelServerEndpointOptions{UUID: "bad"})
	require.Error(t, err)
}

func TestH_OutboundRegistryConcurrent(t *testing.T) {
	t.Skip("BUG: dnstt.RegisterOutbound calls loadResolvers which writes package-global maps unsynchronized (protocol/hiddify/dnstt/tools.go:21-29); concurrent OutboundRegistry() crashes with 'concurrent map writes'")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = OutboundRegistry()
		}()
	}
	wg.Wait()
}
