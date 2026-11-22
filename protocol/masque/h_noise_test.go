package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/hiddify/edgescan"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"

	"github.com/stretchr/testify/require"
)

func hMASQUETLS(t *testing.T) tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert, err := masque.GenerateCert(key, &key.PublicKey)
	require.NoError(t, err)
	config, err := tls.NewMASQUEClient(context.Background(), log.NewNOPFactory().Logger(), defaultServerName, cert, key, &key.PublicKey, option.MASQUEOutboundTLSOptions{})
	require.NoError(t, err)
	return config
}

// With search_noise, an endpoint that answers only www.speedtest.net is found (whichever server
// name is drawn first), the server name gains a point on the network, and the tunnel's next
// connect uses it.
func TestH_MASQUESearchNoise(t *testing.T) {
	store := edgescan.OpenStore(nil, t.Name())
	endpoint := netip.MustParseAddrPort("162.159.198.1:443")
	var probedNames []string
	probe := func(serverName string) warpscan.Probe {
		return func(ctx context.Context, addrPort netip.AddrPort) (time.Duration, error) {
			probedNames = append(probedNames, serverName)
			if serverName != "www.speedtest.net" || addrPort != endpoint {
				return 0, errors.New("blocked")
			}
			return 10 * time.Millisecond, nil
		}
	}
	noises := newMASQUENoises(nil, hMASQUETLS(t))
	noises.probes[noiseProbeKey{"speedtest", false}] = probe("www.speedtest.net")
	scanner := &masqueScanner{
		ctx: context.Background(), logger: log.NewNOPFactory().Logger(), store: store,
		book: store.Book(edgescan.KindWARPMASQUE), status: &warpscan.Status{},
		options: option.MASQUEOutboundOptions{Scanner: &option.WARPScannerOptions{
			Enabled: true, SearchNoise: true, Count: 4, CIDRs: []netip.Prefix{netip.PrefixFrom(endpoint.Addr(), 32)}, Ports: []uint16{443},
		}},
		probes:    map[bool]warpscan.Probe{false: probe(defaultServerName)},
		noises:    noises,
		network:   warpscan.NetworkInfo{Name: "wifi/IR", IPv4: true},
		searching: map[bool]bool{}, found: map[bool]net.Addr{},
	}
	require.Equal(t, defaultServerName, noises.TLSConfig(false).ServerName())

	got, err := scanner.Scan(false, nil)
	require.NoError(t, err)
	require.Equal(t, endpointAddr(endpoint, false).String(), got.String())
	require.Equal(t, "www.speedtest.net", noises.TLSConfig(false).ServerName())
	require.Equal(t, defaultServerName, noises.TLSConfig(true).ServerName(), "per HTTP version")
	score, _ := scanner.book.MethodScore("wifi/IR/h3", warpscan.NoiseMethod("speedtest"))
	require.Positive(t, score)

}

// Without search_noise, only the configured server name is tried.
func TestH_MASQUENoiseCandidates(t *testing.T) {
	store := edgescan.OpenStore(nil, t.Name())
	scanner := &masqueScanner{book: store.Book(edgescan.KindWARPMASQUE), options: option.MASQUEOutboundOptions{Scanner: &option.WARPScannerOptions{Enabled: true}}}
	require.Equal(t, []string{""}, scanner.noiseCandidates("wifi"))
	scanner.options.Scanner.SearchNoise = true
	require.ElementsMatch(t, []string{"", "speedtest"}, scanner.noiseCandidates("wifi"))
	// noise_presets with WireGuard names only: no MASQUE preset is tried
	scanner.options.Scanner.NoisePresets = []string{"dns"}
	require.Equal(t, []string{""}, scanner.noiseCandidates("wifi"))
	scanner.options.Scanner.NoisePresets = []string{"dns", "Speedtest"}
	require.ElementsMatch(t, []string{"", "speedtest"}, scanner.noiseCandidates("wifi"))

	require.NoError(t, validateNoisePresets(scanner.options.Scanner))
	require.Error(t, validateNoisePresets(&option.WARPScannerOptions{NoisePresets: []string{"nope"}}))
}
