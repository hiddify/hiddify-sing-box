package masque

import (
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/hiddify/warpscan"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// EnrollWARP gives the WARP device id a new MASQUE key and returns its tunnel settings. The
// device then only works over MASQUE, not WireGuard.
func EnrollWARP(ctx context.Context, api *cloudflare.CloudflareApi, token string, id string) (*Config, error) {
	privateKey, publicKey, err := masque.GenerateEcKeyPair()
	if err != nil {
		return nil, E.Cause(err, "generate key pair")
	}
	profile, err := api.EnrollKey(ctx, token, id, cloudflare.KeyTypeMasque, cloudflare.TunTypeMasque, base64.StdEncoding.EncodeToString(publicKey))
	if err != nil {
		return nil, err
	}
	if len(profile.Config.Peers) == 0 {
		return nil, E.New("WARP profile has no peers")
	}
	peer := profile.Config.Peers[0]
	return &Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privateKey),
		EndpointV4:     endpointHost(peer.Endpoint.V4),
		EndpointV6:     endpointHost(peer.Endpoint.V6),
		EndpointH2V4:   cloudflare.DefaultEndpointH2V4,
		EndpointH2V6:   cloudflare.DefaultEndpointH2V6,
		EndpointPubKey: peer.PublicKey,
		License:        profile.Account.License,
		ID:             profile.ID,
		AccessToken:    token,
		IPv4:           profile.Config.Interface.Addresses.V4,
		IPv6:           profile.Config.Interface.Addresses.V6,
	}, nil
}

// endpointHost returns the IP of an endpoint written as "ip:port", "[ip]:port" or "ip".
func endpointHost(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return host
	}
	return M.ParseAddr(endpoint).String()
}

// Addresses returns the tunnel addresses of the device; a missing family is skipped.
func (c *Config) Addresses() ([]netip.Prefix, error) {
	var addresses []netip.Prefix
	for _, address := range []string{c.IPv4, c.IPv6} {
		if address == "" {
			continue
		}
		parsed, err := netip.ParseAddr(address)
		if err != nil {
			return nil, E.Cause(err, "parse WARP MASQUE address")
		}
		addresses = append(addresses, netip.PrefixFrom(parsed, parsed.BitLen()))
	}
	if len(addresses) == 0 {
		return nil, E.New("WARP MASQUE config has no address")
	}
	return addresses, nil
}

// ProbeWARP times a handshake with the MASQUE endpoint of the device in config, through
// options' dialer, at peer when it is set: whether MASQUE gets through, for the warp endpoint's
// auto mode. vhttp h3 probes QUIC over UDP, h2 TLS over TCP, and auto both at once, answering
// with the first that gets through.
func ProbeWARP(ctx context.Context, logger log.ContextLogger, options option.MASQUEOutboundOptions, config *Config, peer M.Socksaddr) (time.Duration, error) {
	mode, err := tunnelMode(options)
	if err != nil {
		return 0, err
	}
	tlsConfig, err := warpTLS(ctx, logger, options, config)
	if err != nil {
		return 0, err
	}
	probeDialer, err := dialer.NewWithOptions(dialer.Options{Context: ctx, Options: options.DialerOptions, ResolverOnDetour: true})
	if err != nil {
		return 0, err
	}
	probe := func(ctx context.Context, http2 bool) (time.Duration, error) {
		var endpoint net.Addr
		var err error
		if hasPeer(peer) && peer.Addr.IsValid() {
			endpoint, err = fixedEndpoint(config, peer, http2, options.UseIPv6)
		} else {
			endpoint, err = config.SelectEndpointFromConfig(http2, options.UseIPv6, config.port())
		}
		if err != nil {
			return 0, err
		}
		addrPort, _ := addrPortOf(endpoint)
		return warpscan.MASQUEProbe(probeDialer, tlsConfig, http2)(ctx, addrPort)
	}
	if mode != masque.ModeAuto {
		return probe(ctx, mode == masque.ModeHTTP2)
	}
	return firstProbe(ctx, probe)
}

// firstProbe runs probe over HTTP/3 and HTTP/2 at once and returns the first success, or the
// errors of both.
func firstProbe(ctx context.Context, probe func(ctx context.Context, http2 bool) (time.Duration, error)) (time.Duration, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		http2 bool
		rtt   time.Duration
		err   error
	}
	results := make(chan result, 2)
	for _, http2 := range []bool{false, true} {
		go func() {
			rtt, err := probe(ctx, http2)
			results <- result{http2, rtt, err}
		}()
	}
	var errs [2]error
	for range 2 {
		r := <-results
		if r.err == nil {
			return r.rtt, nil
		}
		if r.http2 {
			errs[1] = E.Cause(r.err, "HTTP/2")
		} else {
			errs[0] = E.Cause(r.err, "HTTP/3")
		}
	}
	return 0, E.Errors(errs[0], errs[1])
}
