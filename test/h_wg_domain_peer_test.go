//go:build with_wireguard && with_awg

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// hiddify-app#2478: a WireGuard or AmneziaWG peer given by a domain, with the app's DNS: a
// fake-IP rule that matches every query, as hiddify-core writes when fake DNS is on. The domain
// is known only to the box's DNS, not to the system: AmneziaWG looked it up with the system
// resolver, which with the VPN up answers from the tunnel, fake addresses included.
func TestH_WireGuardDomainPeerWithFakeDNS(t *testing.T) {
	for _, endpointType := range []string{"wireguard", "awg"} {
		for _, fakeDNS := range []bool{false, true} {
			for _, defaultResolver := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/fakedns=%v/default_domain_resolver=%v", endpointType, fakeDNS, defaultResolver), func(t *testing.T) {
					hTestDomainPeer(t, endpointType, fakeDNS, defaultResolver)
				})
			}
		}
	}
}

func hTestDomainPeer(t *testing.T, endpointType string, fakeDNS bool, defaultResolver bool) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	serverPort := reservation.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, reservation.Close())
	key := func(k *ecdh.PrivateKey) string { return base64.StdEncoding.EncodeToString(k.Bytes()) }
	public := func(k *ecdh.PrivateKey) string { return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()) }

	peerKey := "public_key"
	allowed := "allowed_ips"
	addressKey := "address"
	dnsRules := `[]`
	if fakeDNS {
		dnsRules = `[{"server": "dns-fake", "disable_cache": true}]`
	}
	route := `"final": "direct"`
	if defaultResolver {
		route += `, "default_domain_resolver": "dns-hosts"`
	}
	config := fmt.Sprintf(`{
		"dns": {
			"servers": [
				{"type": "hosts", "tag": "dns-hosts", "predefined": {"awg-peer.hiddify.test": ["127.0.0.1"]}},
				{"type": "fakeip", "tag": "dns-fake", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}
			],
			"rules": %s,
			"final": "dns-hosts"
		},
		"endpoints": [
			{"type": "wireguard", "tag": "server", "mtu": 1280, "address": ["10.79.0.1/32"],
			 "private_key": %q, "listen_port": %d,
			 "peers": [{%q: %q, %q: ["10.79.0.2/32"]}]},
			{"type": %q, "tag": "client", "mtu": 1280, %q: ["10.79.0.2/32"],
			 "private_key": %q,
			 "peers": [{"address": "awg-peer.hiddify.test", "port": %d, %q: %q, %q: ["10.79.0.1/32"], "persistent_keepalive_interval": 1}]}
		],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {%s}
	}`, dnsRules, key(serverKey), serverPort, peerKey, public(clientKey), allowed,
		endpointType, addressKey, key(clientKey), serverPort, peerKey, public(serverKey), allowed, route)
	options, err := json.UnmarshalExtendedContext[option.Options](globalCtx, []byte(config))
	require.NoError(t, err)
	instance := startInstance(t, options)

	client, loaded := instance.Endpoint().Get("client")
	require.True(t, loaded)

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	// the server's tunnel address answers on the host's loopback: the server routes to direct
	destination := M.SocksaddrFrom(netip.MustParseAddr("10.79.0.1"), uint16(listener.Addr().(*net.TCPAddr).Port))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var lastErr error
	for ctx.Err() == nil {
		attempt, attemptCancel := context.WithTimeout(ctx, 3*time.Second)
		lastErr = hEchoThrough(attempt, client.DialContext, destination)
		attemptCancel()
		if lastErr == nil {
			return
		}
	}
	t.Fatal("no connection through the tunnel: ", lastErr)
}

func hEchoThrough(ctx context.Context, dial func(context.Context, string, M.Socksaddr) (net.Conn, error), destination M.Socksaddr) error {
	conn, err := dial(ctx, "tcp", destination)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	payload := []byte("domain peer")
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	_, err = io.ReadFull(conn, make([]byte, len(payload)))
	return err
}
