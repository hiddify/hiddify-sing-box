package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// A connection from an OpenVPN server's client carries the client's user name, so auth_user rules
// and per-user stats see it. Two users share one client certificate here; only one may pass.
func TestH_OpenVPNServerUser(t *testing.T) {
	for _, protocol := range []string{N.NetworkUDP, N.NetworkTCP} {
		t.Run(protocol, func(t *testing.T) {
			runOpenVPNServerUser(t, protocol)
		})
	}
}

func runOpenVPNServerUser(t *testing.T, protocol string) {
	const (
		serverAddress = "10.8.0.1"
		allowedUser   = "allowed-user"
		blockedUser   = "blocked-user"
	)
	openVPNPort := reserveOpenVPNProtocolPort(t, protocol)
	allowedProxyPort := reserveOpenVPNTCPPort(t)
	blockedProxyPort := reserveOpenVPNTCPPort(t)
	echoPort := reserveOpenVPNEchoPort(t)
	readinessPort := reserveOpenVPNEchoPort(t)
	certificates := createOpenVPNCertificateBundle(t)

	serverOptions := option.OpenVPNServerEndpointOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: openVPNPort,
		},
		Network:     protocol,
		Address:     []netip.Prefix{netip.MustParsePrefix(serverAddress + "/24")},
		DuplicateCN: true,
		Users: []auth.User{
			{Username: allowedUser, Password: "allowed-password"},
			{Username: blockedUser, Password: "blocked-password"},
		},
		TLS: &option.OpenVPNInboundTLSOptions{
			CertificatePath:       certificates.serverCertPath,
			KeyPath:               certificates.serverKeyPath,
			ClientCertificatePath: certificates.caPath,
		},
	}
	instanceOptions := openVPNServerInstanceOptions(serverOptions)
	instanceOptions.Outbounds[0].Tag = "direct"
	instanceOptions.Route = &option.RouteOptions{
		Rules: []option.Rule{
			{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{AuthUser: []string{allowedUser}},
					RuleAction: option.RuleAction{
						Action:       C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{Outbound: "direct"},
					},
				},
			},
			{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{Inbound: []string{"openvpn-server"}},
					RuleAction: option.RuleAction{
						Action:        C.RuleActionTypeReject,
						RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault},
					},
				},
			},
		},
	}
	startInstance(t, instanceOptions)

	clientOptions := func(username string, password string) option.OpenVPNClientEndpointOptions {
		options := newOpenVPNTLSClientOptions(protocol, openVPNPort, certificates.caPath, certificates.clientCertPath, certificates.clientKeyPath)
		options.Username = username
		options.Password = password
		return options
	}
	startInstance(t, openVPNClientInstanceOptions(clientOptions(allowedUser, "allowed-password"), allowedProxyPort))
	blockedInstance := startInstance(t, openVPNClientInstanceOptions(clientOptions(blockedUser, "blocked-password"), blockedProxyPort))

	waitForOpenVPNClientReady(t, allowedProxyPort, readinessPort, serverAddress)
	testSuitOpenVPN(t, allowedProxyPort, echoPort, serverAddress)

	waitForOpenVPNStatus(t, requireOpenVPNEndpoint(t, blockedInstance, "openvpn-client"), 30*time.Second, func(status adapter.OpenVPNStatus) bool {
		return status.State == adapter.OpenVPNStateConnected
	})
	closeEcho := startOpenVPNReadinessEcho(t, readinessPort)
	defer closeEcho()
	require.NoError(t, probeOpenVPNTCPWithTimeout(allowedProxyPort, serverAddress, readinessPort, 3*time.Second))
	require.Error(t, probeOpenVPNTCPWithTimeout(blockedProxyPort, serverAddress, readinessPort, 3*time.Second))
}
