//go:build with_v2ray_api

package main

import (
	"context"
	"net/netip"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/experimental/v2rayapi"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// The V2Ray API counts the traffic of an OpenVPN server's client under its user name.
func TestH_OpenVPNServerUserStats(t *testing.T) {
	for _, protocol := range []string{N.NetworkUDP, N.NetworkTCP} {
		t.Run(protocol, func(t *testing.T) {
			runOpenVPNServerUserStats(t, protocol)
		})
	}
}

func runOpenVPNServerUserStats(t *testing.T, protocol string) {
	const (
		serverAddress = "10.8.0.1"
		username      = "counted-user"
		password      = "counted-password"
	)
	openVPNPort := reserveOpenVPNProtocolPort(t, protocol)
	proxyPort := reserveOpenVPNTCPPort(t)
	apiPort := reserveOpenVPNTCPPort(t)
	echoPort := reserveOpenVPNEchoPort(t)
	readinessPort := reserveOpenVPNEchoPort(t)
	certificates := createOpenVPNCertificateBundle(t)

	serverOptions := option.OpenVPNServerEndpointOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: openVPNPort,
		},
		Network: protocol,
		Address: []netip.Prefix{netip.MustParsePrefix(serverAddress + "/24")},
		Users:   []auth.User{{Username: username, Password: password}},
		TLS: &option.OpenVPNInboundTLSOptions{
			CertificatePath:       certificates.serverCertPath,
			KeyPath:               certificates.serverKeyPath,
			ClientCertificatePath: certificates.caPath,
		},
	}
	instanceOptions := openVPNServerInstanceOptions(serverOptions)
	apiAddress := "127.0.0.1:" + strconv.Itoa(int(apiPort))
	instanceOptions.Experimental = &option.ExperimentalOptions{
		V2RayAPI: &option.V2RayAPIOptions{
			Listen: apiAddress,
			Stats: &option.V2RayStatsServiceOptions{
				Enabled: true,
				Users:   []string{username},
			},
		},
	}
	startInstance(t, instanceOptions)

	clientOptions := newOpenVPNTLSClientOptions(protocol, openVPNPort, certificates.caPath, certificates.clientCertPath, certificates.clientKeyPath)
	clientOptions.Username = username
	clientOptions.Password = password
	startInstance(t, openVPNClientInstanceOptions(clientOptions, proxyPort))
	waitForOpenVPNClientReady(t, proxyPort, readinessPort, serverAddress)
	testSuitOpenVPN(t, proxyPort, echoPort, serverAddress)

	connection, err := grpc.NewClient(apiAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer connection.Close()
	for _, direction := range []string{"uplink", "downlink"} {
		name := "user>>>" + username + ">>>traffic>>>" + direction
		var response v2rayapi.GetStatsResponse
		// the server registers the service under its V2Ray name, see v2rayapi/stats.go
		err = connection.Invoke(context.Background(), "/v2ray.core.app.stats.command.StatsService/GetStats", &v2rayapi.GetStatsRequest{Name: name}, &response)
		require.NoError(t, err, name)
		require.Positive(t, response.Stat.Value, name)
	}
}
