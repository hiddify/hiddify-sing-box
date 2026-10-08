//go:build with_wireguard && with_v2ray_api

package box_test

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/experimental/v2rayapi"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// The V2Ray API counts a WireGuard peer's traffic under its username (user>>>alice>>>traffic),
// queried over gRPC as a panel does.
func TestH_WireGuardPeerUsernameV2RayStats(t *testing.T) {
	apiPort := hFreeTCPPort(t)
	users := hWireGuardUserSetup(t, `,
		"experimental": {"v2ray_api": {
			"listen": "127.0.0.1:`+strconv.Itoa(apiPort)+`",
			"stats": {"enabled": true, "users": ["alice", "bob"]}
		}}`, `[]`)

	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB each way
	require.Eventually(t, func() bool { return users.send("alice", payload) == nil }, 10*time.Second, 200*time.Millisecond)
	require.NoError(t, users.send("bob", payload), "bob is routed too, but has no user to count")

	conn, err := grpc.NewClient("127.0.0.1:"+strconv.Itoa(apiPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	stat := func(name string) int64 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// the V2Ray service name sing-box registers, which V2Ray/Xray panels call
		response := new(v2rayapi.QueryStatsResponse)
		err := conn.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats",
			&v2rayapi.QueryStatsRequest{Patterns: []string{name}}, response)
		require.NoError(t, err)
		for _, s := range response.Stat {
			if s.Name == name {
				return s.Value
			}
		}
		return 0
	}
	// counters are updated as the connections close
	require.Eventually(t, func() bool {
		return stat("user>>>alice>>>traffic>>>uplink") >= int64(len(payload)) &&
			stat("user>>>alice>>>traffic>>>downlink") >= int64(len(payload))
	}, 5*time.Second, 100*time.Millisecond, "alice: uplink %d, downlink %d",
		stat("user>>>alice>>>traffic>>>uplink"), stat("user>>>alice>>>traffic>>>downlink"))
	require.Zero(t, stat("user>>>bob>>>traffic>>>uplink"), "bob's peer has no username")
	require.Zero(t, stat("user>>>bob>>>traffic>>>downlink"))
	t.Logf("alice: uplink %d B, downlink %d B", stat("user>>>alice>>>traffic>>>uplink"), stat("user>>>alice>>>traffic>>>downlink"))
}
