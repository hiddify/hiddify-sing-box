package masque

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestH_IsWARPDevice(t *testing.T) {
	require.True(t, isWARPDevice(&Config{EndpointV4: "162.159.198.2"}, "consumer-masque.cloudflareclient.com"))
	require.True(t, isWARPDevice(&Config{EndpointV4: "162.159.199.2"}, "www.cloudflare.com"), "WARP+ endpoint behind another name")
	require.True(t, isWARPDevice(&Config{EndpointV6: "2606:4700:103::2"}, "www.cloudflare.com"))
	require.True(t, isWARPDevice(&Config{EndpointV4: "10.0.0.1"}, ""), "Cloudflare's name by default")
	require.True(t, isWARPDevice(&Config{EndpointV4: "10.0.0.1"}, "zt-masque.cloudflareclient.com"))
	require.False(t, isWARPDevice(&Config{EndpointV4: "10.0.0.1", EndpointH2V4: "10.0.0.2"}, "masque.example.com"))
}

// Cloudflare refuses the link's device: another is registered, once at a time, and the tunnel
// is restarted with it; a refused replacement is replaced again only after the backoff.
func TestH_DeviceRejectedRegisters(t *testing.T) {
	options := option.MASQUEOutboundOptions{Device: &option.MASQUEDeviceOptions{
		PrivateKey: "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgBwuLjlsggKUoQAHnXmQli6jPVuhju5hAV0io0Vt//H6gCgYIKoZIzj0DAQehRANCAAT9CueMifPPo9N28YF+og7UDN6iOwRMy1NVBxwy1fKZxus54nCwix5kIzj1pboJVgCmWBT7fCDLbQWsshNM/Gy1",
		IPv4:       "172.16.0.2",
		EndpointV4: "162.159.198.2:8095",
	}}
	outbound, err := newWARPOutbound(context.Background(), log.NewNOPFactory().Logger(), "masque", options, nil, M.Socksaddr{}, "")
	require.NoError(t, err)
	require.True(t, outbound.registersOnRejection())
	require.Nil(t, outbound.replacementFor(outbound.warpConfig), "no cache file, no replacement")

	var access sync.Mutex
	registered, restarted := 0, 0
	var restartedWith *Config
	release := make(chan struct{})
	outbound.register = func() (*Config, bool) {
		<-release
		access.Lock()
		defer access.Unlock()
		registered++
		return &Config{ID: "registered", ReplacedDevice: options.Device.PrivateKey}, true
	}
	outbound.restart = func(config *Config) {
		access.Lock()
		defer access.Unlock()
		restarted++
		restartedWith = config
	}
	rejection := errors.New("remote error: tls: unknown certificate")
	outbound.deviceRejected(rejection)
	outbound.deviceRejected(rejection) // while the first is handled: dropped
	close(release)
	require.Eventually(t, func() bool {
		access.Lock()
		defer access.Unlock()
		return restarted == 1
	}, 5*time.Second, 10*time.Millisecond)
	access.Lock()
	require.Equal(t, 1, registered)
	require.Equal(t, "registered", restartedWith.ID)
	access.Unlock()
	require.True(t, outbound.recreate.Load(), "a registration, not the saved device")
	require.Eventually(t, func() bool { return !outbound.rejected.Load() }, time.Second, 10*time.Millisecond)

	// the replacement is refused too: not before the backoff
	outbound.deviceRejected(rejection)
	require.Eventually(t, func() bool { return !outbound.rejected.Load() }, time.Second, 10*time.Millisecond)
	access.Lock()
	require.Equal(t, 1, registered, "too soon after the last registration")
	access.Unlock()
	outbound.registerAccess.Lock()
	require.Equal(t, rejectRegisterMin, outbound.registerWait)
	outbound.lastRegistered = time.Now().Add(-2 * rejectRegisterMin)
	outbound.registerAccess.Unlock()
	outbound.deviceRejected(rejection)
	require.Eventually(t, func() bool {
		access.Lock()
		defer access.Unlock()
		return restarted == 2
	}, 5*time.Second, 10*time.Millisecond)
	outbound.registerAccess.Lock()
	require.Equal(t, 2*rejectRegisterMin, outbound.registerWait, "the wait doubles")
	outbound.registerAccess.Unlock()

	// a closed outbound registers nothing
	require.NoError(t, outbound.Close())
	outbound.registerAccess.Lock()
	outbound.lastRegistered = time.Time{}
	outbound.registerAccess.Unlock()
	outbound.deviceRejected(rejection)
	require.Eventually(t, func() bool { return !outbound.rejected.Load() }, time.Second, 10*time.Millisecond)
	access.Lock()
	require.Equal(t, 2, registered)
	access.Unlock()
}
