//go:build with_gvisor && android

package tailscale

import (
	"github.com/sagernet/tailscale/net/netns"
)

func setAndroidProtectFunc(f func(fd int) error) {
	netns.SetAndroidProtectFunc(f)
}
