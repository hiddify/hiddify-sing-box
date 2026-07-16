//go:build with_gvisor && !android

package tailscale

func setAndroidProtectFunc(f func(fd int) error) {
}
