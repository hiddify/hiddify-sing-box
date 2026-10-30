package cachefile

// storedUnlessOff is a store_* switch of Hiddify's that is on by default: WARP and MASQUE devices
// are registered with Cloudflare, and registering again at every start is slow and rate limited,
// so the cache file keeps them unless the option is false.
func storedUnlessOff(option *bool) bool {
	return option == nil || *option
}
