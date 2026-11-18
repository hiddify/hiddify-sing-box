package edgescan

import "runtime"

// Mobile reports whether the box runs on a phone or a tablet, where a scan keeps to fewer
// workers to spare the battery.
var Mobile = runtime.GOOS == "android" || runtime.GOOS == "ios"

// PlatformDefault is mobile on Android and iOS, desktop elsewhere.
func PlatformDefault(mobile, desktop int) int {
	if Mobile {
		return mobile
	}
	return desktop
}
