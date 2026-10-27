//go:build !with_utls

package tls

// IsReality reports whether a client config is REALITY; never without with_utls.
func IsReality(config Config) bool {
	return false
}
