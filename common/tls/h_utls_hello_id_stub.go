//go:build !with_utls

package tls

// UTLSHelloID returns ok false: this build has no uTLS.
func UTLSHelloID(config Config) (client string, version string, ok bool) {
	return "", "", false
}
