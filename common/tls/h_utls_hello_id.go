//go:build with_utls

package tls

// UTLSHelloID returns the client and version of the uTLS fingerprint of config, for code that
// hands the fingerprint to another TLS stack (Xray's in XDRIVE); ok is false without uTLS.
func UTLSHelloID(config Config) (client string, version string, ok bool) {
	utlsConfig, isUTLS := config.(*UTLSClientConfig)
	if !isUTLS {
		return "", "", false
	}
	return utlsConfig.id.Client, utlsConfig.id.Version, true
}
