package constant

// Why a proxy is not secure: what option.InsecureReason returns, and what the app shows. //H
const (
	// InsecurePlaintext: nothing encrypts its traffic, no TLS and no encryption of its own
	// (SOCKS, HTTP, VLESS or Trojan without TLS).
	InsecurePlaintext = "plaintext"
	// InsecureNoCipher: its own encryption is turned off (method none, VMess security none) and
	// no TLS takes its place.
	InsecureNoCipher = "no_cipher"
	// InsecureWeakCipher: its own encryption only hides the data (table, rc4, xor), and anyone on
	// the way can read it.
	InsecureWeakCipher = "weak_cipher"
	// InsecureTLSUnverified: TLS with insecure on and no pinned certificate, so anyone on the way
	// can stand in for the server.
	InsecureTLSUnverified = "tls_insecure"
)
