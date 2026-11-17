package shadowsocks

import "strings"

// methodAliases maps the cipher names Xray accepts to the names sing-shadowsocks knows.
// Subscriptions written for Xray clients use these names (for example "chacha20-poly1305"),
// and sing-shadowsocks rejects them with "unknown method".
var methodAliases = map[string]string{
	"aead_aes_128_gcm":        "aes-128-gcm",
	"aead_aes_256_gcm":        "aes-256-gcm",
	"chacha20-poly1305":       "chacha20-ietf-poly1305",
	"aead_chacha20_poly1305":  "chacha20-ietf-poly1305",
	"xchacha20-poly1305":      "xchacha20-ietf-poly1305",
	"aead_xchacha20_poly1305": "xchacha20-ietf-poly1305",
	"plain":                   "none",
}

// normalizeMethod returns the sing-shadowsocks name of a cipher given in a user's config.
func normalizeMethod(method string) string {
	lower := strings.ToLower(strings.TrimSpace(method))
	if alias, ok := methodAliases[lower]; ok {
		return alias
	}
	return lower
}
