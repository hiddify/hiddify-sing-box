package masque

import (
	"errors"
	"net/http"
	"strings"
)

// StatusError is a CONNECT-IP request the server answered with another status than 200.
type StatusError struct {
	Status int
	Text   string
}

func (e *StatusError) Error() string {
	return "tunnel connection failed: " + e.Text
}

// rejectedAlerts are the TLS alerts a server sends when it does not accept the client's
// certificate: Cloudflare's edge answers a key it has not enrolled with "unknown certificate",
// over HTTP/2 as "remote error: tls: unknown certificate" and over HTTP/3 as "CRYPTO_ERROR 0x12e
// (remote): tls: unknown certificate".
var rejectedAlerts = []string{
	"tls: unknown certificate",
	"tls: bad certificate",
	"tls: certificate required",
	"tls: certificate unknown",
	"tls: unknown certificate authority",
	"tls: access denied",
	"tls: certificate revoked",
}

// IsRejected reports a connect the server refused because of the device: a TLS alert about the
// client's certificate from the remote side (not a local check of the server's), or a 401/403
// answer to the CONNECT-IP request. A network failure is not a rejection.
func IsRejected(err error) bool {
	if err == nil {
		return false
	}
	var status *StatusError
	if errors.As(err, &status) {
		return status.Status == http.StatusUnauthorized || status.Status == http.StatusForbidden
	}
	message := err.Error()
	if !strings.Contains(message, "remote error") && !strings.Contains(message, "(remote)") {
		return false
	}
	for _, alert := range rejectedAlerts {
		if strings.Contains(message, alert) {
			return true
		}
	}
	return false
}
