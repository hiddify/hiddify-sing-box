package tls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
)

// verifyPublicKeySHA256 accepts cert when the SHA-256 of its public key (SubjectPublicKeyInfo
// DER) is one of pins, hex in either case.
func verifyPublicKeySHA256(cert *x509.Certificate, pins []string) error {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	actual := hex.EncodeToString(sum[:])
	for _, pin := range pins {
		if strings.EqualFold(strings.TrimSpace(pin), actual) {
			return nil
		}
	}
	return x509.CertificateInvalidError{Cert: cert, Reason: x509.NotAuthorizedToSign, Detail: "remote endpoint's public key matches none of certificate_public_key_sha256"}
}
