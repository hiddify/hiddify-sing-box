package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func selfSigned(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return key, der
}

// certificate_public_key_sha256 pins the endpoint by the hash of its key, as masque:// links
// carry it, instead of the profile's key.
func TestH_MASQUEClientPinsPublicKeySHA256(t *testing.T) {
	clientKey, clientCert := selfSigned(t)
	edgeKey, edgeCert := selfSigned(t)
	otherKey, _ := selfSigned(t)
	parsed, err := x509.ParseCertificate(edgeCert)
	require.NoError(t, err)
	sum := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	pin := strings.ToUpper(hex.EncodeToString(sum[:]))

	verify := func(options option.MASQUEOutboundTLSOptions) error {
		config, err := NewMASQUEClient(context.Background(), log.NewNOPFactory().Logger(), "edge", [][]byte{clientCert}, clientKey, &otherKey.PublicKey, options)
		require.NoError(t, err)
		return config.(*STDClientConfig).config.VerifyPeerCertificate([][]byte{edgeCert}, nil)
	}
	require.Error(t, verify(option.MASQUEOutboundTLSOptions{}), "the profile's key is another one")
	require.NoError(t, verify(option.MASQUEOutboundTLSOptions{CertificatePublicKeySHA256: []string{"00", pin}}))
	require.Error(t, verify(option.MASQUEOutboundTLSOptions{CertificatePublicKeySHA256: []string{"00"}}))
	_ = edgeKey
}
