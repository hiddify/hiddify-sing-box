//go:build with_tailscale && !with_tailcat

package derp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestH_DERPVerifyClientInboundStub(t *testing.T) {
	t.Parallel()
	keys, err := resolveTailcatVerifyKeys(context.Background(), []string{"tailcat-in"})
	require.Nil(t, keys)
	require.ErrorContains(t, err, "with_tailcat")
}

func selfSignedPEM(t *testing.T) (string, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "derp.test"},
		DNSNames:     []string{"derp.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestH_DERPStartFailsWithVerifyClientInboundWithoutTailcat(t *testing.T) {
	t.Parallel()
	cert, key := selfSignedPEM(t)
	svc, err := NewService(context.Background(), log.NewNOPFactory().Logger(), "derp", option.DERPServiceOptions{
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
			Enabled: true, Certificate: []string{cert}, Key: []string{key},
		}},
		ConfigPath:          filepath.Join(t.TempDir(), "derp.json"),
		VerifyClientInbound: []string{"tailcat-in"},
	})
	require.NoError(t, err)
	err = svc.Start(adapter.StartStateStart)
	require.ErrorContains(t, err, "verify_client_inbound requires Tailcat")
}
