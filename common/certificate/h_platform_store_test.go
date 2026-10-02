package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type hPlatformInterface struct {
	adapter.PlatformInterface
	certificates []string
}

func (p *hPlatformInterface) SystemCertificates() []string {
	return p.certificates
}

func hNewCA(t *testing.T, name string) (*x509.Certificate, string, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		DNSNames:     []string{"leaf.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), leaf
}

func hNewSystemStore(t *testing.T, platform adapter.PlatformInterface) *Store {
	t.Helper()
	ctx := context.Background()
	if platform != nil {
		ctx = service.ContextWith[adapter.PlatformInterface](ctx, platform)
	}
	store, err := NewStore(ctx, logger.NOP(), option.CertificateOptions{Store: C.CertificateStoreSystem})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	return store
}

func hVerify(pool *x509.CertPool, leaf *x509.Certificate) error {
	_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "leaf.test"})
	return err
}

func TestH_StorePlatformSystemCertificates(t *testing.T) {
	t.Parallel()
	ca, caPEM, leaf := hNewCA(t, "hiddify platform test CA")
	store := hNewSystemStore(t, &hPlatformInterface{certificates: []string{caPEM}})
	require.NotNil(t, store.systemPool)
	expected := x509.NewCertPool()
	expected.AddCert(ca)
	require.True(t, expected.Equal(store.systemPool))
	require.NoError(t, hVerify(store.Pool(), leaf))
	require.Equal(t, C.CertificateStoreSystem, store.StoreKind())
	require.False(t, store.ExclusiveAnchors())
}

func TestH_StorePlatformSkipsInvalidPEM(t *testing.T) {
	t.Parallel()
	caA, caPEMA, leafA := hNewCA(t, "hiddify platform CA A")
	caB, caPEMB, leafB := hNewCA(t, "hiddify platform CA B")
	store := hNewSystemStore(t, &hPlatformInterface{certificates: []string{"not a pem", caPEMA, "", caPEMB}})
	expected := x509.NewCertPool()
	expected.AddCert(caA)
	expected.AddCert(caB)
	require.True(t, expected.Equal(store.systemPool))
	require.NoError(t, hVerify(store.Pool(), leafA))
	require.NoError(t, hVerify(store.Pool(), leafB))
}

func TestH_StorePlatformFallbackToSystemPool(t *testing.T) {
	t.Parallel()
	_, _, leaf := hNewCA(t, "hiddify untrusted CA")
	for name, platform := range map[string]adapter.PlatformInterface{
		"nil-platform": nil,
		"empty":        &hPlatformInterface{},
		"invalid-only": &hPlatformInterface{certificates: []string{"garbage", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := hNewSystemStore(t, platform)
			require.NotNil(t, store.systemPool)
			require.Error(t, hVerify(store.Pool(), leaf))
		})
	}
}

func TestH_StorePlatformIgnoredForBundledStores(t *testing.T) {
	t.Parallel()
	_, caPEM, leaf := hNewCA(t, "hiddify ignored CA")
	ctx := service.ContextWith[adapter.PlatformInterface](context.Background(), &hPlatformInterface{certificates: []string{caPEM}})
	for _, storeType := range []string{C.CertificateStoreMozilla, C.CertificateStoreNone} {
		store, err := NewStore(ctx, logger.NOP(), option.CertificateOptions{Store: storeType})
		require.NoError(t, err)
		require.Nil(t, store.systemPool)
		require.Error(t, hVerify(store.Pool(), leaf))
		require.True(t, store.ExclusiveAnchors())
		store.Close()
	}
	_, err := NewStore(ctx, logger.NOP(), option.CertificateOptions{Store: "bogus"})
	require.ErrorContains(t, err, "unknown certificate store")
}
