package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/sagernet/quic-go/http3"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

func NewMASQUEClient(ctx context.Context, logger logger.ContextLogger, serverName string, cert [][]byte, privateKey *ecdsa.PrivateKey, peerPublicKey *ecdsa.PublicKey, options option.MASQUEOutboundTLSOptions) (Config, error) {
	var tlsConfig tls.Config
	tlsConfig.ServerName = serverName
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	tlsConfig.Certificates = []tls.Certificate{
		{
			Certificate: cert,
			PrivateKey:  privateKey,
		},
	}
	if options.CipherSuites != nil {
	find:
		for _, cipherSuite := range options.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("unknown cipher_suite: ", cipherSuite)
		}
	}
	for _, curve := range options.CurvePreferences {
		tlsConfig.CurvePreferences = append(tlsConfig.CurvePreferences, tls.CurveID(curve))
	}
	// verifyCertificate pins the peer key: the WARP endpoint presents a certificate signed for a
	// name it never reveals, so the key is the only identity worth checking.
	verifyCertificate := func(cert *x509.Certificate) error {
		if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
			return x509.ErrUnsupportedAlgorithm
		}
		if !cert.PublicKey.(*ecdsa.PublicKey).Equal(peerPublicKey) {
			return x509.CertificateInvalidError{Cert: cert, Reason: 10, Detail: "remote endpoint has a different public key than what we trust in config.json"}
		}
		return nil
	}
	verifyPeerCertificate := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return nil
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		return verifyCertificate(cert)
	}
	if !options.Insecure {
		tlsConfig.VerifyPeerCertificate = verifyPeerCertificate
	}
	// Cloudflare's WARP endpoint publishes no ECH config of its own and rejects the public
	// cloudflare-ech.com one, so this is always the fallback path: accept the rejection and let
	// Go retry the plain handshake, which the pin above still covers. //H
	tlsConfig.EncryptedClientHelloRejectionVerify = func(state tls.ConnectionState) error {
		return nil
	}
	var config Config = &STDClientConfig{
		ctx:                   ctx,
		config:                &tlsConfig,
		serverName:            serverName,
		fragment:              options.Fragment,
		fragmentFallbackDelay: time.Duration(options.FragmentFallbackDelay),
		recordFragment:        options.RecordFragment,
	}
	if options.ECH != nil && options.ECH.Enabled { //H
		// ECH is applied to the underlying client; the tunnel hands this config to http2/quic-go,
		// so the ClientHello carries the encrypted config list.
		echConfig, err := parseECHClientConfig(ctx, config.(ECHCapableConfig), option.OutboundTLSOptions{ECH: options.ECH})
		if err != nil {
			return nil, err
		}
		config = echConfig
		// The tunnel clones this config and calls Client(), never ClientHandshake: resolve the
		// DNS-based config list now instead of on first use.
		if echClient, isECH := config.(*ECHClientConfig); isECH {
			if err = echClient.FetchConfig(ctx); err != nil {
				return nil, err
			}
		}
	}
	if options.KernelRx || options.KernelTx {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTLSClientConfig{
			Config:   config,
			logger:   logger,
			kernelTx: options.KernelTx,
			kernelRx: options.KernelRx,
		}
	}
	return config, nil
}
