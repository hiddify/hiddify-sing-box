package masque

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"

	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// deviceConfig is the tunnel config of an enrolled device (option device), with its keys in the
// forms Config reads: SEC 1 DER in base64, and PEM. A device that cannot work fails the config.
func deviceConfig(device *option.MASQUEDeviceOptions) (*Config, error) {
	keyDER, err := decodeBase64(device.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "MASQUE device private_key")
	}
	if _, err := x509.ParseECPrivateKey(keyDER); err != nil {
		parsed, pkcs8Err := x509.ParsePKCS8PrivateKey(keyDER)
		key, isECDSA := parsed.(*ecdsa.PrivateKey)
		if pkcs8Err != nil || !isECDSA {
			return nil, E.New("MASQUE device private_key is not an ECDSA key")
		}
		if keyDER, err = x509.MarshalECPrivateKey(key); err != nil {
			return nil, err
		}
	}
	publicKey := strings.TrimSpace(device.EndpointPublicKey)
	if !strings.HasPrefix(publicKey, "-----BEGIN") {
		publicDER, err := decodeBase64(publicKey)
		if err != nil {
			return nil, E.Cause(err, "MASQUE device endpoint_public_key")
		}
		publicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	}
	config := &Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(keyDER),
		EndpointV4:     endpointHost(device.EndpointV4),
		EndpointV6:     endpointHost(device.EndpointV6),
		EndpointH2V4:   endpointHost(device.EndpointH2V4),
		EndpointH2V6:   endpointHost(device.EndpointH2V6),
		EndpointPubKey: publicKey,
		License:        device.License,
		ID:             device.ID,
		IPv4:           endpointHost(device.IPv4),
		IPv6:           endpointHost(device.IPv6),
	}
	if config.EndpointH2V4 == "" && config.EndpointH2V6 == "" {
		config.EndpointH2V4, config.EndpointH2V6 = cloudflare.DefaultEndpointH2V4, cloudflare.DefaultEndpointH2V6
	}
	if config.EndpointV4 == "" && config.EndpointV6 == "" {
		return nil, E.New("MASQUE device has no endpoint")
	}
	if _, err := config.GetEcEndpointPublicKey(); err != nil {
		return nil, E.Cause(err, "MASQUE device endpoint_public_key")
	}
	if _, err := config.Addresses(); err != nil {
		return nil, err
	}
	return config, nil
}

// decodeBase64 reads standard or URL base64, with or without padding.
func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimRight(strings.TrimSpace(value), "=")
	if strings.ContainsAny(value, "-_") {
		return base64.RawURLEncoding.DecodeString(value)
	}
	return base64.RawStdEncoding.DecodeString(value)
}
