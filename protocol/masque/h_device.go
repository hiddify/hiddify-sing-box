package masque

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/cloudflare"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// deviceConfig is the tunnel config of an enrolled device (option device), with its keys in the
// forms Config reads: SEC 1 DER in base64, and PEM. A device that cannot work fails the config.
// DeviceConfig is the tunnel config of a device enrolled elsewhere (a masque:// link's), for the
// warp endpoint: an error when it cannot work.
func DeviceConfig(device *option.MASQUEDeviceOptions) (*Config, error) {
	return deviceConfig(device)
}

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
	if publicKey == "" { // the edge's fixed certificate, as masque:// links leave it out
		publicKey = cloudflare.MASQUEEndpointPublicKey
	}
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
		EndpointPort:   endpointPort(device.EndpointV4, device.EndpointV6),
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

// endpointPort is the port of the first endpoint written with one, else 0.
func endpointPort(endpoints ...string) int {
	for _, endpoint := range endpoints {
		if _, port, err := net.SplitHostPort(endpoint); err == nil {
			if value, err := strconv.Atoi(port); err == nil && value > 0 && value <= 65535 {
				return value
			}
		}
	}
	return 0
}

// port is the port of the device's endpoints: the one its endpoints were given with, else 443.
func (c *Config) port() int {
	if c.EndpointPort != 0 {
		return c.EndpointPort
	}
	return profilePort
}

// decodeBase64 reads standard or URL base64, with or without padding.
func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimRight(strings.TrimSpace(value), "=")
	if strings.ContainsAny(value, "-_") {
		return base64.RawURLEncoding.DecodeString(value)
	}
	return base64.RawStdEncoding.DecodeString(value)
}
