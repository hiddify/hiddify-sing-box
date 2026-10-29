package option

// MASQUEDeviceOptions is a WARP device already enrolled for MASQUE, as share links and other
// clients carry it: the outbound uses it as is, without Cloudflare's API, which is blocked on
// many networks.
type MASQUEDeviceOptions struct {
	// PrivateKey is the device's ECDSA key: base64 (standard or URL) of SEC 1 or PKCS #8 DER.
	PrivateKey string `json:"private_key"`
	// EndpointPublicKey is the key of Cloudflare's endpoint: PEM, or base64 of PKIX DER.
	EndpointPublicKey string `json:"endpoint_public_key"`
	// IPv4 and IPv6 are the tunnel addresses; at least one is required.
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
	// The endpoints, an IP or "ip:port" (the port is not used: 443). The HTTP/2 ones are
	// Cloudflare's defaults when empty.
	EndpointV4   string `json:"endpoint_v4,omitempty"`
	EndpointV6   string `json:"endpoint_v6,omitempty"`
	EndpointH2V4 string `json:"endpoint_h2_v4,omitempty"`
	EndpointH2V6 string `json:"endpoint_h2_v6,omitempty"`
	ID           string `json:"id,omitempty"`
	License      string `json:"license,omitempty"`
}
