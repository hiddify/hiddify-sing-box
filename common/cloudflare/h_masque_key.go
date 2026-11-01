package cloudflare

// MASQUEEndpointPublicKey is the P-256 public key (PKIX DER, base64) of the fixed self-signed
// certificate Cloudflare's MASQUE edge presents: the same on the WARP (162.159.198.0/24,
// 2606:4700:103::/48), WARP+ (162.159.199.2) and Zero Trust (162.159.197.2) endpoints, on every
// port. It is what registration hands out as the peer's key, so a device enrolled elsewhere
// (a masque:// link) can pin the endpoint without it. Read on 2026-11-02 with
// `openssl s_client -connect 162.159.199.2:443 -servername consumer-masque.cloudflareclient.com`.
const MASQUEEndpointPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w=="
