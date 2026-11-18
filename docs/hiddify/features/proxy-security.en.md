# Proxy security

[فارسی](proxy-security.fa.md) · [All Hiddify features](../index.md)

Every outbound and endpoint is marked secure or not secure from its options, with the reason when
it is not. The app shows the mark in the proxy list. There is no option: it is worked out when the
outbound is created.

## Why use it

A proxy gets traffic past filtering, but not every proxy hides it. A SOCKS or HTTP proxy, VLESS or
Trojan without TLS, or Shadowsocks with method `none` sends everything in the clear: the network
between the device and the server, and whoever filters it, can read and change it. TLS with
`insecure` on accepts any certificate, so anyone on the way can stand in for the server. Users
rarely see this in a share link; the mark tells them.

## How it gets past filtering

It does not. It only reports what the other options already do.

## How it works

A proxy is **secure** when something encrypts its traffic and checks who the server is:

- its own encryption: Shadowsocks (not `none`), VMess (not `none` or `zero`), VLESS encryption,
  Snell, Mieru, Sudoku, WireGuard, AmneziaWG, WARP, SSH, Tor, Psiphon, OpenVPN, Tailscale, dnstt,
  Soar, GooseRelay, MasterDnsVPN with a real cipher;
- or TLS that verifies the server's certificate;
- or TLS with `insecure` on, but the certificate pinned (`certificate_sha256` or
  `certificate_public_key_sha256`; for MASQUE, `certificate_public_key_sha256`);
- or REALITY, which checks the server by its public key.

Otherwise it is **not secure**, for one of these reasons (`C.Insecure*`):

| Reason | Meaning | Examples |
|---|---|---|
| `plaintext` | nothing encrypts the traffic | SOCKS; HTTP, VLESS, Trojan, AnyTLS, Hysteria, TUIC, Naive or TrustTunnel without TLS |
| `no_cipher` | its own encryption is off and no TLS replaces it | Shadowsocks `none`, VMess `none`/`zero`, Sudoku `aead_method: none`, MasterDnsVPN `encryption: none` |
| `weak_cipher` | its own encryption only hides the data | ShadowsocksR `table`/`rc4`, MasterDnsVPN `xor` (its default) |
| `tls_insecure` | TLS with `insecure` on and no pinned certificate | Trojan, VLESS, Hysteria2 with `insecure: true`; MASQUE with `insecure: true` and no pin |

VMess with a cipher stays secure with `insecure` TLS: its own encryption, keyed by the UUID, still
protects the traffic. VMess `none` takes the reason of its TLS. A lazy outbound is judged by the
options of the real one. An `xray` outbound is judged by its first proxy outbound in the Xray
config: its protocol, `streamSettings.security` and `tlsSettings.allowInsecure` with the
`pinnedPeerCertSha256` family. Groups (selector, urltest, balancer, fallback), direct, block,
ShadowTLS (its inner proxy decides) and Bond have no reason.

The outbound and endpoint managers keep the reason of each tag when they create it, also on a hot
reload, and drop it when the outbound is removed.

## Configuration

Nothing to configure. In Go:

```go
reason := adapter.InsecureReason(box.Outbound(), "my-proxy") // "" when secure
reason = option.InsecureReason(&option.SOCKSOutboundOptions{})  // C.InsecurePlaintext
```

| Function | Returns |
|---|---|
| `option.InsecureReason(options any)` | the reason of an outbound or endpoint with these options (a pointer, as the registry creates them) |
| `adapter.InsecureReason(manager, tag)` | the reason the outbound manager keeps for the outbound or endpoint `tag`; "" for a group or an unknown tag |

hiddify-core sends it in `OutboundInfo.is_secure` and `OutboundInfo.insecure_reason`.

## Notes

- The mark is about the path between the device and the proxy server. Past the server, a site
  without HTTPS is readable whatever the proxy.
- A detour does not change the mark: a SOCKS proxy dialed through a secure one is still read in
  the clear between the secure one's server and the SOCKS server.
- WireGuard-family endpoints without a peer key check are not looked into; they are taken as
  encrypted.

## See also

- [REALITY in Hiddify](reality-hiddify.en.md)
- [App considerations](../app_considerations.md)
