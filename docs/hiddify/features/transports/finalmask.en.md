# finalmask

[فارسی](finalmask.fa.md) · [All Hiddify features](../../index.md)

`finalmask` applies Xray-core's finalmask masks to the connections an outbound opens. A mask
changes the bytes on the wire: it splits them, adds noise packets, adds headers, or wraps them in
another protocol (DNS, ICMP, a Minecraft-like stream and more). It is the `finalmask` field of the
dial fields, so you can set it on any outbound that dials (and on DNS servers and other places that
take dial fields). The JSON is the same as Xray's `streamSettings.finalmask`.

## Why use it

- To use an Xray server that is set up with finalmask masks: the client must apply the same
  masks, or the server cannot read the traffic.
- To change how a connection looks on the wire without changing the protocol: split the TLS
  ClientHello (`fragment`), send junk UDP packets before a WireGuard or QUIC handshake (`noise`),
  or obfuscate UDP with a password (`salamander`).

## How it gets past filtering

Filters match on the first bytes and packets of a connection, their sizes and their timing.
Masks change exactly that. `fragment` cuts the ClientHello into small pieces so a filter that does
not reassemble them cannot read the SNI. `noise` sends random packets first, so the real handshake
does not start the flow. Header and wrapping masks make the traffic look like another protocol, or
like random bytes.

Masks that only change sizes and timing (`fragment`, `noise`) work with any server. Masks that
change the content (headers, `salamander`, `sudoku`, `xdns`, `xicmp`, `xmc`, `mkcp-legacy`,
`realm`) need the same mask on the server, which means an Xray server configured for it. A mask
does not help when the filter blocks the server's IP address.

## How it works

- `tcp` masks wrap every TCP connection the outbound opens, and `udp` masks every UDP socket and
  connected UDP connection.
- Masks run in list order: the first mask gets the bytes the outbound writes, and the last mask's
  output goes on the wire. Replies pass through them in reverse.
- The masks sit under the protocol and its TLS layer, so they see exactly what would go on the
  wire. With `detour`, they wrap the connection made through the detour outbound.
- Only the client side is implemented: inbounds do not take `finalmask`.
- The masks are Xray-core's own code (ported from Xray-core v26.7.28), so their behavior and
  settings follow Xray's documentation for `finalmask`.

## Configuration

A VLESS outbound whose ClientHello is fragmented, and a WireGuard endpoint that sends noise before
each handshake:

```json
{
  "outbounds": [
    {
      "type": "vless",
      "server": "example.com",
      "server_port": 443,
      "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
      "tls": { "enabled": true, "server_name": "example.com" },
      "finalmask": {
        "tcp": [
          { "type": "fragment", "settings": { "packets": "tlshello", "length": "100-200", "delay": "10-20" } }
        ]
      }
    }
  ],
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wg",
      "address": ["10.0.0.2/32"],
      "private_key": "...",
      "peers": [{ "address": "203.0.113.1", "port": 51820, "public_key": "...", "allowed_ips": ["0.0.0.0/0"] }],
      "finalmask": {
        "udp": [
          { "type": "noise", "settings": { "noise": [{ "rand": "10-50", "delay": "5-10" }] } }
        ]
      }
    }
  ]
}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `finalmask.tcp` | array | — | Masks for TCP connections, in order. |
| `finalmask.udp` | array | — | Masks for UDP, in order. |
| `finalmask.quicParams` | object | — | Accepted so Xray configs load; not used. QUIC protocols have their own options in sing-box. |
| `…[].type` | string | — | Mask type (see below). Case does not matter. |
| `…[].settings` | object | `{}` | The mask's settings, exactly as in Xray. |

Supported mask types:

| Type | `tcp` | `udp` | What it does | Main settings |
|---|---|---|---|---|
| `fragment` | yes | — | Splits the first writes (or the TLS ClientHello) into small pieces with delays. | see below |
| `header-custom` | yes | yes | Adds custom bytes the server expects (a fake protocol header). | TCP: `clients`, `servers`, `errors`; UDP: `mode`, `client`, `server` |
| `sudoku` | yes | yes | Sudoku obfuscation, keyed by a password. | `password`, `ascii`, `customTable`, `customTables`, `paddingMin`, `paddingMax` |
| `xmc` | yes | — | Makes the stream look like a Minecraft connection. | `hostname`, `profiles`, `password` |
| `noise` | — | yes | Sends random or fixed packets before the real ones. | `noise` (list of `rand`, `randRange`, `type`, `packet`, `delay`), `reset` |
| `salamander` | — | yes | Hysteria2's Salamander obfuscation; with `packetSize`, the Gecko variant that also changes packet sizes. | `password`, `packetSize` (at most 2048) |
| `mkcp-legacy` | — | yes | mKCP's old packet headers (`dns`, `dtls`, `srtp`, `utp`, `wechat`, `wireguard`) or its AES-GCM layer. | `header`, `value` |
| `xdns` | — | yes | Carries UDP in DNS queries. | `resolvers` (client, each with `+udp://`) |
| `xicmp` | — | yes | Carries UDP in ICMP echo packets. | `ips`, `dgram` |
| `realm` | — | yes | Connects to the peer through NAT hole punching, using STUN servers and a rendezvous URL. | `url` (`realm://` or `realm+http://`), `stunServers`, `tlsConfig` |

An unknown type, a TCP-only type in `udp` (or the other way round) or bad settings is a
configuration error that names the mask, such as `finalmask.tcp[0] fragment`.

`fragment` settings:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `packets` | string | — | `tlshello` splits the TLS ClientHello; a range such as `"1-3"` splits those writes of the connection. |
| `length` | range | — | Size of each piece in bytes. |
| `delay` | range | `0` | Wait between pieces in milliseconds. |
| `lengths` | range list | — | One length per piece, in place of `length`. |
| `delays` | range list | — | One delay per piece, in place of `delay`. |
| `maxSplit` | range | — | Largest number of pieces. |

A range is `"from-to"` or a number; a range list is an array of them, or a single one.

Related options: the outbound's [`tls_fragment`](../tls-fragment.en.md) is added as the first
`fragment` mask. [`tls_tricks`](../tls-tricks.en.md) changes the ClientHello itself and is not a mask.
`tls_fragment` cannot be used with `tcp_fast_open`.

## See also

- [TLS fragment](../tls-fragment.en.md)
- [TLS tricks](../tls-tricks.en.md)
- [XHTTP transport](xhttp.en.md)
