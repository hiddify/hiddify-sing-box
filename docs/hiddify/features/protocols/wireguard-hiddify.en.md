# WireGuard: Hiddify additions

[فارسی](wireguard-hiddify.fa.md) · [All Hiddify features](../../index.md)

Hiddify adds a few things to the upstream WireGuard endpoint (`"type": "wireguard"`): fake
"noise" packets before each handshake, a user name per peer, automatic recovery when the UDP
socket stops working, and UDP fragmentation turned on by default. Everything else in the endpoint
works as in upstream sing-box and is documented there. This page covers only the Hiddify parts.

## Why use it

- **Noise** helps when a network blocks WireGuard by its first packet. It works with any normal
  WireGuard server, because the server simply drops the fake packets.
- **Peer user names** give per-user stats and `auth_user` route rules when you run WireGuard as a
  server.
- **Recovery** brings the tunnel back on its own after the device sleeps, the NAT mapping expires
  or the network drops the flow, instead of waiting for a network change.
- **UDP fragmentation** keeps WireGuard working inside another tunnel with a smaller MTU.

## How it gets past filtering

Many filters look only at the first few packets of a UDP flow. If those do not look like a
WireGuard handshake, the flow is let through or classified as something else. With noise turned
on, the client sends a few fake packets to the server before every handshake initiation:

- In the default mode the packets are random bytes with a header that looks like the start of a
  QUIC packet.
- In `quic` mode the packets are real QUIC version 1 Initial packets to the name you set in `sni`.
  A filter that decrypts QUIC Initials (anyone can, the keys come from the packet itself) finds a
  valid TLS 1.3 ClientHello for that name with ALPN `h3`. The flow then looks like the start of an
  HTTP/3 connection.

Noise does not change the WireGuard packets themselves. A filter that reads the whole flow can
still find the handshake after the noise. For that case, use [AmneziaWG](amneziawg.en.md).
Noise also does not help when UDP is blocked.

## How it works

### Noise

- Before each handshake initiation, including retries, the client sends `count` fake packets,
  waiting `delay` milliseconds between them. Then it sends the handshake.
- In the default mode each packet is: one byte picked at random from `header` (if set), the bytes
  `00 00 00 01 08`, 8 random bytes, the bytes `00 00 44 D0`, then `size` random bytes.
- In `quic` mode the first packet carries the ClientHello and the rest carry PING frames, as QUIC
  retransmissions would. Each packet is padded to at least 1200 bytes. `size` and `header` are not
  used.
- For a peer given by domain, the noise goes to every resolved address of that domain.
- A noise packet that fails to send is logged and skipped; it never stops the handshake.

### Peer user names

WireGuard accepts a packet from a peer only when its source address is in that peer's
`allowed_ips`. So the source address of a connection tells which peer sent it. When a peer has a
`name`, connections from its addresses get that user name, the same as a user of a VLESS or Trojan
inbound. When `allowed_ips` of named peers overlap, the most specific prefix wins.

### Recovery (Hiddify's wireguard-go)

The endpoint runs on Hiddify's copy of wireguard-go (`replace/wireguard-go`), which adds:

- **New port after failed handshakes.** A handshake that keeps failing from the same socket rarely
  recovers. After 3 unanswered initiations (about 15 seconds) while the peer has no valid session,
  or when a handshake cycle gives up, the socket is reopened on a new random port, which gives a
  new UDP flow. A configured `listen_port` is kept. This happens at most once every 90 seconds.
- **Reopen when receiving fails.** If the socket returns a permanent error, or ten errors in a row,
  the socket is reopened one second later. Before, the tunnel stopped receiving until the network
  changed.
- **IPv4 kept without IPv6.** When the endpoint opens its own sockets (no `detour`) and the IPv6
  socket cannot be opened (IPv6 off, or no IPv6 on the bound interface), the endpoint keeps
  working on IPv4. Before, it did not start.
- **Bounded waits.** Dialing the UDP connection through a `detour` gives up after 15 seconds and is
  retried, so a hung detour does not block the tunnel. TCP connections through the tunnel give up
  after 15 seconds instead of about a minute.

### UDP fragmentation

The endpoint now lets the system fragment its UDP packets, as official WireGuard does. Before, the
"don't fragment" flag was set, so a packet larger than the path MTU (for example WireGuard inside
another tunnel) was dropped. Set `"udp_fragment": false` to get the old behavior.

## Configuration

```json
{
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wg-out",
      "address": ["10.8.0.2/32"],
      "private_key": "<base64 private key>",
      "peers": [
        {
          "address": "203.0.113.10",
          "port": 51820,
          "public_key": "<base64 server public key>",
          "allowed_ips": ["0.0.0.0/0", "::/0"]
        }
      ],
      "noise": {
        "fake_packet": {
          "enabled": true,
          "count": "2-4",
          "delay": "5-15",
          "mode": "quic",
          "sni": "www.google.com"
        }
      }
    }
  ]
}
```

### Noise fields (`noise.fake_packet`)

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Send fake packets before each handshake. |
| `count` | range | none | How many packets to send. Nothing is sent while this is `0`. |
| `size` | range | none | Random bytes per packet, in the default mode. Nothing is sent in the default mode while this is `0`. |
| `delay` | range | `0` | Milliseconds to wait between two fake packets. |
| `mode` | string | `""` | `""` for random packets, `"quic"` for real QUIC Initial packets. |
| `sni` | string | `"www.google.com"` | Server name in the QUIC ClientHello. Only used with `"mode": "quic"`. |
| `header` | list of bytes | none | Default mode only: each packet starts with one of these bytes, picked at random. Write it as numbers, such as `[192, 193, 194]`, or as a base64 string. |
| `no_modify` | bool | `false` | Default mode only: send the packets exactly as built, without writing the peer's `reserved` bytes into them. `quic` mode always does this. |

A range is written as a number (`3`), a string (`"2-4"` or `"3"`), or an object
(`{"from": 2, "to": 4}`). Both ends are included, and each packet gets a new random value.
`from` must not be larger than `to`.

### Peer field

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | none | User name for connections from this peer. Stats and `auth_user` route rules see this name. |

### Dialer field default

| Field | Type | Default | Meaning |
|---|---|---|---|
| `udp_fragment` | bool | `true` | Let the system fragment WireGuard UDP packets. Upstream's default for this endpoint is `false`. |

### Notes

- The `warp` endpoint takes the same `noise` block and passes it to its WireGuard connection.
- A `wireguard` endpoint with an `awg` block fails to start: use the [`awg` endpoint](amneziawg.en.md)
  for AmneziaWG obfuscation, or the `awg` block of a `warp` endpoint.
- Noise works with any WireGuard server. The server needs no change.

## See also

- [AmneziaWG](amneziawg.en.md)
- [WARP](warp.en.md)
