# WARP

[فارسی](warp.fa.md) · [All Hiddify features](../../index.md)

WARP connects you to Cloudflare's free WARP VPN over WireGuard, over AmneziaWG when you set
`awg`, or over MASQUE (HTTP/3 or HTTP/2) when you set `masque`. It registers a free WARP account
by itself, so you don't need a key or a server. It can also send fake packets before each
handshake, look for a Cloudflare address that answers, and switch to another one when the
address in use stops working. It is an endpoint: `"type": "warp"` in the `endpoints` list.

## Why use it

- You get a working VPN with no server of your own and no account setup.
- The traffic leaves from a Cloudflare address, which many sites trust more than a VPS address.
- The scanner finds an address and port that work on your current network, and remembers them
  per network. When you move from home Wi-Fi to mobile data, it starts from what worked there
  before.

If your network blocks UDP, or blocks WireGuard even with noise, set `masque`: the tunnel then
runs over HTTP/3, or HTTP/2 on TCP. See [WARP over MASQUE](warp-masque.en.md) for how MASQUE
gets past filtering.

## How it gets past filtering

- **Noise.** Before each WireGuard handshake, WARP can send a few fake packets. Some filters
  only look at the first packets of a UDP flow, and a flow that starts with something else is
  not seen as WireGuard. In `quic` mode the fake packets are real QUIC version 1 Initial packets
  with a TLS ClientHello for a well-known name (`www.google.com` by default). A filter that
  decrypts QUIC Initials sees the start of a normal QUIC connection to that site.
- **Other addresses and ports.** Cloudflare serves WARP on many addresses and ports. When the
  default one is blocked, the scanner finds one that is not.
- **A new source port.** When handshakes keep failing, the WireGuard device opens a new socket
  on a new source port. This helps when a filter has flagged one connection, or when a NAT
  mapping expired while the device slept.

Limits: noise does not help against a filter that blocks all UDP, or all traffic to
Cloudflare's WARP ranges. The traffic is still WireGuard after the noise, so a filter that
checks the whole flow can still find it.

## How it works

**Account.** At start, WARP needs a profile: a private key, the tunnel addresses and the
Cloudflare peer. It takes the first one it finds:

1. The saved profile in the cache file, when `cache_file.store_warp_config` is on and
   `profile.recreate` is off. It is saved under `unique_identifier`, or the tag when that is
   empty.
2. A profile written in the config itself (`private_key`, `interface`, `peers`).
3. A new free account, registered with Cloudflare's API. With `profile.license`, the license
   (for example a WARP+ key) is applied to it. The request goes through `profile.detour` when
   set. If it fails, WARP tries again through each outbound in turn.

A new profile is saved in the cache file when `store_warp_config` is on, so later starts don't
register a new account. When registration fails, it is tried again after 1 s, then after twice
as long each time, up to every 30 s, until it works or the endpoint closes.

**Tunnel.** WARP then starts one of three tunnels inside it:

- WireGuard, by default.
- AmneziaWG, when any `awg` setting is set.
- MASQUE, when any `masque` setting is set, or `masque.enabled`. The device gets a MASQUE key
  instead of using its WireGuard one, so it is registered and saved apart from the WireGuard
  device of the same endpoint (under `unique_identifier` + `/masque`). The scanner then looks for
  MASQUE endpoints over HTTP/3 and HTTP/2. `server` and `server_port` set the MASQUE server.

`awg` and `masque` together are a config error. When the first start fails (AmneziaWG fails at
once when its detour does not work yet), it is tried again in the same way as registration.

**Peer.** The tunnel uses the profile's IPv4 peer address (its IPv6 one when there is no IPv4
one) and one of its ports, chosen at random. `server` and `server_port` replace them. Without the
scanner and without `server_port`, a port that completes no handshake within 10 seconds is
replaced by the profile's next port.

**Connected state.** The peer gets a keepalive every 25 seconds, as in the WARP apps, so the
handshake stays fresh while the path works. WARP counts as connected (no "Connecting...") only
while the last handshake is less than 3 minutes old; through a detour that stops working, it
shows as connecting again. Over MASQUE, it counts as connected while it has a connection to the
server.

**Status and display type.** The type shown for the endpoint names the tunnel:
`WARP · WG`, `WARP · AWG` or `WARP · MASQUE`; then, once the scanner has chosen,
` · 🔍 <address:port>` or ` · 🔍 Not found`; then the mark of its status, as for every outbound
and endpoint:

| Status | Mark | When |
|---|---|---|
| registering | ` 🔑 Registering...` | A device is being registered. |
| searching | ` 🔍 Searching...` | The scanner looks for an endpoint that answers. |
| connecting | ` ⏳ Connecting...` | It has not connected yet. |
| reconnecting | ` ⏳ Reconnecting...` | It was connected and the peer stopped answering. |
| failed | ` ❌ Failed` | The config cannot work (a profile without peers, MASQUE not in the build). |
| ready | | It carries traffic. |

The hourglass flips between ⏳ and ⌛ each second. For example
`WARP · MASQUE · 🔍 162.159.198.1:443`, or `WARP · WG ⏳ Reconnecting...`.

**Group detour.** When `detour` is a group (a selector, URL test or balancer), WARP follows the
member it resolves to, through nested groups. When the group moves to another member, WARP
reconnects through the new one: the WireGuard or AmneziaWG socket, or the MASQUE connection,
would otherwise stay on the member the group left.

**Noise.** Before each handshake initiation, the device sends `count` fake packets, with a
random `delay` between them. In the default mode each packet is a short header and `size`
random bytes. In `quic` mode the first packet carries the ClientHello for `sni`, and the others
carry PING frames, as QUIC retransmissions would. Noise applies to the WireGuard mode. With
`awg`, AmneziaWG's own junk settings are used instead.

**Handshake recovery.** After 3 unanswered handshake initiations, when there is no working
session, the device reopens its socket on a new source port. It also does this when it gives up
on a handshake. This happens at most once every 90 seconds. A set `listen_port` is kept.

**Scanner.** With `scanner.enabled`, WARP looks for an endpoint (address and port) that
answers before it connects:

- Each probe is a real WireGuard handshake made with the profile's keys, sent after the
  configured noise, through the endpoint's own dialer. `detour` and interface binding apply.
- Endpoints are tried in this order: the endpoints known on this network, by score; then
  endpoints that scored well on other networks; then random addresses in `cidrs` on `ports`;
  then endpoints at the lowest score (-10) last.
- An endpoint that answers slower than `max_rtt` counts as a failure.
- The scan ends when an endpoint with a score of 3 or more answers, or when 4 endpoints have
  answered. Among the answers, the higher score wins, then the lower round-trip time.
- IPv4 and IPv6 ranges are both scanned when the network has a global address of that family.
  When one family is unreachable, it is skipped for the rest of the scan.
- If no endpoint answers, WARP uses the profile's endpoint.
- The scanner is off when `server` is set.

**Scores.** Each endpoint has a score from -10 to 10 on each network:

- An answer adds 1, up to 10. An answer from a negative score sets it to 1.
- A failure takes 1, at most once an hour, so one outage costs one point.
- An endpoint that answered in the last 7 days never drops below -5.

Scores are kept in the cache file when `cache_file` is enabled. A network not seen for 90 days
is forgotten, and each network keeps its best 64 endpoints.

**Network names.** A network is named by the type of the default interface (Wi-Fi, cellular,
ethernet), plus the country and the /16 (IPv4) or /32 (IPv6) of the public address. The public
address comes from `https://www.cloudflare.com/cdn-cgi/trace`, or from
`https://www.speedtest.net/cdn-cgi/trace` when the first does not answer. The request goes
through the endpoint's dialer. This keeps a carrier's address pool, or an ISP that changes your
address, as one network. The Wi-Fi name is not used, because reading it needs a location
permission. When neither trace answers, the interface type alone names the network.

**Failover.** With the scanner on, WARP checks the endpoint in use:

- after a network change (it waits 2 seconds, then names the new network), and
- every minute, when traffic goes out but no handshake has completed for 3 minutes.

The check probes the endpoint in use twice. If it answers, its score goes up. If not, its score
goes down, and WARP scans again without it. It starts a new inner WireGuard endpoint on the best
answer, switches traffic to it, and then closes the old one. If the scan finds nothing, WARP
keeps the current endpoint. The first handshake of each endpoint also counts as an answer.

## Configuration

```json
{
  "experimental": {
    "cache_file": {
      "enabled": true,
      "store_warp_config": true
    }
  },
  "endpoints": [
    {
      "type": "warp",
      "tag": "warp",
      "noise": {
        "fake_packet": {
          "enabled": true,
          "mode": "quic",
          "count": "2-4",
          "delay": "10-30"
        }
      },
      "scanner": {
        "enabled": true
      }
    }
  ],
  "route": {
    "final": "warp"
  }
}
```

### Endpoint fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `profile` | object | | How to get the WARP account. See below. |
| `unique_identifier` | string | the tag | Key of the saved profile and scores in the cache file. |
| `server` | string | profile's peer | Peer address to use instead of the profile's. Turns the scanner off. |
| `server_port` | number | a profile port | Peer port to use instead of the profile's. |
| `noise` | object | off | Fake packets before each handshake. See below. |
| `awg` | object | | AmneziaWG settings (`jc`, `jmin`, `jmax`, `s1`–`s4`, `h1`–`h4`, `i1`–`i5`). When any is set, the tunnel uses AmneziaWG instead of WireGuard. |
| `masque` | object | | MASQUE settings. When any is set, or `enabled`, the tunnel uses MASQUE instead of WireGuard. See below. Needs the `with_masque` build tag. |
| `scanner` | object | off | Endpoint scanner and failover. See below. |
| `mtu` | number | WireGuard default | Tunnel MTU. |
| `system` | bool | `false` | Use a system interface, as in the `wireguard` endpoint. |
| `name` | string | | Interface name when `system` is on. |
| `listen_port` | number | random | Local UDP port. |
| `udp_timeout` | duration | | UDP NAT timeout, as in the `wireguard` endpoint. |
| `workers` | number | | WireGuard worker count, as in the `wireguard` endpoint. |
| `private_key`, `interface`, `peers` | | | A complete WARP profile in Cloudflare's format. When given, no account is registered. |

Dial fields (`detour`, `bind_interface` and the rest) apply to the tunnel, the scanner probes
and the network name check.

### `profile`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `private_key` | string | random | WireGuard private key for the new account. |
| `license` | string | | WARP license key to apply to the new account (for example WARP+). |
| `id`, `auth_token` | string | | An existing device. With both, the device is fetched instead of registered, and `private_key` is required: it must be the device's own key. |
| `detour` | string | direct | Outbound tag used to reach Cloudflare's API for registration. |
| `recreate` | bool | `false` | Ignore the saved profile and get a new one. |

### `masque`

An empty `masque` object is dropped when the config is read, so write `"masque": {"enabled": true}`
to use MASQUE with every default.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Use MASQUE with every default. |
| `vhttp` | string | `auto` | `h3`, `h2`, or `auto` (HTTP/3, falling back to HTTP/2). |
| `server_name` | string | `consumer-masque.cloudflareclient.com` | TLS server name. |
| `use_ipv6` | bool | `false` | Use the IPv6 endpoint. |
| `tls` | object | | `insecure`, `cipher_suites`, `curve_preferences`, `fragment`, `fragment_fallback_delay`, `record_fragment`, `kernel_tx`, `kernel_rx`. |
| `udp_keepalive_period` | duration | `30s` | QUIC keepalive. |
| `udp_initial_packet_size` | number | | First QUIC packet size. |
| `reconnect_delay` | duration | | Wait between connect attempts. |

The endpoint's `mtu` (1280 to 9000 over MASQUE), `udp_timeout`, `scanner`, `server`,
`server_port` and dialer fields apply too. `noise`, `listen_port`, `workers`, `system` and `name`
are WireGuard settings and are not used.

### `noise.fake_packet`

Ranges take a number (`5`), a string (`"5-10"`) or an object (`{"from": 5, "to": 10}`).

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Send fake packets. |
| `count` | range | | Number of packets before each handshake. Nothing is sent when it is 0. |
| `delay` | range | | Wait between packets, in milliseconds. |
| `mode` | string | `""` | `quic` sends real QUIC Initial packets. Empty sends random packets. |
| `sni` | string | `www.google.com` | Server name in the QUIC ClientHello. Only for `quic` mode. |
| `size` | range | | Random bytes in each packet. Needed in the default mode. Not used in `quic` mode. |
| `header` | bytes (base64) | | Bytes to pick the first byte of each packet from. Not used in `quic` mode. |
| `no_modify` | bool | `false` | Send packets as they are, without the changes the WireGuard connection makes to its packets. `quic` mode always sends them as they are. |

### `scanner`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Scan for an endpoint that answers, and fail over. |
| `ports` | list of numbers | profile's ports, or a built-in list of WARP ports | Ports to try on random addresses. |
| `cidrs` | list of prefixes | Cloudflare's WARP ranges | Ranges to pick random addresses from. |
| `max_rtt` | duration | `1s` | Slowest handshake accepted. |
| `timeout` | duration | `2s` | How long one probe waits for an answer. |
| `count` | number | `64` | Most endpoints tried in one scan. Known endpoints are always tried. |
| `concurrency` | number | `8` | Probes run at once. |

The default ranges are `162.159.192.0/24`, `162.159.193.0/24`, `162.159.195.0/24`,
`188.114.96.0/24` to `188.114.99.0/24`, `2606:4700:d0::/64` and `2606:4700:d1::/64`.

Notes:

- The endpoint needs the `with_wireguard` build tag, and `awg` needs `with_awg`. Both are in the
  default tags.
- The profile and the scores live in the cache file. Without `cache_file`, each start registers
  a new account and the scanner starts with no history.
- The tunnel starts in the background. Connections wait for the first start to finish. If it
  failed, they fail with "endpoint not initialized".
- If registration or the first start fails, the error is logged and it is tried again until it
  works or the endpoint closes.

## See also

- [WARP over MASQUE](warp-masque.en.md)
