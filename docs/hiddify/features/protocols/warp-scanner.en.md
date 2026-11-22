# WARP scanner and noise

[فارسی](warp-scanner.fa.md) · [All Hiddify features](../../index.md)

How a [WARP](warp.en.md) endpoint finds a way through a network that blocks it: the **endpoint
scanner** looks for a Cloudflare address and port that answers, **noise** sends a few decoy
packets before each WireGuard handshake, the **noise search** tries ready-made noises when the
configured one gets no answer, and **auto mode** races WireGuard, AmneziaWG and MASQUE. This page
explains how they work together. The fields are listed on the [WARP](warp.en.md) page.

## Why use it

- Many filters block WARP by the first packets of a flow: a WireGuard handshake initiation is
  easy to recognise (fixed size, fixed first bytes). Noise changes what the flow starts with.
- Filters block some Cloudflare addresses or ports and not others; the scanner finds one that
  works and remembers it for each network.
- A noise that works on one network can fail on another. The noise search finds one that works on
  the network you are on, and remembers it too.
- Auto mode does the same for the tunnel: on a network where UDP is throttled MASQUE may win,
  elsewhere WireGuard.

## How it gets past filtering

A filter that classifies a UDP flow by its first packets sees something else first:

| Noise | What the filter sees first |
|---|---|
| random (default) | short packets that start like a QUIC long header, then random bytes |
| `raw` | random bytes of random sizes, no structure at all |
| `quic` | a real QUIC version 1 Initial, with a TLS ClientHello for `www.google.com` |
| `packets` | whatever the templates build: a DNS query, a SIP request, a QUIC packet |

The WireGuard handshake follows in the same flow. A filter that only looks at the start lets it
through; one that keeps watching the whole flow can still find WireGuard, and then MASQUE (HTTPS
to Cloudflare) is the way out.

## How it works

### Noise modes

The noise of the `wireguard` and `warp` endpoints (`noise.fake_packet`) is sent before each
handshake initiation, `count` packets with a random `delay` between them:

- **Default mode** (no `mode`): each packet is one byte from `header` (or none), the bytes
  `00 00 00 01 08`, 8 random bytes, `00 00 44 D0`, then `size` random bytes. This came from
  GFW-knocker; it starts like a QUIC long header.
- **`raw`**: `size` random bytes, nothing else. This is Xray's WARP noise (`wnoise=random`) and
  AmneziaWG's junk packets.
- **`quic`**: real QUIC Initials for `sni` (`www.google.com` by default): the first carries the
  ClientHello, the others PING frames, as QUIC retransmissions would.
- **`packets`**: templates sent first, in order, in the AmneziaWG `i1`–`i5` syntax: `<b 0xHEX>`
  bytes, `<r N>` random bytes, `<rc N>` random letters and digits, `<rd N>` random digits, `<t>`
  the Unix time (4 bytes), `<qi SNI>` a QUIC Initial. Then the `count` packets of the mode.

With `awg`, AmneziaWG sends its own noise instead: `i1`–`i5`, then `jc` junk packets of `jmin` to
`jmax` bytes. Cloudflare only accepts standard WireGuard messages, so for WARP the AmneziaWG
headers `h1`–`h4` stay 1–4 and `s1`–`s4` stay 0: only the packets before the handshake change.

### Noise presets

Taken from WARP configs that work (Xray links and AmneziaWG "WG Mimic" configs). Each works as
WireGuard noise and as AmneziaWG settings.

| Preset | Sends before the handshake | Looks like |
|---|---|---|
| `xray-random` | 5 random packets of 5 to 10 bytes, 2 to 5 ms apart | nothing in particular: tiny packets break a size-based fingerprint |
| `quic` | 2 to 4 QUIC Initials for `www.google.com` | the start of an HTTP/3 connection to Google |
| `dns-google` | 3 DNS queries for `google.com` (A, AAAA, HTTPS), each with a random id, then 6 junk packets of 56 to 160 bytes | DNS traffic |
| `dns-cloudflare` | 2 DNS queries for `cloudflare.com` (A, AAAA), then 9 junk packets of 81 to 224 bytes | DNS traffic to Cloudflare |
| `dns-www-cloudflare` | 2 DNS queries for `www.cloudflare.com` (A, AAAA), then 6 junk packets of 43 to 109 bytes | DNS traffic to Cloudflare |
| `quic-mimic` | a recorded QUIC Initial (1,210 bytes: 276 recorded, 934 random) and a short-header packet, then 4 junk packets of 60 to 199 bytes | a QUIC connection |
| `sip` | a SIP `INVITE` and its `100 Trying` answer, then 10 junk packets of 42 to 224 bytes | a VoIP call setup |
| `stun` | 2 STUN Binding Requests, each with a random transaction id, then 4 junk packets of 40 to 120 bytes | a video call or WebRTC client checking its address |

As AmneziaWG settings, a preset's templates become `i1`, `i2`, … and its junk `jc`, `jmin`,
`jmax`; `quic` becomes `<qi www.google.com>` packets. `awg` mode without `awg` settings uses
`dns-google`.

The presets are not only for WARP: any [WireGuard](wireguard-hiddify.en.md) endpoint takes one
as its noise `mode` (`"mode": "sip"`), and any [AmneziaWG](amneziawg.en.md) endpoint as its `ip`
(`"ip": "sip"`). `dns` and `random` are short for `dns-google` and `xray-random`.

### Endpoint scanner

With `scanner.enabled`, before it connects WARP probes endpoints (address and port) with a real
WireGuard handshake made with the device's own key, after the same noise the tunnel will send,
through the endpoint's dialer (so `detour` applies). Endpoints are tried in this order: the ones
that worked on this network, by score; then ones that scored well elsewhere; then new addresses
in `cidrs` on `ports`; the lowest scores last. New addresses come from a walk: each network walks
the addresses and ports of each range in an order of its own, and a scan goes on where the last
one stopped, so an endpoint that failed is not tried again until the range was walked, and two
devices walk it in different orders. The ranges, and the blocks of addresses that answered, are
drawn by their rating on the network (see [Search and deep search](#search-and-deep-search)). The scan stops when an endpoint with a score of 3 or
more answers, or 4 have answered, and the best is used. Scores (-10 to 10 per endpoint and
network) are kept in the cache file; a network is named by its interface type, country and public
address range. After a network change, and when traffic goes out with no handshake for 3 minutes,
the endpoint in use is probed again and replaced when it no longer answers.

For MASQUE the scanner probes with a TLS handshake to the MASQUE endpoints, over HTTP/3 and HTTP/2
apart.

The same scanner, with its scores and its walk, finds the CDN edges of the
[Psiphon](psiphon.en.md) outbound.

### Ratings

Endpoints, noises and the tunnels of auto mode are each rated on each network, with the same
score that Hiddify uses for DNS resolvers and the servers of a sequential DNS group: from -10 to 10,
0 for unknown.

- A success adds 1, up to 10. A success from a negative score sets it to 1, so a choice that
  works again is not held back by its past.
- A failure takes 1, at most once an hour, so one outage costs one point. A choice that succeeded
  in the last 7 days never drops below -5.
- An endpoint is marked down only when it answered on the network before: a new endpoint that
  failed is not tried again before the walk of the space ends, so it is not recorded.
- A failure counts only when another choice succeeded in its place. When nothing answers at all,
  the network is the likely cause, not the choices, and no score moves: a scan in which no
  endpoint answers marks no endpoint down, a noise is marked down only when another noise got
  through, and a tunnel that stayed silent in a race only when another tunnel answered.

Noises and tunnels are drawn in a **weighted random order**: every 2.5 points double the chance
to come first, so a choice at 10 is 16 times as likely as an unknown one, and 256 times as likely
as one at -10. The noise or tunnel that works on the network is used most of the time, and the
others are still tried now and then: when the network starts blocking the one in use, or lets an
old one through again, the ratings follow without a reset. Endpoints are ranked, not drawn: the
scan already probes 8 at a time and adds random addresses, and the best answer wins.

### Last way first

The scanner remembers the way through that worked last: for each tunnel the endpoint and the
noise (kept when the endpoint's first handshake completes, or when a search found it), and in
auto mode the tunnel that connected. The next start tries it before anything else, on any
network:

1. Auto mode takes the tunnel that connected last without a race, unless it failed to connect on
   this network. The network is named meanwhile, for the tunnel ratings.
2. The tunnel makes two handshakes with the last endpoint, after the last noise, each within 3
   seconds, before the network is named or anything is scanned. When one answers, the endpoint
   connects at once, and shows as ready as soon as its handshake completes.
3. Then, in the background, the network is named, the answer counts there, and one scan round
   runs. WARP moves to an endpoint the round found only when it is clearly better: a higher
   score, or the same score and a handshake in less than two thirds of the time. The round does
   not show as a search.
4. When the last way does not answer, the start searches as before; in auto mode the tunnels
   race again first.

WARP over MASQUE does the same for each HTTP version: the endpoint its tunnel connected to last
is checked with one TLS handshake (two tries) before the first scan, and used when it answers. A
working MASQUE tunnel is not moved to a better endpoint: it takes the best one when it reconnects.

The ways are saved with the scores in the cache file (`edge-scanner`), for 30 days. A noise the
scanner may no longer use (`search_noise` turned off, a preset left out of `noise_presets`) is
not tried.

### Search and deep search

A search goes on round after round for `search_timeout` (1 minute): the first round usually
finds an endpoint, and on a network that filters most of them the next rounds walk on through
the ranges, each where the last stopped. A round that ends in less than 5 seconds waits for the
rest of them, so a small space is not probed in a tight loop. When nothing answers in that time,
the endpoint uses the profile's endpoint as before, and offers a **deep search**: the app asks
the user, since it may go on for hours and use a lot of battery and CPU. A deep search has no
time limit and runs `deep_concurrency` probes at once (twice `concurrency`); when it finds an
endpoint, WARP switches to it. `search_timeout` is the one setting: below zero, the search is a
deep one from the start (the endpoint starts with a 1 minute search, then goes on deep in the
background); above 3 minutes, a deep one with that limit. Phones scan with fewer workers than
desktops: `concurrency` is 8 on Android and iOS and 32 elsewhere, and all the scans of the
process together run at most 32 probes at once on a phone and 128 on a desktop, however many WARP
endpoints and Psiphon outbounds search.

**Behind another proxy** (a `detour` that is not `direct`), a search is a single round, as
before: it searches that proxy's network, and waiting minutes there only delays the fallback to
the profile's endpoint.

**Only with a network.** A search probes only while the device has a network: with no Wi-Fi
and no mobile data, or with the network paused by the system (a phone asleep), it waits, on the
network monitor's events and without polling, and spends no CPU or battery on probes that cannot
answer. The time it waits does not count toward `search_timeout`, so a search is not given up
because the network was away. Psiphon waits the same way before each attempt of its tunnel core.

**Shared between the scanners.** The WARP scanner (for WARP over WireGuard, AmneziaWG and
MASQUE) and the Psiphon scanner, when they reach the network
directly (no `detour`, or a `direct` one) share one store for the whole process: the same scores,
one name for the network, found once, and the same search when they look for the same thing at the
same time (two WARP endpoints with the same tunnel and noise wait for one search instead of
probing the network twice). The store survives a hot reload, so a changed outbound goes on with
what was learned, and it is saved in the cache file in one entry (`edge-scanner`), with a book
per kind of target. What an endpoint kept under its own key before joins it once. A scanner
behind another detour sees that detour's network, and keeps a store of its own.

**Blocks, sets and server names.** Each network also rates the address blocks it tried, an
IPv4 /24 and an IPv6 /48 by default (`block_bits_ipv4`, `block_bits_ipv6`), from -10 to 10 like
the endpoints: an answer adds a point, and a failure while other addresses answered takes one, at
most once an hour. New addresses are drawn by weighted random: a block that answered comes up
more the better it scored, and a block that did not answer only as often as its weight, so most
tries go where the network lets traffic through. The ranges (or the CDN sets of the Psiphon
scanner) and the TLS server names are drawn the same way, by their rating on the network: a scan
does not go through every name or every set in turn, and the ones that never answered still get
their turn.

**The cache.** The scores are kept in the cache file for 30 days: a network not seen for that
long is forgotten, and so is a record, block or rating that neither succeeded nor failed in that
time. A network keeps at most 128 endpoints and 512 blocks, and the book is saved in a compact
form (arrays of numbers, Unix times, short keys).

### Noise search

With `scanner.search_noise`, the scanner also looks for a noise:

1. The noises to try are the configured one (`noise`, or the `awg` settings) and the presets of
   `noise_presets` (all by default). They are drawn in a weighted random order by their rating on
   the network (see Ratings). Where no noise was rated yet, the configured noise counts as 2, so it
   comes first more often than an untried preset.
2. The scan runs with the first. It probes up to `count` endpoints when this noise got through on
   the network before, or when no noise has yet; otherwise at most 16: the endpoints known to
   answer come first, so a few are enough to tell.
3. When no endpoint answers, the scan runs with the next noise, on at most 16 endpoints.
4. The first noise that gets an answer is used: the tunnel starts with it. It gains a point on the
   network, and the noises tried before it lose one.

The probe always sends what the tunnel sends, so a noise that gets the probe through gets the
tunnel through. Each search costs at most the number of presets times 16 probes, run 8 at once,
beyond the first scan.

#### MASQUE: the server name as noise

MASQUE has no decoy packets: what a filter reads first is the TLS server name of its handshake,
`consumer-masque.cloudflareclient.com` by default, and a filter that knows it can block it. With
`search_noise`, the MASQUE scanner (of the `masque` outbound, and of the `warp` endpoint in
`masque` and `auto` modes) tries other server names the same way it tries noises:

| Preset | Server name |
|---|---|
| `speedtest` | `www.speedtest.net` |

The configured `server_name` (or the default) and the presets are drawn by their rating, scanned in
turn, and the first that gets an answer is used for the tunnel's connects, per HTTP version. It is
kept with the last way. Cloudflare's endpoint answers any server name, and the tunnel still pins
the endpoint's key, so the name changes nothing but what the filter sees. `noise_presets` names
the presets of both kinds: each tunnel takes its own, and a list with no MASQUE preset leaves
MASQUE with its configured name.

### Auto mode

With `"mode": "auto"`, WARP has a WireGuard, an AmneziaWG and a MASQUE device of its own, and
starts by racing the three tunnels:

1. One handshake with each at once, to the device's own endpoint: WireGuard with the endpoint's
   `noise`, AmneziaWG with its `awg` settings (or `dns-google`), MASQUE with a TLS handshake. Two
   tries each, within 5 seconds.
2. One of the tunnels that answered becomes the inner tunnel, drawn by its rating on the network
   (see Ratings), so the tunnel that connects there is used most of the time. The network is named
   during the race, and the scanner of the chosen tunnel takes the name over. A tunnel that stayed
   silent while another answered loses a point. `WARP · Auto 🔍 Searching...` shows during the
   race, then `WARP · WG`, `WARP · AWG` or `WARP · MASQUE`.
3. The chosen tunnel then runs as in its own mode: the scanner and the noise search apply to it
   (the WireGuard scanner for WireGuard and AmneziaWG, the MASQUE scanner for MASQUE).
4. The chosen tunnel has 20 seconds to connect. When it connects, it gains a point on the network.
   An answer to one handshake does not prove that the tunnel carries traffic: when it does not
   connect, it loses a point, the race runs again without it, and when every tunnel failed it
   starts over.
5. When none answered, one of the tunnels that did not fail to connect is drawn by rating, so the
   scanner and the noise search can still look for an endpoint and a noise.
6. When a group `detour` moves to another member, the race runs again: the new proxy may carry
   another tunnel better, or only one (a proxy without UDP, such as SOCKS4, carries MASQUE over
   HTTP/2 only). After a selector the user moved, at once; after a group that moved by itself (a
   URL test, a balancer), at most every 30 seconds, through a new tunnel next to the one in use
   that replaces it only once it connects (see [group detour](warp.en.md)). A network change
   forgets which tunnels failed.
7. While the endpoint has not been connected for 3 minutes, it races again, at most every 10
   minutes, and moves to another tunnel that answers.

The race uses the configured noise, not the presets: the noise search runs inside the tunnel that
was chosen.

## Configuration

Search endpoints and noise, with auto mode:

```json
{
  "experimental": {
    "cache_file": { "enabled": true, "store_warp_config": true }
  },
  "endpoints": [
    {
      "type": "warp",
      "tag": "warp",
      "mode": "auto",
      "noise": {
        "fake_packet": { "enabled": true, "mode": "quic", "count": "2-4", "delay": "10-30" }
      },
      "scanner": { "enabled": true, "search_noise": true }
    }
  ]
}
```

Only some presets:

```json
"scanner": { "enabled": true, "search_noise": true, "noise_presets": ["dns-google", "sip", "quic-mimic"] }
```

A DNS-looking noise for plain WireGuard, written by hand:

```json
"noise": {
  "fake_packet": {
    "enabled": true,
    "packets": ["<r 2><b 0x0100000100000000000106676f6f676c6503636f6d00000100010000291000000000000000>"],
    "mode": "raw",
    "count": "6",
    "size": "56-160"
  }
}
```

| Field | Where | Meaning |
|---|---|---|
| `scanner.enabled` | warp | Scan for an endpoint that answers, and fail over. |
| `scanner.search_noise` | warp, masque | Also look for a noise preset that gets through (for MASQUE, a server name). |
| `scanner.noise_presets` | warp, masque | The presets to try, in a weighted random order by their rating; all when empty. WireGuard and MASQUE presets can be mixed. An unknown name is a config error. |
| `noise.fake_packet.mode` | warp, wireguard | `""`, `raw` or `quic`. |
| `noise.fake_packet.packets` | warp, wireguard | Templates sent first, in the AmneziaWG `i1`–`i5` syntax. |
| `mode` | warp | `wg`, `awg`, `masque` or `auto`. |

The other scanner fields (`ports`, `cidrs`, `max_rtt`, `timeout`, `count`, `concurrency`) are on the
[WARP](warp.en.md) page.

## Notes

- The ratings of endpoints, noises and tunnels are kept in the cache file; without `cache_file`,
  every start scans from nothing. A noise saved by an older version counts as 3 on its network.
- The scanner is off when `server` is set.
- Noise does not help against a filter that blocks all UDP, or all of Cloudflare's WARP ranges:
  then auto mode, or `masque` with `vhttp` `auto` (HTTP/2 over TCP), is the way.

## Sources and credits

Parts of this feature come from these projects. Thanks to their authors.

- [kyochikuto/sing-box-plus](https://github.com/kyochikuto/sing-box-plus): the WireGuard probe is adapted from it.
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core): the `xray-random` noise preset.
- [amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go): the junk packets that the AmneziaWG presets copy.

Related projects:

- [bepass-org/warp-plus](https://github.com/bepass-org/warp-plus): has a WARP endpoint scanner too.

## See also

- [WARP](warp.en.md)
- [WARP over MASQUE](warp-masque.en.md)
- [WireGuard: Hiddify additions](wireguard-hiddify.en.md)
- [AmneziaWG](amneziawg.en.md)
