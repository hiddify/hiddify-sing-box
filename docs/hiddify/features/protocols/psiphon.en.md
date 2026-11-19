# Psiphon

[فارسی](psiphon.fa.md) · [All Hiddify features](../../index.md)

The Psiphon outbound connects to the Psiphon network through the official Psiphon tunnel core,
built into sing-box. Psiphon runs the servers, so you only need this outbound. It is an
outbound: `"type": "psiphon"` in the `outbounds` list.

## Why use it

- You get a working proxy with no server of your own and no account.
- It is a good last resort when your own servers are blocked: Psiphon keeps many servers and
  many ways to reach them, and updates its server list by itself.
- You can pick the country the traffic leaves from with `egress_region`.

Psiphon is shared by many users. It is often slower than your own server, and it carries TCP
only.

## How it gets past filtering

Psiphon does the work, not sing-box. The tunnel core knows many Psiphon servers and several
obfuscated protocols to reach them. It tries them until one connects, and downloads a signed,
updated server list once it is in. When one server or protocol is blocked, it moves to another.

When Psiphon is the first hop, the built-in tunnel core is a fork (the Shir o Khorshid branch)
that can also front through CDN edges it scans for: the edges of Akamai, Fastly, Cloudflare,
CloudFront, Bunny and others, each with the TLS server names it answers for. A network that
blocks Psiphon's own fronting addresses rarely blocks every edge of every CDN. Hiddify's
[scanner](warp-scanner.en.md) finds the edges that get through on your network first, with a quick
TLS handshake, and the tunnel core dials those before it walks the rest itself.

It does not help when the network blocks all traffic to the outside, or when every Psiphon
server it knows is blocked and it cannot fetch a new list.

## How it works

- At start, the outbound builds a Psiphon config (see `config` below), opens its data store in
  `data_directory`, and starts the tunnel core in the background. Startup does not wait for the
  tunnel.
- Until the tunnel is up, the outbound shows "Connecting..." and connections through it fail.
  When the first tunnel is up, the mark goes away, and Hiddify's
  [monitoring](../groups/monitoring.en.md) tests it at once.
- The tunnel core makes its own connections to Psiphon servers. These go through this
  outbound's dial settings (for example `detour`), through a local SOCKS bridge, so they do
  not loop back into your VPN. If you set `upstream_proxy_url`, that proxy is used instead.
- The tunnel core's connections always go through that bridge or proxy, which carries TCP only,
  so in-proxy (WebRTC) protocols are turned off and the QUIC ones are left out. As the first hop
  it tries every other protocol, the CDN fronted ones included. Behind another proxy (a `detour`,
  such as Hiddify's extra security chain, or `upstream_proxy_url`) it tries the TCP protocols,
  with tactics off: that proxy already gets out, so the scanner is off too. A `config` that sets
  `LimitTunnelProtocols` keeps its own list.
- **Scanner** (first hop only, unless `scanner.enabled` says otherwise): before the tunnel core
  starts, the scanner names the network (interface type, country and public address range),
  then tries the CDN edges with a TLS handshake that looks like Chrome's, with each set's server
  names and with none. The certificate is not checked: an edge answers a name it does not serve
  with its own certificate and fronts all the same, while a network that filters the name resets
  the handshake. Edges Psiphon connected over on this network come first, then good ones from
  other networks, then the addresses a few names of each CDN resolve to (most addresses of a
  CDN's ranges do not answer), then new ones: each network walks the edges in an order of its
  own and goes on where the last scan stopped. The scan stops once `candidates` edges of each CDN
  could have answered. For each CDN that answered, the tunnel core gets a dial override that
  applies only to the Psiphon servers fronting through that CDN (matched by their fronting
  addresses), with its edges and the server name they answered with: an edge of another CDN
  only answers 400 or 404. Each server of a CDN that answered then cycles through that CDN's
  edges; the tunnel core's own scan, which numbers its candidates across all servers and pairs
  every edge with every server, is off then, and on only when the scanner found no edge. Only the edge Psiphon connects over gains a point on the network: an edge
  that answers TLS may still not front Psiphon. Scores are kept in the cache file, and the
  detected network also names the tunnel core's network, so what worked on Wi-Fi is not tried
  first on mobile data.
- **Search and deep search** (first hop only): the scans and the tunnel core's attempts go on
  for the scanner's `search_timeout` (3 minutes); an attempt ends at the end of that time. When
  no tunnel comes up in it, the outbound stops trying and offers a deep search: the app asks the
  user, since it may go on for hours and use a lot of battery and CPU. A deep search gives the
  tunnel core no time limit in its aggressive mode, with more workers, and the scans
  `deep_concurrency` probes. A new network starts a normal search again. `search_timeout` below
  zero is a deep search from the start, and above 3 minutes a deep one with that limit. Behind
  another proxy there is no search time.
- **Only with a network:** before each attempt of the tunnel core, Psiphon waits until the device
  has a network (Wi-Fi or mobile data, not paused); the wait does not count toward the search
  time. A network change while it searches starts the attempt again on the new network.
- **First hop:** Psiphon is the first hop with no `detour`, or with a `direct` one (looked up at
  the start, when every outbound exists), and without `upstream_proxy_url`. Its scanner then
  shares the store of the WARP scanners that reach the network directly (see
  [WARP scanner and noise](warp-scanner.en.md#search-and-deep-search)): the same scores and
  network name, and one scan for two Psiphon outbounds (one per region) that scan at once.
- **Hot reload:** a changed Psiphon outbound (its region, its scanner) is replaced without a
  restart: the new one starts, then the old one closes, and the new one goes on with the shared
  scores. The tunnel core's data store and notice writer are global; they are shared, counted and
  kept across the replacement (tested: US, then DE, then US again).
- **Protocols by their rating:** the protocols that brought a tunnel up on the network are
  rated there, and up to 3 of them, drawn by weight, are tried first for the first 20
  candidates, then all of them: the tunnel core does not go through every protocol before the
  one that works. The CDN sets and the server names are drawn by their rating the same way (see
  [WARP scanner and noise](warp-scanner.en.md#search-and-deep-search)).
- When the network changes, the outbound tells the tunnel core to reconnect.
- When the tunnel core stops (it gives up after `establish_tunnel_timeout`, or fails), it is
  started again after 5 seconds, then twice as long each time, up to every 5 minutes; a
  connection resets the wait.
- Several Psiphon outbounds can run at once, for example one per `egress_region`. Each keeps its
  downloads in `data_directory/<tag>`; what an earlier version kept in `data_directory` itself is
  moved there. The tunnel core reports its state without saying which outbound it is about, so
  next to other Psiphon outbounds each one checks its own tunnel before it shows as connected.
- Each TCP connection is opened through the Psiphon tunnel to its real destination. UDP is not
  supported.

## Configuration

```json
{
  "type": "psiphon",
  "tag": "psiphon",
  "egress_region": "DE"
}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `config` | string | `""` | A Psiphon config to start from. `"hiddify"` uses the config built into the Hiddify app, if this build has one; otherwise a warning is logged and the defaults are used. Any other value is the Psiphon JSON config, either encrypted with this build's key or in base64. Empty means the defaults. |
| `data_directory` | string | `"data/psiphon"` | Where Psiphon keeps its data: each outbound in a folder named after its tag. |
| `egress_region` | string | `""` | Two-letter country code of the exit server, for example `"US"` or `"DE"`. Empty lets Psiphon choose. |
| `propagation_channel_id` | string | `"FFFFFFFFFFFFFFFF"` | Psiphon client identity value. |
| `sponsor_id` | string | `"FFFFFFFFFFFFFFFF"` | Psiphon client identity value. |
| `network_id` | string | `"test"` | Psiphon network ID. With the scanner on and this unset, the network the scanner detects. |
| `client_platform` | string | `"<system>_hiddify"` | Platform string sent to Psiphon, for example `Android_hiddify` or `Windows_hiddify`; Psiphon picks its tactics by it. |
| `client_version` | string | `""` | Version string sent to Psiphon. |
| `remote_server_list_url` | string | Psiphon's public list URL | Where to download the server list. |
| `remote_server_list_download_filename` | string | `"remote_server_list"` | File name for the downloaded list. |
| `remote_server_list_signature_public_key` | string | Psiphon's public key | Key that checks the list's signature. |
| `upstream_proxy_url` | string | `""` | Send Psiphon's own connections through this proxy, for example `socks5://127.0.0.1:1080`. Empty uses the outbound's dial settings. |
| `allow_default_dns_resolver_with_bind_to_device` | bool | `true` | Let Psiphon use the system DNS resolver while bound to a network interface. |
| `establish_tunnel_timeout` | duration | `3m` | How long the tunnel core tries to connect before it gives up. Values under one second count as one second. |
| `scanner` | object | | The CDN edge scanner, below. |

### `scanner`

```json
{
  "type": "psiphon",
  "tag": "psiphon",
  "scanner": { "sets": ["psiphon-akamai", "fastly"], "candidates": 2 }
}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | unset | Turn the scanner on or off. Unset: on when Psiphon is the first hop (no `detour` and no `upstream_proxy_url`), off behind another proxy. |
| `sets` | list of strings | all | The built-in CDN sets to use, for the scanner and the tunnel core's own scan: `legacy-android-overrides`, `curated-fronting`, `psiphon-akamai`, `fastly`, `psiphon-bunny`, `cloudflare`, `cloudfront`, `vercel`, `github`, `google`. |
| `cidrs` | list of IPv4 prefixes | built-in sets | Edges to scan instead of the built-in sets. |
| `server_names` | list of strings | `[]` | TLS server names tried with `cidrs`; each edge is also tried without one. |
| `candidates` | int | `2` | How many answering edges of each CDN go to the tunnel core; the scan stops once that many per CDN set answered. |
| `count` | int | `256` | The most edges probed in one round of a scan. |
| `concurrency` | int | `16` on Android and iOS, `48` elsewhere | Probes run at once. |
| `search_timeout` | duration | `3m` | How long the search goes on before it offers a deep search. Below zero, a deep search from the start; above `3m`, a deep one with that limit. |
| `deep_concurrency` | int | twice `concurrency` | Probes a deep search runs at once. |
| `block_bits_ipv4` | int | `24` | Size of the IPv4 blocks rated on each network. |
| `block_bits_ipv6` | int | `48` | Size of the IPv6 blocks rated on each network. |
| `timeout` | duration | `3s` | How long one probe waits for its handshake. |
| `max_rtt` | duration | `2s` | The slowest handshake accepted. |

The usual dial fields (`detour`, `bind_interface` and the rest) also apply, as described above.
The `network` field is accepted but has no effect: the outbound is TCP only.

For each identity and server list field, the order is: the value set in the outbound, then the
value in `config`, then the default.

## Sources and credits

Parts of this feature come from these projects. Thanks to their authors.

- [Psiphon-Labs/psiphon-tunnel-core](https://github.com/Psiphon-Labs/psiphon-tunnel-core): the official Psiphon tunnel core.
- [CluvexStudio/psiphon-tunnel-core](https://github.com/CluvexStudio/psiphon-tunnel-core) (branch `shirokhorshid`): the fork built in, with the CDN fronted protocols, the CDN fronting scan and its edge lists.
- [CluvexStudio/Aether](https://github.com/CluvexStudio/Aether): the protocol choices as first hop and behind a proxy.
- [patterniha/MITM-DomainFronting](https://github.com/patterniha/MITM-DomainFronting): server names in the fork's CDN edge lists.

Related projects:

- [bepass-org/warp-plus](https://github.com/bepass-org/warp-plus): combines WARP with Psiphon.

## See also

- [WARP scanner and noise](warp-scanner.en.md): the scanner engine, its scores and its walk
- [Monitoring](../groups/monitoring.en.md)
- [Balancer](../groups/balancer.en.md)
