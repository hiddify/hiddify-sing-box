# Hiddify sing-box

The core of [Hiddify](https://github.com/hiddify/hiddify-app): [sing-box](https://github.com/SagerNet/sing-box)
(v1.15) with the protocols, transports and fixes that make it work on censored networks.

**Documentation:** [docs/hiddify](docs/hiddify/index.md) · [فارسی](docs/hiddify/index.fa.md). Every
feature below has a page there, in English and Persian, with what it is, how it gets past
filtering and every option. Upstream sing-box options are documented at
[sing-box.sagernet.org](https://sing-box.sagernet.org).

## Thanks to sing-box

Everything here stands on [sing-box](https://github.com/SagerNet/sing-box), by
[nekohasekai (世界)](https://github.com/nekohasekai) and the
[sing-box contributors](https://github.com/SagerNet/sing-box/graphs/contributors). The design of
sing-box, its routing, DNS, inbounds and outbounds, TUN stack and the libraries around it
(sing, sing-tun, sing-quic, sing-mux and more) make a fork like this possible at all. Hiddify keeps
its changes small and close to upstream so it can follow every sing-box release. Thank you.

## Features

### WARP and WireGuard

- [WARP](docs/hiddify/features/protocols/warp.en.md): Cloudflare WARP with no account setup, over
  WireGuard, AmneziaWG or MASQUE, or `auto` (the fastest that answers); an endpoint scanner with
  per-network scores and failover, noise presets and a noise search, a pool of registered devices
  that is only renewed when Cloudflare refuses one.
- [WARP scanner and noise](docs/hiddify/features/protocols/warp-scanner.en.md): how the scanner,
  the noise presets (DNS, QUIC, SIP, random), the noise search and auto mode work together.
- [WARP over MASQUE](docs/hiddify/features/protocols/warp-masque.en.md): the `masque` outbound for
  WARP over HTTP/3 or HTTP/2.
- [AmneziaWG](docs/hiddify/features/protocols/amneziawg.en.md): AmneziaWG 3.1, with the QUIC
  masquerade.
- [WireGuard additions](docs/hiddify/features/protocols/wireguard-hiddify.en.md): noise before
  handshakes (random, QUIC Initials, AmneziaWG-style DNS, QUIC and SIP templates), socket recovery,
  per-peer users.
- [WireGuard outbound (legacy format)](docs/hiddify/features/protocols/wireguard-legacy.en.md).

### Protocols

- [VLESS encryption](docs/hiddify/features/protocols/vless-encryption.en.md),
  [Sudoku](docs/hiddify/features/protocols/sudoku.en.md),
  [Mieru](docs/hiddify/features/protocols/mieru.en.md),
  [TrustTunnel](docs/hiddify/features/protocols/trusttunnel.en.md),
  [SSH](docs/hiddify/features/protocols/ssh.en.md),
  [Psiphon](docs/hiddify/features/protocols/psiphon.en.md),
  [DNSTT](docs/hiddify/features/protocols/dnstt.en.md),
  [GooseRelay](docs/hiddify/features/protocols/gooserelay.en.md),
  [Call tunnel](docs/hiddify/features/protocols/call.en.md),
  [Tunnel](docs/hiddify/features/protocols/tunnel.en.md),
  [Bond](docs/hiddify/features/protocols/bond.en.md).

### Transports and TLS

- [XHTTP](docs/hiddify/features/transports/xhttp.en.md),
  [mKCP](docs/hiddify/features/transports/kcp.en.md),
  [raw](docs/hiddify/features/transports/raw.en.md),
  [custom gRPC paths](docs/hiddify/features/transports/grpc-custom-path.en.md),
  [finalmask](docs/hiddify/features/transports/finalmask.en.md),
  [Shadowsocks simple-obfs server](docs/hiddify/features/transports/shadowsocks-obfs.en.md),
  [rmux](docs/hiddify/features/transports/rmux.en.md).
- [TLS fragment](docs/hiddify/features/tls-fragment.en.md),
  [TLS tricks](docs/hiddify/features/tls-tricks.en.md),
  [REALITY additions](docs/hiddify/features/reality-hiddify.en.md) (post-quantum key share,
  `key_share`, fragmentation, Firefox 148 and Safari 26.3 fingerprints),
  [PROXY protocol](docs/hiddify/features/proxy-protocol.en.md).

### DNS

- [DNS group](docs/hiddify/features/dns/dns-group.en.md),
  [bypass_if_failed](docs/hiddify/features/dns/dns-bypass-if-failed.en.md),
  [smart DNS pool](docs/hiddify/features/dns/smart-dns-pool.en.md),
  [DNSCrypt (SDNS)](docs/hiddify/features/dns/sdns.en.md),
  [sslip.io names](docs/hiddify/features/dns/sslip-hosts.en.md).

### Groups and monitoring

- [Balancer](docs/hiddify/features/groups/balancer.en.md) (round robin, lowest delay, consistent
  hashing, sticky sessions, sticky pool),
  [fallback](docs/hiddify/features/groups/fallback.en.md),
  [URL test additions](docs/hiddify/features/groups/urltest.en.md) (more test URLs, failover mode,
  dial penalties),
  [monitoring](docs/hiddify/features/groups/monitoring.en.md) with a connection status for every
  outbound, [unified delay](docs/hiddify/features/groups/unified-delay.en.md).

### Fixes

Many crash, leak and stability fixes on top of sing-box, each with its commit:
[bug-fix log](docs/hiddify/bugfix/v5.en.md). What hiddify-app and hiddify-core need to know:
[app considerations](docs/hiddify/app_considerations.md).

## Building

```bash
git clone --recursive https://github.com/hiddify/hiddify-sing-box
cd hiddify-sing-box
make          # Go 1.26.3 or newer
```

The forks of dependencies live under `replace/` as git submodules, so clone with `--recursive`
(or run `git submodule update --init --recursive`). The default build tags are in the `Makefile`;
`with_kcp`, `with_sudoku`, `with_bond`, `with_call` and `with_tailscale` add optional features.

## Contributing

Read [AGENTS.md](AGENTS.md) first; it holds for people and AI agents alike. In short: read the
Hiddify docs, keep changes to upstream files small (`h_*.go` files, `//H` on changed lines),
improve an existing feature rather than add an overlapping one, test, document in English and
Persian, list the feature here, and rebase on the latest `v5` before opening a pull request. The
step-by-step procedure is the [hiddify-feature skill](.agents/skills/hiddify-feature/SKILL.md).

## Credits

Besides sing-box, this fork takes work from other forks and projects. Thank you to all of them:

- [shtorm-7/sing-box-extended](https://github.com/shtorm-7/sing-box-extended): the base of this
  fork, with AmneziaWG, WARP, tunneling, Mieru, XHTTP, SDNS, unified delay, mKCP, Sudoku, Bond, the
  call tunnel and the fallback group, and its forks of
  [connect-ip-go](https://github.com/shtorm-7/connect-ip-go),
  [sing-dns](https://github.com/shtorm-7/sing-dns) and
  [dnscrypt](https://github.com/shtorm-7/dnscrypt).
- [Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx): many fixes and specs, the
  AmneziaWG 3.x masquerade, the DNS group modes, URL-test penalties and failover, the sticky pool,
  REALITY `key_share`, MASQUE `vhttp`, and [utls-lx](https://github.com/Leadaxe/utls-lx) for the
  Firefox 148 and Safari 26.3 fingerprints.
- [reF1nd/sing-box](https://github.com/reF1nd/sing-box): crash and stability fixes (Trojan, DNS
  deduplication and cache, Shadowsocks 2022, the HTTP transport, FakeIP, MASQUE, resolved).
- [kyochikuto/sing-box-plus](https://github.com/kyochikuto/sing-box-plus): the WARP endpoint
  scanner and QUIC noise, and TLS fragmentation methods.
- [starifly/sing-vmess](https://github.com/starifly/sing-vmess): VLESS encryption.
- [Diniboy1123/usque](https://github.com/Diniboy1123/usque) and
  [connect-ip-go](https://github.com/Diniboy1123/connect-ip-go): WARP over MASQUE.
- [amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go): AmneziaWG.
- [refraction-networking/utls](https://github.com/refraction-networking/utls) and
  [metacubex/utls](https://github.com/metacubex/utls): TLS fingerprints.
- [Psiphon-Labs](https://github.com/Psiphon-Labs): Psiphon.
- [net2share/vaydns](https://github.com/net2share/vaydns): DNSTT.
- [kianmhz/GooseRelayVPN](https://github.com/kianmhz/GooseRelayVPN): GooseRelay.
- [GFW-knocker](https://github.com/GFW-knocker): the WireGuard noise packets.
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core): XHTTP, mKCP, finalmask, VLESS encryption
  and REALITY, which the matching features here follow and are tested against.

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
