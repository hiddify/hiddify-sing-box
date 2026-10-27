# Hiddify sing-box

Features and fixes in the Hiddify fork that upstream sing-box does not have. Each feature page has
an English and a Persian version.

## Features

### Protocols and endpoints

- [WARP](warp.en.md) ([فارسی](warp.fa.md)): Cloudflare WARP over WireGuard or AmneziaWG, with free account registration, noise packets and an endpoint scanner that fails over per network.
- [WARP over MASQUE](warp-masque.en.md) ([فارسی](warp-masque.fa.md)): Cloudflare WARP over MASQUE on HTTP/3, HTTP/2 or both, with its own scanner and failover.
- [AmneziaWG](amneziawg.en.md) ([فارسی](amneziawg.fa.md)): WireGuard with junk packets, padded handshakes and custom message types that defeat WireGuard fingerprinting.
- [WireGuard: Hiddify additions](wireguard-hiddify.en.md) ([فارسی](wireguard-hiddify.fa.md)): noise packets before handshakes, per-peer user names, socket recovery and UDP fragmentation on by default.
- [WireGuard outbound (legacy format)](wireguard-legacy.en.md) ([فارسی](wireguard-legacy.fa.md)): the old WireGuard outbound that upstream removed, kept so old configs still load.
- [VLESS encryption](vless-encryption.en.md) ([فارسی](vless-encryption.fa.md)): Xray's post-quantum VLESS encryption, with Vision over it even without TLS.
- [Sudoku](sudoku.en.md) ([فارسی](sudoku.fa.md)): an encrypted TCP proxy that sends its bytes as sudoku clues, so traffic looks like text or has low randomness, with optional HTTP tunnels (build tag `with_sudoku`).
- [Mieru](mieru.en.md) ([فارسی](mieru.fa.md)): a fully encrypted, padded proxy over TCP or UDP port ranges with no fixed pattern.
- [TrustTunnel](trusttunnel.en.md) ([فارسی](trusttunnel.fa.md)): proxy traffic as HTTP CONNECT streams over HTTP/2 or HTTP/3.
- [SSH](ssh.en.md) ([فارسی](ssh.fa.md)): an SSH server inbound for port forwarding, plus UDP over TCP and a background connection for the SSH outbound.
- [Psiphon](psiphon.en.md) ([فارسی](psiphon.fa.md)): connect through the Psiphon network with no server of your own, and pick the exit country.
- [DNSTT](dnstt.en.md) ([فارسی](dnstt.fa.md)): carry traffic inside DNS queries through public resolvers, which it finds by itself.
- [GooseRelay](gooserelay.en.md) ([فارسی](gooserelay.fa.md)): send traffic through Google Apps Script to your own server, so the network sees only HTTPS to Google.
- [Tunnel](tunnel.en.md) ([فارسی](tunnel.fa.md)): a reverse tunnel that reaches machines behind NAT through a public server.

### Transports and TLS

- [XHTTP](xhttp.en.md) ([فارسی](xhttp.fa.md)): Xray's XHTTP transport with its modes, padding, placements, XMUX and split download.
- [mKCP](kcp.en.md) ([فارسی](kcp.fa.md)): Xray 26's mKCP over UDP for lossy or TCP-throttled networks, hidden by finalmask UDP masks (build tag `with_kcp`).
- [Raw transport](raw.en.md) ([فارسی](raw.fa.md)): the `raw` transport, so configs converted from Xray load.
- [Custom gRPC paths](grpc-custom-path.en.md) ([فارسی](grpc-custom-path.fa.md)): Xray-style multi-segment gRPC paths in `service_name`.
- [finalmask](finalmask.en.md) ([فارسی](finalmask.fa.md)): Xray's finalmask masks (fragment, noise, header-custom and more) on every connection an outbound dials.
- [TLS fragment](tls-fragment.en.md) ([فارسی](tls-fragment.fa.md)): split the ClientHello into small pieces with pauses, so DPI cannot read the server name.
- [TLS tricks](tls-tricks.en.md) ([فارسی](tls-tricks.fa.md)): a mixed-case server name and a padding extension in the ClientHello.
- [REALITY in Hiddify](reality-hiddify.en.md) ([فارسی](reality-hiddify.fa.md)): the post-quantum key share, the `key_share` option, and fragmentation on REALITY.
- [Shadowsocks simple-obfs server](shadowsocks-obfs.en.md) ([فارسی](shadowsocks-obfs.fa.md)): a simple-obfs server on Shadowsocks inbounds, with a decoy when obfs or login fails.
- [rmux](rmux.en.md) ([فارسی](rmux.fa.md)): one more multiplex protocol for many connections in one, next to smux, yamux and h2mux.
- [PROXY protocol](proxy-protocol.en.md) ([فارسی](proxy-protocol.fa.md)): inbounds read the PROXY protocol header and the direct outbound sends it.

### Groups and testing

- [Balancer](balancer.en.md) ([فارسی](balancer.fa.md)): spread connections over members by round robin, lowest delay, consistent hashing or sticky sessions.
- [Fallback](fallback.en.md) ([فارسی](fallback.fa.md)): try members in order and skip one that failed for a while.
- [URL test: Hiddify additions](urltest.en.md) ([فارسی](urltest.fa.md)): more test URLs, a `failover` mode, and a move to another member on the first failed connection.
- [Bond](bond.en.md) ([فارسی](bond.fa.md)): split each connection over several outbounds at once and join it on the server, to add up throttled connections (build tag `with_bond`).
- [Monitoring](monitoring.en.md) ([فارسی](monitoring.fa.md)): background tests of every outbound for delay and exit IP, which feed the groups.
- [Unified delay](unified-delay.en.md) ([فارسی](unified-delay.fa.md)): URL tests time one HTTP round trip on an open connection, so delays compare across protocols.

### DNS

- [DNS group](dns-group.en.md) ([فارسی](dns-group.fa.md)): ask several DNS servers at once, in turn, or stick to the one that works, and drop poisoned answers.
- [DNS rules: bypass_if_failed](dns-bypass-if-failed.en.md) ([فارسی](dns-bypass-if-failed.fa.md)): when a DNS rule's server fails, the query goes on to the next matching rule.
- [Smart DNS pool](smart-dns-pool.en.md) ([فارسی](smart-dns-pool.fa.md)): a local DNS server that spreads queries over many resolvers, made for DNSTT.
- [DNSCrypt (SDNS stamps)](sdns.en.md) ([فارسی](sdns.fa.md)): the `sdns` server, which sends encrypted queries to a DNSCrypt resolver given by its stamp.
- [sslip.io names](sslip-hosts.en.md) ([فارسی](sslip-hosts.fa.md)): the `hosts` server answers `sslip.io` names with the address written in the name.

## Bug fixes

- [v5 bug fixes](bugfix/v5.en.md) ([فارسی](bugfix/v5.fa.md)): bugs fixed on top of sing-box v1.15, newest first, each with its commit.
