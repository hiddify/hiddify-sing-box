# Hiddify sing-box

[فارسی](index.fa.md)

Features and fixes in the Hiddify fork that upstream sing-box does not have. Each feature page has
an English and a Persian version.

## Features

- [TLS fragment](features/tls-fragment.en.md): split the ClientHello into small pieces with pauses, so DPI cannot read the server name.
- [TLS tricks](features/tls-tricks.en.md): a mixed-case server name and a padding extension in the ClientHello.
- [REALITY in Hiddify](features/reality-hiddify.en.md): the post-quantum key share, the `key_share` option, and fragmentation on REALITY.
- [PROXY protocol](features/proxy-protocol.en.md): inbounds read the PROXY protocol header and the direct outbound sends it.

## Protocols

- [WARP](features/protocols/warp.en.md): Cloudflare WARP over WireGuard, AmneziaWG or MASQUE, with free account registration, noise packets and an endpoint scanner that fails over per network.
- [WARP scanner and noise](features/protocols/warp-scanner.en.md): how the endpoint scanner, the noise modes and presets (DNS, QUIC, SIP, random), the noise search and auto mode find a way through.
- [WARP over MASQUE](features/protocols/warp-masque.en.md): the standalone `masque` outbound for WARP over HTTP/3, HTTP/2 or both; for a self-hosted MASQUE server, use upstream `masque-client`.
- [AmneziaWG](features/protocols/amneziawg.en.md): WireGuard with junk packets, padded handshakes and custom message types that defeat WireGuard fingerprinting.
- [WireGuard: Hiddify additions](features/protocols/wireguard-hiddify.en.md): noise packets before handshakes, per-peer user names, socket recovery and UDP fragmentation on by default.
- [WireGuard outbound (legacy format)](features/protocols/wireguard-legacy.en.md): the old WireGuard outbound that upstream removed, kept so old configs still load.
- [VLESS encryption](features/protocols/vless-encryption.en.md): Xray's post-quantum VLESS encryption, with Vision over it even without TLS.
- [Sudoku](features/protocols/sudoku.en.md): an encrypted TCP proxy that sends its bytes as sudoku clues, so traffic looks like text or has low randomness, with optional HTTP tunnels (build tag `with_sudoku`).
- [Mieru](features/protocols/mieru.en.md): a fully encrypted, padded proxy over TCP or UDP port ranges with no fixed pattern.
- [TrustTunnel](features/protocols/trusttunnel.en.md): proxy traffic as HTTP CONNECT streams over HTTP/2 or HTTP/3.
- [SSH](features/protocols/ssh.en.md): an SSH server inbound for port forwarding, plus UDP over TCP and a background connection for the SSH outbound.
- [Psiphon](features/protocols/psiphon.en.md): connect through the Psiphon network with no server of your own, and pick the exit country.
- [DNSTT](features/protocols/dnstt.en.md): carry traffic inside DNS queries through public resolvers, which it finds by itself.
- [GooseRelay](features/protocols/gooserelay.en.md): send traffic through Google Apps Script to your own server, so the network sees only HTTPS to Google.
- [Call tunnel](features/protocols/call.en.md): carry proxy traffic inside a video call on VK, Telemost, Dion, WB Stream or Bitrix24, so it looks like a call to an allowed domestic service; not tested end to end (build tag `with_call`).
- [Tunnel](features/protocols/tunnel.en.md): a reverse tunnel that reaches machines behind NAT through a public server.
- [Bond](features/protocols/bond.en.md): split each connection over several outbounds at once and join it on the server, to add up throttled connections (build tag `with_bond`).

## Transports

- [XHTTP](features/transports/xhttp.en.md): Xray's XHTTP transport with its modes, padding, placements, XMUX and split download.
- [mKCP](features/transports/kcp.en.md): Xray 26's mKCP over UDP for lossy or TCP-throttled networks, hidden by finalmask UDP masks (build tag `with_kcp`).
- [Raw transport](features/transports/raw.en.md): the `raw` transport, so configs converted from Xray load.
- [Custom gRPC paths](features/transports/grpc-custom-path.en.md): Xray-style multi-segment gRPC paths in `service_name`.
- [finalmask](features/transports/finalmask.en.md): Xray's finalmask masks (fragment, noise, header-custom and more) on every connection an outbound dials.
- [Shadowsocks simple-obfs server](features/transports/shadowsocks-obfs.en.md): a simple-obfs server on Shadowsocks inbounds, with a decoy when obfs or login fails.
- [rmux](features/transports/rmux.en.md): one more multiplex protocol for many connections in one, next to smux, yamux and h2mux.

## DNS

- [DNS group](features/dns/dns-group.en.md): ask several DNS servers at once, in turn, or stick to the one that works, and drop poisoned answers.
- [DNS rules: bypass_if_failed](features/dns/dns-bypass-if-failed.en.md): when a DNS rule's server fails, the query goes on to the next matching rule.
- [Smart DNS pool](features/dns/smart-dns-pool.en.md): a local DNS server that spreads queries over many resolvers, made for DNSTT.
- [DNSCrypt (SDNS stamps)](features/dns/sdns.en.md): the `sdns` server, which sends encrypted queries to a DNSCrypt resolver given by its stamp.
- [sslip.io names](features/dns/sslip-hosts.en.md): the `hosts` server answers `sslip.io` names with the address written in the name.

## Groups and monitoring

- [Balancer](features/groups/balancer.en.md): spread connections over members by round robin, lowest delay, consistent hashing, sticky sessions or a sticky pool.
- [Fallback](features/groups/fallback.en.md): try members in order and skip one that failed for a while.
- [URL test: Hiddify additions](features/groups/urltest.en.md): more test URLs, a `failover` mode, and a move to another member on the first failed connection.
- [Monitoring](features/groups/monitoring.en.md): background tests of every outbound for delay and exit IP, which feed the groups.
- [Unified delay](features/groups/unified-delay.en.md): URL tests time one HTTP round trip on an open connection, so delays compare across protocols.

## For app developers

- [App considerations](app_considerations.md): what hiddify-app and hiddify-core need to change or know because of the v5 work.

## Bug fixes

- [v5 bug fixes](bugfix/v5.en.md): bugs fixed on top of sing-box v1.15, newest first, each with its commit.
