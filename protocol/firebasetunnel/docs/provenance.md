# Provenance

This protocol is inspired by [github.com/Hiddify2/Firebase-Tunnel](https://github.com/Hiddify2/Firebase-Tunnel), a small (single-star, no LICENSE file) proof-of-concept that relays a SOCKS5 connection through Firebase Realtime Database REST calls. Because the upstream repository carries no license, **no code was copied or vendored** — the mechanism (batched/compressed/base64 chunks written to sequential database keys, ack-and-delete cleanup, SSE-based session discovery) was studied and reimplemented from scratch for sing-box's architecture.

## What's conceptually the same as the PoC

- Firebase REST `GET`/`PUT`/`DELETE` for session metadata and chunk queues, plus SSE `Listen` for push-based session discovery.
- Chunk batching (time-or-size triggered flush), zstd compression, base64 encoding, sequence-numbered ordering with out-of-order buffering.
- Ack-pointer-then-delete cleanup pattern to bound database growth.
- Session state machine: `pending` → `active` → `closing` → `closed`.

## What's different

| Aspect | Upstream PoC | This implementation |
|---|---|---|
| Client transport entry point | Local SOCKS5 listener | sing-box's own inbound chain (mixed/socks/etc.) feeds connections in; this protocol is purely the outbound leg, exposed as a `net.Conn` via `net.Pipe()` from `DialContext`. |
| Server egress | Raw `net.Dial` to the declared target | `router.RouteConnectionEx`, so the server's own sing-box `route` rules, DNS, and sniffing apply — this cannot be used to bypass routing restrictions configured elsewhere in the same sing-box instance. |
| Multi-tenancy | Single-tenant (no user concept) | `user` label per session, validated against a configured user list; optional per-user PSK turns the label into a verified credential. |
| Traffic accounting | None | Wired into the existing SSM (`service/ssmapi`) traffic manager via `ServerEndpoint.SetTracker`, the same mechanism used for Shadowsocks per-user usage. |
| Auth | Legacy Database Secret only | Legacy secret retained as the simple default, plus an optional Firebase Auth/service-account token path. |
| Payload confidentiality | None (cleartext to anyone who can read the Firebase project) | Optional AES-256-GCM encryption keyed by a per-user PSK. |
| Resource limits | None | Global/per-user session caps, per-user session-creation rate limiting, sender backpressure byte cap. |
| Abandoned-session cleanup | In-session inactivity timeout only | Same, plus a background GC sweep for sessions that never reached `active` or that stalled mid-shutdown. |
| Failure isolation | N/A (single-purpose binary) | Poll/GC loops run under panic recovery with restart backoff so a bug can't take down the rest of the sing-box process. |
| Reconnect behavior | Fixed 2s SSE reconnect delay | Jittered exponential backoff, to avoid thundering-herd reconnects across many sessions/instances sharing a project. |

## Known shared limitation

Both the upstream PoC and this implementation share the same fundamental latency floor (~200ms+ added round-trip) and Firebase rate-limit exposure, since both rely on the same underlying Firebase RTDB polling/SSE mechanism — this is an inherent property of the transport choice, not an implementation gap. See [operations.md](./operations.md).
