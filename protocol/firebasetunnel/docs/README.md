# Firebase Tunnel

A sing-box endpoint pair (`firebasetunnel_client` / `firebasetunnel_server`) that relays TCP byte streams through Firebase Realtime Database, used when direct connectivity between client and server is blocked but Firebase's REST API is reachable.

Adapted from [github.com/Hiddify2/Firebase-Tunnel](https://github.com/Hiddify2/Firebase-Tunnel) (a single-star proof-of-concept with no LICENSE — the logic below was rewritten for sing-box rather than vendored; see [provenance.md](./provenance.md)).

## Documents

- [architecture.md](./architecture.md) — how the relay works, wire format, Firebase database layout
- [configuration.md](./configuration.md) — client/server config reference
- [security.md](./security.md) — threat model, auth options, encryption
- [operations.md](./operations.md) — rate limits, session caps, GC, rollout/rollback
- [provenance.md](./provenance.md) — relationship to the upstream PoC, what was reused vs. rewritten

## Known limitations

- Added latency: Firebase RTDB polling/SSE imposes a realistic floor of ~200ms+ round-trip on top of normal network latency.
- Firebase rate limits apply per project; high-throughput use needs read/write quota headroom (see [operations.md](./operations.md)).
- Default auth is a single shared Firebase Database Secret — coarse-grained (see [security.md](./security.md) for the recommended token/PSK alternatives).
