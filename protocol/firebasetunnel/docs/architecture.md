# Architecture

## Endpoint, not outbound+inbound

`firebasetunnel_client` and `firebasetunnel_server` are both registered as sing-box **Endpoints** (`adapter.Endpoint`), the same shape used by the existing `tunnel_client`/`tunnel_server` pair in `protocol/tunnel/`. An Endpoint can both dial out (`DialContext`) and run its own background listener (`Start`) — exactly the dual nature needed here: the client dials *through* Firebase, the server listens for sessions arriving *via* Firebase and dials the real target.

```
sing-box (client box)                                              sing-box (server box)
┌─────────────────────────┐                                     ┌─────────────────────────┐
│ inbound (mixed/socks/…)  │                                     │  firebasetunnel_server   │
│         │                │                                     │         │                │
│         ▼                │                                     │         ▼                │
│  firebasetunnel_client    │◄──── Firebase Realtime Database ──►│   router.RouteConnectionEx│
│  .DialContext()           │      (sessions/{id}/...)            │         │                │
└─────────────────────────┘                                     │         ▼                │
                                                                   │   direct/other outbound  │
                                                                   └─────────────────────────┘
```

## Session lifecycle

1. **Client** generates a UUIDv4 `session_id`, writes `sessions/{id}/metadata` with `state=pending`, `target_host`/`target_port` (the dial destination), and its configured `user` label.
2. **Server** discovers the new pending session (via a Firebase SSE `Listen` stream on `sessions/`, with a coarse poll fallback), validates `user` against its configured user list, enforces session caps/rate limits, then flips `state=active`.
3. **Client** observes `state=active` and begins relaying.
4. Both sides exchange `net.Pipe()`-backed connections internally: the client hands the caller of `DialContext` one end of a pipe and relays the other end to Firebase; the server does the same and routes its end through `router.RouteConnectionEx` so normal sing-box routing/DNS/sniffing rules apply to the final egress.
5. Bytes are batched (default: every 50ms or 32KiB, whichever first), optionally zstd-compressed, optionally AES-256-GCM encrypted (see [security.md](./security.md)), base64-encoded, and written as sequential `chunk` records.
6. The reading side reassembles chunks in order (buffering any that arrive out of order), writes reassembled bytes to its local pipe end, then records an ack pointer and deletes acknowledged chunks to bound database growth.
7. Either side closing triggers `state=closing` then `state=closed`; the session's Firebase node is deleted on completion. A background GC sweep also removes abandoned sessions (see [operations.md](./operations.md)).

## Firebase database layout

```
sessions/
  {session_id}/
    metadata        - sessionMetadata: session_id, version, target_host, target_port,
                       created_at, state (pending|active|closing|closed), user
    c2s/
      {seq}/        - chunk: client→server data, keyed by monotonically increasing seq
    s2c/
      {seq}/        - chunk: server→client data
    acks/
      c2s_ack        - uint64, highest consecutive c2s seq the server has processed
      s2c_ack        - uint64, highest consecutive s2c seq the client has processed
```

A `chunk` record:

```json
{
  "seq": 42,
  "timestamp": 1719500000000,
  "compressed": true,
  "encrypted": false,
  "data": "<base64>"
}
```

`encrypted` is only set when the session's user has a PSK configured (see [security.md](./security.md)); `data` is then AES-256-GCM ciphertext (nonce-prefixed) rather than the raw/compressed payload.

## Code layout (`protocol/firebasetunnel/`)

| File | Purpose |
|---|---|
| `protocol.go` | Wire types (`sessionMetadata`, `chunk`), Firebase path helpers |
| `firebase.go` | REST client: Get/Put/Delete with retry, SSE `Listen` with jittered reconnect |
| `session.go` | `chunkSender` (batch/compress/encrypt + backpressure cap), `chunkReceiver` (reorder/decrypt/decompress), ack/cleanup |
| `crypto.go` | Optional AES-256-GCM payload encryption keyed by a PSK |
| `compress.go` | zstd wrappers |
| `util.go` | Jittered backoff, token bucket rate limiter |
| `client.go` | `ClientEndpoint`: session creation, `net.Pipe` dial adapter, c2s/s2c relay |
| `server.go` | `ServerEndpoint`: session discovery, user/limit enforcement, relay, GC sweep, SSM tracker hookup |
