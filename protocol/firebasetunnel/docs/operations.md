# Operations

## Expected latency and throughput

Polling/SSE against Firebase Realtime Database imposes a realistic floor of **~200ms+ added round-trip latency** beyond normal network latency — this is inherent to the relay mechanism (inherited from the upstream PoC's own measurements), not something this implementation eliminates. Treat this protocol as a fallback transport for blocked-direct-connectivity scenarios, not a low-latency primary path.

Firebase Realtime Database enforces project-level read/write quotas; high session counts or throughput can hit these limits. See caps below for how this implementation bounds its own usage; operators should also monitor Firebase's own quota dashboards.

## Resource limits (server-side)

| Limit | Config field | Default | Effect when exceeded |
|---|---|---|---|
| Global concurrent sessions | `max_sessions` | 1000 | New session rejected (`state=closed`), logged at Warn. |
| Per-user concurrent sessions | `max_sessions_per_user` | 50 | Same — bounds one user's worst-case resource use. |
| Per-user session creation rate | `max_sessions_per_second_per_user` | 5/s (token bucket) | New session rejected if the user's bucket is empty — protects against a compromised/buggy client spamming session creation. |
| Sender pending-bytes (client and server) | — (internal, `maxPendingBytes`) | 8 MiB | `feed()` returns an error rather than buffering unbounded memory; caller should treat this as backpressure. |

Rejections are logged with the session ID at `Warn` (never with secrets/PSKs) so operators can spot misconfigured clients or abuse attempts.

## Session garbage collection

Two timeout-driven cleanups exist:

1. **In-relay timeout**: an *active* session with no chunk activity for `session_timeout` (default 300s) is torn down by the relay loop itself.
2. **GC sweep**: a background loop (interval = `session_timeout`/2) scans `sessions/` and deletes:
   - sessions stuck in `pending` (never reached `active`) older than `session_timeout` — covers a client that crashed after writing metadata but before the server ever responded,
   - sessions stuck in `closing`/`closed` for more than `session_timeout` + 10s grace — covers a peer that died mid-shutdown handshake.

This prevents unbounded Firebase node growth from abandoned sessions without relying on either side cleanly exiting.

## Failure isolation

- The server's poll loop and GC loop each run under panic recovery with a 5s restart backoff (`runWithRecovery`) — a bug in either does not crash the rest of the sing-box process or other endpoints/inbounds sharing it.
- A sustained Firebase outage degrades the server to "no new sessions accepted, existing sessions time out via `session_timeout`" rather than a stuck goroutine.
- On the client side, `DialContext` fails within `activation_timeout` (default 30s) if the server never marks a session active — bounded rather than indefinite, so outbound groups (`urltest`/`selector`) can fail over to an alternative outbound in reasonable time.
- SSE reconnects use jittered exponential backoff (`jitteredBackoff`, capped at 30s) to avoid thundering-herd reconnects when many sessions/instances share one Firebase project.

## Rollout / rollback

This protocol ships as ordinary registered endpoint types (`firebasetunnel_client`/`firebasetunnel_server`) — there is currently no build-tag or experimental-flag gate. Adopting it for a fleet should be done config-by-config (enable on a small subset first, monitor logs and SSM stats, then widen) rather than relying on a kill switch built into the binary. Disabling it for a given deployment means removing the endpoint from that config; the server endpoint's `Close()` cancels its poll/GC loops but does not forcibly kill in-flight sessions — they drain naturally via the timeout/GC mechanisms above.

## What to monitor

- Server logs at `Warn`/`Error` for: rejected sessions (unknown user, limit/rate exceeded), ack/ingest failures (potential decrypt/auth failures if PSKs are in use), GC deletions (volume spikes may indicate misbehaving clients).
- SSM traffic stats (if a tracker is wired via `SetTracker`) for per-user byte counts, the same surface used for Shadowsocks usage today.
- Firebase project's own console/quota metrics for read/write volume against plan limits.
