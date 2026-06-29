# Configuration reference

## `firebasetunnel_client`

```json
{
  "type": "firebasetunnel_client",
  "tag": "fb-client",
  "firebase_urls": ["https://your-project-default-rtdb.firebaseio.com"],
  "firebase_secret": "YOUR_DATABASE_SECRET",
  "user": "alice",
  "psk": "optional-shared-secret-for-alice",
  "batch_interval": "50ms",
  "batch_max_bytes": 32768,
  "retry_limit": 5,
  "activation_timeout": "30s"
}
```

| Field | Required | Default | Notes |
|---|---|---|---|
| `firebase_urls` | yes | — | First URL is used; list exists for future multi-backend failover. |
| `firebase_secret` | one of secret/token | — | Legacy Firebase Database Secret. Coarse: grants full read/write on the whole project. |
| `firebase_auth_token` | one of secret/token | — | Short-lived Firebase Auth/service-account token; preferred over `firebase_secret`. |
| `user` | yes | — | Self-reported accounting label sent in session metadata. |
| `psk` | no | — | If set, encrypts this client's relayed bytes and lets the server verify the `user` label cryptographically. Must match the server's per-user PSK for this `user`. |
| `batch_interval` | no | `50ms` | How long to accumulate bytes before an early flush timer fires. |
| `batch_max_bytes` | no | `32768` | Flush early once buffered bytes reach this size. |
| `retry_limit` | no | `5` | Firebase REST retry attempts before failing a request. |
| `activation_timeout` | no | `30s` | How long `DialContext` waits for the server to mark a session active before failing (lets outbound groups like `urltest`/`selector` fail over). |

Use it as the target of another outbound's chain, or directly as a `detour`/`outbound` reference, the same way `tunnel_client` is used.

## `firebasetunnel_server`

```json
{
  "type": "firebasetunnel_server",
  "tag": "fb-server",
  "firebase_urls": ["https://your-project-default-rtdb.firebaseio.com"],
  "firebase_secret": "YOUR_DATABASE_SECRET",
  "users": [
    { "name": "alice", "psk": "optional-shared-secret-for-alice" },
    { "name": "bob" }
  ],
  "poll_interval": "200ms",
  "session_timeout": "300s",
  "retry_limit": 5,
  "max_sessions": 1000,
  "max_sessions_per_user": 50,
  "max_sessions_per_second_per_user": 5
}
```

| Field | Required | Default | Notes |
|---|---|---|---|
| `firebase_urls` | yes | — | Must match the client(s)' project. |
| `firebase_secret` / `firebase_auth_token` | one required | — | Same semantics as client. |
| `users` | yes, non-empty | — | Sessions declaring an unlisted `user` are rejected. |
| `users[].psk` | no | — | If set, sessions from this user must encrypt/decrypt correctly under this key or are rejected — turns the `user` label into a verified credential. |
| `poll_interval` | no | `200ms` | Fallback poll cadence alongside the SSE listen stream; also the c2s/s2c chunk poll interval during an active relay. |
| `session_timeout` | no | `300s` | Inactivity timeout for an active session; also drives the GC sweep interval (half this value) and the grace period for abandoned-session cleanup. |
| `retry_limit` | no | `5` | Firebase REST retry attempts. |
| `max_sessions` | no | `1000` | Global concurrent session cap. |
| `max_sessions_per_user` | no | `50` | Per-user concurrent session cap. |
| `max_sessions_per_second_per_user` | no | `5` | Token-bucket rate limit on new session creation per user. |

The server endpoint dials real targets via the router (`router.RouteConnectionEx`), so normal `route` rules, DNS, and sniffing in the server's sing-box config apply to traffic exiting through this tunnel — it is not a raw unrestricted relay.

## Traffic accounting

Per-user upload/download bytes are tracked through the same SSM (`service/ssmapi`) traffic manager used by the Shadowsocks multi-user inbound, so Hiddify Manager can read `firebasetunnel_server` usage the same way it already reads Shadowsocks usage — wire a tracker via `ServerEndpoint.SetTracker(...)` at box-construction time.
