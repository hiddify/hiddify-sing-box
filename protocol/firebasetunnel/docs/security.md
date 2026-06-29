# Security / threat model

## Who can see what

By default (no `psk` configured), relayed application bytes are **cleartext to anyone who can read the Firebase project** — the project owner, anyone holding the `firebase_secret` or a valid auth token, and anyone with read access to the Realtime Database console. Transport security (HTTPS to Firebase) protects bytes in transit between this process and Firebase, but not from Firebase-side observers.

Even with the optional PSK encryption enabled (below), **metadata is never hidden**: `target_host`/`target_port` (the dial destination), session timing, and chunk sizes are visible to anyone with project read access. This protocol does not protect against traffic analysis — an observer who can read the Firebase project can infer what's being accessed and roughly how much data flows, even if the payload itself is encrypted.

## Auth options

| Option | Field | Strength | Notes |
|---|---|---|---|
| Legacy Database Secret | `firebase_secret` | Weak | Single shared secret grants full read/write to the *entire* Firebase project, not just this tunnel's data. Matches the upstream PoC's default; simplest to set up. |
| Firebase Auth / service-account token | `firebase_auth_token` | Better | Short-lived, can be scoped via Firebase security rules. Recommended for anything beyond personal/test use. |

Neither option authenticates *which client* is connecting — that's what the `user` label and optional per-user PSK are for.

## User-label verification (optional, per-user PSK)

Without a PSK, `user` is a **self-reported claim** — the server uses it only as an accounting label, not a credential. Any client holding the project's `firebase_secret`/token could claim to be any user.

Setting `psk` on a `FirebaseTunnelUser` (server) and the matching `psk` on the client turns the label into a verified credential: the server only accepts a session's declared `user` if its chunks decrypt successfully under that user's derived key (AES-256-GCM, key derived from the PSK via SHA-256). A mismatched or missing PSK causes chunk ingestion to fail, and the session is treated as an abuse signal (logged, counted against that user's failure rate) rather than silently relayed.

## Payload encryption

When a PSK is configured for a user, every chunk's payload is encrypted with AES-256-GCM before base64 encoding (`chunk.encrypted = true`). This is **opt-in** — off by default, matching the upstream PoC's simplest-path behavior — because:
- it requires coordinating a PSK between client and server config (extra operational step),
- the metadata-visibility limitation above means it's a partial mitigation, not full traffic confidentiality.

Strongly recommended for anything beyond personal/throwaway test use.

## What this protocol does *not* protect against

- A malicious or compromised Firebase project administrator (full project access bypasses everything above).
- Traffic analysis via session/chunk timing and sizes, even with payload encryption enabled.
- Firebase-side logging/retention outside this protocol's control.
- Denial of service from a party who obtains the shared secret/token (mitigated, not eliminated, by the per-user rate limits and session caps described in [operations.md](./operations.md)).

## Rotation

Secrets and PSKs are currently single-value per config (`firebase_secret`, `users[].psk`) — rotating either requires a coordinated config update on both client and server with a brief overlap window where old sessions using the previous value may fail. Multi-value (list-based) rotation support is a known follow-up, not yet implemented.
