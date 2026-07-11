### Structure

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // Listen Fields

  "psk": "my-pre-shared-key",
  "version": 4,
  "obfs_mode": "",
  "obfs_host": ""
}
```

### Multi-User Structure

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // Listen Fields

  "users": [
    {
      "name": "alice",
      "psk": "alice-pre-shared-key"
    },
    {
      "name": "bob",
      "psk": "bob-pre-shared-key"
    }
  ],
  "version": 4,
  "obfs_mode": "",
  "obfs_host": ""
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### psk

==Required if `users` is not set==

The pre-shared key for single-user authentication. Mutually exclusive with `users`.

#### users

==Required if `psk` is not set==

User list for multi-user mode. Each entry has a `name` and a `psk`. Mutually exclusive with `psk`.

The matched user name is available to routing rules via `auth_user`.

#### version

Snell protocol version. Must be `4` or `5`.

Defaults to `4`.

!!! note "QUIC Proxy Mode (v5)"
    When `version` is `5`, the server automatically accepts QUIC traffic on the
    same port. The destination address and the first QUIC Initial packet are
    encrypted by Snell; subsequent packets are forwarded as-is (QUIC provides
    its own encryption). No additional configuration is required.

#### obfs_mode

Simple-obfs obfuscation mode.

One of `http` `tls`, or empty to disable.

!!! warning
    TLS obfuscation is not supported for v4/v5. Use [ShadowTLS](/configuration/inbound/shadowtls/) instead.

#### obfs_host

The obfuscation hostname used for HTTP/TLS obfuscation.

Defaults to `bing.com` if not set.
