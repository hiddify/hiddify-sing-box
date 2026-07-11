### Structure

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 8388,
  "psk": "my-pre-shared-key",
  "version": 4,
  "reuse": false,
  "network": "",
  "obfs_mode": "",
  "obfs_host": "",

  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### psk

==Required==

The pre-shared key for authentication.

#### version

Snell protocol version. One of `1` `2` `3` `4` `5`.

Defaults to `4`.

| Version | TCP | UDP             |
|---------|-----|-----------------|
| 1, 2    | ✔   | ✘               |
| 3, 4    | ✔   | ✔ (UoT)         |
| 5       | ✔   | ✔ (QUIC proxy)  |

!!! note "QUIC Proxy Mode (v5)"
    In v5, QUIC traffic uses a dedicated proxy path: the destination address
    and the first QUIC Initial packet are encrypted by Snell; subsequent
    packets are forwarded as-is (QUIC provides its own encryption).
    Other UDP traffic falls back to the standard UDP-over-TCP tunnel.

#### network

Enabled network, one of `tcp` `udp`.

Both are enabled by default for v3/v4/v5. For v1/v2 only TCP is enabled by default (no UDP support).

UDP requires version `3` or above.

#### reuse

Enable connection reuse (Snell v4+ only). Reuses an existing TCP connection for
multiple sequential requests, avoiding the overhead of a new TCP and encryption
handshake for each request.

Requires the server to support Snell v4 connection reuse.

Defaults to `false`.

#### obfs_mode

Simple-obfs obfuscation mode.

One of `http` `tls`, or empty to disable.

#### obfs_host

The obfuscation hostname used for HTTP/TLS obfuscation.

Defaults to `bing.com` if not set.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
