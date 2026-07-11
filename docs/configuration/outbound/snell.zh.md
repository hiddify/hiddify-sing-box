### 结构

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

  ... // 拨号字段
}
```

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### psk

==必填==

用于身份验证的预共享密钥。

#### version

Snell 协议版本，可选 `1` `2` `3` `4` `5`。

默认为 `4`。

| 版本    | TCP | UDP              |
|--------|-----|------------------|
| 1, 2   | ✔   | ✘                |
| 3, 4   | ✔   | ✔（UDP over TCP）  |
| 5      | ✔   | ✔（QUIC 代理）      |

!!! note "QUIC 代理模式（v5）"
    v5 的 QUIC 流量采用专用代理路径：目标地址和首个 QUIC Initial 包经 Snell 加密传输，
    后续包直接转发（QUIC 本身已加密）。其他 UDP 流量仍走标准 UDP over TCP 隧道。

#### network

启用的网络，可选 `tcp` `udp`。

v3/v4/v5 默认两者均启用；v1/v2 默认仅 TCP（不支持 UDP）。

UDP 需要版本 `3` 及以上。

#### reuse

启用连接复用（仅限 Snell v4+）。复用已有的 TCP 连接串行处理多个请求，避免每次请求都重新建立 TCP 连接和加密握手的开销。

需要服务端支持 Snell v4 连接复用。

默认为 `false`。

#### obfs_mode

simple-obfs 混淆模式。

可选 `http` `tls`，留空则禁用混淆。

#### obfs_host

用于 HTTP/TLS 混淆的主机名。

未设置时默认为 `bing.com`。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
