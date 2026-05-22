### 结构

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // 监听字段

  "psk": "my-pre-shared-key",
  "version": 4,
  "obfs_mode": "",
  "obfs_host": ""
}
```

### 多用户结构

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // 监听字段

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

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### psk

==未设置 `users` 时必填==

单用户模式的预共享密钥，与 `users` 互斥。

#### users

==未设置 `psk` 时必填==

多用户模式的用户列表，每项包含 `name` 和 `psk`，与 `psk` 互斥。

匹配到的用户名可在路由规则中通过 `auth_user` 使用。

#### version

Snell 协议版本，必须为 `4` 或 `5`。

默认为 `4`。

!!! note "QUIC 代理模式（v5）"
    当 `version` 为 `5` 时，服务端自动在同一端口接收 QUIC 流量。
    目标地址和首个 QUIC Initial 包经 Snell 加密传输，后续包直接转发（QUIC 本身已加密）。
    无需额外配置。

#### obfs_mode

simple-obfs 混淆模式。

可选 `http` `tls`，留空则禁用混淆。

!!! warning
    v4/v5 不支持 TLS 混淆，请改用 [ShadowTLS](/zh/configuration/inbound/shadowtls/)。

#### obfs_host

用于 HTTP/TLS 混淆的主机名。

未设置时默认为 `bing.com`。
