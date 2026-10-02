---
icon: material/new-box
---

# Group

### 结构

```json
{
  "dns": {
    "servers": [
      {
        "type": "group",
        "tag": "dns-group",

        "servers": [
          "dns-a",
          "dns-b"
        ],
        "mode": "parallel",
        "ignore_ranges": [
          "10.10.34.0/24"
        ]
      }
    ]
  }
}
```

### 字段

#### servers

==必填==

此组包含的 DNS 服务器 tag 列表。

限制：

- 组内不能包含另一个组。
- 组内不能包含 `fakeip` 类型的服务器。

- 已弃用的 `multi` 类型服务器也视为组。

#### mode

查询方式，默认使用 `parallel`。

| 模式           | 行为                                   |
|--------------|--------------------------------------|
| `parallel`   | 并发查询所有服务器。                           |
| `sequential` | 按顺序逐个查询，直到某个服务器返回结果。                 |

两种模式下，都会返回经过 `ignore_ranges` 过滤后仍包含应答记录的第一个响应。
不包含应答记录的响应（例如 NXDOMAIN）仅在没有任何服务器返回应答时使用。
如果所有服务器均失败，返回第一个错误（`parallel`）或最后一个错误（`sequential`）。

#### ignore_ranges

IP 范围列表，响应中位于这些范围内的 A 和 AAAA 记录将被丢弃。

过滤后没有剩余应答记录的响应将被忽略，可用于跳过被污染或被屏蔽的响应。

### 已弃用的 `multi` 类型

`multi` 类型是 `group` 的别名，为兼容现有配置而保留：
`"parallel": true` 等同于 `"mode": "parallel"`，否则等同于 `"mode": "sequential"`。`ignore_ranges` 保持不变。
