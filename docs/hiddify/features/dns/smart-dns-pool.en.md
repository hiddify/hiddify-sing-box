# Smart DNS pool

[فارسی](smart-dns-pool.fa.md) · [All Hiddify features](../../index.md)

The smart DNS pool is a local DNS server that sends each query to one of many upstream
resolvers. It moves to another resolver when one is slow, rate-limited or down, and checks the
down ones in the background until they answer again. It is a service: `"type": "smart_dns_pool"`
in the `services` list.

## Why use it

It is made for [DNSTT](../protocols/dnstt.en.md). A DNS tunnel sends a lot of queries, and public resolvers
soon start to limit or refuse them. Point DNSTT at the pool instead of at one resolver, and the
pool spreads the queries over all of yours. DNSTT sees one normal local resolver.

Any other program that uses a plain DNS server can use it too.

## How it gets past filtering

It does not hide anything by itself. It keeps a DNS tunnel running when single resolvers are
throttled or blocked, by spreading the load and leaving out the ones that stop working.

## How it works

- The pool listens on UDP and TCP at `listen` and `listen_port`.
- For each query, it orders the resolvers that are not down by `load_balance`, and tries them
  one after another until one answers. Each try may take at most `per_attempt`, and the whole
  query at most `deadline`.
- When a resolver answers with a refusal, a server failure or HTTP 429, the pool lowers the rate
  it sends to that resolver, and raises it again while the resolver keeps answering.
- After `down_after` timeouts or network errors in a row, a resolver is down. Every
  `probe_interval`, the pool sends it the query that failed. When it answers, it is back in use.

## Configuration

```json
{
  "services": [
    {
      "type": "smart_dns_pool",
      "tag": "dns-pool",
      "listen": "127.0.0.1",
      "listen_port": 19876,
      "load_balance": "lowest_latency",
      "upstreams": [
        { "type": "udp", "address": "8.8.8.8:53" },
        { "type": "udp", "address": "1.1.1.1:53" },
        { "type": "https", "address": "https://cloudflare-dns.com/dns-query" }
      ]
    }
  ],
  "outbounds": [
    {
      "type": "dnstt",
      "tag": "dnstt-out",
      "domain": "t.example.com",
      "pubkey": "<server public key, hex>",
      "resolvers": ["127.0.0.1:19876"]
    }
  ]
}
```

In DNSTT, write the pool's address as `host:port` with no `udp://` prefix.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `listen` | string | `"127.0.0.1"` | Address to listen on. |
| `listen_port` | int | required | Port to listen on, for both UDP and TCP. |
| `upstreams` | list of objects | required | The resolvers. At least one. Fields below. |
| `load_balance` | string | `"roundrobin"` | `roundrobin` takes turns. `weighted` picks at random by `weight`. `lowest_latency` prefers the fastest, and tries untested resolvers first so each gets measured. |
| `deadline` | duration | `5s` | Longest time for one query, over all tries. |
| `per_attempt` | duration | `2s` | Longest time for one try at one resolver. |
| `probe_interval` | duration | `5s` | How often a down resolver is checked. |
| `down_after` | int | `8` | Timeouts or network errors in a row before a resolver is down. |

Each entry in `upstreams`:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `type` | string | `"udp"` | `udp`, `tcp`, `tls` (DoT, also `dot`) or `https` (DoH, also `doh`). |
| `address` | string | required | `host:port` for `udp`, `tcp` and `tls`; the full URL for `https`. |
| `weight` | int | `0` | Used by `weighted`. A resolver with weight `0` is used only when no weighted one is available. |
| `name` | string | protocol and address, e.g. `udp://8.8.8.8:53` | A name for logs. |

The other listen fields from sing-box are accepted, but only `listen` and `listen_port` are
used.

DNSTT's own `smart_pool` field starts a pool like this inside the outbound, with the default
settings, and fills it with the resolvers that pass DNSTT's check.

## See also

- [DNSTT](../protocols/dnstt.en.md)
