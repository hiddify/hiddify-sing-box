# Balancer

[فارسی](balancer.fa.md) · [All Hiddify features](../../index.md)

The balancer is an outbound group that spreads connections over its members. It picks a member
for each connection, using the test results from Hiddify's [monitoring](monitoring.en.md). It is
an outbound: `"type": "balancer"` in the `outbounds` list.

## Why use it

- Spread traffic over several servers instead of loading one.
- Keep each site, or each device and site, on the same server, so logins and sessions do not
  break.
- Always use the fastest server, without the URL test group's own test schedule.

The Hiddify app uses it for its "lowest delay" and "load balance" groups.

## How it gets past filtering

It does not. It only chooses among outbounds that do. It helps when some of your servers are
blocked: members that fail their test are left out.

## How it works

The monitoring tests every outbound and reports the results to the group. For each member, the
balancer uses the delay from the last test:

- A member that failed its test, or has no test result yet, counts as dead.
- A result loaded from the cache at start, not yet tested again, gets 20,000 ms added. A fresh
  test always wins over an old one.
- The acceptable delay is the fastest member's delay (at least 100 ms) times
  `delay_acceptable_ratio`. It always stays below the timeout value, so a dead member is never
  acceptable. A member whose delay is not above the acceptable delay counts as alive.

For UDP connections, the group uses only the members that support UDP, when there are any.

When a connection through a member fails to open, that member is tested again at once. The
connection is not retried on another member.

### Strategies

- **`round-robin`** (default): members are sorted by delay, and connections take turns among
  the alive ones. Until the first test results arrive, all members take turns in config order.
- **`lowest-delay`**: every connection uses the member with the lowest delay. Until the first
  results arrive, it uses the first member.
- **`consistent-hashing`**: the member is chosen from the destination: its registrable domain
  (for example `example.com` for `www.example.com`) or its IP address. The same destination
  always gets the same member while that member is alive. If it is dead, the group tries up to
  `max_retry` other picks from the hash, then the first alive member in the list. If none is
  alive, it uses the hashed member anyway.
- **`sticky-sessions`**: the member is chosen from the source address and the destination
  together. A new pair gets a random member, and the group remembers it, for up to 1,000 pairs,
  for `ttl`. A remembered member that is dead is replaced with another alive member, picked the
  same way as above.

## Configuration

```json
{
  "type": "balancer",
  "tag": "balance",
  "outbounds": ["server-a", "server-b", "server-c"],
  "strategy": "round-robin",
  "delay_acceptable_ratio": 2
}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `outbounds` | list of strings | required | Tags of the members. |
| `strategy` | string | `"round-robin"` | `round-robin`, `lowest-delay`, `consistent-hashing` or `sticky-sessions`. |
| `delay_acceptable_ratio` | number | `2` | How much slower than the fastest member a member may be and still be used. `2` means up to twice the fastest delay. Unset or `0` is `2`. |
| `max_retry` | int | `0` | For `consistent-hashing` and `sticky-sessions`: how many other hash picks to try before going down the list. |
| `ttl` | duration | `0` (no expiry) | For `sticky-sessions`: how long a pair keeps its member. |
| `interrupt_exist_connections` | bool | `false` | When the group's choice changes, also close connections that came in from inbounds. Without it, only connections opened inside sing-box are closed. With `consistent-hashing` and `sticky-sessions`, every new test result counts as a change. |
| `tolerance` | int | | Accepted, not used. |

## See also

- [Monitoring](monitoring.en.md)
- [Fallback](fallback.en.md)
