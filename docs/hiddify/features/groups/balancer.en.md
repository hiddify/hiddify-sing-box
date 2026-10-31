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

### Which connections are closed

Every connection is tracked under the member it went through. A member that becomes faster
only takes the new connections: nothing is closed for speed, so a call or a download through
a working server goes on. Connections are closed in two cases only:

- A member whose test fails has its connections closed; those of the other members stay.
- Once after start: the first tests may move the selection several times while the
  connections opened on the provisional choice are still on it. 30 seconds after start, when
  some member has a result of this run, the connections of the members the group no longer
  uses (not selected for `lowest-delay`, outside the acceptable delay otherwise) are closed
  once. Until a result of this run exists, this waits for the next update.

`interrupt_exist_connections` says whether the connections that came in from inbounds are
closed too in these cases; connections opened inside sing-box always are.

### Strategies

- **`round-robin`** (default): members are sorted by delay, and connections take turns among
  the alive ones. Until the first test results arrive, all members take turns in config order.
- **`lowest-delay`**: every connection uses the member with the lowest delay. At start it uses
  the member that was fastest in the cached results, or the first member when there are none.
  It keeps that member while it answers: another member takes the selection only when it is
  faster by more than `tolerance` and by more than `tolerance_ratio` of the selected member's
  delay, whichever is larger, so the jitter between two close servers does not move the
  group. A member that failed its test is left at once for the fastest live one; when no
  member is live, the selection stays.
- **`consistent-hashing`**: the member is chosen from the destination: its registrable domain
  (for example `example.com` for `www.example.com`) or its IP address. The same destination
  always gets the same member while that member is alive. If it is dead, the group tries up to
  `max_retry` other picks from the hash, then the first alive member in the list. If none is
  alive, it uses the hashed member anyway.
- **`sticky-sessions`**: the member is chosen from the source address and the destination
  together. A new pair gets a random member, and the group remembers it, for up to 1,000 pairs,
  for `ttl`. A remembered member that is dead is replaced with another alive member, picked the
  same way as above.
- **`pool`**: a fixed number of slots (`pool`, 3 by default, at most the number of members),
  each held by a working member. A connection goes to the slot picked by a hash of what
  `sticky_hash` names, so the same app or site keeps its member.
  - A member keeps its slot while it answers, so the connections of the other slots never move.
  - A dead member is replaced in its slot by a working member outside the pool. While there is
    none, the slot is skipped: its connections spread over the working slots, the same way each
    time, and come back when the member answers again.
  - With `pool_tolerance` 0, the slots keep the first working members in config order. With
    more, a member outside replaces a slot member only when it is faster by more than that many
    milliseconds.
  - `sticky_hash` is a list of `process`, `domain` (the registrable domain), `source_ip`,
    `dest_ip` and `dest_port`; the default is `["process", "domain"]`. `["none"]` sends
    connections round-robin over the working slots.
  - Refilling a slot does not interrupt connections.

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
| `strategy` | string | `"round-robin"` | `round-robin`, `lowest-delay`, `consistent-hashing`, `sticky-sessions` or `pool`. |
| `pool` | int | `3` | For `pool`: the number of slots. |
| `pool_tolerance` | int | `0` | For `pool`: how much faster, in milliseconds, a member outside the pool must be to take a slot. At most `15000`. |
| `sticky_hash` | list of strings | `["process", "domain"]` | For `pool`: what a connection sticks to its slot by. `["none"]` turns sticking off. |
| `delay_acceptable_ratio` | number | `2` | How much slower than the fastest member a member may be and still be used. `2` means up to twice the fastest delay. Unset or `0` is `2`. |
| `max_retry` | int | `0` | For `consistent-hashing` and `sticky-sessions`: how many other hash picks to try before going down the list. |
| `ttl` | duration | `0` (no expiry) | For `sticky-sessions`: how long a pair keeps its member. |
| `interrupt_exist_connections` | bool | `false` | When a member dies, or at the one move after start, also close the connections that came in from inbounds. Without it, only connections opened inside sing-box are closed. |
| `tolerance` | int | `50` | For `lowest-delay`: how much faster, in milliseconds, another member must be to take the selection. |
| `tolerance_ratio` | number | `0.1` | For `lowest-delay`: how much faster, as a share of the selected member's delay, another member must be to take the selection. The larger of the two tolerances applies. |

## See also

- [Monitoring](monitoring.en.md)
- [Fallback](fallback.en.md)
