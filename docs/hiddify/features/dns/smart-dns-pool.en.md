# Smart resolver pool

[فارسی](smart-dns-pool.fa.md) · [All Hiddify features](../../index.md)

The smart resolver pool is the resolver handling that every DNS tunnel outbound shares: the
[DNSTT](../protocols/dnstt.en.md) and [MasterDNS](../protocols/masterdns.en.md) outbounds each
run their own pool when their `smart_pool` field is set. The pool spreads the tunnel's queries
over many resolvers, moves to another when one is slow, rate-limited or down, and checks the
down ones in the background until they answer again. It is not a separate server or service:
it lives inside the outbound, and every outbound has its own.

## Why use it

A DNS tunnel sends a lot of queries, and public resolvers soon start to limit or refuse them.
With the pool, the tunnel client sees one local resolver, and the pool keeps the queries flowing
over all the resolvers that work.

The same code also gives every DNS tunnel the same resolver features: `auto` (the built-in list
of about 58,000 public resolvers), a saved score for each resolver so the ones that worked
before are tried first, and a plain-query check before a resolver is used. DoT and DoH resolvers
work for every tunnel through the pool, even for a client that only speaks plain UDP.

## How it gets past filtering

It does not hide anything by itself. It keeps a DNS tunnel running when single resolvers are
throttled or blocked, by spreading the load and leaving out the ones that stop working.

## How it works

- At start, the outbound opens a pool on a free local port and gives its client that address as
  the only resolver. Then it checks the resolvers in `resolvers`, the ones with the best saved
  score first, and adds each one that passes; DNSTT also opens a real tunnel through it,
  MasterDNS sends the plain query of `pretest_domain`. Checking stops once ten are in the pool.
- The pool relays the tunnel's queries over one long-lived socket per resolver, so it adds almost
  nothing to a query's time.
- Each query goes to the resolver with the most spare capacity (`load_balance: auto`): of two
  resolvers drawn at random, the one with fewer queries in flight, lower latency and less loss,
  among those under their rate cap.
- Each resolver's rate cap is learned from what it really answers. When it refuses (REFUSED,
  SERVFAIL, HTTP 429), or drops queries while it still answers others, its cap becomes 90% of
  its recent success rate; the cap grows 10% a second while it keeps answering, and is lifted
  once it no longer holds queries back. A resolver limited to 20 queries a second therefore gets
  about half what a 40 one gets, and the tunnel gets close to the sum of their limits. When
  every resolver is at its cap, a query is sent at once to the one with the most capacity left,
  rather than delayed.
- A refused query is sent again at once to another resolver, up to three resolvers per query.
- Each try is given the resolver's mean latency plus four deviations, like TCP's retransmission
  timeout: a lossy resolver is given up quickly, and a tunnel server that holds polls for a
  second is not mistaken for a lossy one. A resolver that lost packets lately also has its
  unanswered queries sent to a second resolver; a healthy one is never duplicated.
- After `down_after` timeouts or network errors in a row with no answer at all, a resolver is
  down. It gets a copy of a live query every second, and is back in use on its first answer. A
  resolver that still answers some queries is capped, never taken down.
- Each resolver's score, from -10 to 10, is saved in the cache file, under a key of the
  outbound's own (`dnstt_resolvers<record type>`, `masterdns_resolvers`).

## Configuration

`smart_pool` is either `true`, the pool with every default, or an object:

```json
{
  "outbounds": [
    {
      "type": "dnstt",
      "tag": "dnstt-out",
      "domain": "t.example.com",
      "pubkey": "<server public key, hex>",
      "resolvers": ["auto", "8.8.8.8:53", "dot://1.1.1.1:853", "https://cloudflare-dns.com/dns-query"],
      "smart_pool": {
        "enabled": true,
        "load_balance": "lowest_latency"
      }
    },
    {
      "type": "masterdns",
      "tag": "masterdns-out",
      "domains": ["v.example.com"],
      "resolvers": ["auto"],
      "key": "<the server's encrypt_key.txt>",
      "smart_pool": true
    }
  ]
}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Run the pool. `"smart_pool": true` is the same as `{"enabled": true}`. |
| `load_balance` | string | `"auto"` | `auto` sends each query to the resolver with the most spare capacity, as described above. `roundrobin` takes turns. `weighted` picks at random by weight (all equal here). `lowest_latency` prefers the fastest. |
| `deadline` | duration | `5s` | Longest time for one query, over all tries. |
| `per_attempt` | duration | `2s` | Longest time for one try at one resolver; once its latency is known, a try gets its mean latency plus four deviations, at most this. |
| `probe_interval` | duration | `5s` | How often a down resolver is checked. |
| `down_after` | int | `8` | Timeouts or network errors in a row before a resolver is down. |

The resolvers themselves are the outbound's `resolvers`: `host:port` or `host` for UDP,
`tcp://host:port`, `dot://host:853`, `https://host/dns-query`, and `auto`.

## Notes

- The pool changes what the tunnel client sees: one resolver. A client that balances resolvers
  itself (MasterDNS) then balances over the pool as a whole, and measures one MTU for it, so a
  pool of resolvers with different limits gets the MTU of the smallest.
- Measured with local resolvers, 512 KiB download: with three resolvers limited to 20, 30 and 40
  queries a second (the last dropping instead of refusing), MasterDNS takes 12.7 s with the pool
  against 110 s without it, and DNSTT 12.4 s with the pool against 12.5 s with its own resolver
  handling, both at the limit the resolvers allow. With one or three unlimited resolvers, and
  with one limited resolver, the pool matches or beats both tunnels' own handling. Use it with
  every DNS tunnel; it is also what makes DoT, DoH and `auto` resolvers work.
- The pool listens on 127.0.0.1 only, on a port chosen at start, and closes with the outbound.

## See also

- [DNSTT](../protocols/dnstt.en.md)
- [MasterDNS](../protocols/masterdns.en.md)
