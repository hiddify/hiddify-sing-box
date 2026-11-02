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
  nothing to a query's time. Toward the pool, DNSTT runs 300 workers (`udp-workers` sets another
  number), each keeping one query out on a socket of its own, instead of 100 workers that open a
  socket per query, which is meant for real resolvers, for random source ports.
- Each query goes to one of the best resolvers under their rate cap (`load_balance: auto`). A
  resolver's cost is its latency, weighed by its loss. Every resolver within 1.2 times the
  cheapest, plus 5 ms, and within 2 points of the lowest loss, counts as equally good, and those
  take turns, the least recently used first: equal resolvers get equal shares, a clearly slower or
  lossier one is left out. The latency is the resolver's fastest answer of the last ten seconds,
  so a poll the tunnel server held for a second does not sideline the resolver that carried it;
  queries in flight do not count, since a tunnel keeps hundreds of polls in flight at a resolver
  that is not loaded at all. Loss is compared with its uncertainty, so a few samples neither shut
  out a clean resolver nor pass a lossy one as clean. A new resolver gets one query at a time
  until it has answered eight (refusals included): it may be many times slower, and a share of
  the queries there would stall the tunnel's ordered stream. A resolver left out is tried again
  every two seconds.
- Each resolver's rate cap is learned from what it really answers. When it refuses (REFUSED,
  SERVFAIL, HTTP 429), or drops queries while it still answers others, its cap becomes 90% of
  its recent success rate; the cap grows 10% a second while it keeps answering, and is lifted
  once it no longer holds queries back. Each resolver is therefore used up to its limit, and the
  tunnel gets close to the sum of the limits. A resolver in use for less than three seconds is
  measured over the time it has been in use, and for a second after the pool sent it overflow
  its refusals do not lower its cap: otherwise a tunnel that keeps hundreds of queries in flight
  drives the caps far below the limits. When
  every resolver is at its cap, a query is sent at once to the one with the most capacity left,
  rather than delayed.
- A refused query is sent again at once to another resolver, up to three resolvers per query.
- Past the resolver's mean latency plus four deviations, like TCP's retransmission timeout, a
  query is also tried on another resolver, but the first try stays open until `per_attempt` and
  its answer still counts: a tunnel server holds polls, and dropping a late answer would lose its
  data. The retry goes to any resolver when the first one really loses queries, and only to one
  about as fast as the best when it does not, since the query is then most likely held. A
  resolver that lost packets lately also has its unanswered queries sent to a second resolver
  sooner; a healthy one is never hedged.
- With `duplicate` (MasterDNS: 2, its `packet_duplication`), each query also goes to other
  resolvers that have no rate limit, the least lossy first, and every answer reaches the tunnel. The MasterDNS server
  answers each copy with data of its own, so the tunnel keeps more in flight than its client
  would; that is what MasterDnsVPN's own balancer does over several resolvers, and behind the pool
  the client sees one. A rate-limited resolver gets no copies and keeps its quota for new data.
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
| `duplicate` | int | `1`; masterdns: its `packet_duplication`, `2` | Resolvers each query is sent to, copies included. The copies go only to resolvers without a rate limit, and every answer reaches the tunnel. Do not raise it for DNSTT: its client does not gain from it. |

The resolvers themselves are the outbound's `resolvers`: `host:port` or `host` for UDP,
`tcp://host:port`, `dot://host:853`, `https://host/dns-query`, and `auto`.

## Notes

- The pool changes what the tunnel client sees: one resolver. A client that balances resolvers
  itself (MasterDNS) then balances over the pool as a whole, and measures one MTU for it, so a
  pool of resolvers with different limits gets the MTU of the smallest.
- Use the pool with every DNS tunnel; it is also what makes DoT, DoH and `auto` resolvers work.
  Measured on the loopback with
  [`test/dnstunnel-bench/run.sh`](../../../../test/dnstunnel-bench/README.md), which needs no
  internet and no root: `QUICK=1` checks in about two minutes that the pool behaves (spread,
  slow and lossy resolvers avoided, limited ones combined), the full run takes about 40 minutes
  with three rounds. Median download in kbps (kilobits a second) of three rounds: 128 KiB through
  rate-limited resolvers, 5 seconds otherwise. The resolvers: one or three unlimited; one
  unlimited 10 ms away; one limited to 30 queries a second; three limited to 20, 30 and 40 (the
  last dropping instead of refusing); 30 and 40 with a third one dead; three unlimited answering
  after 10, 60 and 250 ms; three unlimited losing 0%, 10% and 30%. "First resolver" is the
  setup's first one alone, which is the fastest and the lossless one in the last two setups.

| Setup | DNSTT, first resolver | DNSTT, pool | MasterDNS, first resolver | MasterDNS, own balancer | MasterDNS, own, no duplication | MasterDNS, pool |
|---|---|---|---|---|---|---|
| one-unlimited | 23365 | **41370** | 22941 | 24754 | 22734 | 22109 |
| one-10ms | 22203 | **33498** | 725 | 545 | 567 | 460 |
| one-limited | 150 | **173** | 79 | 78 | 80 | 79 |
| three-unlimited | 25003 | **34628** | 22120 | 18467 | 29569 | 19093 |
| three-limited | 87 | **281** | 34 | 337 | 327 | **335** |
| three-limited-one-dead | 156 | **228** | 79 | 211 | 275 | 228 |
| three-uneven-latency | 20707 | **30821** | 644 | 17694 | 896 | **18334** |
| three-lossy | 23328 | **37899** | 23041 | 23652 | 74 | **25161** |

  DNSTT is faster through the pool in every setup: 1.4 to 1.8 times DNSTT on its first resolver
  without a rate limit, 3.2 times through three limited resolvers and 1.5 times with one of them
  dead. MasterDNS through the pool matches its own balancer through limited resolvers (10 times
  MasterDNS on the first resolver) and with uneven latency, and is ahead of it with lossy
  resolvers, where its uploads are 8 times faster (the own balancer spreads queries over the
  lossy resolvers too). It is behind its own balancer without duplication on three unlimited
  resolvers and with one resolver dead, and behind MasterDNS alone on one resolver 10 ms away:
  those are open. MasterDNS's
  own balancer sends every packet over two resolvers (`packet_duplication`); the pool does the
  same with `duplicate`, over resolvers without a rate limit, which is worth 20 times on uneven
  latency, where MasterDNS otherwise keeps about one query in flight and waits out each answer.
  Results on the loopback vary by about a fifth between runs, so the table's smaller gaps are not
  differences. The full table, with uploads and query rates, comes from running the script; the
  pool's own benchmark, without a tunnel, is `go run ./cmd/hmrdbench bench` in
  [hmrd_multi_resolver_dns](https://github.com/hiddify/hmrd_multi_resolver_dns).
- The pool listens on 127.0.0.1 only, on a port chosen at start, and closes with the outbound.

## See also

- [DNSTT](../protocols/dnstt.en.md)
- [MasterDNS](../protocols/masterdns.en.md)
