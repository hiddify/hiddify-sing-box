# DNS tunnel benchmark

`run.sh` measures the `dnstt` and `masterdns` outbounds through rate-limited local resolvers,
with and without the [smart resolver pool](../../docs/hiddify/features/dns/smart-dns-pool.en.md).
Everything runs on the loopback: no internet, no root.

```bash
QUICK=1 test/dnstunnel-bench/run.sh                # a check that the pool works, about 2 minutes
test/dnstunnel-bench/run.sh                        # every setup once, about 15 minutes
SETUPS="three-limited" ROUNDS=3 test/dnstunnel-bench/run.sh
WORK=/tmp/bench APPROACHES="dnstt-pool masterdns-pool" test/dnstunnel-bench/run.sh
```

The last form is the one to use while working on the pool: `WORK` keeps every row an earlier run
measured, by setup and approach, and the tables at the end show, for each setup run, the
approaches run now next to the cached rows of the others, marked with their age. An approach
whose code did not change (`dnstt-first`, `masterdns-own`, ...) is not run again. `SKIP_BUILD=1`
reuses the binaries in `WORK` too, for a `sing-box` built against a local hmrd checkout. `CACHE=`
turns the cache off.

Run the quick check first after a change to the pool or a tunnel, and the full benchmark once it
passes. `QUICK=1` runs four setups (`three-unlimited`, `three-uneven-latency`, `three-lossy`,
`three-limited`) once, with `dnstt-first`, `dnstt-pool`, `masterdns-first` and `masterdns-pool`
and short transfers, then prints a PASS or FAIL line for each check and exits with status 1 on a
failure:

- every transfer through a pool completes (a baseline, DNSTT direct through a resolver limited to
  20 queries a second, can stall on its own);
- three equal resolvers each get at least 20% of a pool's queries;
- with uneven latency the 250 ms resolver gets at most 5% (for DNSTT the 60 ms one too: its
  ordered stream stalls on a slow answer; MasterDNS may send its copies there);
- with lossy resolvers DNSTT sends the 30% lossy one at most 5% and the 10% one at most 20% (a
  loss shows only after a timeout, which held polls make long); MasterDNS sends the clean one at
  least 45% (every first copy; the second goes to another resolver without a rate limit) and
  gets at least 90% of MasterDNS's speed on the clean resolver alone;
- through three limited resolvers each pool downloads at least 3 times as fast as its tunnel on
  the first resolver alone: that one allows 20 queries a second of the three's 90, so a pool that
  left a resolver out would stay below it.

It needs Go, `curl` and `nc`. It builds `sing-box` from this tree, the MasterDnsVPN server from
`replace/MasterDnsVPN`, the VayDNS (DNSTT) server and `hmrdbench` at the versions `go.mod` pins,
then starts:

- a MasterDnsVPN server in TCP mode and a VayDNS server, both forwarding every stream to a local
  SOCKS server;
- `hmrdbench http`, the download and upload target;
- for each setup, one `hmrdbench resolver` per resolver: it forwards the two tunnel domains to
  the tunnel servers, and refuses or drops what exceeds its rate.

For each approach it starts a client `sing-box` (a `socks` outbound through the tunnel
outbound), waits until a first request goes through (Ready, in whole seconds, up to 60: resolver
tests and session setup), then times a download and an upload, and prints a markdown table row.
Without a rate limit the download runs for a fixed time, `DOWN_SECONDS` (5 s, 2 s in the quick
check), the same for every approach and long enough for a pool to learn which resolvers lose (a
loss shows only after a timeout); the upload is 512 KiB (128 KiB). Through rate-limited
resolvers, where a tunnel on one resolver takes seconds to deliver anything, both have a fixed
size: 128 and 32 KiB (64 and 8 KiB). `DOWN_SECONDS=0` makes every download fixed-size, and
`DOWN_BYTES` and `UP_BYTES` set one size for every setup. For each transfer the row has:

- the rate in kbps (kilobits a second, 1000 bit/s), or the bytes moved when it failed within
  `MAX_TIME`;
- queries/s: the DNS queries a second the tunnel sent to all the setup's resolvers during the
  transfer, answered, refused or dropped, read from each resolver's counters (`-stats 100ms`);
- for the download, each resolver's share of those queries, in percent and in the setup's order.
  It shows whether an approach really uses every resolver.

| Approach | What it runs |
|---|---|
| `dnstt-first` | DNSTT with the setup's first resolver only: no multi-resolver |
| `dnstt-pool` | DNSTT with every resolver, through the pool (`smart_pool: true`) |
| `masterdns-first` | MasterDnsVPN with the setup's first resolver only: no multi-resolver |
| `masterdns-own` | MasterDnsVPN with every resolver, through its own multi-resolver balancer; it sends every packet over two resolvers (`packet_duplication` 2, the MasterDnsVPN default) |
| `masterdns-own-nodup` | The same with every packet sent once (`packet_duplication` 1): the difference to `masterdns-own` is what duplication is worth |
| `masterdns-pool` | MasterDnsVPN with every resolver, through the pool: MasterDnsVPN sees one resolver and sends each packet once; the pool sends each query to a second resolver without a rate limit (`duplicate`, from `packet_duplication`) and passes both answers on |

Without a setup list it runs all eight below, one round each. The setups without a rate limit
run one after another, alone, since they are bound by the machine; then the rate-limited ones
run at the same time, each on its own resolvers. With `ROUNDS` above 1 it ends with a table of
each approach's median download and upload.

| Setup | Resolvers (`qps:mode[:latency[:loss]]`) |
|---|---|
| `one-unlimited` | `0:refuse` |
| `one-10ms` | `0:refuse:10ms`: one unlimited resolver 10 ms away, the closest to a real one |
| `one-limited` | `30:refuse` |
| `three-unlimited` | `0:refuse 0:refuse 0:refuse` |
| `three-limited` | `20:refuse 30:refuse 40:drop` |
| `three-limited-one-dead` | `30:refuse 40:drop 0:dead` |
| `three-uneven-latency` | `0:refuse:10ms 0:refuse:60ms 0:refuse:250ms` |
| `three-lossy` | `0:refuse 0:refuse:0:0.1 0:refuse:0:0.3` |

Other variables: `ROUNDS` (1; with more than one, or with the cache, a median table follows the
rows), `MAX_TIME` (60 s per transfer; `UP_MAX_TIME` for uploads alone, 15 s in the quick check,
which does not judge them: DNSTT's upload through refusing resolvers can crawl at 1 kbps, with
or without the pool), `MASTERDNS_EXTRA`, `DNSTT_EXTRA`
and `POOL_EXTRA` (more fields for every `masterdns` or `dnstt` outbound or `smart_pool` object,
such as `'"balancing":"round_robin"'` or `'"duplicate":2'`), `CLIENT_EXTRA` (more top-level
fields of the client configuration, such as `'"experimental":{"debug":{"listen":"127.0.0.1:9999"}}'`
for a CPU profile), `QUERY_BYTES` (bounds the
upload a query carries, as a resolver that limits the name length does: DNSTT's `max-qname-len`
and MasterDNS's `max_upload_mtu` are set for about that many bytes; try 50, 100 and 128),
`PARALLEL=all` (every setup at once, faster and noisier; by default the setups without a rate
limit run one after another, being bound by the machine), `BASE_PORT` (27100), `WORK` (a
new temporary directory; its logs, binaries and row cache stay there).

The library itself has a benchmark that needs no tunnel: `go run ./cmd/hmrdbench bench` in
[hmrd_multi_resolver_dns](https://github.com/hiddify/hmrd_multi_resolver_dns).
