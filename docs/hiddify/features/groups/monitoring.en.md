# Monitoring

[فارسی](monitoring.fa.md) · [All Hiddify features](../../index.md)

Monitoring tests every outbound and endpoint in the background: it measures the delay through
each one and finds the IP address and country it exits from. Groups such as the
[balancer](balancer.en.md) choose members from these results, and the app shows them. It is
always on. Its settings are the `monitoring` field of the `experimental` block.

## Why use it

- Groups that use it share one test schedule for the whole config.
- You see the exit IP address, country and provider of each server, not only its delay.
- Tests run only while you use the connection, so an idle device does not keep testing.
- Results are saved, so groups can make a choice right after start, before new tests finish.

## How it gets past filtering

It does not. It finds out which outbounds work, so groups can avoid the blocked ones.

## How it works

### What is tested

- Every outbound and endpoint is tested, except groups. A test opens the URL test address
  through the outbound and measures the delay, as the URL test group does. A test that fails or
  takes longer than `url_test_timeout` marks the outbound as failed.
- A group's result is the result of its selected member. When it has none, it is the best
  result among its members.
- After a successful test, monitoring asks an IP information service, through the same outbound,
  for the exit IP address, country, region, city and network. It does this when the outbound
  has no IP information yet, or only information loaded from the cache. If that request is
  faster than the URL test, its time becomes the delay.

### When tests run

- Tests start with sing-box, and run in cycles every `interval`. Each cycle tests the outbounds
  whose result is older than `interval` or marked for testing, fastest first, `workers` at a
  time.
- When no connection has gone through sing-box for `idle_timeout`, testing stops. The next
  connection starts it again.
- An outbound that is not ready yet, for example Psiphon still connecting, is skipped and tried
  again 3 seconds later.
- Some events test at once: a connection that fails through a balancer member, a selector that
  switches to another outbound (the outbounds that depend on it are tested again), or an
  outbound that finished connecting, such as Psiphon or DNSTT.
- When the network changes, every outbound is tested again 2 seconds after the last change.
  A test broken by the network reset runs again.

### URLs

The tests use the first address in `urls`. If a whole cycle has no successful test, the cycle
runs again with the next address, until one works or the list ends. The address that worked is
used from then on.

### Saved results

Results are saved in the cache file and loaded at the next start. A loaded result is marked as
"from cache" until the outbound is tested again. The balancer adds 20,000 ms to such results,
so a fresh test wins.

Groups that subscribe to monitoring get one update for a burst of results, after
`debounce_window`.

### IP information services

If `ipinfo_url` is set, it is tried first. It must return JSON like ipapi.co's, with fields such
as `ip`, `country_code`, `region`, `city`, `asn` and `org`. If it fails, these services are
tried in turn, starting from a random one:

- ipapi.co
- ip-api.com
- ipinfo.io
- api.ip.sb
- ipwho.is
- api.country.is
- api.my-ip.io

## Configuration

```json
{
  "experimental": {
    "monitoring": {
      "interval": "5m",
      "urls": [
        "https://www.gstatic.com/generate_204",
        "https://cp.cloudflare.com"
      ],
      "url_test_timeout": "5s",
      "idle_timeout": "10m"
    }
  }
}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `interval` | duration | `5m` | How often outbounds are tested. |
| `urls` | list of strings | `["https://www.gstatic.com/generate_204"]` | Test addresses, in order of preference. |
| `ipinfo_url` | string | `""` | An IP information service to try first, for example from your subscription. |
| `workers` | int | `10` | Tests that run at once. |
| `url_test_timeout` | duration | `5s` | Longest time for one test, and for one IP information request. |
| `idle_timeout` | duration | `10m` | Stop testing after this long with no connections. |
| `debounce_window` | duration | `500ms` | How long to collect results before groups get an update. |

The IP information services see a request from the exit IP address of each outbound.

## See also

- [Balancer](balancer.en.md)
- [Fallback](fallback.en.md)
- [Psiphon](../protocols/psiphon.en.md)
- [DNSTT](../protocols/dnstt.en.md)
