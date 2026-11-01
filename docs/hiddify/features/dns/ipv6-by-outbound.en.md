# IPv6 by outbound

[فارسی](ipv6-by-outbound.fa.md) · [All Hiddify features](../../index.md)

Hands a client IPv6 addresses only where they lead somewhere. The monitoring learns, for every
outbound, whether it carries IPv6 (`ipv6_probe` in `experimental.monitoring`); a DNS rule with
`ipv6_by_outbound` then leaves AAAA questions unanswered while the outbound the traffic goes
through cannot carry IPv6, and a route rule with `ipv6_unavailable_via` refuses the IPv6
connections that still come, so the client falls back to IPv4 at once.

## Why use it

- Google, YouTube and most large sites are IPv6-first: a browser that gets an AAAA answer
  connects over IPv6. Through a proxy without IPv6 the proxy accepts the connection and then
  closes it, which Chrome shows as "unexpectedly closed the connection" (`ERR_CONNECTION_CLOSED`)
  and never retries over IPv4, while apps that use IPv4 work. With this, such a browser gets
  IPv4 addresses only, and a server that does carry IPv6 still gives IPv6.
- The TUN keeps its IPv6 route, so nothing leaves the device outside the VPN, and a server
  with only an IPv6 address still routes: no family is ever refused outright.

## How it gets past filtering

It does not; it keeps a working proxy from looking broken.

## How it works

- Every outbound and endpoint is probed on its own: after it answers its URL test, the
  monitoring opens one TCP connection through it to `ipv6_probe` (`[2606:4700:4700::1111]:443`
  by default) with a 3 s limit, closes it, and records whether it got through, for that
  outbound. So one proxy can carry IPv6 while the next one does not. Each outbound is probed
  once per run, and once more when its result was read from the cache; the result is saved
  with its URL test results.
- A group answers for the member it has selected, so the answer follows the selection.
- `ipv6_by_outbound` on a DNS rule: while the named outbound is known to have no IPv6, the
  query runs with the `ipv4_only` strategy (AAAA gets an empty answer); otherwise the rule's own
  strategy applies. An outbound not probed yet changes nothing.
- `ipv6_unavailable_via` on a route rule: matches a connection to an IPv6 address while the
  named outbound is known to have no IPv6. With `"action": "reject"` the client gets a reset
  and tries IPv4; it never matches an IPv4 destination, an outbound with IPv6, or one not
  probed yet.

## Configuration

```json
{
  "dns": {
    "rules": [
      { "action": "route", "server": "remote", "strategy": "prefer_ipv4", "ipv6_by_outbound": "select" }
    ]
  },
  "route": {
    "rules": [
      { "ip_version": 6, "ipv6_unavailable_via": "select", "action": "reject" }
    ]
  },
  "experimental": {
    "monitoring": { "ipv6_probe": "[2606:4700:4700::1111]:443" }
  }
}
```

| Field | Where | Type | Default | Meaning |
|---|---|---|---|---|
| `ipv6_by_outbound` | DNS rule action `route`, `route_options` | string | | An outbound, or a group; while it cannot carry IPv6, AAAA questions get an empty answer. |
| `ipv6_unavailable_via` | route rule | string | | An outbound, or a group; the rule matches an IPv6 destination while it cannot carry IPv6. |
| `ipv6_probe` | `experimental.monitoring` | string | `[2606:4700:4700::1111]:443` | The IPv6 address and port the probe connects to. `none` turns the probe off: nothing is known, and the two rule fields do nothing. |

## Notes

- Hiddify's own configs set both rules on the main selector, so the behaviour follows the
  proxy the user picked.
- The probe is one connection per outbound per run; through a proxy it is one more connection
  that server sees, to Cloudflare's resolver.

## See also

- [Monitoring](../groups/monitoring.en.md)
- [DNS group](dns-group.en.md)
