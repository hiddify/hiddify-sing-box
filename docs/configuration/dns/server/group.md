---
icon: material/new-box
---

# Group

### Structure

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
        ],
        "error_ttl": "1m",
        "win_ttl": "10m"
      }
    ]
  }
}
```

### Fields

#### servers

==Required==

List of DNS server tags to include in this group.

Restrictions:

- A group cannot contain another group.
- A group cannot contain a `fakeip` server.

- A server of the deprecated `multi` type counts as a group.

#### mode

How the servers are queried. `parallel` is used by default.

| Mode         | Behavior                                                                 |
|--------------|--------------------------------------------------------------------------|
| `parallel`   | All servers are queried concurrently.                                    |
| `sequential` | Servers are queried one at a time, in order, until one returns an answer. |
| `stable`     | The current server is queried alone. When it fails, the other servers are queried concurrently and the first to answer becomes the current server. |
| `fastest`    | Like `stable`, but the current server is kept only for `win_ttl`; then all servers are queried concurrently again and the fastest becomes the current server. |

In every mode, the first response that still contains answers after `ignore_ranges` filtering is returned.
An A or AAAA query needs an A or AAAA record: a CNAME left alone after filtering is not an answer.
SERVFAIL and REFUSED count as failures. A response without answers (for example NXDOMAIN) is only returned
if no server returns an answer.
If every server fails, the error from the first failure (`parallel`, `stable`, `fastest`) or the last failure
(`sequential`) is returned.

In `stable` and `fastest` mode:

- The current server gets half of the time left for the query, so the others still have time to answer.
- A server that fails, or whose answer `ignore_ranges` empties, is skipped for `error_ttl`. When every server
  failed recently, all of them are queried.
- When the network changes, the record of failures and the current server are cleared.

#### error_ttl

How long a failed server is skipped in `stable` and `fastest` mode. `1m` is used by default.

#### win_ttl

How long the fastest server stays current in `fastest` mode. `10m` is used by default.

#### ignore_ranges

List of IP ranges whose A and AAAA records are dropped from responses.

A response that has no answers left after filtering is discarded, and in `stable` and `fastest` mode the
server that sent it counts as failed. Use this to skip poisoned or blocked responses,
such as those pointing to a censor's block page.

### Deprecated `multi` type

The `multi` type is an alias of `group`, kept for existing configurations:
`"parallel": true` is `"mode": "parallel"`, otherwise `"mode": "sequential"`. `ignore_ranges` is unchanged.
