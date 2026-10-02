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
        ]
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

In both modes, the first response that still contains answers after `ignore_ranges` filtering is returned.
A response without answers (for example NXDOMAIN) is only returned if no server returns an answer.
If every server fails, the error from the first failure (`parallel`) or the last failure (`sequential`) is returned.

#### ignore_ranges

List of IP ranges whose A and AAAA records are dropped from responses.

A response that has no answers left after filtering is discarded. Use this to skip poisoned or blocked responses,
such as those pointing to a censor's block page.

### Deprecated `multi` type

The `multi` type is an alias of `group`, kept for existing configurations:
`"parallel": true` is `"mode": "parallel"`, otherwise `"mode": "sequential"`. `ignore_ranges` is unchanged.
