# Adaptive processors

[فارسی](adaptive-processors.fa.md) · [All Hiddify features](../index.md)

With `experimental.debug.procs`, the number of processors the Go runtime uses (GOMAXPROCS)
follows the load: one while the proxy has little to do, more while it is busy. Without it, the
runtime uses one for every CPU core at all times.

## Why use it

A proxy's data path is a chain of goroutines that hand each packet to the next: the socket
reader, the QUIC or WireGuard connection, the stream's reader, the writer of acknowledgements.
With spare processors the Go runtime wakes another thread for every such hand-over. That thread
finds the work already taken, looks for more for a moment and goes back to sleep. On a tunnel
that carries thousands of packets a second, these wake-ups are most of the CPU the proxy uses,
more than the encryption and the system calls together.

With one processor, a goroutine that is handed a packet simply runs next on the thread that is
already awake. The same download takes about half the CPU at the same speed. Measured on macOS
(Apple silicon, 12 cores), CPU seconds for a gigabyte downloaded:

| Protocol | Every core | Adaptive |
|---|---|---|
| Hysteria2 (salamander) | 13.3 | 5.3 |
| Hysteria | 15.3 | 5.5 |
| TUIC | 8.7 | 3.6 |
| XHTTP over HTTP/3 | 12.0 | 7.5 |
| WireGuard | 13.3 | 9.2 |
| OpenVPN over UDP | 7.7 | 4.5 |
| OpenVPN over TCP | 6.7 | 3.9 |
| gRPC | 4.0 | 2.2 |
| XHTTP over HTTP/1.1 | 2.7 | 1.6 |
| Shadowsocks 2022 | 2.3 | 1.5 |

Uploads gain about as much. On Linux a thread is woken at a lower cost and the gain is smaller:
on a shared 12-core server, Hysteria2 took a quarter to a third less CPU, TUIC up to a quarter
less, and the TCP protocols the same as before.

## How it gets past filtering

It does not. It only changes how much CPU the proxy uses.

## How it works

- The governor starts once the box is started, so everything that sizes itself by the number of
  processors at start still sees them all. It sets the number to `min`.
- Every 100 ms it reads how long goroutines waited for a processor, which the Go runtime
  measures. The waits of the tick, added up and divided by its length, are the number of
  goroutines that were waiting on average: the load, as in a system's load average.
- A load of 1 or more means there is more work than the processors can take: it adds one, or
  two when the load is 4 or more. A start, a test of hundreds of proxies or a download of several
  gigabits a second gets its cores within a tick or two.
- After 3 quiet seconds (a load under 0.25) it takes one processor away and watches for a second.
  If the load is back, it returns the processor and waits twice as long before the next try, up
  to 2 minutes.
- While nothing runs at all it looks less often, down to every 2 seconds, so an idle proxy is not
  woken for it.
- When the box closes, the runtime gets back the number it had.
- GOMAXPROCS belongs to the whole process, so only one governor runs at a time. Only Go code
  runs on these processors: an app that shares the process with the core is not affected.

## Configuration

```json
{
  "experimental": {
    "debug": {
      "procs": {
        "enabled": true
      }
    }
  }
}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `procs.enabled` | bool | `false` | Let the number of Go processors follow the load. |
| `procs.min` | int | `1` | The least number of processors. |
| `procs.max` | int | CPU cores | The most. |

A `max` below `min`, or a negative number, is a configuration error when the config loads.

### Notes

- hiddify-core turns it on in the configs it builds.
- A `GOMAXPROCS` in the environment is a number somebody chose: the governor does not start.
  `HIDDIFY_PROCS=off` in the environment turns it off whatever the config says, and
  `HIDDIFY_PROCS=auto` turns it on, to compare.
- One processor has a price. The garbage collector takes its share of that processor in slices,
  so during a heavy download a goroutine may wait a few milliseconds a few times a second, and a
  system call that blocks, such as a sync of the cache file to disk, holds the processor until the
  runtime hands it on, which can take up to 20 ms. Neither counts as load. If that shows in calls
  or games, set `min` to 2: it avoids both, and keeps about half of the saving.
- On a machine that is busy with other work, the proxy's threads wait for the system too, and
  the governor adds processors: that is intended.
- The log has `procs: 1 Go processor(s) while there is little to do, up to 12 under load` at
  start, and each change at debug level.

## See also

- [Paced reads](paced-reads.en.md)
- [Lazy outbounds and keep top](groups/keep-top.en.md)
