# Paced reads

[فارسی](paced-reads.fa.md) · [All Hiddify features](../index.md)

On a connection that is busy, the proxy waits a moment before it reads, so that each read brings
a batch of packets instead of one. It has no option: it is on, and it only acts on connections
that already carry megabytes a second.

## Why use it

A socket becomes readable with every packet that arrives, and the goroutine that reads it is
woken for each: a wake of its thread, a poll of the kernel, a read, a read that finds nothing,
and back to sleep. Behind the read, every packet then goes through the rest of the path on its
own: a QUIC or WireGuard packet is decrypted, acknowledged, handed to the stream's reader and
written to the application, one at a time. When the packets of a download arrive evenly, as they
do on a fast line, on a wired network or behind another tunnel, the proxy spends more on these
wake-ups than on the data.

Read a moment later, the same packets come as a batch: one wake-up, one or two system calls, one
acknowledgement for the batch, one large write to the application. Measured, CPU seconds for a
gigabyte downloaded, without and with it:

| | Without | With |
|---|---|---|
| WireGuard, macOS | 17 to 26, at 170 to 265 Mbit/s | 9, at 260 to 270 Mbit/s |
| WireGuard, Linux (two runs on a shared server) | 26 and 61 | 19 and 34 |
| TUIC, Linux (same two runs) | 23 and 29 | 11 and 24 |
| Six downloads at once over XHTTP (HTTP/2), macOS | 2.5 | 1.8 |
| Six downloads at once over Shadowsocks 2022, macOS | 1.6 | 1.2 |
| XHTTP over HTTP/2 with TLS, one download over loopback, macOS | 1.75 to 1.77 | 1.41 to 1.45 |

A single download that fills a fast line gains little on macOS: its packets already arrive in
bursts, and a read takes a burst.

## How it gets past filtering

It does not. It only changes how much CPU the proxy uses.

## How it works

- **Streams (TCP).** Once a connection brings more than 4 MB a second, a read that would find
  the socket empty waits first, long enough for about 48 KB to arrive, at least 250 microseconds
  and at most 2 ms, and then takes it all in one call. A sender that waits for its data to be
  read only gets slower: a peer that answers at once (a database or a file server on the local
  network), or a stream behind a multiplexer's window, which stops when the window is full. So a
  paced connection is tried without the waits now and then: after 0.2 seconds of pacing, after
  2 seconds the next time and twice as long each time after that, up to 30 seconds, and at once
  when it brings less than 85% of what it brought when it was last read at once, two windows of
  25 ms in a row. A try reads it at once for 75 ms. If it is then 15% faster, the waits held it
  back, and it is left alone for 5 seconds, and twice as long each time it happens again, up to
  2 minutes; if it is not, it is paced on.
- **A connection that sends more than it receives is not paced.** What comes in answers what it
  sends: acknowledgements, and window updates of HTTP/2 and of a multiplexer, which an upload
  waits for.
- **Datagram sockets read through their raw connection.** QUIC (TUIC, Hysteria2, XHTTP over
  HTTP/3, MASQUE), OpenVPN over UDP and the UDP relay read the socket themselves, many packets
  at a call. For them the proxy measures how long the reads wait for the next arrival. While they
  wait 250 microseconds or less on average, which is 4000 wake-ups a second or more, a reader that
  is woken waits before it reads: about 24 arrivals' time, at least 200 microseconds and at most
  1 ms.
- **Datagram sockets read one datagram at a call**, as Hysteria2 with salamander and Hysteria
  are: from 3000 datagrams a second their reads go the same way, on Linux, Android, macOS and
  iOS.
- **The wait of these datagram sockets is a small part of their path's round trip**, at most a
  32nd of it. A socket measures the round trip with its first exchange: the time from the first
  datagram written to the first one that arrives (a QUIC or OpenVPN handshake). A socket whose
  round trip is not known, whose peer is this machine, or whose path is shorter than 8 ms (the
  local network, a server nearby) is not paced: there a wait is several round trips, and QUIC's
  congestion control, which sees every acknowledgement late, slows down. A Hysteria2 download over
  loopback ran at a third of its speed. A socket so busy that the shortest wait would gather more
  than 64 arrivals is not paced either: its reads take a batch anyway.
- **WireGuard** has sockets of its own. Its receives are paced from 4000 datagrams a second,
  with a wait of at least 250 microseconds and at most 1 ms, on macOS, Linux and Android, where
  a receive call takes many datagrams. On Windows and iOS a receive call takes one datagram, and
  there is nothing to gather. A tunnel that sends at least as many datagrams as it receives is
  not paced: what it receives are the acknowledgements of its upload, which the upload waits for.
  Over loopback a download through WireGuard runs at 1.9 to 2 Gbit/s with it and at 1.2 without.
- A connection that is not busy is never held back: a call, a game, DNS and a page that loads
  are read at once, as before. A busy connection that calms down is read at once again within
  25 ms.
- What arrives during a wait stays in the socket's own buffer.
- If the system does not keep short waits (a coarse clock, a process the system holds back, a
  machine whose processors are all busy), three waits in a row that take more than twice as long
  as asked, and half a millisecond more, turn pacing off for every connection for 30 seconds, and
  for twice as long each time it happens again, up to 16 minutes. Reading at once is always
  correct.

## Configuration

There is none. `HIDDIFY_NO_READ_PACE=1` in the environment turns it off, to compare.

### Notes

- The packets of a busy connection may be up to 2 ms late (TCP), up to 1 ms (WireGuard), or a
  32nd of the round trip and at most 1 ms (the other datagram sockets). A tunnel carries all its connections on one socket, so while a
  download runs through a QUIC or WireGuard tunnel, a call through the same tunnel gets that delay
  too.
- A tracked datagram socket is read through the router's connection (its reader is not
  replaceable), which is what lets QUIC and the batch readers get the paced raw connection.
- AmneziaWG runs on its own fork of WireGuard and is not paced.

## See also

- [Adaptive processors](adaptive-processors.en.md)
- [WireGuard: Hiddify additions](protocols/wireguard-hiddify.en.md)
