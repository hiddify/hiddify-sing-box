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

A single download that fills a fast line gains little on macOS: its packets already arrive in
bursts, and a read takes a burst.

## How it gets past filtering

It does not. It only changes how much CPU the proxy uses.

## How it works

- **Streams (TCP).** Once a connection brings more than 4 MB a second, a read that would find
  the socket empty waits first, long enough for about 48 KB to arrive and at most 2 ms, and then
  takes it all in one call. The first tenth of a second is a trial: a download keeps its speed,
  but an exchange of questions and answers with a peer that answers at once (a database or a
  file server on the local network) only gets slower, since nothing more arrives while the read
  waits. A connection that brings less than 70% of what it brought before is left alone for 5
  seconds, and twice as long each time it happens again, up to 2 minutes.
- **Datagram sockets read through their raw connection.** QUIC (TUIC, Hysteria2, XHTTP over
  HTTP/3, MASQUE), OpenVPN over UDP and the UDP relay read the socket themselves, many packets
  at a call. For them the proxy measures how long the reads wait for the next arrival. While they wait 250 microseconds or less on average, which is 4000 wake-ups a second
  or more, a reader that is woken waits before it reads: about 24 arrivals' time, at most 1 ms.
- **Datagram sockets read one datagram at a call**, as Hysteria2 with salamander and Hysteria
  are: from 3000 datagrams a second their reads go the same way, on Linux, Android, macOS and
  iOS.
- **WireGuard** has sockets of its own. Its receives are paced from 4000 datagrams a second,
  with a wait of at most 1 ms, on macOS, Linux and Android, where a receive call takes many
  datagrams. On Windows and iOS a receive call takes one datagram, and there is nothing to
  gather.
- A connection that is not busy is never held back: a call, a game, DNS and a page that loads
  are read at once, as before. A busy connection that calms down is read at once again within
  25 ms.
- What arrives during a wait stays in the socket's own buffer.
- If the system does not keep short waits (a coarse clock, a process the system holds back),
  three waits in a row that come late turn pacing off for every connection for 30 seconds, and
  for twice as long each time it happens again, up to 16 minutes. Reading at once is always
  correct.

## Configuration

There is none. `HIDDIFY_NO_READ_PACE=1` in the environment turns it off, to compare.

### Notes

- The packets of a busy connection may be up to 2 ms late (TCP) or 1 ms late (the others). A
  tunnel carries all its connections on one socket, so while a download runs through a QUIC or
  WireGuard tunnel, a call through the same tunnel gets that delay too.
- A tracked datagram socket is read through the router's connection (its reader is not
  replaceable), which is what lets QUIC and the batch readers get the paced raw connection.
- AmneziaWG runs on its own fork of WireGuard and is not paced.

## See also

- [Adaptive processors](adaptive-processors.en.md)
- [WireGuard: Hiddify additions](protocols/wireguard-hiddify.en.md)
