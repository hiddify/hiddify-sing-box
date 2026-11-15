# Multiplex: Hiddify additions

[فارسی](multiplex-hiddify.fa.md) · [All Hiddify features](../../index.md)

sing-box multiplexing (`"multiplex"` on an outbound, with `smux`, `yamux` or `h2mux`) carries many
connections inside one connection to the server. Hiddify adds the [rmux](rmux.en.md) protocol and
changes how far a yamux stream's window may grow.

## Why use it

A multiplexed connection starts without a handshake of its own and shows the network fewer
connections. With a larger yamux window, a fast download through one stream keeps its speed.

## How it gets past filtering

It does not on its own. It runs inside the outbound's protocol and transport, which are what the
network sees.

## How it works

- **yamux streams may grow their window to 1 MB.** yamux starts every stream with a window of
  256 KB and by default never lets it grow, so the server stops each time 256 KB wait to be read,
  until a window update comes back. A download through one stream over loopback ran at 10.6
  Gbit/s; with the window allowed to grow to 1 MB it runs at 12.4 to 13.2, with 7% less CPU. A
  window is what the receiver allows, so any yamux server follows it. A stream whose reader stops
  can hold up to 1 MB, which is why it stops there: at 4 MB the same download ran at 13.4 Gbit/s,
  but the process took 23 MB more memory. Under a memory limit (always on in the iOS network
  extension, which may use 50 MB) or in low-memory mode, the window stays at 256 KB.

## Configuration

There is none: the window applies to every yamux stream, on clients and servers, except under a
memory limit or in low-memory mode.

## See also

- [rmux](rmux.en.md)
- [Paced reads](../paced-reads.en.md)
