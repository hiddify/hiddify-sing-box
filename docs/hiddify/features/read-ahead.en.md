# Read ahead

[فارسی](read-ahead.fa.md) · [All Hiddify features](../index.md)

A VMess or Shadowsocks client over plain TCP reads its socket 64 KB at a time and takes the
stream's chunks out of what it read, instead of reading every chunk from the socket in two
system calls. It has no option: it is on for these protocols when nothing lies between them and
the TCP connection.

## Why use it

VMess and Shadowsocks send their data in encrypted chunks of up to 16 KB, each behind an
encrypted length of 18 bytes. Their clients read the length and then the chunk, each read
straight from the socket: two system calls for every 16 KB downloaded, which on a fast line costs
more than decrypting the data. Xray reads the socket in large pieces, and downloaded through VMess
and Shadowsocks over plain TCP at almost twice the speed. The Shadowsocks rows include the
batching below.

Measured over loopback on macOS, a download through one connection:

| | Before | With read ahead | Xray |
|---|---|---|---|
| VMess (AES-128-GCM) | 11.2 Gbit/s, 0.74 CPU s/GB | 14.2 Gbit/s, 0.66 CPU s/GB | 21.8 Gbit/s |
| Shadowsocks AES-128-GCM | 11.9 Gbit/s, 0.64 CPU s/GB | 19.5 Gbit/s, 0.46 CPU s/GB | 23.5 Gbit/s |
| Shadowsocks ChaCha20-Poly1305 | 4.8 Gbit/s, 1.76 CPU s/GB | 5.9 Gbit/s, 1.52 CPU s/GB | 6.2 Gbit/s |
| Shadowsocks 2022 AES-128-GCM | 12.4 Gbit/s, 0.61 CPU s/GB | 15.1 Gbit/s, 0.53 CPU s/GB | 12.6 Gbit/s |

## How it gets past filtering

It does not. It only changes how the client reads the socket.

## How it works

- The connection is read up to 64 KB at a call, and the protocol's small reads are served from
  what was read. A read of 64 KB or more goes straight to the socket.
- What was read ahead is kept in a pooled buffer only until it is all taken: a connection that
  waits holds no buffer, so hundreds of idle connections on a phone cost nothing.
- A Shadowsocks AEAD client hands on in one buffer, up to 64 KB, the chunks that are already
  read ahead in full, so they reach the application in one write instead of one write for each
  chunk. It never waits for a chunk that has not arrived. An AEAD chunk is at most 16383 bytes, so
  "read in full" is known before the chunk is read. VMess bounds its chunks only at 64 KB, and its
  reader cannot take a chunk in two reads, so it hands on one chunk at a time.
- An error that comes with data is returned after the data.
- Writes go to the connection as before.
- It is used when VMess or Shadowsocks runs straight over TCP. Over TLS, WebSocket, gRPC or another
  transport the chunks are already read from memory, and over a Shadowsocks plugin the plugin
  reads the socket.

## Configuration

There is none.

## See also

- [Paced reads](paced-reads.en.md)
