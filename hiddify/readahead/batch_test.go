package readahead

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// chunkConn reads a stream framed as Shadowsocks's AEAD stream is, an 18-byte length and a
// chunk with a 16-byte tag, and keeps what does not fit in a read for the next, as its reader
// does.
type chunkConn struct {
	net.Conn
	cache []byte
}

func (c *chunkConn) Read(p []byte) (int, error) {
	if len(c.cache) == 0 {
		header := make([]byte, 18)
		if _, err := io.ReadFull(c.Conn, header); err != nil {
			return 0, err
		}
		body := make([]byte, int(binary.BigEndian.Uint16(header))+16)
		if _, err := io.ReadFull(c.Conn, body); err != nil {
			return 0, err
		}
		c.cache = body[:len(body)-16]
	}
	n := copy(p, c.cache)
	c.cache = c.cache[n:]
	return n, nil
}

const (
	chunkPlain = 16383
	chunkWire  = 18 + chunkPlain + 16
)

func frame(payload []byte) []byte {
	out := make([]byte, 18, 18+len(payload)+16)
	binary.BigEndian.PutUint16(out, uint16(len(payload)))
	out = append(out, payload...)
	return append(out, make([]byte, 16)...)
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

func batched(t *testing.T, client net.Conn) N.ReadWaiter {
	t.Helper()
	ahead := New(client)
	conn := Batch(&chunkConn{Conn: ahead}, ahead, chunkWire, chunkPlain)
	waiter, isWaiter := conn.(N.ReadWaiter)
	if !isWaiter {
		t.Fatal("a batch is not a read waiter")
	}
	waiter.InitializeReadWaiter(N.ReadWaitOptions{})
	return waiter
}

// The chunks that are already read ahead reach the copy loop together, whole and in order: one
// write for several chunks instead of one for each.
func TestBatchGathersTheChunksReadAhead(t *testing.T) {
	client, server := tcpPair(t)
	const chunks = 64
	var stream, plain []byte
	for i := range chunks {
		payload := bytes.Repeat([]byte{byte(i)}, chunkPlain)
		plain = append(plain, payload...)
		stream = append(stream, frame(payload)...)
	}
	go func() {
		server.Write(stream)
		server.Close()
	}()
	time.Sleep(50 * time.Millisecond) // the stream is there, as a fast download's is
	waiter := batched(t, client)
	var got []byte
	buffers := 0
	for {
		buffer, err := waiter.WaitReadBuffer()
		if err != nil {
			if err != io.EOF {
				t.Fatal(err)
			}
			break
		}
		got = append(got, buffer.Bytes()...)
		buffer.Release()
		buffers++
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("the stream changed")
	}
	t.Logf("%d chunks in %d buffers", chunks, buffers)
	if buffers > chunks/2 {
		t.Fatalf("%d buffers for %d chunks", buffers, chunks)
	}
}

// A chunk is handed on as soon as it is there: the reader does not wait for the next one.
func TestBatchDoesNotWaitForTheNextChunk(t *testing.T) {
	client, server := tcpPair(t)
	first := frame(bytes.Repeat([]byte{1}, 1000))
	second := frame(bytes.Repeat([]byte{2}, 1000))
	go func() {
		server.Write(first)
		time.Sleep(300 * time.Millisecond)
		server.Write(second)
	}()
	waiter := batched(t, client)
	started := time.Now()
	buffer, err := waiter.WaitReadBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(started); took > 150*time.Millisecond {
		t.Fatalf("the first chunk waited %v for the second", took)
	}
	if buffer.Len() != 1000 {
		t.Fatalf("got %d bytes", buffer.Len())
	}
	buffer.Release()
	buffer, err = waiter.WaitReadBuffer()
	if err != nil || buffer.Len() != 1000 || buffer.Byte(0) != 2 {
		t.Fatalf("the second chunk: %v", err)
	}
	buffer.Release()
}

// An error that comes after data is returned by the next read, once the data is handed on.
func TestBatchKeepsTheErrorForTheNextRead(t *testing.T) {
	client, server := tcpPair(t)
	var stream []byte
	for range 4 {
		stream = append(stream, frame(bytes.Repeat([]byte{7}, chunkPlain))...)
	}
	stream = append(stream, 0, 1) // a chunk cut short by the end of the stream
	go func() {
		server.Write(stream)
		server.Close()
	}()
	time.Sleep(50 * time.Millisecond)
	waiter := batched(t, client)
	var got int
	for {
		buffer, err := waiter.WaitReadBuffer()
		if err != nil {
			if err != io.ErrUnexpectedEOF && err != io.EOF {
				t.Fatalf("error %v", err)
			}
			break
		}
		got += buffer.Len()
		buffer.Release()
	}
	if got != 4*chunkPlain {
		t.Fatalf("%d bytes before the error, want %d", got, 4*chunkPlain)
	}
}

// Without a connection read ahead below it, there is nothing to batch.
func TestBatchNeedsAReadAheadConn(t *testing.T) {
	client, _ := tcpPair(t)
	conn := &chunkConn{Conn: client}
	if Batch(conn, client, chunkWire, chunkPlain) != net.Conn(conn) {
		t.Fatal("batched without a read-ahead connection")
	}
}
