package readahead

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"testing"
	"time"
)

// countingConn counts the reads of the connection below.
type countingConn struct {
	net.Conn
	reads int
}

func (c *countingConn) Read(p []byte) (int, error) {
	c.reads++
	return c.Conn.Read(p)
}

// chunked reads a stream of chunks the way an AEAD protocol does: an 18-byte length, then the
// chunk.
func chunked(t *testing.T, r io.Reader, chunks int, size int) []byte {
	t.Helper()
	var out []byte
	header := make([]byte, 18)
	body := make([]byte, size)
	for range chunks {
		if _, err := io.ReadFull(r, header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(r, body); err != nil {
			t.Fatal(err)
		}
		out = append(out, header...)
		out = append(out, body...)
	}
	return out
}

// A stream read in small pieces arrives whole and in order, in a few large reads of the socket:
// two reads a chunk straight from the socket were one system call each.
func TestReadAheadServesSmallReadsFromLargeOnes(t *testing.T) {
	server, client := net.Pipe()
	const chunks, size = 64, 16 << 10
	stream := make([]byte, chunks*(18+size))
	for i := range stream {
		stream[i] = byte(rand.Uint32())
	}
	go func() {
		server.Write(stream)
		server.Close()
	}()
	below := &countingConn{Conn: client}
	conn := New(below)
	got := chunked(t, conn, chunks, size)
	if !bytes.Equal(got, stream) {
		t.Fatal("the stream changed")
	}
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("after the stream: %v", err)
	}
	if conn.(*Conn).ahead != nil {
		t.Fatal("a buffer is kept after everything was taken")
	}
	// net.Pipe hands over one write at a time: here it counts the reads, as many as the pieces
	// the writer made, at most one per Size
	if below.reads > len(stream)/Size+4 {
		t.Fatalf("%d reads of the connection for %d bytes", below.reads, len(stream))
	}
}

// Over a real socket, the reads of the socket stay few as well.
func TestReadAheadOverTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const chunks, size = 256, 16 << 10
	stream := make([]byte, chunks*(18+size))
	for i := range stream {
		stream[i] = byte(i * 7)
	}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Write(stream)
		conn.Close()
	}()
	tcp, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	below := &countingConn{Conn: tcp}
	conn := New(below)
	time.Sleep(50 * time.Millisecond) // let the stream arrive, as a fast download does
	got := chunked(t, conn, chunks, size)
	if !bytes.Equal(got, stream) {
		t.Fatal("the stream changed")
	}
	t.Logf("%d reads of the socket for %d chunks", below.reads, chunks)
	if below.reads > chunks/2 {
		t.Fatalf("%d reads of the socket for %d chunks: two a chunk straight from the socket", below.reads, chunks)
	}
}

// An error that comes with data is returned once the data is taken.
type errorAfter struct {
	net.Conn
	data []byte
	err  error
}

func (c *errorAfter) Read(p []byte) (int, error) {
	n := copy(p, c.data)
	c.data = c.data[n:]
	if len(c.data) == 0 {
		return n, c.err
	}
	return n, nil
}

func TestReadAheadKeepsTheErrorForLast(t *testing.T) {
	failure := errors.New("reset")
	conn := New(&errorAfter{data: []byte("hello world"), err: failure})
	buffer := make([]byte, 5)
	var got []byte
	for {
		n, err := conn.Read(buffer)
		got = append(got, buffer[:n]...)
		if err != nil {
			if !errors.Is(err, failure) {
				t.Fatalf("error %v", err)
			}
			break
		}
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q before the error", got)
	}
	if New(conn) != conn {
		t.Fatal("wrapped twice")
	}
	if conn.(*Conn).ReaderReplaceable() || !conn.(*Conn).WriterReplaceable() {
		t.Fatal("a read below would skip what was read ahead; writes may go below")
	}
}
