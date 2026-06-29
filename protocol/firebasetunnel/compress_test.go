package firebasetunnel

import (
	"bytes"
	"testing"
)

func TestCompressRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte(""),
		[]byte("hello world"),
		bytes.Repeat([]byte("a"), 100000),
		[]byte{0x00, 0xff, 0x10, 0x20},
	}
	for _, data := range cases {
		compressed := compressBytes(data)
		out, err := decompressBytes(compressed)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		if !bytes.Equal(out, data) {
			t.Fatalf("round trip mismatch: got %d bytes, want %d", len(out), len(data))
		}
	}
}

func TestDecompressInvalid(t *testing.T) {
	_, err := decompressBytes([]byte("not zstd data"))
	if err == nil {
		t.Fatal("expected error decompressing invalid data")
	}
}
