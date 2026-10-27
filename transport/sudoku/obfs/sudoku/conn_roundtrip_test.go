package sudoku

import (
	"bytes"
	"io"
	"testing"
)

// TestConn_Roundtrip exercises the optimized Conn encode/decode hot paths:
// the no-padding fast path (pMin==pMax==0), the always-padding path
// (pMin==pMax==100), a probabilistic range, and the adaptive read-size /
// 4-byte fast hint decode path across a variety of payload sizes and modes.
func TestConn_Roundtrip(t *testing.T) {
	modes := []string{"prefer_entropy", "prefer_ascii"}
	paddings := []struct{ min, max int }{
		{0, 0},     // no-padding specialized path
		{100, 100}, // always-padding specialized path
		{20, 60},   // probabilistic path
	}
	sizes := []int{1, 3, 4, 7, 16, 100, 1000, 64 * 1024}

	for _, mode := range modes {
		for _, pad := range paddings {
			for _, size := range sizes {
				payload := make([]byte, size)
				for i := range payload {
					payload[i] = byte(i*31 + 7)
				}

				table := NewTable("conn-roundtrip-seed", mode)

				// Encode via Conn.Write.
				w := &mockConn{}
				enc := NewConn(w, table, pad.min, pad.max, false)
				if _, err := enc.Write(payload); err != nil {
					t.Fatalf("mode=%s pad=%v size=%d write: %v", mode, pad, size, err)
				}

				// Decode via Conn.Read using the same table.
				dec := NewConn(&mockConn{readBuf: w.writeBuf}, table, pad.min, pad.max, false)
				got := make([]byte, size)
				if _, err := io.ReadFull(dec, got); err != nil {
					t.Fatalf("mode=%s pad=%v size=%d read: %v", mode, pad, size, err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("mode=%s pad=%v size=%d roundtrip mismatch", mode, pad, size)
				}
			}
		}
	}
}
