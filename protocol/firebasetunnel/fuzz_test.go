package firebasetunnel

import (
	"context"
	"encoding/json"
	"testing"
)

func FuzzIngestChunk(f *testing.F) {
	f.Add([]byte(`{"seq":0,"timestamp":1000,"compressed":false,"data":"aGVsbG8="}`))
	f.Add([]byte(`{"seq":0,"timestamp":1000,"compressed":true,"encrypted":false,"data":"aGVsbG8="}`))
	f.Add([]byte(`{"seq":0,"has_hmac":true,"data":"aGVsbG8="}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var c chunk
		if err := json.Unmarshal(data, &c); err != nil {
			return // invalid JSON — not a bug
		}
		receiver, _ := newChunkReceiver(nil, nil, "fuzz-session", "c2s")
		// Must not panic regardless of input.
		_, _ = receiver.ingest(context.Background(), c)
	})
}

func FuzzParseSessionMetadata(f *testing.F) {
	f.Add([]byte(`{"session_id":"abc","version":1,"target_host":"1.2.3.4","target_port":80,"created_at":1000,"state":"pending","user":"alice"}`))
	f.Add([]byte(`{"state":"active"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var m sessionMetadata
		_ = json.Unmarshal(data, &m)
		// Verify field access doesn't panic.
		_ = m.SessionID + m.User + string(m.State)
		_ = m.TargetPort
		_ = m.CreatedAt
	})
}

func FuzzDecodeChunkPayload(f *testing.F) {
	// Seed: valid base64, empty, random-looking.
	f.Add([]byte("aGVsbG8="), false, false, false)
	f.Add([]byte(""), false, false, false)
	f.Add([]byte("AAAAAAAAAAAAAAAA"), true, false, false) // looks encrypted
	f.Fuzz(func(t *testing.T, rawData []byte, encrypted, compressed, hasHMAC bool) {
		c := chunk{
			Seq:        0,
			Encrypted:  encrypted,
			Compressed: compressed,
			HasHMAC:    hasHMAC,
			Data:       string(rawData),
		}
		// Must not panic; errors are expected for malformed inputs.
		_, _ = decodeChunkPayload(c, nil, nil, "fuzz-session", "c2s")
	})
}
