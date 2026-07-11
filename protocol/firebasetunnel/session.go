package firebasetunnel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
)

const compressMinBytes = 64

// maxPendingBytes bounds in-memory buffering in chunkSender beyond the
// channel's slot count, so a burst of large writes can't balloon memory
// before backpressure kicks in.
const maxPendingBytes = 8 * 1024 * 1024

// maxChunkBytes is the maximum decoded payload size for a single chunk.
// Rejects oversized chunks from malicious/buggy clients before allocating.
const maxChunkBytes = 1 * 1024 * 1024 // 1 MiB

// chunkSender accumulates outgoing bytes, batches/compresses/optionally
// encrypts them, and writes them to Firebase as sequential chunk nodes.
type chunkSender struct {
	rawCh   chan []byte
	pending chanCounter
}

type chanCounter struct {
	mu    sync.Mutex
	bytes int
}

func (c *chanCounter) add(n int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bytes+n > maxPendingBytes {
		return false
	}
	c.bytes += n
	return true
}

func (c *chanCounter) sub(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bytes -= n
}

// newChunkSender creates a sender that flushes to queuePath on fb.
// sessionID and direction ("c2s"/"s2c") are bound into AEAD additional data
// when encrypting, so chunks cannot be replayed across sessions or directions.
// hmacKey (non-nil) enables HMAC integrity tags on unencrypted chunks.
func newChunkSender(ctx context.Context, queuePath, sessionID, direction string, fb *firebaseClient, batchInterval time.Duration, batchMaxBytes int, key *[32]byte, hmacKey []byte, logger log.ContextLogger) *chunkSender {
	rawCh := make(chan []byte, 1024)
	s := &chunkSender{rawCh: rawCh}
	go s.flusherTask(ctx, queuePath, sessionID, direction, fb, batchInterval, batchMaxBytes, key, hmacKey, logger)
	return s
}

// feed enqueues data for the next batch. Returns an error if the pending
// byte budget is exceeded (caller should treat this as backpressure, not
// retry indefinitely) or if ctx is done.
func (s *chunkSender) feed(ctx context.Context, data []byte) error {
	if !s.pending.add(len(data)) {
		return fmt.Errorf("firebasetunnel: sender backpressure limit exceeded")
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case s.rawCh <- cp:
		return nil
	case <-ctx.Done():
		s.pending.sub(len(data))
		return ctx.Err()
	}
}

func (s *chunkSender) flusherTask(ctx context.Context, queuePath, sessionID, direction string, fb *firebaseClient, batchInterval time.Duration, batchMaxBytes int, key *[32]byte, hmacKey []byte, logger log.ContextLogger) {
	buffer := make([]byte, 0, batchMaxBytes)
	var seq uint64
	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	flush := func(flushCtx context.Context) {
		if len(buffer) == 0 {
			return
		}
		n := len(buffer)
		if err := flushBuffer(flushCtx, queuePath, sessionID, direction, fb, &buffer, &seq, key, hmacKey); err != nil && logger != nil {
			logger.WarnContext(flushCtx, "firebasetunnel: flush error: ", err)
		}
		s.pending.sub(n)
	}

	for {
		select {
		case <-ticker.C:
			flush(ctx)
		case data, ok := <-s.rawCh:
			if !ok {
				flush(ctx)
				return
			}
			buffer = append(buffer, data...)
			if len(buffer) >= batchMaxBytes {
				flush(ctx)
			}
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			flush(flushCtx)
			cancel()
			return
		}
	}
}

func flushBuffer(ctx context.Context, queuePath, sessionID, direction string, fb *firebaseClient, buffer *[]byte, seq *uint64, key *[32]byte, hmacKey []byte) error {
	raw := make([]byte, len(*buffer))
	copy(raw, *buffer)
	*buffer = (*buffer)[:0]

	var payload []byte
	compressed := false
	if len(raw) >= compressMinBytes {
		payload = compressBytes(raw)
		compressed = true
	} else {
		payload = raw
	}

	encrypted := false
	hasHMAC := false
	if key != nil {
		aad := chunkAAD(sessionID, direction, *seq)
		enc, err := encryptPayloadAAD(*key, payload, aad)
		if err != nil {
			return fmt.Errorf("firebasetunnel: encrypting chunk seq=%d: %w", *seq, err)
		}
		payload = enc
		encrypted = true
	} else if len(hmacKey) > 0 {
		payload = appendHMACTag(hmacKey, payload)
		hasHMAC = true
	}

	c := chunk{
		Seq:        *seq,
		Timestamp:  nowMillis(),
		Compressed: compressed,
		Encrypted:  encrypted,
		HasHMAC:    hasHMAC,
		Data:       base64.StdEncoding.EncodeToString(payload),
	}
	if err := fb.Put(ctx, pathChunk(queuePath, *seq), &c); err != nil {
		return fmt.Errorf("firebasetunnel: writing chunk seq=%d: %w", *seq, err)
	}
	*seq++
	return nil
}

// chunkReceiver reassembles an in-order byte stream from chunks that may
// arrive out of order, buffering until contiguous, then delivering on the
// channel returned by newChunkReceiver.
type chunkReceiver struct {
	mu        sync.Mutex
	pending   map[uint64][]byte
	nextSeq   uint64
	outCh     chan []byte
	ackPtr    *uint64
	key       *[32]byte
	hmacKey   []byte
	sessionID string
	direction string
}

// newChunkReceiver creates a receiver for chunks arriving on sessionID/direction.
// hmacKey (non-nil) enables HMAC verification on unencrypted chunks.
func newChunkReceiver(key *[32]byte, hmacKey []byte, sessionID, direction string) (*chunkReceiver, <-chan []byte) {
	outCh := make(chan []byte, 1024)
	r := &chunkReceiver{
		pending:   make(map[uint64][]byte),
		outCh:     outCh,
		key:       key,
		hmacKey:   hmacKey,
		sessionID: sessionID,
		direction: direction,
	}
	return r, outCh
}

// ingest processes one chunk, returning the new ack pointer if it advanced.
// Duplicate (already-delivered) chunks are silently ignored. Decrypt/HMAC
// failures are returned as errors — callers should treat them as an
// auth/abuse signal, not a transient fault.
func (r *chunkReceiver) ingest(ctx context.Context, c chunk) (*uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if c.Seq < r.nextSeq {
		return nil, nil
	}

	payload, err := decodeChunkPayload(c, r.key, r.hmacKey, r.sessionID, r.direction)
	if err != nil {
		return nil, err
	}
	r.pending[c.Seq] = payload

	oldAck := r.ackPtr
	for {
		data, ok := r.pending[r.nextSeq]
		if !ok {
			break
		}
		delete(r.pending, r.nextSeq)
		select {
		case r.outCh <- data:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		ack := r.nextSeq
		r.ackPtr = &ack
		r.nextSeq++
	}

	if !ackEqual(r.ackPtr, oldAck) {
		return r.ackPtr, nil
	}
	return nil, nil
}

func ackEqual(a, b *uint64) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func decodeChunkPayload(c chunk, key *[32]byte, hmacKey []byte, sessionID, direction string) ([]byte, error) {
	// Reject oversized chunks before any allocation.
	if len(c.Data) > base64.StdEncoding.EncodedLen(maxChunkBytes) {
		return nil, fmt.Errorf("firebasetunnel: chunk seq=%d exceeds max size cap", c.Seq)
	}

	decoded, err := base64.StdEncoding.DecodeString(c.Data)
	if err != nil {
		return nil, fmt.Errorf("firebasetunnel: base64-decoding chunk seq=%d: %w", c.Seq, err)
	}
	if c.Encrypted {
		if key == nil {
			return nil, fmt.Errorf("firebasetunnel: chunk seq=%d is encrypted but no key configured", c.Seq)
		}
		aad := chunkAAD(sessionID, direction, c.Seq)
		decoded, err = decryptPayloadAAD(*key, decoded, aad)
		if err != nil {
			return nil, fmt.Errorf("firebasetunnel: decrypting chunk seq=%d: %w", c.Seq, err)
		}
	} else if c.HasHMAC {
		if len(hmacKey) == 0 {
			return nil, fmt.Errorf("firebasetunnel: chunk seq=%d has HMAC tag but no HMAC key configured", c.Seq)
		}
		decoded, err = verifyAndStripHMACTag(hmacKey, decoded)
		if err != nil {
			return nil, fmt.Errorf("firebasetunnel: chunk seq=%d: %w", c.Seq, err)
		}
	}
	if c.Compressed {
		decoded, err = decompressBytes(decoded)
		if err != nil {
			return nil, fmt.Errorf("firebasetunnel: decompressing chunk seq=%d: %w", c.Seq, err)
		}
	}
	return decoded, nil
}

// fetchNewChunks reads all chunks from queuePath with seq > after, sorted
// by seq. Firebase collapses integer-keyed objects into JSON arrays, so
// both shapes are handled.
func fetchNewChunks(ctx context.Context, fb *firebaseClient, queuePath string, after *uint64) ([]chunk, error) {
	var raw interface{}
	found, err := fb.Get(ctx, queuePath, &raw)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	var chunks []chunk
	switch v := raw.(type) {
	case map[string]interface{}:
		for _, val := range v {
			ck, err := interfaceToChunk(val)
			if err != nil {
				return nil, err
			}
			chunks = append(chunks, ck)
		}
	case []interface{}:
		for _, val := range v {
			if val == nil {
				continue
			}
			ck, err := interfaceToChunk(val)
			if err != nil {
				return nil, err
			}
			chunks = append(chunks, ck)
		}
	default:
		return nil, nil
	}

	if after != nil {
		filtered := chunks[:0]
		for _, ck := range chunks {
			if ck.Seq > *after {
				filtered = append(filtered, ck)
			}
		}
		chunks = filtered
	}

	sortChunksBySeq(chunks)
	return chunks, nil
}

func interfaceToChunk(v interface{}) (chunk, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return chunk{}, err
	}
	var ck chunk
	if err := json.Unmarshal(data, &ck); err != nil {
		return chunk{}, err
	}
	return ck, nil
}

func sortChunksBySeq(chunks []chunk) {
	n := len(chunks)
	for i := 1; i < n; i++ {
		key := chunks[i]
		j := i - 1
		for j >= 0 && chunks[j].Seq > key.Seq {
			chunks[j+1] = chunks[j]
			j--
		}
		chunks[j+1] = key
	}
}

// updateAckAndCleanup persists the new ack pointer and deletes all chunks
// with seq <= ack from queuePath (best-effort, parallel deletes).
func updateAckAndCleanup(ctx context.Context, fb *firebaseClient, ackFieldPath, queuePath string, ack uint64, logger log.ContextLogger) error {
	if err := fb.Put(ctx, ackFieldPath, ack); err != nil {
		return fmt.Errorf("firebasetunnel: updating ack: %w", err)
	}
	var wg sync.WaitGroup
	for seq := uint64(0); seq <= ack; seq++ {
		wg.Add(1)
		go func(seq uint64) {
			defer wg.Done()
			if err := fb.Delete(ctx, pathChunk(queuePath, seq)); err != nil && logger != nil {
				logger.WarnContext(ctx, "firebasetunnel: cleanup chunk seq=", seq, " failed: ", err)
			}
		}(seq)
	}
	wg.Wait()
	return nil
}
