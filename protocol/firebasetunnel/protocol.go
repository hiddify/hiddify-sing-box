// Package firebasetunnel implements a sing-box endpoint pair that relays
// TCP byte streams through Firebase Realtime Database, adapted from
// github.com/Hiddify2/Firebase-Tunnel (a single-star proof-of-concept with
// no LICENSE; logic below is rewritten for sing-box rather than vendored).
//
// Database layout, keyed by an opaque per-session UUID:
//
//	sessions/
//	  {session_id}/
//	    metadata/        - sessionMetadata (written by client on creation)
//	    c2s/{seq}/        - chunk, client-to-server queue
//	    s2c/{seq}/        - chunk, server-to-client queue
//	    acks/
//	      c2s_ack         - uint64, highest consecutive seq the server processed
//	      s2c_ack         - uint64, highest consecutive seq the client processed
//
// Sequence numbers start at 0 and increase monotonically per direction per
// session. Out-of-order chunks are buffered and only delivered once all
// predecessors have arrived. Acknowledged chunks are deleted to bound
// database growth.
package firebasetunnel

import (
	"fmt"
	"time"
)

const protocolVersion = 1

type sessionState string

const (
	sessionStatePending sessionState = "pending"
	sessionStateActive  sessionState = "active"
	sessionStateClosing sessionState = "closing"
	sessionStateClosed  sessionState = "closed"
)

// sessionMetadata is written by the client when a session is created. The
// server reads it to know where to connect and which configured user the
// session should be attributed to.
type sessionMetadata struct {
	SessionID  string       `json:"session_id"`
	Version    int          `json:"version"`
	TargetHost string       `json:"target_host"`
	TargetPort uint16       `json:"target_port"`
	CreatedAt  uint64       `json:"created_at"`
	State      sessionState `json:"state"`
	// User is a self-reported accounting label, verified against the
	// session's PSK (if configured) rather than trusted outright.
	User string `json:"user,omitempty"`
}

// chunk is a single batched, optionally compressed, base64-encoded segment
// of relayed bytes stored at sessions/{id}/c2s/{seq} or sessions/{id}/s2c/{seq}.
type chunk struct {
	Seq        uint64 `json:"seq"`
	Timestamp  uint64 `json:"timestamp"`
	Compressed bool   `json:"compressed"`
	// Encrypted indicates Data is AES-256-GCM ciphertext (nonce-prefixed, with
	// session-ID+direction+seq as AEAD additional data) rather than a plain
	// zstd/raw payload. Set only when the session's user has a PSK configured.
	Encrypted bool `json:"encrypted,omitempty"`
	// HasHMAC indicates that the last hmacTagLen bytes of the decoded Data are
	// an HMAC-SHA256 tag over the payload, present on unencrypted chunks when
	// the firebase_secret is set. Provides integrity without confidentiality.
	HasHMAC bool   `json:"has_hmac,omitempty"`
	Data    string `json:"data"`
}

func pathMetadata(sessionID string) string {
	return "sessions/" + sessionID + "/metadata"
}

func pathC2S(sessionID string) string {
	return "sessions/" + sessionID + "/c2s"
}

func pathS2C(sessionID string) string {
	return "sessions/" + sessionID + "/s2c"
}

func pathAcks(sessionID string) string {
	return "sessions/" + sessionID + "/acks"
}

func pathSessionsRoot() string {
	return "sessions"
}

func pathChunk(queuePath string, seq uint64) string {
	return fmt.Sprintf("%s/%d", queuePath, seq)
}

func nowMillis() uint64 {
	return uint64(time.Now().UnixMilli())
}
