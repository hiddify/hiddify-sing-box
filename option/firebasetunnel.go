package option

import "github.com/sagernet/sing/common/json/badoption"

// FirebaseTunnelUser identifies a client allowed to connect to the inbound.
// If PSK is set, payload bytes are encrypted with AES-256-GCM keyed from it.
type FirebaseTunnelUser struct {
	Name string `json:"name"`
	PSK  string `json:"psk,omitempty"`
}

// FirebaseTunnelInboundOptions configures the server side of the Firebase Tunnel
// protocol. It listens for pending sessions in the Firebase Realtime Database
// and routes each one through the sing-box router, with per-user traffic
// accounting handled automatically.
type FirebaseTunnelInboundOptions struct {
	FirebaseURLs      badoption.Listable[string] `json:"firebase_urls"`
	FirebaseSecret    string                     `json:"firebase_secret,omitempty"`
	FirebaseAuthToken string                     `json:"firebase_auth_token,omitempty"`
	RetryLimit        uint32                     `json:"retry_limit,omitempty"`

	Users              []FirebaseTunnelUser `json:"users"`
	PollInterval       badoption.Duration   `json:"poll_interval,omitempty"`
	SessionTimeout     badoption.Duration   `json:"session_timeout,omitempty"`
	MaxSessions        int                  `json:"max_sessions,omitempty"`
	MaxSessionsPerUser int                  `json:"max_sessions_per_user,omitempty"`
	// MaxSessionsPerSecondPerUser rate-limits new session creation per user
	// (token bucket). Zero → built-in default (5/s).
	MaxSessionsPerSecondPerUser int `json:"max_sessions_per_second_per_user,omitempty"`
}

// FirebaseTunnelOutboundOptions configures the client side of the Firebase Tunnel
// protocol. It dials by writing a session request to Firebase and waiting for the
// server (inbound) to activate it.
type FirebaseTunnelOutboundOptions struct {
	FirebaseURLs      badoption.Listable[string] `json:"firebase_urls"`
	FirebaseSecret    string                     `json:"firebase_secret,omitempty"`
	FirebaseAuthToken string                     `json:"firebase_auth_token,omitempty"`
	RetryLimit        uint32                     `json:"retry_limit,omitempty"`

	User              string             `json:"user"`
	PSK               string             `json:"psk,omitempty"`
	BatchInterval     badoption.Duration `json:"batch_interval,omitempty"`
	BatchMaxBytes     int                `json:"batch_max_bytes,omitempty"`
	ActivationTimeout badoption.Duration `json:"activation_timeout,omitempty"`
}
