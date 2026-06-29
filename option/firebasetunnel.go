package option

import "github.com/sagernet/sing/common/json/badoption"

// FirebaseTunnelUser identifies a client allowed to connect to a
// firebasetunnel_server endpoint. Name is used purely as a traffic
// accounting label (surfaced via the SSM traffic manager) unless PSK is
// set, in which case the server also requires the client's chunks to
// decrypt successfully under that user's key before accepting the label.
type FirebaseTunnelUser struct {
	Name string `json:"name"`
	// PSK, if set, both authenticates this user (decrypt-or-reject) and
	// encrypts this user's relayed payload bytes against a passive reader
	// of the underlying Firebase project. Optional: omit to match the
	// upstream PoC's behavior (relayed bytes are cleartext to anyone who
	// can read the Firebase project).
	PSK string `json:"psk,omitempty"`
}

// FirebaseTunnelClientOptions configures the client side of a Firebase
// Realtime Database relay tunnel (adapted from github.com/Hiddify2/Firebase-Tunnel).
//
// firebase_secret is the legacy Firebase Database Secret, appended as
// ?auth=<secret> to every REST call. Anyone holding it has full read/write
// access to the entire Firebase project, not just this tunnel's data —
// prefer firebase_auth_token for anything beyond personal/test use.
type FirebaseTunnelClientOptions struct {
	FirebaseURLs     badoption.Listable[string] `json:"firebase_urls"`
	FirebaseSecret   string                     `json:"firebase_secret,omitempty"`
	FirebaseAuthToken string                    `json:"firebase_auth_token,omitempty"`
	// User is this client's self-reported identity, recorded in session
	// metadata for traffic accounting. Verified by PSK if PSK is set.
	User          string             `json:"user"`
	PSK           string             `json:"psk,omitempty"`
	BatchInterval badoption.Duration `json:"batch_interval,omitempty"`
	BatchMaxBytes int                `json:"batch_max_bytes,omitempty"`
	RetryLimit    uint32             `json:"retry_limit,omitempty"`
	// ActivationTimeout bounds how long Dial waits for the server to mark
	// a session Active before failing fast (so outbound groups like
	// urltest/selector can fail over promptly during a Firebase outage).
	ActivationTimeout badoption.Duration `json:"activation_timeout,omitempty"`
}

// FirebaseTunnelServerOptions configures the server side of a Firebase
// Realtime Database relay tunnel.
type FirebaseTunnelServerOptions struct {
	FirebaseURLs      badoption.Listable[string] `json:"firebase_urls"`
	FirebaseSecret    string                     `json:"firebase_secret,omitempty"`
	FirebaseAuthToken string                     `json:"firebase_auth_token,omitempty"`
	Users             []FirebaseTunnelUser       `json:"users"`
	PollInterval      badoption.Duration         `json:"poll_interval,omitempty"`
	SessionTimeout    badoption.Duration         `json:"session_timeout,omitempty"`
	RetryLimit        uint32                     `json:"retry_limit,omitempty"`
	// MaxSessions caps total concurrent sessions for this endpoint.
	// Zero means use the built-in default (1000).
	MaxSessions int `json:"max_sessions,omitempty"`
	// MaxSessionsPerUser caps concurrent sessions for any single user.
	// Zero means use the built-in default (50).
	MaxSessionsPerUser int `json:"max_sessions_per_user,omitempty"`
	// MaxSessionsPerSecondPerUser rate-limits new session creation per
	// user (token bucket). Zero means use the built-in default (5/s).
	MaxSessionsPerSecondPerUser int `json:"max_sessions_per_second_per_user,omitempty"`
}
