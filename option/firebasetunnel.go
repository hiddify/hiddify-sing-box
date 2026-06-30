package option

import "github.com/sagernet/sing/common/json/badoption"

// FirebaseTunnelUser identifies a client allowed to connect when this
// endpoint acts as a server. Name is used as a traffic-accounting label
// (surfaced via the SSM traffic manager). If PSK is set the server also
// requires the client's chunks to decrypt successfully before accepting
// the label.
type FirebaseTunnelUser struct {
	Name string `json:"name"`
	// PSK authenticates this user and encrypts their relayed payload bytes
	// against a passive reader of the Firebase project. Optional: omit to
	// relay cleartext (anyone who can read the project can see the data).
	PSK string `json:"psk,omitempty"`
}

// FirebaseTunnelServerConfig holds options that are only meaningful when
// this endpoint acts as a server (inbound). Its presence in
// FirebaseTunnelOptions switches the endpoint into server mode; omitting
// it (nil) selects client (outbound) mode.
type FirebaseTunnelServerConfig struct {
	Users              []FirebaseTunnelUser `json:"users"`
	PollInterval       badoption.Duration   `json:"poll_interval,omitempty"`
	SessionTimeout     badoption.Duration   `json:"session_timeout,omitempty"`
	MaxSessions        int                  `json:"max_sessions,omitempty"`
	MaxSessionsPerUser int                  `json:"max_sessions_per_user,omitempty"`
	// MaxSessionsPerSecondPerUser rate-limits new session creation per user
	// (token bucket). Zero → built-in default (5/s).
	MaxSessionsPerSecondPerUser int `json:"max_sessions_per_second_per_user,omitempty"`
}

// FirebaseTunnelClientConfig holds options that are only meaningful when
// this endpoint acts as a client (outbound).
type FirebaseTunnelClientConfig struct {
	// User is this client's self-reported identity, verified by PSK if set.
	User              string             `json:"user"`
	PSK               string             `json:"psk,omitempty"`
	BatchInterval     badoption.Duration `json:"batch_interval,omitempty"`
	BatchMaxBytes     int                `json:"batch_max_bytes,omitempty"`
	ActivationTimeout badoption.Duration `json:"activation_timeout,omitempty"`
}

// FirebaseTunnelOptions configures a Firebase Realtime Database relay tunnel
// (adapted from github.com/Hiddify2/Firebase-Tunnel).
//
// Role is determined by which sub-config is present:
//   - Server != nil → server (inbound) mode: listens for pending sessions
//     written to the Firebase project and routes them through sing-box.
//   - Client != nil → client (outbound) mode: dials by writing a session
//     request to Firebase and waiting for the server to activate it.
//
// Exactly one of Server or Client must be set.
//
// firebase_secret is the legacy Firebase Database Secret appended as
// ?auth=<secret> to every REST call. Anyone holding it has full read/write
// access to the entire Firebase project — prefer firebase_auth_token for
// anything beyond personal/test use.
type FirebaseTunnelOptions struct {
	FirebaseURLs      badoption.Listable[string] `json:"firebase_urls"`
	FirebaseSecret    string                     `json:"firebase_secret,omitempty"`
	FirebaseAuthToken string                     `json:"firebase_auth_token,omitempty"`
	RetryLimit        uint32                     `json:"retry_limit,omitempty"`

	// Exactly one must be non-nil.
	Server *FirebaseTunnelServerConfig `json:"server,omitempty"`
	Client *FirebaseTunnelClientConfig `json:"client,omitempty"`
}
