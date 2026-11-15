package xhttp

import "time"

// hRequestOnly is the size below which a connection's first upload is taken for the proxy
// protocol's request alone.
//
// VLESS, VMess and Trojan write their request as soon as the connection is up, and the
// application's first bytes in a second write a moment later, unless a sniffer read them first.
// In packet-up each write that finds the upload idle is an upload of its own, and the second
// one was held back by sc_min_posts_interval_ms after the first: the application's first bytes
// (a TLS hello, an HTTP request) left 30 ms late on every connection. Xray's client keeps the
// request until those bytes come and sends both in its first upload. Here the second upload
// follows a first one that carried the request alone without the interval, which is the same
// 30 ms sooner and does not hold the request back when the application is silent at first.
const hRequestOnly = 512

// hSleepUntil sleeps until at. A sleep of tens of milliseconds ends up to a millisecond late,
// a short one on time: so the last millisecond is slept on its own, and an interval of 30 ms
// between two uploads is 30 ms, not 31.
func hSleepUntil(at time.Time) {
	for {
		left := time.Until(at)
		if left <= 0 {
			return
		}
		if left > 2*time.Millisecond {
			time.Sleep(left - time.Millisecond)
			continue
		}
		time.Sleep(left)
		return
	}
}
