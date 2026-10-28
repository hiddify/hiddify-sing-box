package v2rayhttp

import (
	"crypto/rand"
	"io"
	"math/big"
	"net/http"
)

// Behind a PROXY protocol hop, Xray's raw TCP HTTP header server reads at most 256 bytes at first, PROXY header
// included: 200 to 228 bytes of the request. It parses what it has but the last 4 bytes, and fails when the cut
// falls in a header name ("malformed MIME header"); when the whole request fits, its Trojan inbound reads its
// request from what is left of that read only and rejects a piece shorter than its 58-byte header. The headers
// are sent in any order, so the request starts with a cookie whose value covers every place the cut can fall:
// the request is then longer than that first read, and the cut is always inside a value.
const (
	hPaddingCoverFrom = 180
	hPaddingCoverTo   = 250
)

func hWriteRequestPadding(writer io.Writer, header http.Header, requestLineLength int) error {
	if header.Get("Cookie") != "" {
		return nil
	}
	start := requestLineLength + len("Cookie: ")
	if start > hPaddingCoverFrom {
		return nil
	}
	extra, err := rand.Int(rand.Reader, big.NewInt(32))
	if err != nil {
		return err
	}
	value := hCookieValue(hPaddingCoverTo - start + int(extra.Int64()))
	_, err = writer.Write([]byte("Cookie: " + value + "\r\n"))
	return err
}

// hCookieValue looks like analytics cookies: _ga=GA1.1.<digits>.<digits>; _gid=...; then a session id.
func hCookieValue(length int) string {
	digits := func(n int) string {
		value := make([]byte, n)
		for i := range value {
			d, _ := rand.Int(rand.Reader, big.NewInt(10))
			value[i] = byte('0' + d.Int64())
		}
		return string(value)
	}
	value := "_ga=GA1.1." + digits(10) + "." + digits(10) + "; _gid=GA1.1." + digits(10) + "." + digits(10) + "; sid="
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for len(value) < length {
		i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		value += string(alphabet[i.Int64()])
	}
	if len(value) > length && length > 0 {
		value = value[:length]
	}
	return value
}
