package cloudflare

import (
	"errors"
	"fmt"
	"net/http"
)

// StatusError is an answer of the WARP API that is not a success. Cloudflare answered, so the
// network works; the request was refused.
type StatusError struct {
	Operation string
	Code      int
}

func (e *StatusError) Error() string {
	return fmt.Sprint(e.Operation, ": status code ", e.Code)
}

// DeviceGone reports whether err is the API saying the device or its token no longer exists or
// is not allowed: the device cannot be used again, whatever the network.
func DeviceGone(err error) bool {
	var statusError *StatusError
	if !errors.As(err, &statusError) {
		return false
	}
	switch statusError.Code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		return true
	}
	return false
}

// Problem says why the device of profile cannot be used, empty when it can: it is disabled, or its
// account has used up its quota.
func (p *CloudflareProfile) Problem() string {
	if !p.Enabled {
		return "the device is disabled"
	}
	if p.Account.Quota > 0 && p.Account.Usage >= p.Account.Quota {
		return "the account has used up its quota"
	}
	return ""
}
