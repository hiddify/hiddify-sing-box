package bitrix

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (c *Client) LoadCookieString(cookieStr string) error {
	cookieStr = strings.TrimSpace(cookieStr)
	if cookieStr == "" {
		return fmt.Errorf("empty cookie string")
	}
	u, err := url.Parse(c.portal)
	if err != nil {
		return fmt.Errorf("parse portal %s: %w", c.portal, err)
	}
	var cookies []*http.Cookie
	for piece := range strings.SplitSeq(cookieStr, ";") {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		eq := strings.IndexByte(piece, '=')
		if eq <= 0 {
			continue
		}
		cookies = append(cookies, &http.Cookie{Name: piece[:eq], Value: piece[eq+1:], Path: "/"})
	}
	c.HTTP.Jar.SetCookies(u, cookies)
	return nil
}

func (c *Client) EnsureLogin() error {
	if c.checkSession() {
		c.Logger.Debug("[auth] session valid, reusing saved cookies")
		return nil
	}
	if c.email == "" || c.password == "" {
		return fmt.Errorf("ensureLogin: no email/password")
	}
	c.Logger.Debug("[auth] session dead, re-logging in")
	return c.loginWithPassword(c.email, c.password)
}

func (c *Client) checkSession() bool {
	body, final, err := c.getPage(c.portal + "/")
	if err != nil {
		return false
	}
	if strings.Contains(final, "auth2.bitrix24.net") {
		return false
	}
	if m := reSessid.FindStringSubmatch(body); m != nil {
		c.sessid = m[1]
		return true
	}
	return false
}

func (c *Client) withRelogin(do func() ([]byte, int, error)) ([]byte, int, error) {
	body, status, err := do()
	if err != nil {
		return body, status, err
	}
	if token := csrfTokenFromBody(body); token != "" && token != c.sessid {
		c.Logger.Debug("[auth] stale csrf token, retrying with the one from the response")
		c.sessid = token
		body, status, err = do()
		if err != nil {
			return body, status, err
		}
	}
	if !looksUnauth(body, status) {
		return body, status, err
	}
	if c.email == "" || c.password == "" {
		return body, status, err
	}
	c.Logger.Debug(fmt.Sprintf("[auth] unauthenticated response (status %d), re-logging in and retrying", status))
	if lerr := c.loginWithPassword(c.email, c.password); lerr != nil {
		return body, status, fmt.Errorf("relogin: %w", lerr)
	}
	return do()
}

func csrfTokenFromBody(body []byte) string {
	var out struct {
		Errors []struct {
			Code       any             `json:"code"`
			CustomData json.RawMessage `json:"customData"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return ""
	}
	for _, e := range out.Errors {
		if e.Code != "invalid_csrf" {
			continue
		}
		var customData struct {
			CSRF string `json:"csrf"`
		}
		if err := json.Unmarshal(e.CustomData, &customData); err != nil {
			continue
		}
		return customData.CSRF
	}
	return ""
}

func looksUnauth(body []byte, status int) bool {
	if status == 401 || status == 403 {
		return true
	}
	s := strings.TrimSpace(string(body))
	if s == "" || s[0] != '{' {
		return true
	}
	low := strings.ToLower(s)
	return strings.Contains(low, "not_authorized") ||
		strings.Contains(low, "unauthorized") ||
		strings.Contains(low, "invalid_token") ||
		strings.Contains(low, "user_not_authorized")
}
