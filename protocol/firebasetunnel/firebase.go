package firebasetunnel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sagernet/sing-box/log"
)

// sseEvent is a parsed Server-Sent Event from Firebase's streaming endpoint.
type sseEvent struct {
	Event string
	Data  string
}

// firebaseClient is an async Firebase Realtime Database REST client.
// Safe for concurrent use.
//
// Auth: if authToken is set, requests use ?access_token=<token> (short-lived
// Firebase Auth / service-account token, recommended). Otherwise secret is
// used as ?auth=<secret> (legacy Database Secret: anyone holding it has
// full read/write access to the entire Firebase project, not just this
// tunnel's data).
type firebaseClient struct {
	baseURL    string
	secret     string
	authToken  string
	http       *http.Client
	retryLimit uint32
	logger     log.ContextLogger
}

func newFirebaseClient(baseURL, secret, authToken string, retryLimit uint32, logger log.ContextLogger) *firebaseClient {
	transport := &http.Transport{
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}
	return &firebaseClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		secret:     secret,
		authToken:  authToken,
		http:       &http.Client{Timeout: 30 * time.Second, Transport: transport},
		retryLimit: retryLimit,
		logger:     logger,
	}
}

func (c *firebaseClient) authParam() string {
	if c.authToken != "" {
		return "access_token=" + c.authToken
	}
	return "auth=" + c.secret
}

func (c *firebaseClient) url(path string) string {
	p := strings.TrimPrefix(path, "/")
	return fmt.Sprintf("%s/%s.json?%s", c.baseURL, p, c.authParam())
}

func (c *firebaseClient) streamURL(path string) string {
	p := strings.TrimPrefix(path, "/")
	return fmt.Sprintf(`%s/%s.json?%s&orderBy="$key"`, c.baseURL, p, c.authParam())
}

func (c *firebaseClient) Get(ctx context.Context, path string, v interface{}) (bool, error) {
	resp, err := c.doWithRetry(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("firebasetunnel: reading GET response from %s: %w", path, err)
	}
	if strings.TrimSpace(string(body)) == "null" {
		return false, nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return false, fmt.Errorf("firebasetunnel: decoding GET response from %s: %w", path, err)
	}
	return true, nil
}

func (c *firebaseClient) Put(ctx context.Context, path string, v interface{}) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("firebasetunnel: encoding PUT body for %s: %w", path, err)
	}
	resp, err := c.doWithRetry(ctx, http.MethodPut, c.url(path), body)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *firebaseClient) Delete(ctx context.Context, path string) error {
	resp, err := c.doWithRetry(ctx, http.MethodDelete, c.url(path), nil)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// doWithRetry issues an HTTP request with exponential backoff retry on
// transient errors/status codes. Caller must close the returned response body.
func (c *firebaseClient) doWithRetry(ctx context.Context, method, url string, body []byte) (*http.Response, error) {
	delay := 200 * time.Millisecond
	var lastErr error
	for attempt := uint32(0); attempt <= c.retryLimit; attempt++ {
		var reqBody io.Reader
		if body != nil {
			reqBody = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
		} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		} else if resp.StatusCode == http.StatusNotFound && method == http.MethodDelete {
			return resp, nil
		} else {
			resp.Body.Close()
			if !shouldRetryStatus(resp.StatusCode) {
				return nil, fmt.Errorf("firebasetunnel: %s %s failed with status %d", method, url, resp.StatusCode)
			}
			lastErr = fmt.Errorf("firebasetunnel: %s status %d", method, resp.StatusCode)
		}
		if c.logger != nil {
			c.logger.WarnContext(ctx, "firebasetunnel: ", method, " attempt ", attempt, " failed: ", lastErr)
		}
		if attempt < c.retryLimit {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
			if delay < 10*time.Second {
				delay *= 2
			}
		}
	}
	return nil, fmt.Errorf("firebasetunnel: %s %s failed after %d attempts: %w", method, url, c.retryLimit+1, lastErr)
}

func shouldRetryStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// listen opens a Server-Sent Events stream for path, reconnecting
// automatically (with jittered backoff) on transient errors. Cancel ctx to
// stop. Closes the returned channel only when ctx is done.
func (c *firebaseClient) listen(ctx context.Context, path string) <-chan sseEvent {
	ch := make(chan sseEvent, 256)
	go c.listenLoop(ctx, path, ch)
	return ch
}

func (c *firebaseClient) listenLoop(ctx context.Context, path string, ch chan<- sseEvent) {
	defer close(ch)
	u := c.streamURL(path)
	consecutiveFailures := 0
	for {
		err := c.runSSELoop(ctx, u, ch)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			consecutiveFailures = 0
			continue
		}
		consecutiveFailures++
		backoff := jitteredBackoff(consecutiveFailures)
		if c.logger != nil {
			c.logger.ErrorContext(ctx, "firebasetunnel: SSE stream error, reconnecting in ", backoff, ": ", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func (c *firebaseClient) runSSELoop(ctx context.Context, url string, ch chan<- sseEvent) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("firebasetunnel: SSE connect: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("firebasetunnel: SSE connect failed with status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var currentEvent, currentData string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if currentEvent != "" && currentData != "" {
				select {
				case ch <- sseEvent{Event: currentEvent, Data: currentData}:
				case <-ctx.Done():
					return nil
				}
				currentEvent, currentData = "", ""
			}
		case strings.HasPrefix(line, "event:"):
			currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			currentData = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
	}
	if err := scanner.Err(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("firebasetunnel: SSE read: %w", err)
	}
	if ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("firebasetunnel: SSE stream ended unexpectedly")
}
