package urltest

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// ErrDownloadInconclusive says the download test could not tell whether the outbound carries
// data: the download server sent no body, as it answered with something else (a rate limit, a
// redirect) or not at all (unreachable from the exit, down, or slower than ctx).
var ErrDownloadInconclusive = E.New("download test inconclusive")

// URLTestDownload fetches link through detour and reads its whole body. Meant after the plain
// URL test passed: a censor that freezes a connection once its first kilobytes have passed lets
// the plain test's few bytes through, so that outbound looks healthy while every page and video
// through it hangs. Only a body that stops is taken as that: no byte for idle, or the connection
// cut, or ctx ending, once the body has begun; a slow body whose bytes keep coming passes. The
// error says how many bytes arrived. Anything before the body wraps ErrDownloadInconclusive.
func URLTestDownload(ctx context.Context, link string, detour N.Dialer, idle time.Duration) error {
	if detour == nil {
		return E.New("urltest dialer is nil")
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return err
	}
	port := linkURL.Port()
	if port == "" {
		port = "80"
		if linkURL.Scheme == "https" {
			port = "443"
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	instance, err := detour.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPortStr(linkURL.Hostname(), port))
	if err != nil {
		return E.Errors(ErrDownloadInconclusive, err)
	}
	defer instance.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return err
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return instance, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
			// the size asked for is what has to pass, not a compressed copy of it
			DisableCompression: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return E.Errors(ErrDownloadInconclusive, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return E.Errors(ErrDownloadInconclusive, E.New("the download server answered ", response.Status))
	}
	stalled := time.AfterFunc(idle, cancel)
	defer stalled.Stop()
	var received int64
	buffer := make([]byte, 32<<10)
	for {
		stalled.Reset(idle)
		n, readErr := response.Body.Read(buffer)
		received += int64(n)
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return E.Cause(readErr, "download stalled after ", received, " bytes")
		}
	}
}
