package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	CM "github.com/sagernet/sing-box/service/manager/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type Client struct {
	boxService.Adapter

	ctx        context.Context
	logger     log.ContextLogger
	options    option.ManagerAPIClientOptions
	httpClient *http.Client
	baseURL    string
}

func NewClient(ctx context.Context, logger log.ContextLogger, tag string, options option.ManagerAPIClientOptions) (*Client, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return outboundDialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
	}
	scheme := "http"
	if options.TLS != nil {
		tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		if !common.Contains(tlsConfig.NextProtos(), "http/1.1") {
			tlsConfig.SetNextProtos(append([]string{"http/1.1"}, tlsConfig.NextProtos()...))
		}
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			rawConn, err := outboundDialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			if err != nil {
				return nil, err
			}
			return tls.ClientHandshake(ctx, rawConn, tlsConfig)
		}
		scheme = "https"
	}
	return &Client{
		Adapter:    boxService.NewAdapter(C.TypeManagerAPI, tag),
		ctx:        ctx,
		logger:     logger,
		options:    options,
		httpClient: &http.Client{Transport: transport},
		baseURL:    scheme + "://" + options.ServerOptions.Build().String() + "/manager/v1",
	}, nil
}

func (s *Client) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(func() error {
		s.httpClient.CloseIdleConnections()
		return nil
	})
	return nil
}

func (s *Client) doJSON(method, path string, query url.Values, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(b)
	}
	u := s.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(s.ctx, method, u, reqBody)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.options.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.options.APIKey)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return CM.ErrNotFound
	}
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(resp.Body)
		return E.New("manager-api http ", resp.StatusCode, ": ", string(msg))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func filtersQuery(filters map[string][]string) url.Values {
	q := url.Values{}
	for k, vs := range filters {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	return q
}

func intPath(id int) string       { return "/" + strconv.Itoa(id) }
func stringPath(id string) string { return "/" + id }
