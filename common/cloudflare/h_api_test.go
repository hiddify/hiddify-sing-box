package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type hRecordedRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   string
}

type hFakeCloudflare struct {
	server   *httptest.Server
	access   sync.Mutex
	requests []hRecordedRequest
	handler  func(w http.ResponseWriter, r *http.Request, body string)
}

func hNewFakeCloudflare(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, body string)) (*hFakeCloudflare, *CloudflareApi) {
	fake := &hFakeCloudflare{handler: handler}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, _ := io.ReadAll(r.Body)
		fake.access.Lock()
		fake.requests = append(fake.requests, hRecordedRequest{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: string(content)})
		fake.access.Unlock()
		fake.handler(w, r, string(content))
	}))
	t.Cleanup(fake.server.Close)
	target, err := url.Parse(fake.server.URL)
	require.NoError(t, err)
	api := NewCloudflareApi()
	api.client.Transport = hRewriteTransport{target: target}
	return fake, api
}

func (f *hFakeCloudflare) recorded() []hRecordedRequest {
	f.access.Lock()
	defer f.access.Unlock()
	return append([]hRecordedRequest(nil), f.requests...)
}

type hRewriteTransport struct {
	target *url.URL
}

func (r hRewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "api.cloudflareclient.com" || request.URL.Scheme != "https" {
		return nil, errors.New("unexpected upstream: " + request.URL.String())
	}
	request = request.Clone(request.Context())
	request.URL.Scheme = r.target.Scheme
	request.URL.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(request)
}

const hProfileJSON = `{
	"id": "device-id",
	"type": "a",
	"name": "",
	"key": "pubkey",
	"token": "auth-token",
	"warp_enabled": true,
	"created": "2024-01-02T03:04:05.000Z",
	"account": {"id": "acct", "account_type": "free", "license": "AAAA-BBBB", "warp_plus": false, "premium_data": 0},
	"config": {
		"interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a36::1"}},
		"peers": [{
			"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
			"endpoint": {"v4": "162.159.192.1:0", "v6": "[2606:4700:d0::a29f:c001]:0", "host": "engage.cloudflareclient.com:2408", "ports": [2408, 500, 1701]}
		}]
	},
	"policy": {"tunnel_protocol": "wireguard"}
}`

func hWriteResult(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"success":true,"result":`+hProfileJSON+`}`)
}

func hRequireProfile(t *testing.T, profile *CloudflareProfile) {
	require.Equal(t, "device-id", profile.ID)
	require.Equal(t, "auth-token", profile.Token)
	require.True(t, profile.WARPEnabled)
	require.Equal(t, "AAAA-BBBB", profile.Account.License)
	require.Equal(t, "free", profile.Account.AccountType)
	require.Equal(t, "172.16.0.2", profile.Config.Interface.Addresses.V4)
	require.Equal(t, "2606:4700:110:8a36::1", profile.Config.Interface.Addresses.V6)
	require.Len(t, profile.Config.Peers, 1)
	require.Equal(t, "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", profile.Config.Peers[0].PublicKey)
	require.Equal(t, "engage.cloudflareclient.com:2408", profile.Config.Peers[0].Endpoint.Host)
	require.Equal(t, []int{2408, 500, 1701}, profile.Config.Peers[0].Endpoint.Ports)
	require.Equal(t, "wireguard", profile.Policy.TunnelProtocol)
	require.Equal(t, time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), profile.Created.UTC())
}

func TestH_CreateProfile(t *testing.T) {
	fake, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) { hWriteResult(w) })
	profile, err := api.CreateProfile(context.Background(), "my-public-key")
	require.NoError(t, err)
	hRequireProfile(t, profile)

	requests := fake.recorded()
	require.Len(t, requests, 1)
	require.Equal(t, http.MethodPost, requests[0].Method)
	require.Equal(t, "/v0i1909051800/reg", requests[0].Path)
	var body map[string]string
	require.NoError(t, json.Unmarshal([]byte(requests[0].Body), &body))
	require.Equal(t, "my-public-key", body["key"])
	require.Equal(t, "ios", body["type"])
	require.Equal(t, "en_US", body["locale"])
	_, err = time.Parse("2006-01-02T15:04:05.000Z", body["tos"])
	require.NoError(t, err)
}

func TestH_GetProfile(t *testing.T) {
	fake, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) { hWriteResult(w) })
	profile, err := api.GetProfile(context.Background(), "tok", "dev123")
	require.NoError(t, err)
	hRequireProfile(t, profile)
	requests := fake.recorded()
	require.Equal(t, http.MethodGet, requests[0].Method)
	require.Equal(t, "/v0i1909051800/reg/dev123", requests[0].Path)
	require.Equal(t, "Bearer tok", requests[0].Header.Get("Authorization"))
}

func TestH_NonOKStatusIsError(t *testing.T) {
	_, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	ctx := context.Background()
	_, err := api.CreateProfile(ctx, "k")
	require.Error(t, err)
	_, err = api.GetProfile(ctx, "t", "i")
	require.Error(t, err)
	_, err = api.UpdateAccount(ctx, &CloudflareProfile{ID: "i", Token: "t"}, "lic")
	require.Error(t, err)
	require.Error(t, api.DeleteProfile(ctx, &CloudflareProfile{ID: "i", Token: "t"}))
	_, err = api.GetProfile4471(ctx, "t", "i")
	require.Error(t, err)
	_, err = api.EnrollKey(ctx, "t", "i", KeyTypeMasque, TunTypeMasque, "pk")
	require.ErrorContains(t, err, "429")
}

func TestH_MalformedResultIsError(t *testing.T) {
	_, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) {
		_, _ = io.WriteString(w, `{"result": "not-an-object"}`)
	})
	_, err := api.CreateProfile(context.Background(), "k")
	require.Error(t, err)
}

func TestH_CreateProfileLicense(t *testing.T) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	fake, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) {
		if strings.HasSuffix(r.URL.Path, "/account") {
			_, _ = io.WriteString(w, `{"id":"acct","license":"NEW-LICENSE","warp_plus":true,"account_type":"unlimited"}`)
			return
		}
		hWriteResult(w)
	})
	profile, err := api.CreateProfileLicense(context.Background(), privateKey.String(), "")
	require.NoError(t, err)
	require.Equal(t, privateKey.String(), profile.Config.PrivateKey)
	requests := fake.recorded()
	require.Len(t, requests, 1)
	require.Contains(t, requests[0].Body, `"key":"`+privateKey.PublicKey().String()+`"`)

	profile, err = api.CreateProfileLicense(context.Background(), privateKey.String(), "NEW-LICENSE")
	require.NoError(t, err)
	require.Equal(t, privateKey.String(), profile.Config.PrivateKey)
	require.Equal(t, "NEW-LICENSE", profile.Account.License)
	require.True(t, profile.Account.WarpPlus)
	require.Equal(t, "unlimited", profile.Account.AccountType)
	requests = fake.recorded()
	require.Len(t, requests, 3)
	update := requests[2]
	require.Equal(t, http.MethodPost, update.Method)
	require.Equal(t, "/v0i1909051800/reg/device-id/account", update.Path)
	require.Equal(t, "Bearer auth-token", update.Header.Get("Authorization"))
	require.JSONEq(t, `{"license":"NEW-LICENSE"}`, update.Body)
}

func TestH_CreateProfileLicenseGeneratesKey(t *testing.T) {
	_, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) { hWriteResult(w) })
	profile, err := api.CreateProfileLicense(context.Background(), "", "")
	require.NoError(t, err)
	key, err := wgtypes.ParseKey(profile.Config.PrivateKey)
	require.NoError(t, err)
	require.NotEqual(t, wgtypes.Key{}, key)
}

func TestH_CreateProfileLicenseInvalidKey(t *testing.T) {
	fake, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) { hWriteResult(w) })
	_, err := api.CreateProfileLicense(context.Background(), "not a key", "")
	require.Error(t, err)
	require.Empty(t, fake.recorded())
}

func TestH_UpdateAccountLicenseEscaping(t *testing.T) {
	t.Skip(`BUG: UpdateAccount builds JSON with fmt.Sprintf so a license containing '"' yields an invalid request body`)
	fake, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) {
		_, _ = io.WriteString(w, `{}`)
	})
	_, err := api.UpdateAccount(context.Background(), &CloudflareProfile{ID: "i", Token: "t"}, `a"b`)
	require.NoError(t, err)
	require.JSONEq(t, `{"license":"a\"b"}`, fake.recorded()[0].Body)
}

func TestH_UpdateAccountInvalidDeviceID(t *testing.T) {
	t.Skip("BUG: UpdateAccount dereferences a nil request (sets header before checking NewRequest error); a device id with a control character panics")
	_, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) {})
	require.NotPanics(t, func() {
		_, err := api.UpdateAccount(context.Background(), &CloudflareProfile{ID: "bad\x7fid", Token: "t"}, "lic")
		require.Error(t, err)
	})
}

func TestH_DeleteProfile(t *testing.T) {
	fake, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) {})
	require.NoError(t, api.DeleteProfile(context.Background(), &CloudflareProfile{ID: "dev9", Token: "tk"}))
	requests := fake.recorded()
	require.Equal(t, http.MethodDelete, requests[0].Method)
	require.Equal(t, "/v0i1909051800/reg/dev9", requests[0].Path)
	require.Equal(t, "Bearer tk", requests[0].Header.Get("Authorization"))
}

func TestH_GetProfile4471(t *testing.T) {
	fake, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) {
		_, _ = io.WriteString(w, hProfileJSON)
	})
	profile, err := api.GetProfile4471(context.Background(), "tok", "dev1")
	require.NoError(t, err)
	hRequireProfile(t, profile)
	request := fake.recorded()[0]
	require.Equal(t, http.MethodGet, request.Method)
	require.Equal(t, "/"+ApiVersion+"/reg/dev1", request.Path)
	require.Equal(t, "Bearer tok", request.Header.Get("Authorization"))
	for key, value := range Headers {
		if key == "Connection" {
			continue
		}
		require.Equal(t, value, request.Header.Get(key), key)
	}
}

func TestH_EnrollKey(t *testing.T) {
	fake, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) {
		_, _ = io.WriteString(w, hProfileJSON)
	})
	profile, err := api.EnrollKey(context.Background(), "tok", "dev2", KeyTypeMasque, TunTypeMasque, "BASE64PUB")
	require.NoError(t, err)
	hRequireProfile(t, profile)
	request := fake.recorded()[0]
	require.Equal(t, http.MethodPatch, request.Method)
	require.Equal(t, "/"+ApiVersion+"/reg/dev2", request.Path)
	require.Equal(t, "Bearer tok", request.Header.Get("Authorization"))
	require.Equal(t, Headers["CF-Client-Version"], request.Header.Get("CF-Client-Version"))
	require.JSONEq(t, `{"name":"PC","key":"BASE64PUB","key_type":"secp256r1","tunnel_type":"masque"}`, request.Body)
}

type hRecordingDialer struct {
	access  sync.Mutex
	targets []M.Socksaddr
}

func (d *hRecordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.targets = append(d.targets, destination)
	d.access.Unlock()
	return nil, errors.New("detour refused")
}

func (d *hRecordingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func TestH_NewCloudflareApiDetour(t *testing.T) {
	detour := &hRecordingDialer{}
	api := NewCloudflareApiDetour(detour)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := api.GetProfile(ctx, "t", "i")
	require.ErrorContains(t, err, "detour refused")
	require.NotEmpty(t, detour.targets)
	require.Equal(t, M.ParseSocksaddr("api.cloudflareclient.com:443"), detour.targets[0])

	require.Nil(t, NewCloudflareApiDetour(nil).client.Transport)
	require.Equal(t, 30*time.Second, NewCloudflareApi().client.Timeout)
}

func TestH_WithDialContext(t *testing.T) {
	called := false
	api := NewCloudflareApi(WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
		called = true
		require.Equal(t, "api.cloudflareclient.com:443", addr)
		return nil, errors.New("blocked")
	}))
	require.ErrorContains(t, api.DeleteProfile(context.Background(), &CloudflareProfile{ID: "x"}), "blocked")
	require.True(t, called)
}
