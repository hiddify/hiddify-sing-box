package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/tidwall/gjson"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type CloudflareApi struct {
	client http.Client
}

const baseUrl = "https://api.cloudflareclient.com/v0i1909051800/"

func NewCloudflareApiDetour(detour N.Dialer) *CloudflareApi {
	opts := make([]CloudflareApiOption, 0, 1)
	if detour != nil {
		opts = append(opts, WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
		}))
	}
	return NewCloudflareApi(opts...)
}
func NewCloudflareApi(opts ...CloudflareApiOption) *CloudflareApi {
	api := &CloudflareApi{http.Client{Timeout: 30 * time.Second}}
	for _, opt := range opts {
		opt(api)
	}
	return api
}

func (api *CloudflareApi) CreateProfile(ctx context.Context, publicKey string) (*CloudflareProfile, error) {
	request, err := http.NewRequest("POST", baseUrl+"reg", strings.NewReader(
		fmt.Sprintf(
			"{\"install_id\":\"\",\"tos\":\"%s\",\"key\":\"%s\",\"fcm_token\":\"\",\"type\":\"ios\",\"locale\":\"en_US\"}",
			time.Now().Format("2006-01-02T15:04:05.000Z"),
			publicKey,
		),
	))
	if err != nil {
		return nil, err
	}
	response, err := api.client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("status code is not 200")
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	profile := new(CloudflareProfile)
	return profile, json.NewDecoder(strings.NewReader(gjson.Get(string(content), "result").Raw)).Decode(profile)
}

func (api *CloudflareApi) GetProfile(ctx context.Context, authToken string, id string) (*CloudflareProfile, error) {
	request, err := http.NewRequest("GET", baseUrl+"reg/"+id, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+authToken)
	response, err := api.client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("status code is not 200")
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	profile := new(CloudflareProfile)
	return profile, json.NewDecoder(strings.NewReader(gjson.Get(string(content), "result").Raw)).Decode(profile)
}

func (api *CloudflareApi) UpdateAccount(ctx context.Context, profile *CloudflareProfile, license string) (*CloudflareProfile, error) {
	deviceId := profile.ID
	authToken := profile.Token
	request, err := http.NewRequest("POST", fmt.Sprint(baseUrl, "reg/", deviceId, "/account"), strings.NewReader(
		fmt.Sprintf("{\"license\":\"%s\"}", license),
	))
	request.Header.Set("Authorization", "Bearer "+authToken)
	if err != nil {
		return nil, err
	}
	response, err := api.client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("status code is not 200")
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	ia := new(IdentityAccount)
	if err := json.Unmarshal([]byte(content), ia); err != nil {
		return nil, err
	}

	profile.Account = *ia
	return profile, nil
}

func (api *CloudflareApi) CreateProfileLicense(ctx context.Context, privateKey string, license string) (*CloudflareProfile, error) {
	var wgKey wgtypes.Key
	var err error
	if privateKey != "" {
		wgKey, err = wgtypes.ParseKey(privateKey)
		if err != nil {

			return nil, err
		}
	} else {
		wgKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {

			return nil, err
		}
	}
	profile, err := api.CreateProfile(ctx, wgKey.PublicKey().String())
	if err != nil {
		return nil, err
	}
	profile.Config.PrivateKey = wgKey.String()
	if license == "" {
		return profile, nil
	}
	return api.UpdateAccount(ctx, profile, license)
}

func (api *CloudflareApi) DeleteProfile(ctx context.Context, profile *CloudflareProfile) error {
	request, err := http.NewRequest("DELETE", fmt.Sprint(baseUrl, "reg/", profile.ID), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+profile.Token)
	response, err := api.client.Do(request.WithContext(ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("status code is not 200")
	}
	return nil
}
