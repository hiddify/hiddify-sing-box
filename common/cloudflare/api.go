package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

type CloudflareApi struct {
	client http.Client
}

func NewCloudflareApi(opts ...CloudflareApiOption) *CloudflareApi {
	api := &CloudflareApi{http.Client{Timeout: 30 * time.Second}}
	for _, opt := range opts {
		opt(api)
	}
	return api
}

func (api *CloudflareApi) CreateProfile(ctx context.Context, publicKey string) (*CloudflareProfile, error) {
	request, err := http.NewRequest("POST", "https://api.cloudflareclient.com/v0i1909051800/reg", strings.NewReader(
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
	request, err := http.NewRequest("GET", "https://api.cloudflareclient.com/v0i1909051800/reg/"+id, nil)
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
