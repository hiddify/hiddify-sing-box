package cloudflare

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GetProfileWithKey fetches an existing device. The API does not return the
// device's private key, so it must be given; it is checked against the public
// key the device was registered with.
func (api *CloudflareApi) GetProfileWithKey(ctx context.Context, authToken string, id string, privateKey string) (*CloudflareProfile, error) {
	if privateKey == "" {
		return nil, E.New("WARP profile with id and auth_token needs its private_key")
	}
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return nil, E.Cause(err, "parse WARP private_key")
	}
	profile, err := api.GetProfile(ctx, authToken, id)
	if err != nil {
		return nil, err
	}
	if profile.Key != "" && profile.Key != key.PublicKey().String() {
		return nil, E.New("WARP private_key does not match device ", id)
	}
	profile.Config.PrivateKey = key.String()
	return profile, nil
}
