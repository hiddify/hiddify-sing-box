package cloudflare

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestH_GetProfileWithKey(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	_, api := hNewFakeCloudflare(t, func(w http.ResponseWriter, r *http.Request, body string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"result":`+strings.Replace(hProfileJSON, `"key": "pubkey"`, `"key": "`+key.PublicKey().String()+`"`, 1)+`}`)
	})
	profile, err := api.GetProfileWithKey(context.Background(), "auth-token", "device-id", key.String())
	require.NoError(t, err)
	require.Equal(t, key.String(), profile.Config.PrivateKey, "the endpoint needs the private key to start")

	other, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	_, err = api.GetProfileWithKey(context.Background(), "auth-token", "device-id", other.String())
	require.ErrorContains(t, err, "does not match")

	_, err = api.GetProfileWithKey(context.Background(), "auth-token", "device-id", "")
	require.ErrorContains(t, err, "needs its private_key")
}
