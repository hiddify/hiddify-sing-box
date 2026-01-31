package cloudflare

import (
	"time"

	C "github.com/sagernet/sing-box/constant"
)

type IdentityAccount struct {
	Created                  time.Time `json:"created"`
	Updated                  time.Time `json:"updated"`
	License                  string    `json:"license"`
	PremiumData              int64     `json:"premium_data"`
	WarpPlus                 bool      `json:"warp_plus"`
	AccountType              string    `json:"account_type"`
	ReferralRenewalCountdown int64     `json:"referral_renewal_countdown"`
	Role                     string    `json:"role"`
	ID                       string    `json:"id"`
	Quota                    int64     `json:"quota"`
	Usage                    int64     `json:"usage"`
	ReferralCount            int64     `json:"referral_count"`
	TTL                      time.Time `json:"ttl"`
}
type CloudflareProfile struct {
	ID              string          `json:"id"`
	Type            string          `json:"type"`
	Name            string          `json:"name"`
	Key             string          `json:"key"`
	Account         IdentityAccount `json:"account"`
	Config          C.WARPConfig    `json:"config"`
	Token           string          `json:"token"`
	WARPEnabled     bool            `json:"warp_enabled"`
	WaitlistEnabled bool            `json:"waitlist_enabled"`
	Created         time.Time       `json:"created"`
	Updated         time.Time       `json:"updated"`
	Tos             time.Time       `json:"tos"`
	Place           int             `json:"place"`
	Locale          string          `json:"locale"`
	Enabled         bool            `json:"enabled"`
	InstallID       string          `json:"install_id"`
	FcmToken        string          `json:"fcm_token"`
	Policy          struct {
		TunnelProtocol string `json:"tunnel_protocol"`
	} `json:"policy"`
}
