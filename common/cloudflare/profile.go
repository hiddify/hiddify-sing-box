package cloudflare

import "time"

type CloudflareProfile struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Key     string `json:"key"`
	Account struct {
		ID                       string    `json:"id"`
		AccountType              string    `json:"account_type"`
		Created                  time.Time `json:"created"`
		Updated                  time.Time `json:"updated"`
		PremiumData              int       `json:"premium_data"`
		Quota                    int       `json:"quota"`
		Usage                    int       `json:"usage"`
		WARPPlus                 bool      `json:"warp_plus"`
		ReferralCount            int       `json:"referral_count"`
		ReferralRenewalCountdown int       `json:"referral_renewal_countdown"`
		Role                     string    `json:"role"`
		License                  string    `json:"license"`
		TTL                      time.Time `json:"ttl"`
	} `json:"account"`
	Config struct {
		ClientID  string `json:"client_id"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4    string `json:"v4"`
				V6    string `json:"v6"`
				Host  string `json:"host"`
				Ports []int  `json:"ports"`
			} `json:"endpoint"`
		} `json:"peers"`
		Services struct {
			HTTPProxy string `json:"http_proxy"`
		} `json:"services"`
		Metrics struct {
			Ping   int `json:"ping"`
			Report int `json:"report"`
		} `json:"metrics"`
	} `json:"config"`
	Token           string    `json:"token"`
	WARPEnabled     bool      `json:"warp_enabled"`
	WaitlistEnabled bool      `json:"waitlist_enabled"`
	Created         time.Time `json:"created"`
	Updated         time.Time `json:"updated"`
	Tos             time.Time `json:"tos"`
	Place           int       `json:"place"`
	Locale          string    `json:"locale"`
	Enabled         bool      `json:"enabled"`
	InstallID       string    `json:"install_id"`
	FcmToken        string    `json:"fcm_token"`
	Policy          struct {
		TunnelProtocol string `json:"tunnel_protocol"`
	} `json:"policy"`
}
