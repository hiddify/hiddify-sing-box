package ipinfo

import (
	"strconv"
	"strings"
)

// parseASN accepts JSON numbers, "12322", "AS12322", or "AS12322 Org Name".
func parseASN(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0
		}
		if strings.HasPrefix(strings.ToUpper(s), "AS") {
			s = strings.Fields(s)[0]
			s = s[2:]
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0
		}
		return int(n)
	default:
		return 0
	}
}

func stringField(data map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := data[key].(string); ok {
			if s := strings.TrimSpace(v); s != "" && s != "null" {
				return s
			}
		}
	}
	return ""
}

func floatField(data map[string]interface{}, keys ...string) float64 {
	for _, key := range keys {
		if v, ok := data[key].(float64); ok {
			return v
		}
	}
	return 0
}

// parseIpApiJSON fills IpInfo from an ipapi.co-compatible object, including the
// custom panel schema:
//
//	ip, city, region, country_code, latitude, longitude, asn ("AS1234"|1234), org, ...
func parseIpApiJSON(data map[string]interface{}, info *IpInfo) {
	info.IP = stringField(data, "ip")
	info.CountryCode = strings.ToUpper(stringField(data, "country_code"))
	if info.CountryCode == "" {
		// Some APIs put the ISO code in `country` (ipinfo.io); ignore full names.
		if c := strings.ToUpper(stringField(data, "country")); len(c) == 2 {
			info.CountryCode = c
		}
	}
	info.Region = stringField(data, "region", "region_name")
	info.City = stringField(data, "city")
	info.Org = stringField(data, "org")
	info.PostalCode = stringField(data, "postal", "postal_code", "zip")
	info.Latitude = floatField(data, "latitude", "lat")
	info.Longitude = floatField(data, "longitude", "lon", "lng")
	if asn := parseASN(data["asn"]); asn != 0 {
		info.ASN = asn
	}
}
