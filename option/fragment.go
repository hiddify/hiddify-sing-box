package option

import (
	"math/rand"
)

type TLSFragmentOptions struct {
	Enabled bool   `json:"enabled,omitempty"`
	Size    string `json:"size,omitempty"`   // Fragment size in Bytes
	Sleep   string `json:"sleep,omitempty"`  // Time to sleep between sending the fragments in milliseconds
	Method  string `json:"method,omitempty"` // Wether to fragment only clientHello or a range of TCP packets. Valid options: ['tlsHello', 'range']
	Range   string `json:"range,omitempty"`  // Ra
}

func RandBetween(min int, max int) int {
	if max == min {
		return min
	}
	return rand.Intn(max-min+1) + min

}
