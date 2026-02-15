package mieru

import (
	"fmt"
	"strings"

	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/option"
)

func validateMieruTransport(transport []option.MieruTransportPort) error {

	for _, pr := range transport {
		if getTransportProtocol(pr.Transport) == nil {
			return fmt.Errorf("transport must be TCP or UDP")
		}
		if pr.Port != 0 && pr.PortRange != "" {
			return fmt.Errorf("invalid format: both port and port_range should not be set")
		}
		if pr.Port == 0 && pr.PortRange == "" {
			return fmt.Errorf("invalid format: either port or port_range must be set")
		}
		if pr.Port != 0 {
			continue
		}
		begin, end, err := beginAndEndPortFromPortRange(pr.PortRange)
		if err != nil {
			return fmt.Errorf("invalid server_ports format")
		}

		if begin < 1 || begin > 65535 {
			return fmt.Errorf("begin port must be between 1 and 65535")
		}
		if end < 1 || end > 65535 {
			return fmt.Errorf("end port must be between 1 and 65535")
		}
		if begin > end {
			return fmt.Errorf("begin port must be less than or equal to end port")
		}

	}
	return nil
}

func beginAndEndPortFromPortRange(portRange string) (int, int, error) {
	var begin, end int

	_, err := fmt.Sscanf(portRange, "%d-%d", &begin, &end)
	return begin, end, err

}

func getTransportProtocol(transport string) *mierupb.TransportProtocol {
	switch strings.ToUpper(transport) {
	case "TCP":
		return mierupb.TransportProtocol_TCP.Enum()
	case "UDP":
		return mierupb.TransportProtocol_UDP.Enum()
	default:
		return nil
	}
}
