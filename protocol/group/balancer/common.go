package balancer

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"golang.org/x/net/publicsuffix"
)

func getKey(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return ""
	}

	var metadataHost string
	if metadata.Destination.IsFqdn() {
		metadataHost = metadata.Destination.Fqdn
	} else {
		metadataHost = metadata.Domain
	}

	if metadataHost != "" {
		// ip host
		if ip := net.ParseIP(metadataHost); ip != nil {
			return metadataHost
		}

		if etld, err := publicsuffix.EffectiveTLDPlusOne(metadataHost); err == nil {
			return etld
		}
	}

	var destinationAddr netip.Addr
	if len(metadata.DestinationAddresses) > 0 {
		destinationAddr = metadata.DestinationAddresses[0]
	} else {
		destinationAddr = metadata.Destination.Addr
	}

	if !destinationAddr.IsValid() {
		return ""
	}

	return destinationAddr.String()
}

func getKeyWithSrcAndDst(metadata *adapter.InboundContext) string {
	dst := getKey(metadata)
	src := ""
	if metadata != nil {
		src = metadata.Source.Addr.String()
	}

	return fmt.Sprintf("%s%s", src, dst)
}

func jumpHash(key uint64, buckets int32) int32 {
	var b, j int64

	for j < int64(buckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}

	return int32(b)
}

func sortOutboundsByDelay(outbounds []adapter.Outbound, history map[string]*adapter.URLTestHistory) []adapter.Outbound {
	sortedOutbounds := append([]adapter.Outbound{}, outbounds...)
	sort.SliceStable(sortedOutbounds, func(i, j int) bool {
		var delayi uint16 = monitoring.TimeoutDelay
		if his, ok := history[sortedOutbounds[i].Tag()]; ok && his != nil {
			delayi = his.Delay
		}
		var delayj uint16 = monitoring.TimeoutDelay
		if his, ok := history[sortedOutbounds[j].Tag()]; ok && his != nil {
			delayj = his.Delay
		}
		return delayi < delayj
	})
	return sortedOutbounds
}
func getAcceptableIndex(sortedOutbounds []adapter.Outbound, history map[string]*adapter.URLTestHistory, delayAcceptableRatio float64) int {
	minDelay := monitoring.TimeoutDelay
	if his, ok := history[sortedOutbounds[0].Tag()]; ok && his != nil {
		minDelay = his.Delay
	}

	maxAcceptableDelay := float64(math.Max(100, float64(minDelay))) * delayAcceptableRatio

	maxAvailableIndex := 0
	for i, outbound := range sortedOutbounds {

		if his, ok := history[outbound.Tag()]; ok && his != nil && his.Delay <= uint16(maxAcceptableDelay) {
			maxAvailableIndex = i
		}
	}

	return maxAvailableIndex

}

func getMinDelay(history map[string]*adapter.URLTestHistory) uint16 {
	minDelay := monitoring.TimeoutDelay

	for _, his := range history {
		if his != nil && his.Delay < minDelay {
			minDelay = his.Delay
		}
	}

	return minDelay

}

func getDelayMap(history map[string]*adapter.URLTestHistory) map[string]uint16 {
	delayMap := make(map[string]uint16)
	for tag, his := range history {
		if his != nil {
			delayMap[tag] = his.Delay
		} else {
			delayMap[tag] = monitoring.TimeoutDelay
		}
	}

	return delayMap

}
