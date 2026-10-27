package balancer

import (
	"fmt"
	"github.com/sagernet/sing-box/option"
	"math"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
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

func getModifiedDelay(his *adapter.URLTestHistory) uint16 {
	if his == nil {
		return monitoring.TimeoutDelay
	}
	delay := his.Delay
	if delay == 0 {
		delay = monitoring.TimeoutDelay
	}
	if his.IsFromCache && delay < 20000 {
		// if the history is from cache, we can not trust the delay
		delay += 20000
	}
	return delay
}

// getMaxAcceptableDelay returns the largest delay still accepted next to minDelay. It stays
// below TimeoutDelay, so a timed out outbound is never accepted and a large ratio cannot
// overflow uint16.
func getMaxAcceptableDelay(minDelay uint16, delayAcceptableRatio float64) uint16 {
	maxAcceptableDelay := math.Max(100, float64(minDelay)) * delayAcceptableRatio
	if maxAcceptableDelay >= float64(monitoring.TimeoutDelay) {
		return monitoring.TimeoutDelay - 1
	}
	return uint16(maxAcceptableDelay)
}

func getTagDelay(tag string, history map[string]*adapter.URLTestHistory) uint16 {
	if his, ok := history[tag]; ok && his != nil {
		return getModifiedDelay(his)
	}
	return monitoring.TimeoutDelay
}

func filterOutbounds(outbounds []adapter.Outbound, network string) []adapter.Outbound {
	res := []adapter.Outbound{}
	for _, out := range outbounds {
		if !common.Contains(out.Network(), network) {
			continue
		}
		res = append(res, out)
	}
	if len(res) == 0 {
		return outbounds
	}
	return res
}
func convertOutbounds(outbounds []adapter.Outbound) map[string][]adapter.Outbound {
	return map[string][]adapter.Outbound{
		N.NetworkTCP: filterOutbounds(outbounds, N.NetworkTCP),
		N.NetworkUDP: filterOutbounds(outbounds, N.NetworkUDP),
	}
}

func sortOutboundsByDelay(outbounds map[string][]adapter.Outbound, history map[string]*adapter.URLTestHistory) map[string][]adapter.Outbound {
	res := map[string][]adapter.Outbound{}
	for net, outs := range outbounds {
		res[net] = append([]adapter.Outbound{}, outs...)
		sort.SliceStable(res[net], func(i, j int) bool {
			var delayi uint16 = getTagDelay(res[net][i].Tag(), history)
			var delayj uint16 = getTagDelay(res[net][j].Tag(), history)
			return delayi < delayj
		})
	}

	return res
}
func getAcceptableIndex(sortedOutbounds map[string][]adapter.Outbound, history map[string]*adapter.URLTestHistory, delayAcceptableRatio float64) map[string]int {
	res := map[string]int{}
	for net, outs := range sortedOutbounds {
		minDelay := getTagDelay(outs[0].Tag(), history)

		maxAcceptableDelay := getMaxAcceptableDelay(minDelay, delayAcceptableRatio)

		maxAvailableIndex := 0
		for i, outbound := range outs {
			delay := getTagDelay(outbound.Tag(), history)
			if delay <= maxAcceptableDelay {
				maxAvailableIndex = i
			}
		}
		res[net] = maxAvailableIndex
	}
	return res

}

func getMinDelay(outbounds map[string][]adapter.Outbound, history map[string]*adapter.URLTestHistory) (map[string]adapter.Outbound, map[string]uint16) {
	delays := map[string]uint16{}
	bestOuts := map[string]adapter.Outbound{}
	for net, outs := range outbounds {
		minDelay := monitoring.TimeoutDelay
		var minOut adapter.Outbound
		for _, out := range outs {

			d := getTagDelay(out.Tag(), history)
			if d <= minDelay {
				minDelay = d
				minOut = out
			}
		}
		delays[net] = minDelay
		bestOuts[net] = minOut
	}
	return bestOuts, delays

}

func getDelayMap(history map[string]*adapter.URLTestHistory) map[string]uint16 {
	delayMap := make(map[string]uint16)
	for tag, his := range history {
		delayMap[tag] = getModifiedDelay(his)
	}

	return delayMap

}

// aliveSet names the members within the acceptable delay, per network, so a strategy can tell
// whether an update changed which members it uses.
func aliveSet(outbounds map[string][]adapter.Outbound, delays map[string]uint16, maxAcceptableDelay map[string]uint16) map[string]string {
	result := make(map[string]string, len(outbounds))
	for network, members := range outbounds {
		var alive strings.Builder
		for _, member := range members {
			if delay, loaded := delays[member.Tag()]; loaded && delay <= maxAcceptableDelay[network] {
				alive.WriteString(member.Tag())
				alive.WriteByte(0)
			}
		}
		result[network] = alive.String()
	}
	return result
}

func aliveSetChanged(previous, current map[string]string) bool {
	if previous == nil {
		return true
	}
	for network, alive := range current {
		if previous[network] != alive {
			return true
		}
	}
	return false
}

// defaultDelayAcceptableRatio is used when delay_acceptable_ratio is unset: at 0 no member is within
// the acceptable delay, so round robin used only the fastest and the hashing strategies none.
const defaultDelayAcceptableRatio = 2

func acceptableRatio(options option.BalancerOutboundOptions) float64 {
	if options.DelayAcceptableRatio <= 0 {
		return defaultDelayAcceptableRatio
	}
	return options.DelayAcceptableRatio
}
