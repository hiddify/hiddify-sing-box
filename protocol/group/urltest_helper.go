package group

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/ipinfo"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	N "github.com/sagernet/sing/common/network"
)

const TimeoutDelay = 65000

func urltestTimeout(ctx context.Context, logger log.Logger, realTag string, outbound adapter.Outbound, url string, history adapter.URLTestHistoryStorage, timeout time.Duration) *adapter.URLTestHistory {
	testCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t, err := urltest.URLTest(testCtx, url, outbound)
	if err != nil || t == 0 {
		t = TimeoutDelay
	}

	his := history.StoreURLTestHistory(realTag, &adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: t,
	})
	logger.Debug("outbound new ping ", realTag, " = ", his.Delay)
	return his
}

func CheckOutbound(logger log.Logger, ctx context.Context, history adapter.URLTestHistoryStorage, router adapter.OutboundManager, url string, outbound adapter.Outbound, ipbatch *batch.Batch[string]) uint16 {
	realTag := RealTag(outbound)
	hisbefore := history.LoadURLTestHistory(realTag)
	timeout := C.TCPTimeout
	isTimeoutBefore := isTimeout(hisbefore)

	if !isTimeoutBefore {
		timeout = time.Duration(max(200, hisbefore.Delay)) * time.Millisecond * 4
		logger.Debug("outbound is already connected ", realTag, " = ", hisbefore.Delay, " set timeout for new urltest to ", timeout)
	}
	his := urltestTimeout(ctx, logger, realTag, outbound, url, history, timeout)

	if outbound.Type() == C.TypeWireGuard && his.Delay > 1000 { // double check for wireguard
		his = urltestTimeout(ctx, logger, realTag, outbound, url, history, timeout)
	}
	if isTimeout(his) && !isTimeoutBefore {
		his = urltestTimeout(ctx, logger, realTag, outbound, url, history, C.TCPTimeout)
	}

	if !isTimeout(his) && his.IpInfo == nil {
		if ipbatch == nil {
			go CheckIP(logger, ctx, history, router, outbound)
		} else {
			ipbatch.Go(realTag+"ip", func() (string, error) {
				CheckIP(logger, ctx, history, router, outbound)
				return "", nil
			})
		}
	}

	return his.Delay
}

func CheckIP(logger log.Logger, ctx context.Context, history adapter.URLTestHistoryStorage, router adapter.OutboundManager, outbound adapter.Outbound) {
	if outbound == nil {
		return
	}
	if history == nil {
		return
	}
	realTag := RealTag(outbound)
	detour, loaded := router.Outbound(realTag)
	if !loaded {
		return
	}
	his := history.LoadURLTestHistory(realTag)
	if isTimeout(his) {
		return
	}
	if his.IpInfo != nil {
		// logger.Debug("ip already calculated ", fmt.Sprint(his.IpInfo))
		return
	}
	newip, t, err := ipinfo.GetIpInfo(logger, ctx, detour)
	if err != nil {
		// g.logger.Debug("outbound ", realTag, " IP unavailable (", t, "ms): ", err)
		// g.history.AddOnlyIpToHistory(realTag, &urltest.History{
		// 	Time:   time.Now(),
		// 	Delay:  TimeoutDelay,
		// 	IpInfo: &ipinfo.IpInfo{},
		// })
		return
	}
	// g.logger.Trace("outbound ", realTag, " IP ", fmt.Sprint(newip), " (", t, "ms): ", err)
	history.AddOnlyIpToHistory(realTag, &adapter.URLTestHistory{
		Time:   time.Now(),
		Delay:  t,
		IpInfo: newip,
	})
}

func isTimeout(history *adapter.URLTestHistory) bool {
	return history == nil || history.Delay == TimeoutDelay || history.Delay == 0
}

func (g *URLTestGroup) urlTestEx(ctx context.Context, force bool, force_check_even_previous_not_completed bool) (map[string]uint16, error) {
	if t := g.selectedOutboundTCP; t != nil {
		go g.urltestImp(t, nil)
	}
	if t := g.selectedOutboundUDP; t != nil && t != g.selectedOutboundTCP {
		go g.urltestImp(t, nil)
	}

	if force_check_even_previous_not_completed && time.Since(g.lastForceRecheck) < 15*time.Second {
		return make(map[string]uint16), nil
	}

	if g.checking.Swap(true) {
		if !force_check_even_previous_not_completed {
			return make(map[string]uint16), nil
		}
		if g.checkingEx.Swap(true) {
			g.performUpdateCheck()
			return make(map[string]uint16), nil
		}
		defer g.checkingEx.Store(false)
		g.lastForceRecheck = time.Now()
	}
	defer g.checking.Store(false)

	result, err := g.urlTestExImp(ctx, force, force_check_even_previous_not_completed)
	if err != nil {
		return nil, err
	}
	if !force_check_even_previous_not_completed && g.currentLinkIndex == 0 {
		for i := 1; i < len(g.links); i++ {
			result, err := g.urlTestExImp(ctx, force, force_check_even_previous_not_completed)
			if err != nil {
				return nil, err
			}
			if g.hasOneAvailableOutbound() {
				g.currentLinkIndex = i
				return result, nil
			}

		}
	}
	return result, nil
}
func (g *URLTestGroup) urlTestExImp(ctx context.Context, force bool, force_check_even_previous_not_completed bool) (map[string]uint16, error) {
	result := make(map[string]uint16)
	ipbatch, _ := batch.New(ctx, batch.WithConcurrencyNum[string](10))
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	var resultAccess sync.Mutex
	for _, detour := range g.outbounds {
		tag := detour.Tag()
		realTag := RealTag(detour)
		if checked[realTag] {
			continue
		}
		history := g.history.LoadURLTestHistory(realTag)
		if !force && !isTimeout(history) && time.Since(history.Time) < g.interval {
			continue
		}
		checked[realTag] = true
		p, loaded := g.outbound.Outbound(realTag)
		if !loaded {
			continue
		}
		b.Go(realTag, func() (any, error) {
			if !force_check_even_previous_not_completed && g.checkingEx.Load() {
				return nil, nil
			}
			t := g.urltestImp(p, ipbatch)
			resultAccess.Lock()
			result[tag] = t
			g.performOutboundUpdateCheck(detour)
			resultAccess.Unlock()
			return nil, nil
		})
	}
	b.Wait()
	ipbatch.Wait()

	g.performUpdateCheck()

	return result, nil
}
func (g *URLTestGroup) urltestImp(outbound adapter.Outbound, ipbatch *batch.Batch[string]) uint16 {
	return CheckOutbound(g.logger, g.ctx, g.history, g.outbound, g.links[g.currentLinkIndex], outbound, ipbatch)
}

func (g *URLTestGroup) hasOneAvailableOutbound() bool {
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), "tcp") {
			continue
		}
		realTag := RealTag(detour)
		history := g.history.LoadURLTestHistory(realTag)
		if isTimeout(history) {
			continue
		}
		g.logger.Debug("has one outbound ", realTag, " available: ", history.Delay, "ms")
		return true
	}
	g.logger.Debug("no available outbound ")
	return false
}

func (g *URLTestGroup) forceUpdateOutbound(tcp adapter.Outbound, udp adapter.Outbound) bool {
	update := false
	if tcp != nil && g.selectedOutboundTCP != tcp {
		g.selectedOutboundTCP = tcp
		// g.tcpConnectionFailureCount.Reset()
		// go g.checkHistoryIp(g.selectedOutboundTCP)
		update = true

	}
	if udp != nil && g.selectedOutboundUDP != udp {
		g.selectedOutboundUDP = udp
		// g.udpConnectionFailureCount.Reset()
		update = true
	}
	if update {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
	return update
}
func (g *URLTestGroup) performOutboundUpdateCheck(outbound adapter.Outbound) {
	tcpOutbound, shouldReselectTCP := g.getPreferredOutbound(outbound, g.selectedOutboundTCP, N.NetworkTCP)
	udpOutbound, shouldReselectUDP := g.getPreferredOutbound(outbound, g.selectedOutboundUDP, N.NetworkUDP)
	if shouldReselectTCP {
		tcpOutbound, _ = g.Select(N.NetworkTCP)
	}
	if shouldReselectUDP {
		udpOutbound, _ = g.Select(N.NetworkUDP)
	}

	g.forceUpdateOutbound(tcpOutbound, udpOutbound)
}

func (g *URLTestGroup) getPreferredOutbound(newOutbound, selectedOutbound adapter.Outbound, networkType string) (outbound adapter.Outbound, shouldReselect bool) {
	if newOutbound == nil {
		return nil, false
	}

	if !common.Contains(newOutbound.Network(), networkType) {
		return nil, false
	}

	newHistory := g.history.LoadURLTestHistory(RealTag(newOutbound))
	if isTimeout(newHistory) {
		if newOutbound == selectedOutbound {
			return nil, true
		}
		return nil, false
	}

	if selectedOutbound == nil {
		return newOutbound, false
	}

	selectedHistory := g.history.LoadURLTestHistory(RealTag(selectedOutbound))
	if isTimeout(selectedHistory) {
		return newOutbound, false
	}

	if newHistory == nil || selectedHistory == nil {
		return nil, false
	}

	if newHistory.Delay+g.tolerance < selectedHistory.Delay {
		return newOutbound, false
	}

	return selectedOutbound, false
}
