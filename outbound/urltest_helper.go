package outbound

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/hiddify/ipinfo"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/batch"
)

func urltestTimeout(ctx context.Context, logger log.Logger, realTag string, outbound adapter.Outbound, url string, history *urltest.HistoryStorage, timeout time.Duration) *urltest.History {
	testCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t, err := urltest.URLTest(testCtx, url, outbound)
	if err != nil || t == 0 {
		t = TimeoutDelay
	}

	his := history.StoreURLTestHistory(realTag, &urltest.History{
		Time:  time.Now(),
		Delay: t,
	})
	logger.Debug("outbound new ping ", realTag, " = ", his.Delay)
	return his
}

func CheckOutbound(logger log.Logger, ctx context.Context, history *urltest.HistoryStorage, router adapter.Router, url string, outbound adapter.Outbound, ipbatch *batch.Batch[string]) uint16 {
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

func CheckIP(logger log.Logger, ctx context.Context, history *urltest.HistoryStorage, router adapter.Router, outbound adapter.Outbound) {
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
	history.AddOnlyIpToHistory(realTag, &urltest.History{
		Time:   time.Now(),
		Delay:  t,
		IpInfo: newip,
	})
}
