package transport

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func hCNAMEReply(target string, addresses ...string) func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		response, _ := hReply(addresses...)(ctx, message)
		cname := &mDNS.CNAME{Hdr: mDNS.RR_Header{Name: "example.com.", Rrtype: mDNS.TypeCNAME, Class: mDNS.ClassINET, Ttl: 60}, Target: target}
		response.Answer = append([]mDNS.RR{cname}, response.Answer...)
		return response, nil
	}
}

func hRcode(rcode int) func(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return func(_ context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		return new(mDNS.Msg).SetRcode(message, rcode), nil
	}
}

// A CNAME left alone after ignore_ranges removed the addresses is not an answer to an A query.
func TestH_GroupCNAMEOnlyIsNotAnAnswer(t *testing.T) {
	for _, mode := range []string{"sequential", "parallel"} {
		poisoned := hMember("poisoned", hCNAMEReply("cdn.example.com.", "10.10.34.36"))
		honest := hMember("honest", hDelayed(50e6, hCNAMEReply("cdn.example.com.", "93.184.216.34")))
		group := hNewGroup(t, option.GroupDNSServerOptions{Mode: mode, IgnoreRanges: hPrefixes("10.10.34.0/24")}, poisoned, honest)
		response, err := hExchange(t, group)
		require.NoError(t, err, mode)
		require.Equal(t, []string{"93.184.216.34"}, hAnswerIPs(response), mode)
	}
}

// SERVFAIL and REFUSED are failures of the server; NXDOMAIN is an answer, used when nothing better comes.
func TestH_GroupRcodes(t *testing.T) {
	for _, rcode := range []int{mDNS.RcodeServerFailure, mDNS.RcodeRefused} {
		failing := hMember("failing", hRcode(rcode))
		empty := hMember("empty", hDelayed(50e6, hRcode(mDNS.RcodeNameError)))
		group := hNewGroup(t, option.GroupDNSServerOptions{Mode: "sequential"}, failing, empty)
		response, err := hExchange(t, group)
		require.NoError(t, err)
		require.Equal(t, mDNS.RcodeNameError, response.Rcode, "the failed server's %s is not the answer", mDNS.RcodeToString[rcode])
	}
	only := hNewGroup(t, option.GroupDNSServerOptions{}, hMember("failing", hRcode(mDNS.RcodeServerFailure)))
	_, err := hExchange(t, only)
	require.Error(t, err, "a group whose servers all fail reports an error")
}

func hModeGroup(t *testing.T, mode string, members ...*hGroupMember) *GroupTransport {
	return hNewGroup(t, option.GroupDNSServerOptions{Mode: mode, ErrorTTL: badoption.Duration(time.Minute), WinTTL: badoption.Duration(time.Minute)}, members...)
}

func hCalls(members ...*hGroupMember) []int32 {
	var calls []int32
	for _, member := range members {
		calls = append(calls, member.calls.Load())
	}
	return calls
}

func TestH_GroupStableSticksAndFailsOver(t *testing.T) {
	var aDown atomic.Bool
	a := hMember("a", func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		if aDown.Load() {
			return nil, hErrMember
		}
		return hReply("1.1.1.1")(ctx, message)
	})
	b := hMember("b", hReply("2.2.2.2"))
	group := hModeGroup(t, C.DNSGroupModeStable, a, b)
	for range 3 {
		response, err := hExchange(t, group)
		require.NoError(t, err)
		require.Equal(t, []string{"1.1.1.1"}, hAnswerIPs(response))
	}
	require.Equal(t, []int32{3, 0}, hCalls(a, b), "a stable group asks only its current server")

	aDown.Store(true)
	response, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"2.2.2.2"}, hAnswerIPs(response))
	aDown.Store(false)
	for range 2 {
		response, err = hExchange(t, group)
		require.NoError(t, err)
		require.Equal(t, []string{"2.2.2.2"}, hAnswerIPs(response), "b stays current after a recovers")
	}
	require.Equal(t, []int32{4, 3}, hCalls(a, b))

	group.Reset()
	response, err = hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.1"}, hAnswerIPs(response), "a new network starts from the first server")
}

func TestH_GroupStableHangingServerGetsHalfTheTime(t *testing.T) {
	hanging := hMember("hanging", hHang)
	b := hMember("b", hReply("2.2.2.2"))
	group := hModeGroup(t, C.DNSGroupModeStable, hanging, b)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	response, err := group.Exchange(ctx, new(mDNS.Msg).SetQuestion("example.com.", mDNS.TypeA))
	require.NoError(t, err)
	require.Equal(t, []string{"2.2.2.2"}, hAnswerIPs(response))
	require.Less(t, time.Since(start), 350*time.Millisecond)
	_, err = hExchange(t, group)
	require.NoError(t, err)
	require.EqualValues(t, 1, hanging.calls.Load(), "the hanging server is skipped for error_ttl")
}

func TestH_GroupFastestElectsAndRemembers(t *testing.T) {
	slow := hMember("slow", hDelayed(100*time.Millisecond, hReply("1.1.1.1")))
	fast := hMember("fast", hDelayed(10*time.Millisecond, hReply("2.2.2.2")))
	group := hModeGroup(t, C.DNSGroupModeFastest, slow, fast)
	for range 3 {
		response, err := hExchange(t, group)
		require.NoError(t, err)
		require.Equal(t, []string{"2.2.2.2"}, hAnswerIPs(response))
	}
	require.Equal(t, []int32{1, 3}, hCalls(slow, fast), "only the election asks every server")

	group.modes.access.Lock()
	group.modes.currentUntil = time.Now()
	group.modes.access.Unlock()
	_, err := hExchange(t, group)
	require.NoError(t, err)
	require.Equal(t, []int32{2, 4}, hCalls(slow, fast), "win_ttl ended, so a new election runs")
}

func TestH_GroupModesIgnoredAnswerIsFailure(t *testing.T) {
	poisoned := hMember("poisoned", hReply("10.10.34.36"))
	honest := hMember("honest", hReply("93.184.216.34"))
	group := hNewGroup(t, option.GroupDNSServerOptions{Mode: C.DNSGroupModeStable, IgnoreRanges: hPrefixes("10.10.34.0/24")}, poisoned, honest)
	for range 3 {
		response, err := hExchange(t, group)
		require.NoError(t, err)
		require.Equal(t, []string{"93.184.216.34"}, hAnswerIPs(response))
	}
	require.EqualValues(t, 1, poisoned.calls.Load())
}

func TestH_GroupModesAllFailed(t *testing.T) {
	a := hMember("a", hFail(hErrMember))
	b := hMember("b", hRcode(mDNS.RcodeRefused))
	for _, mode := range []string{C.DNSGroupModeStable, C.DNSGroupModeFastest} {
		group := hModeGroup(t, mode, a, b)
		for range 2 {
			_, err := hExchange(t, group)
			require.Error(t, err, mode)
		}
	}
	require.Equal(t, []int32{4, 4}, hCalls(a, b), "servers that all failed are still asked")
}
