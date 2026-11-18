package psiphon

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// A Tunnels notice carries its count as a JSON number; anything else is not a count, where the
// type assertion it replaced panicked.
func TestH_NoticeCount(t *testing.T) {
	for _, test := range []struct {
		data  map[string]interface{}
		count float64
		ok    bool
	}{
		{map[string]interface{}{"count": float64(2)}, 2, true},
		{map[string]interface{}{"count": 3}, 3, true},
		{map[string]interface{}{"count": int64(1)}, 1, true},
		{map[string]interface{}{"count": json.Number("4")}, 4, true},
		{map[string]interface{}{"count": "2"}, 0, false},
		{map[string]interface{}{"count": nil}, 0, false},
		{map[string]interface{}{}, 0, false},
		{nil, 0, false},
	} {
		count, ok := noticeCount(test.data)
		require.Equal(t, test.ok, ok, "%v", test.data)
		require.Equal(t, test.count, count, "%v", test.data)
	}
}

// psiphon-tunnel-core has one notice writer for the process. A Psiphon that closes while another
// runs (a reload) must not leave the other deaf: it would never see its Tunnels notice and show
// as connecting with a working tunnel.
func TestH_NoticeHubSurvivesAnotherClose(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	old := &Psiphon{logger: logger, ctx: context.Background()}
	current := &Psiphon{logger: logger, ctx: context.Background()}
	seen := make(chan float64, 4)
	listen := func(p *Psiphon) {
		require.NoError(t, listenNotices(p, func(event NoticeEvent) {
			if event.Type == "Tunnels" {
				if count, ok := noticeCount(event.Data); ok {
					p.setConnected(count > 0)
					if p == current {
						seen <- count
					}
				}
			}
		}))
	}
	listen(old)
	listen(current)
	old.Close() // the old box closes after the new one started

	psiphon.NoticeTunnels(1)
	select {
	case count := <-seen:
		require.Equal(t, float64(1), count)
	case <-time.After(2 * time.Second):
		t.Fatal("the running instance no longer gets notices")
	}
	require.True(t, current.connected.Load())

	stopListeningNotices(current)
	noticeHub.access.Lock()
	require.Empty(t, noticeHub.listeners, "with the last instance gone, a notice goes nowhere")
	noticeHub.access.Unlock()
}

// Notices do not say which controller sent them: next to another instance, a Tunnels notice only
// makes each instance check its own controller, and one without a tunnel stays connecting.
func TestH_NoticeOfAnotherInstance(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	first := &Psiphon{logger: logger, ctx: context.Background()}
	second := &Psiphon{logger: logger, ctx: context.Background()}
	for _, p := range []*Psiphon{first, second} {
		require.NoError(t, listenNotices(p, func(event NoticeEvent) { p.onNotice(event, func() {}) }))
	}
	defer stopListeningNotices(first)
	defer stopListeningNotices(second)

	psiphon.NoticeTunnels(1) // from a controller neither of them has
	time.Sleep(200 * time.Millisecond)
	require.False(t, first.connected.Load(), "another instance's tunnel is not this one's")
	require.False(t, second.connected.Load())

	stopListeningNotices(second)
	psiphon.NoticeTunnels(1) // alone, the notice is its own
	require.Eventually(t, first.connected.Load, time.Second, 10*time.Millisecond)
}

// startProcess puts tunnel-core's notice writer and the hub as a new process has them, with
// startStderr as the stderr of the program's start, and then points os.Stderr at NUL as
// hprocess.DetachStdio does on Windows. Everything is put back after the test, and the hub is
// installed again by the next test that listens.
func startProcess(t *testing.T, startStderr *os.File) {
	stderr := os.Stderr
	os.Stderr = startStderr
	psiphon.ResetNoticeWriter()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	os.Stderr = null
	resetHub := func() {
		noticeHub.access.Lock()
		noticeHub.install = sync.Once{}
		noticeHub.installed = nil
		noticeHub.listeners = nil
		noticeHub.access.Unlock()
	}
	resetHub()
	t.Cleanup(func() {
		os.Stderr = stderr
		psiphon.ResetNoticeWriter()
		resetHub()
		null.Close()
	})
}

// SetNoticeWriter refuses unless the writer is the default, which it finds by comparing with the
// current os.Stderr. The Windows core points os.Stderr at NUL once it is set up
// (hprocess.DetachStdio): the hub then could not be installed and no Psiphon ever connected.
func TestH_NoticeHubInstallsWhenStderrIsReplaced(t *testing.T) {
	startProcess(t, os.Stderr)

	p := &Psiphon{logger: log.NewNOPFactory().Logger(), ctx: context.Background()}
	seen := make(chan struct{}, 1)
	require.NoError(t, listenNotices(p, func(event NoticeEvent) {
		if event.Type == "Tunnels" {
			seen <- struct{}{}
		}
	}))
	psiphon.NoticeTunnels(1)
	select {
	case <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("the installed hub gets no notice")
	}
	stopListeningNotices(p)
}

// Once the hub is installed (PreStart, before tunnel-core runs), a notice with no instance
// listening goes nowhere: not to the stderr of the program's start, on Windows the pipe to the app,
// which reads it for a crash's last lines.
func TestH_NoticeHubKeepsNoticesOffStartStderr(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	defer reader.Close()
	startProcess(t, writer)

	require.NoError(t, installNoticeHub())
	psiphon.NoticeTunnels(0) // a notice with nobody listening
	writer.Close()
	written, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Empty(t, string(written))
}
