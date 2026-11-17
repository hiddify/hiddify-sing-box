package telemost

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kulikov0/headless-client/webrtc"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
)

func hBridge(t *testing.T, iceServers []webrtc.ICEServer) *Bridge {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Bridge{
		ctx:      ctx,
		cancel:   cancel,
		connInfo: &ConnInfo{ConferenceURI: "https://telemost.yandex.ru/j/1", ICEServers: iceServers},
		peers:    make(map[string]string),
		seenPids: make(map[string]bool),
		logger:   logger.NOP(),
	}
}

func hMessage(t *testing.T, message map[string]any) []byte {
	raw, err := json.Marshal(message)
	require.NoError(t, err)
	return raw
}

// A closed relay answers with an error: its peer connections are gone, and the session's
// signalling went on calling into them and crashed the process.
func TestH_ClosedRelayAnswersAnError(t *testing.T) {
	relay := NewSFURelay(logger.NOP())
	require.NoError(t, relay.Init(nil))
	relay.Close()
	relay.Close()
	_, err := relay.SetSubOffer("v=0")
	require.ErrorIs(t, err, errRelayClosed)
	require.ErrorIs(t, relay.SetPubAnswer("v=0"), errRelayClosed)
	_, err = relay.CreatePubOffer()
	require.ErrorIs(t, err, errRelayClosed)
	relay.AddPubICECandidate(webrtc.ICECandidateInit{Candidate: "candidate:1"})
	relay.RemoveSharingDataChannel()
}

// A relay that cannot be made leaves the session without one, and the signalling for it is
// refused: before, the failure was only logged and the next message crashed the process on the
// missing relay.
func TestH_SignallingWithoutARelayIsRefused(t *testing.T) {
	bridge := hBridge(t, []webrtc.ICEServer{{URLs: []string{"not-an-ice-url"}}})
	require.Error(t, bridge.initRelay())
	_, err := bridge.session()
	require.Error(t, err)

	bridge.handleMessage(hMessage(t, map[string]any{"uid": "1", "subscriberSdpOffer": map[string]any{"sdp": "v=0", "pcSeq": 1}}))
	bridge.handleMessage(hMessage(t, map[string]any{"uid": "2", "publisherSdpAnswer": map[string]any{"sdp": "v=0"}}))
	bridge.handleMessage(hMessage(t, map[string]any{"uid": "3", "webrtcIceCandidate": map[string]any{"candidate": "candidate:1", "target": "PUBLISHER"}}))
	bridge.enableScreenshare()
	bridge.disableScreenshare()
}

// A connect that gives up ends the session it started.
func TestH_ClosedBridgeStopsJoining(t *testing.T) {
	bridge := hBridge(t, nil)
	bridge.connInfo.MediaServerURL = "wss://127.0.0.1:1/ws"
	done := make(chan struct{})
	go func() {
		bridge.Run()
		close(done)
	}()
	bridge.Close()
	<-done
}
