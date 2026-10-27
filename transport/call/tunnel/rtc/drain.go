package rtc

import (
	"github.com/sagernet/sing-box/transport/call/common"

	"github.com/kulikov0/headless-client/webrtc"
)

func DrainSenderRTCP(sender *webrtc.RTPSender) {
	common.DrainSenderRTCP(sender)
}

func DrainTrack(track *webrtc.TrackRemote) {
	if track == nil {
		return
	}
	buf := make([]byte, common.UDPBufSize)
	for {
		if _, _, err := track.Read(buf); err != nil {
			return
		}
	}
}
