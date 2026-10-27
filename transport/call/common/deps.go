package common

import (
	"github.com/sagernet/sing/common/logger"

	"github.com/kulikov0/headless-client/webrtc"
)

type ResolveFunc func(hostname string) (string, error)

type PeerConnectionConfigurer interface {
	ConfigureSettingEngine(settingEngine *webrtc.SettingEngine)
}

type (
	AddTunnelTracksFunc func(pc *webrtc.PeerConnection, logger logger.ContextLogger, prefix string) *webrtc.TrackLocalStaticSample
	ReadTrackFunc       func(track *webrtc.TrackRemote, handler func([]byte), logger logger.ContextLogger, prefix string)
)
