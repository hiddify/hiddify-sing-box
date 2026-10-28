//go:build !with_masque

package warp

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const masqueIncluded = false

var errMASQUENotIncluded = E.New(`WARP over MASQUE is not included in this build, rebuild with -tags with_masque`)

func (w *WARPEndpoint) connectMASQUE(done <-chan struct{}, profile *warpProfile) {
	w.fail(errMASQUENotIncluded)
}

func registerMASQUEProfile(ctx context.Context, profile *option.WARPProfile) (*warpProfile, error) {
	return nil, errMASQUENotIncluded
}

func (w *WARPEndpoint) probeMASQUE(ctx context.Context, profile *warpProfile) (time.Duration, error) {
	return 0, errMASQUENotIncluded
}
