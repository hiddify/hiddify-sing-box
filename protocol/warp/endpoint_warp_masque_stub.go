//go:build !with_masque

package warp

import E "github.com/sagernet/sing/common/exceptions"

func (w *WARPEndpoint) connectMASQUE() {
	w.logger.ErrorContext(w.ctx, E.New(`WARP over MASQUE is not included in this build, rebuild with -tags with_masque`))
}
