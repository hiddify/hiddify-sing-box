//go:build !with_masque

package warp

import E "github.com/sagernet/sing/common/exceptions"

func (w *WARPEndpoint) connectMASQUE() {
	w.fail(E.New(`WARP over MASQUE is not included in this build, rebuild with -tags with_masque`))
}
