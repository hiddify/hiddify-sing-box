//go:build with_sudoku

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/sudoku"
)

func registerSudokuInbound(registry *inbound.Registry) {
	sudoku.RegisterInbound(registry)
}

func registerSudokuOutbound(registry *outbound.Registry) {
	sudoku.RegisterOutbound(registry)
}
