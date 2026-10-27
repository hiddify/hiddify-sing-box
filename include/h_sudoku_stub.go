//go:build !with_sudoku

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerSudokuInbound(registry *inbound.Registry) {
	inbound.Register[option.SudokuInboundOptions](registry, C.TypeSudoku, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SudokuInboundOptions) (adapter.Inbound, error) {
		return nil, E.New(`Sudoku is not included in this build, rebuild with -tags with_sudoku`)
	})
}

func registerSudokuOutbound(registry *outbound.Registry) {
	outbound.Register[option.SudokuOutboundOptions](registry, C.TypeSudoku, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SudokuOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`Sudoku is not included in this build, rebuild with -tags with_sudoku`)
	})
}
