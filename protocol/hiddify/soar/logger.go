package soar

import (
	"context"
	"log/slog"
	"strings"

	"github.com/sagernet/sing/common/logger"
)

// slogHandler writes the Soar client's slog records to the outbound's logger at the same level,
// with their attributes as key=value.
type slogHandler struct {
	logger logger.ContextLogger
	attrs  []slog.Attr
}

func newSlogLogger(l logger.ContextLogger) *slog.Logger {
	return slog.New(&slogHandler{logger: l})
}

func (h *slogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *slogHandler) Handle(ctx context.Context, record slog.Record) error {
	var b strings.Builder
	b.WriteString("soar: ")
	b.WriteString(record.Message)
	write := func(attr slog.Attr) bool {
		b.WriteByte(' ')
		b.WriteString(attr.Key)
		b.WriteByte('=')
		b.WriteString(attr.Value.String())
		return true
	}
	for _, attr := range h.attrs {
		write(attr)
	}
	record.Attrs(write)
	message := b.String()
	switch {
	case record.Level >= slog.LevelError:
		h.logger.ErrorContext(ctx, message)
	case record.Level >= slog.LevelWarn:
		h.logger.WarnContext(ctx, message)
	case record.Level >= slog.LevelInfo:
		h.logger.InfoContext(ctx, message)
	default:
		h.logger.DebugContext(ctx, message)
	}
	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &slogHandler{logger: h.logger, attrs: append(append([]slog.Attr(nil), h.attrs...), attrs...)}
}

func (h *slogHandler) WithGroup(string) slog.Handler {
	return h
}
