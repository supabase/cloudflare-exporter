package converge

import (
	"context"
	"io"

	"github.com/sirupsen/logrus"
)

type loggerKeyType struct{}

var loggerKey loggerKeyType

// ContextWithLogger returns a child context carrying the given logrus entry.
func ContextWithLogger(ctx context.Context, l *logrus.Entry) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// LoggerFromContext extracts the logrus entry stored by ContextWithLogger.
// If none is present it returns a silent (discard) entry so callers never
// need a nil check.
func LoggerFromContext(ctx context.Context) *logrus.Entry {
	if l, ok := ctx.Value(loggerKey).(*logrus.Entry); ok {
		return l
	}
	nop := logrus.New()
	nop.SetOutput(io.Discard)
	return logrus.NewEntry(nop)
}
