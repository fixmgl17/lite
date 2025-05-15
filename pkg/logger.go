package pkg

import (
	"io"
	"os"

	"github.com/mattn/go-isatty"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger(l zapcore.Level, w io.Writer) *zap.SugaredLogger {
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "time"

	if f, ok := w.(*os.File); !ok || os.Getenv("TERM") == "dumb" ||
		(!isatty.IsTerminal(f.Fd()) && !isatty.IsCygwinTerminal(f.Fd())) {
		encoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder
	} else {
		encoderCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	encoderCfg.ConsoleSeparator = "  "
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder := zapcore.NewConsoleEncoder(encoderCfg)
	core := zapcore.NewCore(encoder, zapcore.AddSync(w), l)
	return zap.New(core, zap.AddCaller()).Sugar()
}
