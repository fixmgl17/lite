package cmd

import (
	"fmt"
	"io"
	"lite/app"
	"lite/common"
	"lite/pkg"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger = pkg.NewLogger(zapcore.DebugLevel, os.Stdout)

func getDefaultConfigFile() string {
	for _, v := range []string{"config.toml", "config.json"} {
		info, err := os.Stat(v)
		if err == nil && !info.IsDir() {
			return v
		}
	}
	return ""
}

func buildLogger(config *app.LogConfig) (logger *zap.SugaredLogger, close func() error, err error) {
	var (
		level  zapcore.Level
		writer io.Writer
	)
	switch strings.ToLower(config.Level) {
	case "debug":
		level = zapcore.DebugLevel
	case "info", "":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	case "fatal":
		level = zapcore.FatalLevel
	default:
		return nil, nil, fmt.Errorf("invalid log level: %s", config.Level)
	}
	if config.Output == "" {
		writer = os.Stdout
	} else if strings.ToLower(config.Output) == "discard" {
		writer = io.Discard
	} else {
		var (
			maxSize int64
			err     error
		)
		if config.MaxSize != "" {
			maxSize, err = pkg.ParseSize(config.MaxSize)
			if err != nil {
				return nil, nil, err
			}
		}
		fw := &fileWriter{
			Path:    config.Output,
			MaxSize: maxSize,
		}
		err = fw.Open()
		if err != nil {
			return nil, nil, err
		}
		writer = fw
		close = fw.Close
	}
	logger = pkg.NewLogger(level, writer)
	return
}

type fileWriter struct {
	file         *os.File
	size         int64
	lastSyncTime time.Time
	Path         string
	MaxSize      int64
}

func (fw *fileWriter) Open() error {
	fw.Close()
	f, err := os.OpenFile(fw.Path, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	fw.file = f
	fw.size = info.Size()
	fw.file.Seek(fw.size, io.SeekStart)
	fw.lastSyncTime = time.Now()
	return nil
}

func (fw *fileWriter) Write(p []byte) (n int, err error) {
	if fw.MaxSize > 0 && int64(len(p))+(fw.size) > fw.MaxSize {
		fw.file.Seek(0, io.SeekStart)
		fw.file.Truncate(0)
		fw.size = 0
	}
	n, err = fw.file.Write(p)
	fw.size += int64(n)
	if time.Since(fw.lastSyncTime) >= 1*time.Second {
		fw.file.Sync()
		fw.lastSyncTime = time.Now()
	}
	return
}

func (fw *fileWriter) Close() error {
	err := common.TryToClose(fw.file)
	fw.file = nil
	return err
}
