package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// maxLogSize bounds the log file, which normally lives in tmpfs.
const maxLogSize = 2 << 20

type cappedFile struct {
	mu   sync.Mutex
	f    *os.File
	size int64
}

func (c *cappedFile) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.size+int64(len(p)) > maxLogSize {
		if err := c.f.Truncate(0); err == nil {
			_, _ = c.f.Seek(0, io.SeekStart)
			c.size = 0
		}
	}
	n, err := c.f.Write(p)
	c.size += int64(n)
	return n, err
}

func newLogger(path, level string) (*slog.Logger, func(), error) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	var (
		w       io.Writer = os.Stderr
		closeFn           = func() {}
	)
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("open log: %w", err)
		}
		st, _ := f.Stat()
		cf := &cappedFile{f: f}
		if st != nil {
			cf.size = st.Size()
		}
		w = cf
		closeFn = func() { _ = f.Close() }
	}
	h := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: lv,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.String("time", a.Value.Time().Format("2006-01-02 15:04:05"))
			}
			return a
		},
	})
	return slog.New(h), closeFn, nil
}
